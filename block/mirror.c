/*
 * Image mirroring
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Paolo Bonzini  <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "trace.h"
#include "blockjob.h"
#include "block_int.h"
#include "qemu/ratelimit.h"
#include "bitmap.h"

#define SLICE_TIME    100000000ULL /* ns */
#define MAX_IN_FLIGHT 16

/* The mirroring buffer is a list of granularity-sized chunks.
 * Free chunks are organized in a list.
 */
typedef struct MirrorBuffer {
    QSIMPLEQ_ENTRY(MirrorBuffer) next;
} MirrorBuffer;

typedef struct MirrorBlockJob {
    BlockJob common;
    RateLimit limit;
    BlockDriverState *target;
    MirrorSyncMode mode;
    BlockdevOnError on_source_error, on_target_error;
    bool synced;
    bool complete;
    int64_t sector_num;
    int64_t granularity;
    size_t buf_size;
    unsigned long *cow_bitmap;
    HBitmapIter hbi;
    uint8_t *buf;
    QSIMPLEQ_HEAD(, MirrorBuffer) buf_free;
    int buf_free_count;

    unsigned long *in_flight_bitmap;
    int in_flight;
    int ret;
} MirrorBlockJob;

typedef struct MirrorOp {
    MirrorBlockJob *s;
    QEMUIOVector qiov;
    int64_t sector_num;
    int nb_sectors;
} MirrorOp;

static void mirror_iteration_done(MirrorOp *op)
{
    MirrorBlockJob *s = op->s;
    struct iovec *iov;
    int64_t cluster_num;
    int i, nb_chunks;

    s->in_flight--;
    iov = op->qiov.iov;
    for (i = 0; i < op->qiov.niov; i++) {
        MirrorBuffer *buf = (MirrorBuffer *) iov[i].iov_base;
        QSIMPLEQ_INSERT_TAIL(&s->buf_free, buf, next);
        s->buf_free_count++;
    }

    cluster_num = op->sector_num / s->granularity;
    nb_chunks = op->nb_sectors / s->granularity;
    bitmap_clear(s->in_flight_bitmap, cluster_num, nb_chunks);

    trace_mirror_iteration_done(s, op->sector_num, op->nb_sectors);
    g_slice_free(MirrorOp, op);
    qemu_coroutine_enter(s->common.co, NULL);
}

static void mirror_write_complete(void *opaque, int ret)
{
    MirrorOp *op = opaque;
    MirrorBlockJob *s = op->s;
    BlockDriverState *source = s->common.bs;
    BlockDriverState *target = s->target;
    BlockErrorAction action;

    if (ret < 0) {
        bdrv_set_dirty(source, op->sector_num, op->nb_sectors);
        action = block_job_error_action(&s->common, target, s->on_target_error,
                                        false, -ret);
        if (action == BDRV_ACTION_REPORT && s->ret >= 0) {
            s->ret = ret;
        }
    }
    mirror_iteration_done(op);
}

static void mirror_read_complete(void *opaque, int ret)
{
    MirrorOp *op = opaque;
    MirrorBlockJob *s = op->s;
    BlockDriverState *source = s->common.bs;
    BlockDriverState *target = s->target;
    BlockErrorAction action;
    if (ret < 0) {
        bdrv_set_dirty(source, op->sector_num, op->nb_sectors);
        action = block_job_error_action(&s->common, source, s->on_source_error,
                                        true, -ret);
        if (action == BDRV_ACTION_REPORT && s->ret >= 0) {
            s->ret = ret;
        }

        mirror_iteration_done(op);
        return;
    }
    bdrv_aio_writev(target, op->sector_num, &op->qiov, op->nb_sectors,
                    mirror_write_complete, op);
}

static void coroutine_fn mirror_iteration(MirrorBlockJob *s)
{
    BlockDriverState *source = s->common.bs;
    int nb_sectors, nb_sectors_chunk, nb_chunks;
    int64_t end, sector_num, next_cluster, next_sector, hbitmap_next_sector;
    MirrorOp *op;

    s->sector_num = hbitmap_iter_next(&s->hbi);
    if (s->sector_num < 0) {
        bdrv_dirty_iter_init(source, &s->hbi);
        s->sector_num = hbitmap_iter_next(&s->hbi);
        trace_mirror_restart_iter(s, bdrv_get_dirty_count(source));
        assert(s->sector_num >= 0);
    }

    hbitmap_next_sector = s->sector_num;
    sector_num = s->sector_num;
    nb_sectors_chunk = s->granularity >> BDRV_SECTOR_BITS;
    end = s->common.len >> BDRV_SECTOR_BITS;

    /* Extend the QEMUIOVector to include all adjacent blocks that will
     * be copied in this operation.
     *
     * We have to do this if we have no backing file yet in the destination,
     * and the cluster size is very large.  Then we need to do COW ourselves.
     * The first time a cluster is copied, copy it entirely.  Note that,
     * because both the granularity and the cluster size are powers of two,
     * the number of sectors to copy cannot exceed one cluster.
     *
     * We also want to extend the QEMUIOVector to include more adjacent
     * dirty blocks if possible, to limit the number of I/O operations and
     * run efficiently even with a small granularity.
     */
    nb_chunks = 0;
    nb_sectors = 0;
    next_sector = sector_num;
    next_cluster = sector_num / nb_sectors_chunk;

    /* Wait for I/O to this cluster (from a previous iteration) to be done.  */
    while (test_bit(next_cluster, s->in_flight_bitmap)) {
        trace_mirror_yield_in_flight(s, sector_num, s->in_flight);
        qemu_coroutine_yield();
    }

    do {
        int added_sectors, added_chunks;

        if (!bdrv_get_dirty(source, next_sector) ||
            test_bit(next_cluster, s->in_flight_bitmap)) {
            assert(nb_sectors > 0);
            break;
        }

        added_sectors = nb_sectors_chunk;
        if (s->cow_bitmap && !test_bit(next_cluster, s->cow_bitmap)) {
            bdrv_round_to_clusters(s->target,
                                   next_sector, added_sectors,
                                   &next_sector, &added_sectors);

            /* On the first iteration, the rounding may make us copy
             * sectors before the first dirty one.
             */
            if (next_sector < sector_num) {
                assert(nb_sectors == 0);
                sector_num = next_sector;
                next_cluster = next_sector / nb_sectors_chunk;
            }
        }

        added_sectors = MIN(added_sectors, end - (sector_num + nb_sectors));
        added_chunks = (added_sectors + nb_sectors_chunk - 1) / nb_sectors_chunk;

        /* When doing COW, it may happen that there is not enough space for
         * a full cluster.  Wait if that is the case.
         */
        while (nb_chunks == 0 && s->buf_free_count < added_chunks) {
            trace_mirror_yield_buf_busy(s, nb_chunks, s->in_flight);
            qemu_coroutine_yield();
        }
        if (s->buf_free_count < nb_chunks + added_chunks) {
            trace_mirror_break_buf_busy(s, nb_chunks, s->in_flight);
            break;
        }

        /* We have enough free space to copy these sectors.  */
        if (s->cow_bitmap) {
            bitmap_set(s->cow_bitmap, next_cluster, added_chunks);
        }
        nb_sectors += added_sectors;
        nb_chunks += added_chunks;
        next_sector += added_sectors;
        next_cluster += added_chunks;
    } while (next_sector < end);

    /* Allocate a MirrorOp that is used as an AIO callback.  */
    op = g_slice_new(MirrorOp);
    op->s = s;
    op->sector_num = sector_num;
    op->nb_sectors = nb_sectors;

    /* Now make a QEMUIOVector taking enough granularity-sized chunks
     * from s->buf_free.
     */
    qemu_iovec_init(&op->qiov, nb_chunks);
    next_sector = sector_num;
    while (nb_chunks-- > 0) {
        MirrorBuffer *buf = QSIMPLEQ_FIRST(&s->buf_free);
        QSIMPLEQ_REMOVE_HEAD(&s->buf_free, next);
        s->buf_free_count--;
        qemu_iovec_add(&op->qiov, buf, s->granularity);

        /* Advance the HBitmapIter in parallel, so that we do not examine
         * the same sector twice.
         */
        if (next_sector > hbitmap_next_sector && bdrv_get_dirty(source, next_sector)) {
            hbitmap_next_sector = hbitmap_iter_next(&s->hbi);
        }

        next_sector += nb_sectors_chunk;
    }

    bdrv_reset_dirty(source, sector_num, nb_sectors);

    /* Copy the dirty cluster.  */
    s->in_flight++;
    trace_mirror_one_iteration(s, sector_num, nb_sectors);
    bdrv_aio_readv(source, sector_num, &op->qiov, nb_sectors,
                   mirror_read_complete, op);
}

static void mirror_free_init(MirrorBlockJob *s)
{
    int granularity = s->granularity;
    size_t buf_size = s->buf_size;
    uint8_t *buf = s->buf;

    assert(s->buf_free_count == 0);
    QSIMPLEQ_INIT(&s->buf_free);
    while (buf_size != 0) {
        MirrorBuffer *cur = (MirrorBuffer *)buf;
        QSIMPLEQ_INSERT_TAIL(&s->buf_free, cur, next);
        s->buf_free_count++;
        buf_size -= granularity;
        buf += granularity;
    }
}

static void coroutine_fn mirror_run(void *opaque)
{
    MirrorBlockJob *s = opaque;
    BlockDriverState *bs = s->common.bs;
    int64_t sector_num, end, nb_sectors_chunk, length;
    uint64_t last_pause_ns;
    BlockDriverInfo bdi;
    char backing_filename[1024];
    int ret = 0;
    int n;

    if (block_job_is_cancelled(&s->common)) {
        goto immediate_exit;
    }

    s->common.len = bdrv_getlength(bs);
    if (s->common.len < 0) {
        block_job_completed(&s->common, s->common.len);
        return;
    }

    length = (bdrv_getlength(bs) + s->granularity - 1) / s->granularity;
    s->in_flight_bitmap = bitmap_new(length);

    /* If we have no backing file yet in the destination, we cannot let
     * the destination do COW.  Instead, we copy sectors around the
     * dirty data if needed.  We need a bitmap to do that.
     */
    bdrv_get_backing_filename(s->target, backing_filename,
                              sizeof(backing_filename));
    if (backing_filename[0] && !s->target->backing_hd) {
        bdrv_get_info(s->target, &bdi);
        if (s->buf_size < bdi.cluster_size) {
            s->buf_size = bdi.cluster_size;
            s->cow_bitmap = bitmap_new(length);
        }
    }

    end = s->common.len >> BDRV_SECTOR_BITS;
    s->buf = qemu_blockalign(bs, s->buf_size);
    nb_sectors_chunk = s->granularity >> BDRV_SECTOR_BITS;
    mirror_free_init(s);

    if (s->mode == MIRROR_SYNC_MODE_FULL || s->mode == MIRROR_SYNC_MODE_TOP) {
        /* First part, loop on the sectors and initialize the dirty bitmap.  */
        BlockDriverState *base;
        base = s->mode == MIRROR_SYNC_MODE_FULL ? NULL : bs->backing_hd;
        for (sector_num = 0; sector_num < end; ) {
            int64_t next = (sector_num | (nb_sectors_chunk - 1)) + 1;
            ret = bdrv_co_is_allocated_above(bs, base,
                                             sector_num, next - sector_num, &n);

            if (ret < 0) {
                break;
            } else if (ret == 1) {
                bdrv_set_dirty(bs, sector_num, n);
                sector_num = next;
            } else {
                sector_num += n;
            }
        }
    }

    if (ret < 0) {
        goto immediate_exit;
    }

    bdrv_dirty_iter_init(bs, &s->hbi);
    last_pause_ns = qemu_get_clock_ns(rt_clock);
    for (;;) {
        uint64_t delay_ns;
        int64_t cnt;
        bool should_complete;

        if (s->ret < 0) {
            ret = s->ret;
            break;
        }

        cnt = bdrv_get_dirty_count(bs);

        /* Note that even when no rate limit is applied we need to yield
         * periodically with no pending I/O so that qemu_aio_flush() returns.
         * We do so every SLICE_TIME milliseconds, or when the source is
         * clean, whichever comes first.
         */
        if (qemu_get_clock_ns(rt_clock) - last_pause_ns < SLICE_TIME) {
            if (s->in_flight == MAX_IN_FLIGHT || s->buf_free_count == 0 ||
                (cnt == 0 && s->in_flight > 0)) {
                trace_mirror_yield(s, s->in_flight, s->buf_free_count, cnt);
                qemu_coroutine_yield();
                continue;
            } else if (cnt != 0) {
                mirror_iteration(s);
                continue;
            }
        }

        if (s->in_flight > 0 || cnt != 0) {
            should_complete = false;
        } else {
            trace_mirror_before_flush(s);
            bdrv_flush(s->target);

            /* We're out of the streaming phase.  From now on, if the
             * job is cancelled we will actually complete all pending
             * I/O and report completion, so that drive-reopen can be
             * used to pivot to the mirroring target.
             */
            s->synced = true;
            s->common.offset = end * BDRV_SECTOR_SIZE;

            should_complete = block_job_is_cancelled(&s->common) || s->complete;
            if (should_complete) {
                /* The dirty bitmap is not updated while operations are pending.
                 * If we're about to exit, wait for pending operations before
                 * calling bdrv_get_dirty_count(bs), or we may exit while the
                 * source has dirty data to copy!
                 *
                 * Note that I/O can be submitted by the guest while
                 * mirror_populate runs.
                 */
                trace_mirror_before_drain(s, cnt);
                bdrv_drain_all();
            }
            cnt = bdrv_get_dirty_count(bs);
        }

        ret = 0;
        trace_mirror_before_sleep(s, cnt, s->synced);
        if (!s->synced) {
            /* Publish progress */
            s->common.offset = (end - cnt) * BDRV_SECTOR_SIZE;

            if (s->common.speed) {
                delay_ns = ratelimit_calculate_delay(&s->limit, nb_sectors_chunk);
            } else {
                delay_ns = 0;
            }

            block_job_sleep_ns(&s->common, rt_clock, delay_ns);
            if (block_job_is_cancelled(&s->common)) {
                break;
            }
        } else if (!should_complete) {
            delay_ns = (s->in_flight == 0 && cnt == 0 ? SLICE_TIME : 0);
            block_job_sleep_ns(&s->common, rt_clock, delay_ns);
        } else if (cnt == 0) {
            /* The two disks are in sync.  Exit and report successful
             * completion.
             */
            assert(s->in_flight == 0);
            assert(QLIST_EMPTY(&bs->tracked_requests));
            s->common.cancelled = false;
            break;
        }
        last_pause_ns = qemu_get_clock_ns(rt_clock);
    }

immediate_exit:
    g_free(s->buf);
    g_free(s->cow_bitmap);
    g_free(s->in_flight_bitmap);
    bdrv_set_dirty_tracking(bs, 0);
    bdrv_iostatus_disable(s->target);
    if (s->complete && ret == 0) {
        bdrv_swap(s->target, s->common.bs);
    } else {
        bdrv_close(s->target);
    }
    bdrv_delete(s->target);
    block_job_completed(&s->common, ret);
}

static void mirror_set_speed(BlockJob *job, int64_t speed, Error **errp)
{
    MirrorBlockJob *s = container_of(job, MirrorBlockJob, common);

    if (speed < 0) {
        error_set(errp, QERR_INVALID_PARAMETER, "speed");
        return;
    }
    ratelimit_set_speed(&s->limit, speed / BDRV_SECTOR_SIZE, SLICE_TIME);
}

static void mirror_iostatus_reset(BlockJob *job)
{
    MirrorBlockJob *s = container_of(job, MirrorBlockJob, common);

    bdrv_iostatus_reset(s->target);
}

static void mirror_query(BlockJob *job, BlockJobInfo *info)
{
    MirrorBlockJob *s = container_of(job, MirrorBlockJob, common);

    info->has_target = true;
    info->target = g_new0(BlockJobTargetInfo, 1);
    info->target->info = bdrv_query_info(s->target);
    info->target->stats = bdrv_query_stats(s->target);
}

static void mirror_complete(BlockJob *job, Error **errp)
{
    MirrorBlockJob *s = container_of(job, MirrorBlockJob, common);
    int ret;

    ret = bdrv_ensure_backing_file(s->target);
    if (ret < 0) {
        char backing_filename[PATH_MAX];
        bdrv_get_full_backing_filename(s->target, backing_filename,
                                       sizeof(backing_filename));
        error_set(errp, QERR_OPEN_FILE_FAILED, backing_filename);
        return;
    }
    if (!s->synced) {
        error_set(errp, QERR_BLOCK_JOB_NOT_READY, job->bs->device_name);
        return;
    }

    s->complete = true;
    block_job_resume(job);
}

static BlockJobType mirror_job_type = {
    .instance_size = sizeof(MirrorBlockJob),
    .job_type      = "mirror",
    .set_speed     = mirror_set_speed,
    .iostatus_reset= mirror_iostatus_reset,
    .query         = mirror_query,
    .complete      = mirror_complete,
};

void mirror_start(BlockDriverState *bs, BlockDriverState *target,
                  int64_t speed, int64_t granularity, int64_t buf_size,
                  MirrorSyncMode mode, BlockdevOnError on_source_error,
                  BlockdevOnError on_target_error,
                  BlockDriverCompletionFunc *cb,
                  void *opaque, Error **errp)
{
    MirrorBlockJob *s;

    assert ((granularity & (granularity - 1)) == 0);

    if ((on_source_error == BLOCKDEV_ON_ERROR_STOP ||
         on_source_error == BLOCKDEV_ON_ERROR_ENOSPC) &&
        !bdrv_iostatus_is_enabled(bs)) {
        error_set(errp, QERR_INVALID_PARAMETER, "on-source-error");
        return;
    }

    s = block_job_create(&mirror_job_type, bs, speed, cb, opaque, errp);
    if (!s) {
        return;
    }

    s->on_source_error = on_source_error;
    s->on_target_error = on_target_error;
    s->target = target;
    s->mode = mode;
    s->granularity = granularity;
    s->buf_size = MAX(buf_size, granularity);

    bdrv_set_dirty_tracking(bs, granularity >> BDRV_SECTOR_BITS);
    bdrv_set_on_error(s->target, on_target_error, on_target_error);
    bdrv_iostatus_enable(s->target);
    s->common.co = qemu_coroutine_create(mirror_run);
    trace_mirror_start(bs, s, s->common.co, opaque);
    qemu_coroutine_enter(s->common.co, s);
}
