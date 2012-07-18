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

enum {
    /*
     * Size of data buffer for populating the image file.  This should be large
     * enough to process multiple clusters in a single call, so that populating
     * contiguous regions of the image is efficient.
     */
    BLOCK_SIZE = 512 * BDRV_SECTORS_PER_DIRTY_CHUNK, /* in bytes */
};

#define SLICE_TIME 100000000ULL /* ns */

typedef struct MirrorBlockJob {
    BlockJob common;
    RateLimit limit;
    BlockDriverState *target;
    MirrorSyncMode mode;
    BlockdevOnError on_source_error, on_target_error;
    bool synced;
    bool complete;
    int64_t sector_num;
    size_t buf_size;
    unsigned long *cow_bitmap;
    HBitmapIter hbi;
    uint8_t *buf;
} MirrorBlockJob;

static int coroutine_fn mirror_iteration(MirrorBlockJob *s,
                                         BlockErrorAction *p_action)
{
    BlockDriverState *source = s->common.bs;
    BlockDriverState *target = s->target;
    QEMUIOVector qiov;
    int ret, nb_sectors;
    int64_t end, sector_num, cluster_num;
    struct iovec iov;

    s->sector_num = hbitmap_iter_next(&s->hbi);
    if (s->sector_num < 0) {
        bdrv_dirty_iter_init(source, &s->hbi);
        s->sector_num = hbitmap_iter_next(&s->hbi);
        trace_mirror_restart_iter(s, bdrv_get_dirty_count(source));
        assert(s->sector_num >= 0);
    }

    /* If we have no backing file yet in the destination, and the cluster size
     * is very large, we need to do COW ourselves.  The first time a cluster is
     * copied, copy it entirely.
     *
     * Because both BDRV_SECTORS_PER_DIRTY_CHUNK and the cluster size are
     * powers of two, the number of sectors to copy cannot exceed one cluster.
     */
    sector_num = s->sector_num;
    nb_sectors = BDRV_SECTORS_PER_DIRTY_CHUNK;
    cluster_num = sector_num / BDRV_SECTORS_PER_DIRTY_CHUNK;
    if (s->cow_bitmap && !test_bit(cluster_num, s->cow_bitmap)) {
        trace_mirror_cow(s, sector_num);
        bdrv_round_to_clusters(s->target,
                               sector_num, BDRV_SECTORS_PER_DIRTY_CHUNK,
                               &sector_num, &nb_sectors);
        bitmap_set(s->cow_bitmap, sector_num / BDRV_SECTORS_PER_DIRTY_CHUNK,
                   nb_sectors / BDRV_SECTORS_PER_DIRTY_CHUNK);
    }

    end = s->common.len >> BDRV_SECTOR_BITS;
    nb_sectors = MIN(nb_sectors, end - sector_num);
    bdrv_reset_dirty(source, sector_num, nb_sectors);

    /* Copy the dirty cluster.  */
    iov.iov_base = s->buf;
    iov.iov_len  = nb_sectors * 512;
    qemu_iovec_init_external(&qiov, &iov, 1);

    trace_mirror_one_iteration(s, sector_num, nb_sectors);
    ret = bdrv_co_readv(source, sector_num, nb_sectors, &qiov);
    if (ret < 0) {
        *p_action = block_job_error_action(&s->common, source,
                                           s->on_source_error, true, -ret);
        goto fail;
    }
    ret = bdrv_co_writev(target, sector_num, nb_sectors, &qiov);
    if (ret < 0) {
        *p_action = block_job_error_action(&s->common, target,
                                           s->on_target_error, false, -ret);
        s->synced = false;
        goto fail;
    }
    return 0;

fail:
    /* Try again later.  */
    bdrv_set_dirty(source, sector_num, nb_sectors);
    return ret;
}

static void coroutine_fn mirror_run(void *opaque)
{
    MirrorBlockJob *s = opaque;
    BlockDriverState *bs = s->common.bs;
    int64_t sector_num, end, length;
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
            length = (bdrv_getlength(bs) + BLOCK_SIZE - 1) / BLOCK_SIZE;
            s->cow_bitmap = bitmap_new(length);
        }
    }

    end = s->common.len >> BDRV_SECTOR_BITS;
    s->buf = qemu_blockalign(bs, s->buf_size);

    if (s->mode == MIRROR_SYNC_MODE_FULL || s->mode == MIRROR_SYNC_MODE_TOP) {
        /* First part, loop on the sectors and initialize the dirty bitmap.  */
        BlockDriverState *base;
        base = s->mode == MIRROR_SYNC_MODE_FULL ? NULL : bs->backing_hd;
        for (sector_num = 0; sector_num < end; ) {
            int64_t next = (sector_num | (BDRV_SECTORS_PER_DIRTY_CHUNK - 1)) + 1;
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
    for (;;) {
        uint64_t delay_ns;
        int64_t cnt;
        bool should_complete;

        cnt = bdrv_get_dirty_count(bs);
        if (cnt != 0) {
            BlockErrorAction action = BDRV_ACTION_REPORT;
            ret = mirror_iteration(s, &action);
            if (ret < 0 && action == BDRV_ACTION_REPORT) {
                break;
            }
            cnt = bdrv_get_dirty_count(bs);
        }

        if (cnt != 0) {
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
                delay_ns = ratelimit_calculate_delay(&s->limit, BDRV_SECTORS_PER_DIRTY_CHUNK);
            } else {
                delay_ns = 0;
            }

            /* Note that even when no rate limit is applied we need to yield
             * with no pending I/O here so that qemu_aio_flush() returns.
             */
            block_job_sleep_ns(&s->common, rt_clock, delay_ns);
            if (block_job_is_cancelled(&s->common)) {
                break;
            }
        } else if (!should_complete) {
            delay_ns = (cnt == 0 ? SLICE_TIME : 0);
            block_job_sleep_ns(&s->common, rt_clock, delay_ns);
            continue;
        } else if (cnt == 0) {
            /* The two disks are in sync.  Exit and report successful
             * completion.
             */
            assert(QLIST_EMPTY(&bs->tracked_requests));
            s->common.cancelled = false;
            break;
        }
    }

immediate_exit:
    g_free(s->buf);
    g_free(s->cow_bitmap);
    bdrv_set_dirty_tracking(bs, false);
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
                  int64_t speed, MirrorSyncMode mode,
                  BlockdevOnError on_source_error,
                  BlockdevOnError on_target_error,
                  BlockDriverCompletionFunc *cb,
                  void *opaque, Error **errp)
{
    MirrorBlockJob *s;

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
    s->buf_size = BLOCK_SIZE;

    bdrv_set_dirty_tracking(bs, true);
    bdrv_set_on_error(s->target, on_target_error, on_target_error);
    bdrv_iostatus_enable(s->target);
    s->common.co = qemu_coroutine_create(mirror_run);
    trace_mirror_start(bs, s, s->common.co, opaque);
    qemu_coroutine_enter(s->common.co, s);
}
