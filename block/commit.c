/*
 * Live block commit
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Jeff Cody   <jcody@redhat.com>
 *  Based on stream.c by Stefan Hajnoczi
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "trace.h"
#include "block_int.h"
#include "blockjob.h"
#include "qemu/ratelimit.h"

enum {
    /*
     * Size of data buffer for populating the image file.  This should be large
     * enough to process multiple clusters in a single call, so that populating
     * contiguous regions of the image is efficient.
     */
    COMMIT_BUFFER_SIZE = 512 * 1024, /* in bytes */
};

#define SLICE_TIME 100000000ULL /* ns */

typedef struct CommitBlockJob {
    BlockJob common;
    RateLimit limit;
    BlockDriverState *active;
    BlockDriverState *top;
    BlockDriverState *base;
    BlockdevOnError on_error;
    int base_flags;
    int top_flags;
} CommitBlockJob;

static int coroutine_fn commit_populate(BlockDriverState *bs,
                                        BlockDriverState *base,
                                        int64_t sector_num, int nb_sectors,
                                        void *buf)
{
    if (bdrv_read(bs, sector_num, buf, nb_sectors)) {
        return -EIO;
    }
    if (bdrv_write(base, sector_num, buf, nb_sectors)) {
        return -EIO;
    }
    return 0;
}

static void coroutine_fn commit_run(void *opaque)
{
    CommitBlockJob *s = opaque;
    BlockDriverState *active = s->active;
    BlockDriverState *top = s->top;
    BlockDriverState *base = s->base;
    int64_t sector_num, end;
    int error = 0;
    int ret = 0;
    int n = 0;
    void *buf;
    int bytes_written = 0;

    s->common.len = bdrv_getlength(top);
    if (s->common.len < 0) {
        block_job_completed(&s->common, s->common.len);
        return;
    }

    end = s->common.len >> BDRV_SECTOR_BITS;
    buf = qemu_blockalign(top, COMMIT_BUFFER_SIZE);

    for (sector_num = 0; sector_num < end; sector_num += n) {
        uint64_t delay_ns = 0;
        bool copy;

wait:
        /* Note that even when no rate limit is applied we need to yield
         * with no pending I/O here so that qemu_aio_flush() returns.
         */
        block_job_sleep_ns(&s->common, rt_clock, delay_ns);
        if (block_job_is_cancelled(&s->common)) {
            break;
        }
        /* Copy if allocated above the base */
        ret = bdrv_co_is_allocated_above(top, base, sector_num,
                                         COMMIT_BUFFER_SIZE / BDRV_SECTOR_SIZE,
                                         &n);
        copy = (ret == 1);
        trace_commit_one_iteration(s, sector_num, n, ret);
        if (ret >= 0 && copy) {
            if (s->common.speed) {
                delay_ns = ratelimit_calculate_delay(&s->limit, n);
                if (delay_ns > 0) {
                    goto wait;
                }
            }
            ret = commit_populate(top, base, sector_num, n, buf);
            bytes_written += n * BDRV_SECTOR_SIZE;
        }
        if (ret < 0) {
            BlockErrorAction action =
                block_job_error_action(&s->common, s->common.bs, s->on_error,
                                       true, -ret);
            if (action == BDRV_ACTION_STOP) {
                n = 0;
                continue;
            }
            if (error == 0) {
                error = ret;
            }
            if (action == BDRV_ACTION_REPORT) {
                break;
            }
        }
        ret = 0;

        /* Publish progress */
        s->common.offset += n * BDRV_SECTOR_SIZE;
    }

    if (!block_job_is_cancelled(&s->common) && sector_num == end && ret == 0) {
        /* success */
        if (bdrv_delete_intermediate(active, top, base)) {
            /* something went wrong! */
            /* TODO:add error reporting here */
        }
    }

    /* restore base open flags here if appropriate (e.g., change the base back
     * to r/o) */
    if (s->base_flags != bdrv_get_flags(base)) {
        bdrv_reopen(base, s->base_flags);
    }
    if (s->top_flags != bdrv_get_flags(top)) {
        bdrv_reopen(top, s->top_flags);
    }

    qemu_vfree(buf);
    block_job_completed(&s->common, ret);
}

static void commit_set_speed(BlockJob *job, int64_t speed, Error **errp)
{
    CommitBlockJob *s = container_of(job, CommitBlockJob, common);

    if (speed < 0) {
        error_set(errp, QERR_INVALID_PARAMETER, "speed");
        return;
    }
    ratelimit_set_speed(&s->limit, speed / BDRV_SECTOR_SIZE, SLICE_TIME);
}

static BlockJobType commit_job_type = {
    .instance_size = sizeof(CommitBlockJob),
    .job_type      = "commit",
    .set_speed     = commit_set_speed,
};

void commit_start(BlockDriverState *bs, BlockDriverState *base,
                 BlockDriverState *top, int64_t speed,
                 BlockdevOnError on_error, BlockDriverCompletionFunc *cb,
                 void *opaque, int orig_base_flags, int orig_top_flags,
                 Error **errp)
{
    CommitBlockJob *s;

    if ((on_error == BLOCKDEV_ON_ERROR_STOP ||
         on_error == BLOCKDEV_ON_ERROR_ENOSPC) &&
        !bdrv_iostatus_is_enabled(bs)) {
        error_set(errp, QERR_INVALID_PARAMETER_COMBINATION);
        return;
    }

    s = block_job_create(&commit_job_type, bs, speed, cb, opaque, errp);
    if (!s) {
        return;
    }

    s->base   = base;
    s->top    = top;
    s->active = bs;

    s->base_flags = orig_base_flags;
    s->top_flags  = orig_top_flags;

    s->on_error = on_error;
    s->common.co = qemu_coroutine_create(commit_run);

    trace_commit_start(bs, base, top, s, s->common.co, opaque,
                       orig_base_flags, orig_top_flags);
    qemu_coroutine_enter(s->common.co, s);

    return;
}
