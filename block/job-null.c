/*
 * Null Block Job Driver
 *
 * Copyright Red Hat, Inc. 2015
 *
 * Authors:
 *  Jeff Cody   <jcody@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "trace.h"
#include "block/block_int.h"
#include "block/blockjob.h"
#include "qapi/qmp/qerror.h"
#include "qemu/ratelimit.h"

#define NULL_BUFFER_SIZE  (512 * 1024) /* in bytes */

#define SLICE_TIME 100000000ULL /* ns */

typedef struct NullBlockJob {
    BlockJob common;
    RateLimit limit;
} NullBlockJob;


typedef struct {
    int ret;
} NullCompleteData;

static void null_complete(BlockJob *job, void *opaque)
{
    NullBlockJob *s = container_of(job, NullBlockJob, common);
    NullCompleteData *data = opaque;
    int ret = data->ret;

    if (!block_job_is_cancelled(&s->common) && ret == 0) {
        /* success */
    }

    /* do whatever final steps needed */

    block_job_completed(&s->common, ret);
    g_free(data);
}

static void coroutine_fn null_run(void *opaque)
{
    NullBlockJob *s = opaque;
    NullCompleteData *data;
    int64_t sector_num, end;
    int ret = 0;
    int n = 1024;
    void *buf = NULL;

    ret = s->common.len = bdrv_getlength(s->common.bs);

    if (s->common.len < 0) {
        goto out;
    }

    end = s->common.len >> BDRV_SECTOR_BITS;
    buf = qemu_blockalign(s->common.bs, NULL_BUFFER_SIZE);

    for (sector_num = 0; sector_num < end; sector_num += n) {
        uint64_t delay_ns = 0;

wait:
        /* Note that even when no rate limit is applied we need to yield
         * with no pending I/O here so that bdrv_drain_all() returns.
         */
        block_job_sleep_ns(&s->common, QEMU_CLOCK_REALTIME, delay_ns);
        if (block_job_is_cancelled(&s->common)) {
            break;
        }

        if (s->common.speed) {
            delay_ns = ratelimit_calculate_delay(&s->limit, n);
            if (delay_ns > 0) {
                goto wait;
            }
        }

        ret = bdrv_read(s->common.bs, sector_num, buf, n);
        if (ret < 0) {
            goto out;
        }
        /* Publish progress */
        s->common.offset += n * BDRV_SECTOR_SIZE;
    }

    ret = 0;

out:
    qemu_vfree(buf);

    data = g_malloc(sizeof(*data));
    data->ret = ret;
    block_job_defer_to_main_loop(&s->common, null_complete, data);
}


static void null_set_speed(BlockJob *job, int64_t speed, Error **errp)
{
    NullBlockJob *s = container_of(job, NullBlockJob, common);

    if (speed < 0) {
        error_setg(errp, QERR_INVALID_PARAMETER, "speed");
        return;
    }
    ratelimit_set_speed(&s->limit, speed / BDRV_SECTOR_SIZE, SLICE_TIME);
}

static const BlockJobDriver null_job_driver = {
    .instance_size = sizeof(NullBlockJob),
    .job_type      = BLOCK_JOB_TYPE_NULL,
    .set_speed     = null_set_speed,
};

void null_start(BlockDriverState *bs, int64_t speed, BlockCompletionFunc *cb,
                void *opaque, Error **errp)
{
    NullBlockJob *s;
    
    s = block_job_create(&null_job_driver, bs, speed, cb, opaque, errp);
    if (!s) {
        return;
    }

    s->common.co = qemu_coroutine_create(null_run);

    qemu_coroutine_enter(s->common.co, s);
}
