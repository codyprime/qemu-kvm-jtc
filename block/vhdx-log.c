/*
 * Block driver for Hyper-V VHDX Images
 *
 * Copyright (c) 2013 Red Hat, Inc.,
 *
 * Authors:
 *  Jeff Cody <jcody@redhat.com>
 *
 *  This is based on the "VHDX Format Specification v0.95", published 4/12/2012
 *  by Microsoft:
 *      https://www.microsoft.com/en-us/download/details.aspx?id=29681
 *
 * This file covers the functionality of the metadata log writing, parsing, and
 * replay.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */
#include "qemu-common.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "block/vhdx.h"

/* 
 * All the formats on disk are little endian - the following
 * are helper import/export functions to correctly convert
 * endianness from disk read to native cpu format, and back again.
 */

static void vhdx_desc_le_import(VHDXLogDescriptor *d)
{
    assert(d != NULL);

    le32_to_cpus(&d->signature);
    le32_to_cpus(&d->trailing_bytes);
    le64_to_cpus(&d->leading_bytes);
    le64_to_cpus(&d->file_offset);
    le64_to_cpus(&d->sequence_number);
}

static void vhdx_desc_le_export(VHDXLogDescriptor *d,
                                VHDXLogDescriptor *new_d)
{
    assert(d != NULL);
    assert(new_d != NULL);

    new_d->signature       = cpu_to_le32(d->signature);
    new_d->trailing_bytes  = cpu_to_le32(d->trailing_bytes);
    new_d->leading_bytes   = cpu_to_le64(d->leading_bytes);
    new_d->file_offset     = cpu_to_le64(d->file_offset);
    new_d->sequence_number = cpu_to_le64(d->sequence_number);
}

static void vhdx_entry_hdr_le_import(VHDXLogEntryHeader *hdr)
{
    assert(hdr != NULL);

    le32_to_cpus(&hdr->signature);
    le32_to_cpus(&hdr->checksum);
    le32_to_cpus(&hdr->entry_length);
    le32_to_cpus(&hdr->tail);
    le64_to_cpus(&hdr->sequence_number);
    le32_to_cpus(&hdr->descriptor_count);
    leguid_to_cpus(&hdr->log_guid);
    le64_to_cpus(&hdr->flushed_file_offset);
    le64_to_cpus(&hdr->last_file_offset);
}

static void vhdx_entry_hdr_le_export(VHDXLogEntryHeader *hdr,
                                     VHDXLogEntryHeader *new_hdr)
{
    assert(hdr != NULL);
    assert(new_hdr != NULL);

    new_hdr->signature           = cpu_to_le32(hdr->signature);
    new_hdr->checksum            = cpu_to_le32(hdr->checksum);
    new_hdr->entry_length        = cpu_to_le32(hdr->entry_length);
    new_hdr->tail                = cpu_to_le32(hdr->tail);
    new_hdr->sequence_number     = cpu_to_le64(hdr->sequence_number);
    new_hdr->descriptor_count    = cpu_to_le32(hdr->descriptor_count);
    new_hdr->flushed_file_offset = cpu_to_le64(hdr->flushed_file_offset);
    new_hdr->last_file_offset    = cpu_to_le64(hdr->last_file_offset);
    memcpy(&new_hdr->log_guid, &hdr->log_guid, sizeof(MSGUID));
    cpu_to_leguids(&new_hdr->log_guid);
}

/* The log located on the disk is circular buffer containing
 * sectors of 4096 bytes each.
 *
 * It is assumed for the read/write functions below that the
 * circular buffer scheme uses a 'one sector open' to indicate
 * the buffer is full.  Given the validation methods used for each
 * sector, this method should be compatible with other methods that
 * do not waste a sector.
 */


/* Reads num_sectors from the log (all log sectors are 4096 bytes),
 * into buffer 'buffer'.  Upon return, *sectors_read will contain
 * the number of sectors successfully read.
 *
 * It is assumed that 'buffer' is already allocated, and of sufficient
 * size (i.e. >= 4096*num_sectors).
 *
 * If 'peek' is true, then the tail (read) pointer for the circular buffer is
 * not modified.
 *
 * 0 is returned on success, -errno otherwise.  */
static int vhdx_log_read(BlockDriverState *bs, VHDXLogEntries *log,
                         uint32_t *sectors_read, void *buffer,
                         uint32_t num_sectors, bool peek)
{
    int ret = 0;
    uint64_t offset;
    uint32_t tail;
    uint32_t read = 0;

    tail = log->tail;

    while(num_sectors) {
        if (tail == log->head) {
            /* empty */
            break;
        }
        offset = log->offset + tail;

        tail += VHDX_LOG_SECTOR_SIZE;
        /* we are guaranteed that a) log sectors are 4096 bytes,
         * and b) the log length is a multiple of 1MB. So, there
         * is always a round number of sectors in the buffer */
        tail = (tail >= log->length) ? 0 : tail;

        ret = bdrv_pread(bs->file, offset, buffer, VHDX_LOG_SECTOR_SIZE);
        if (ret < 0) {
            goto exit;
        }
        read++;
        num_sectors--;
        if (!peek) {
            log->tail = tail;
        }
    }

exit:
    *sectors_read = read;
    return ret;
}

/* Writes num_sectors to the log (all log sectors are 4096 bytes),
 * from buffer 'buffer'.  Upon return, *sectors_written will contain
 * the number of sectors successfully written.
 *
 * It is assumed that 'buffer' is at least 4096*num_sectors large.
 *
 * 0 is returned on success, -errno otherwise */
static int vhdx_log_write_sector(BlockDriverState *bs, VHDXLogEntries *log,
                                 uint32_t *sectors_written, void *buffer,
                                 uint32_t num_sectors)
{
    int ret = 0;
    uint64_t offset;
    uint32_t head_tmp;
    uint32_t written = 0;

    while(num_sectors) {
        /* check if we are full */
        head_tmp = log->head + VHDX_LOG_SECTOR_SIZE;
        head_tmp = head_tmp >= log->length ? 0 : head_tmp;
        if (head_tmp == log->tail) {
            /* full */
            break;
        }
        offset = log->offset + log->head;
        ret = bdrv_pwrite_sync(bs->file, offset, 
                               buffer + *sectors_written * VHDX_LOG_SECTOR_SIZE,
                               VHDX_LOG_SECTOR_SIZE);
        if (ret < 0) {
            goto exit;
        }

        log->head = head_tmp;
        written++;
        num_sectors--;
    }

exit:
    *sectors_written = written;
    return ret;
}

#if 0
static int vhdx_log_flush_data_desc()
{
    int ret = 0;

    return ret;
}

static int vhdx_log_flush_desc()
{
    int ret = 0;

    return ret;
}
#endif

/*
 * Given a log header, this will validate that the descriptors and the
 * corresponding data sectors (if applicable)
 *
 * Validation consists of:
 *      1. Making sure the sequence numbers matches the entry header
 *      2. Verifying a valid signature ('zero' or desc' for descriptors)
 *      3. File offset field is a multiple of 4KB
 *      4. If a data descriptor, the corresponding data sector
 *         has its signature ('data') and matching sequence number
 *  
 * 'buffer' is the data buffer containing the descriptor
 * hdr is the log entry header
 * TODO: is the data_desc_count best in here, or by the caller?
 *
 * Returns true if valid
 */
static bool vhdx_log_desc_valid(uint8_t *buffer, VHDXLogEntryHeader hdr,
                                uint32_t *data_desc_count)
{
    bool ret = false;
    VHDXLogDescriptor desc;   /* 32 bytes */
    uint32_t desc_count_extra;
    uint32_t desc_sector_offset = 1;
    uint32_t count = 0;

    memcpy(&desc, buffer, sizeof(desc));
    vhdx_desc_le_import(&desc);

    if (desc.sequence_number != hdr.sequence_number) {
        goto exit;
    }
    if (desc.file_offset % 4096) {
        goto exit;
    }

    if (!memcmp(buffer, "zero", 4)) {
        if (!desc.zero_length % 4096) {
            /* valid */
            ret = true;
            goto exit;
        }
    }

    if (hdr.descriptor_count > 126) {
        desc_count_extra = hdr.descriptor_count - 126;
        desc_sector_offset += desc_count_extra / 128;
        if (desc_count_extra % 128) {
            desc_sector_offset++;
        }
    }

    if (!memcmp(buffer, "desc", 4)) {
        count++;

        /* need to read desc_sector_offset sectors from circular buffer */
    }

exit:
    *data_desc_count = count;
    return ret;
}



static int vhdx_validate_log_entry(BlockDriverState *bs, BDRVVHDXState *s,
                                   VHDXLogEntries *log,
                                   uint64_t offset, uint64_t *seq, bool *valid)
{
    int ret = 0;
    VHDXLogEntryHeader hdr;
    //vhdx_log_entry_info info;
    uint8_t *buffer;
    uint32_t i;
    uint32_t desc_sectors;
    uint32_t sectors_read = 0;
 
    *valid = false;
    ret = vhdx_log_read(bs->file, &s->log, &sectors_read, &hdr, 1, true); 
    if (ret < 0) {
        goto exit;
    }

    vhdx_entry_hdr_le_import(&hdr);

    /* if the individual entry length is larger than the whole log
     * buffer, that is obviously invalid */
    if (log->length > hdr.entry_length) {
        goto exit;
    }

    /* length of entire entry must be in units of 1MB */
    if (hdr.entry_length % (1024*1024)) {
        goto exit;
    }

    /* sequence # must be > 0 */
    if (hdr.sequence_number == 0) {
        goto exit;
    }

    if (*seq > 0) {
        if (hdr.sequence_number != *seq + 1) {
            goto exit;
        }
    }

    if (!guid_eq(hdr.log_guid, s->headers[s->curr_header]->log_guid)) {
        goto exit;
    }

    desc_sectors = hdr.descriptor_count >> 7;
    desc_sectors += 1;  /* to account for the header */

    buffer = qemu_blockalign(bs, desc_sectors);
    ret = vhdx_log_read(bs->file, &s->log, &sectors_read, buffer,
                        desc_sectors, false );
    if (ret < 0) {
        goto free_and_exit;
    }
    if (sectors_read != desc_sectors) {
        goto free_and_exit;
    }
    if (!vhdx_checksum_is_valid(buffer, hdr.entry_length, 4)) {
        goto free_and_exit;
    }
    //info.desc_count = hdr.descriptor_count;

    for (i=0; i < hdr.descriptor_count; i++) {
        /* validate descriptors and data sectors */
    }


    *valid = true;

free_and_exit:
    qemu_vfree(buffer);
exit:
    return ret;
}


/* Search through the log circular buffer, and find the valid, active
 * log sequence, if any exists
 * */
static int vhdx_log_search(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
#if 0
    uint64_t offset = 0;
    uint64_t curr_seq = 0;
    bool seq_valid = false;
    VHDXLogEntryHeader hdr;
    VHDXLogEntries curr_log;

    memcpy(&curr_log, &s->log, sizeof(VHDXLogEntries));
    curr_log.head = curr_log.tail = 0;

    for(;;) {

        offset = s->log.offset + s->log.head;


        ret = vhdx_validate_log_entry(bs, s, &curr_log, offset, &curr_seq,
                                      &seq_valid);
        if (ret < 0) {
            goto exit;
        }
    }

exit:
#endif
    return ret;
}

/* Parse the replay log.  Per the VHDX spec, if the log is present
 * it must be replayed prior to opening the file, even read-only.
 *
 * If read-only, we must replay the log in RAM (or refuse to open
 * a dirty VHDX file read-only */
int vhdx_parse_log(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    int i;
    VHDXHeader *hdr;

    hdr = s->headers[s->curr_header];

    /* either either the log guid, or log length is zero,
     * then a replay log is present */
    for (i = 0; i < sizeof(hdr->log_guid.data4); i++) {
        ret |= hdr->log_guid.data4[i];
    }
    if (hdr->log_guid.data1 == 0 &&
        hdr->log_guid.data2 == 0 &&
        hdr->log_guid.data3 == 0 &&
        ret == 0) {
        goto exit;
    }

    /* per spec, only log version of 0 is supported */
    if (hdr->log_version != 0) {
        ret = -EINVAL;
        goto exit;
    }

    if (hdr->log_length == 0) {
        goto exit;
    }

    s->log.offset = hdr->log_offset;
    s->log.length = hdr->log_length;
    s->log.hdr = qemu_blockalign(bs, sizeof(VHDXLogEntryHeader));

    ret = -ENOTSUP;
    /* now flush the log */
//    return vhdx_log_flush(bs, s);

exit:
    return ret;
}


