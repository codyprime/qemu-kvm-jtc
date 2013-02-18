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
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include "qemu-common.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "migration/migration.h"
#if defined(CONFIG_UUID)
#include <uuid/uuid.h>
#endif
#include "qemu/crc32c.h"
#include "block/vhdx.h"

#define vhdx_nop(x) do { (void)(x); } while (0)

/* Help macros to copy data from file buffers to header
 * structures, with proper endianness.  These help avoid
 * using packed structs */

/* Do not use directly, see macros below */
#define _hdr_copy(item, buf, size, offset, to_cpu) \
    memcpy((item), (buf)+(offset), (size));        \
    to_cpu((item));                                \
    (offset) += (size);

/* for all of these, buf should be a uint8_t buffer */

/* copy 16-bit header field */
#define hdr_copy16(item, buf, offset) \
    _hdr_copy((item), (buf), 2, (offset), (le16_to_cpus))

/* copy 32-bit header field */
#define hdr_copy32(item, buf, offset) \
    _hdr_copy((item), (buf), 4, (offset), (le32_to_cpus))

/* copy 64-bit header field */
#define hdr_copy64(item, buf, offset) \
    _hdr_copy((item), (buf), 8, (offset), (le64_to_cpus))

/* copy variable-length header field, no endian swapping */
#define hdr_copy(item, buf, size, offset) \
    _hdr_copy((item), (buf), (size), (offset), vhdx_nop)

/* copies a defined msguid field, with correct endianness
 * a msguid entry has 3 data types with endianness sensitivity,
 * followed by a byte array */
#define hdr_copy_guid(item, buf, offset)             \
        hdr_copy32(&(item).data1, (buf), (offset));  \
        hdr_copy16(&(item).data2, (buf), (offset));  \
        hdr_copy16(&(item).data3, (buf), (offset));  \
        hdr_copy(&(item).data4, (buf), sizeof((item).data4), (offset));


/* Several metadata and region table data entries are identified by
 * guids in  a MS-specific GUID format. */


/* ------- Known Region Table GUIDs ---------------------- */
static const ms_guid bat_guid =      { .data1 = 0x2dc27766,
                                       .data2 = 0xf623,
                                       .data3 = 0x4200,
                                       .data4 = { 0x9d, 0x64, 0x11, 0x5e,
                                                  0x9b, 0xfd, 0x4a, 0x08}};

static const ms_guid metadata_guid = { .data1 = 0x8b7ca206,
                                       .data2 = 0x4790,
                                       .data3 = 0x4b9a,
                                       .data4 = { 0xb8, 0xfe, 0x57, 0x5f,
                                                  0x05, 0x0f, 0x88, 0x6e}};



/* ------- Known Metadata Entry GUIDs ---------------------- */
static const ms_guid file_param_guid =   { .data1 = 0xcaa16737,
                                           .data2 = 0xfa36,
                                           .data3 = 0x4d43,
                                           .data4 = { 0xb3, 0xb6, 0x33, 0xf0,
                                                      0xaa, 0x44, 0xe7, 0x6b}};

static const ms_guid virtual_size_guid = { .data1 = 0x2FA54224,
                                           .data2 = 0xcd1b,
                                           .data3 = 0x4876,
                                           .data4 = { 0xb2, 0x11, 0x5d, 0xbe,
                                                      0xd8, 0x3b, 0xf4, 0xb8}};

static const ms_guid page83_guid =       { .data1 = 0xbeca12ab,
                                           .data2 = 0xb2e6,
                                           .data3 = 0x4523,
                                           .data4 = { 0x93, 0xef, 0xc3, 0x09,
                                                      0xe0, 0x00, 0xc7, 0x46}};

static const ms_guid logical_sector_guid = {.data1 = 0x8141bf1d,
                                            .data2 = 0xa96f,
                                            .data3 = 0x4709,
                                            .data4 = { 0xba, 0x47, 0xf2, 0x33,
                                                       0xa8, 0xfa, 0xab, 0x5f}};

static const ms_guid phys_sector_guid =  { .data1 = 0xcda348c7,
                                           .data2 = 0x445d,
                                           .data3 = 0x4471,
                                           .data4 = { 0x9c, 0xc9, 0xe9, 0x88,
                                                      0x52, 0x51, 0xc5, 0x56}};

static const ms_guid parent_locator_guid = {.data1 = 0xa8d35f2d,
                                            .data2 = 0xb30b,
                                            .data3 = 0x454d,
                                            .data4 = { 0xab, 0xf7, 0xd3, 0xd8,
                                                       0x48, 0x34, 0xab, 0x0c}};



#define META_FILE_PARAMETER_PRESENT      0x01
#define META_VIRTUAL_DISK_SIZE_PRESENT   0x02
#define META_PAGE_83_PRESENT             0x04
#define META_LOGICAL_SECTOR_SIZE_PRESENT 0x08
#define META_PHYS_SECTOR_SIZE_PRESENT    0x10
#define META_PARENT_LOCATOR_PRESENT      0x20

#define META_ALL_PRESENT    \
    (META_FILE_PARAMETER_PRESENT | META_VIRTUAL_DISK_SIZE_PRESENT | \
     META_PAGE_83_PRESENT | META_LOGICAL_SECTOR_SIZE_PRESENT | \
     META_PHYS_SECTOR_SIZE_PRESENT)

typedef struct vhdx_metadata_entries {
    vhdx_metadata_table_entry file_parameters_entry;
    vhdx_metadata_table_entry virtual_disk_size_entry;
    vhdx_metadata_table_entry page83_data_entry;
    vhdx_metadata_table_entry logical_sector_size_entry;
    vhdx_metadata_table_entry phys_sector_size_entry;
    vhdx_metadata_table_entry parent_locator_entry;
    uint16_t present;
} vhdx_metadata_entries;


typedef struct BDRVVHDXState {
    CoMutex lock;

    int curr_header;
    vhdx_header *headers[2];

    vhdx_region_table_header rt;
    vhdx_region_table_entry bat_rt;         /* region table for the BAT */
    vhdx_region_table_entry metadata_rt;    /* region table for the metadata */
    vhdx_region_table_entry *unknown_rt;
    unsigned int unknown_rt_size;

    vhdx_metadata_table_header  metadata_hdr;
    vhdx_metadata_entries metadata_entries;

    vhdx_file_parameters params;

    uint64_t virtual_disk_size;
    uint32_t logical_sector_size;
    uint32_t physical_sector_size;

    uint8_t region_table_buf[VHDX_HEADER_BLOCK_SIZE];

    /* TODO */

} BDRVVHDXState;

/* CRC-32C, Castagnoli polynomial, code 0x11EDC6F41 */
static uint32_t vhdx_checksum(uint8_t *buf, size_t size)
{
    uint32_t chksum;
    chksum =  crc32c(0xffffffff, buf, size);

    return chksum;
}

/* validates the checksum of a region of table entries, substituting zero
 * in for the in-place checksum field of the region.
 * buf: buffer to compute crc32c over,
 * size: size of the buffer to checksum
 * crc_offset: offset into buf that contains the existing 4-byte checksum
 */
static int vhdx_validate_checksum(uint8_t *buf, size_t size, int crc_offset)
{
    uint32_t crc_orig;
    uint32_t crc;

    assert(buf != NULL);
    assert(size > (crc_offset+4));

    memcpy(&crc_orig, buf+crc_offset, sizeof(crc_orig));
    memset(buf+crc_offset, 0, sizeof(crc_orig));

    crc = vhdx_checksum(buf, size);

    memcpy(buf+crc_offset, &crc_orig, sizeof(crc_orig));

    crc_orig = le32_to_cpu(crc_orig);
    return crc == crc_orig ? 0 : 1;
}

/*
 * Per the MS VHDX Specification, for every VHDX file:
 *      - The header section is fixed size - 1 MB
 *      - The header section is always the first "object"
 *      - The first 64KB of the header is the File Identifier
 *      - The first uint64 (8 bytes) is the VHDX Signature ("vhdxfile")
 *      - The following 512 bytes constitute a UTF-16 string identifiying the
 *        software that created the file, and is optional and diagnostic only.
 *
 *  Therefore, we probe by looking for the vhdxfile signature "vhdxfile"
 */
static int vhdx_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    if (buf_size >= 8 && !strncmp((char *)buf, "vhdxfile", 8)) {
        return 100;
    }
    return 0;
}

static void vhdx_print_header(vhdx_header *h)
{
#if 0
    int i;

    printf("\n===== VHDX Header ==================================================\n");
    printf("signature: 0x%" PRIx32 "\n", h->signature);
    printf("checksum: 0x%" PRIx32 "\n", h->checksum);
    printf("sequence_number: 0x%" PRIx64 "\n", h->sequence_number);
    printf("file_write_guid: 0x");
    for (i=0; i<16; i++) {
        printf("%" PRIx8, h->file_write_guid[i]);
    }
    printf("\ndata_write_guid: 0x");
    for (i=0; i<16; i++) {
        printf("%" PRIx8, h->data_write_guid[i]);
    }
    printf("\nlog_guid: 0x");
    for (i=0; i<16; i++) {
        printf("%" PRIx8, h->log_guid[i]);
    }
    printf("\nlog_version: 0x%" PRIx16 "\n", h->log_version);
    printf("version: 0x%" PRIx16 "\n", h->version);
    printf("log_length: 0x%" PRIx32 "\n", h->log_length);
    printf("log_offset: 0x%" PRIx64 "\n", h->log_offset);
    printf("==========================================================================\n\n");
#endif
}


static void vhdx_fill_header(vhdx_header *h, uint8_t *buffer)
{
    int offset=0;
    assert(h != NULL);
    assert(buffer != NULL);

    /* use memcpy to avoid unaligned data read */
    hdr_copy32(&h->signature,       buffer, offset);
    hdr_copy32(&h->checksum,        buffer, offset);
    hdr_copy64(&h->sequence_number, buffer, offset);

    hdr_copy_guid(h->file_write_guid, buffer, offset);
    hdr_copy_guid(h->data_write_guid, buffer, offset);
    hdr_copy_guid(h->log_guid, buffer, offset);

    hdr_copy16(&h->log_version,     buffer,  offset);
    hdr_copy16(&h->version,         buffer,  offset);
    hdr_copy32(&h->log_length,      buffer,  offset);
    hdr_copy64(&h->log_offset,      buffer,  offset);
}


/* opens the specified header block from the VHDX file header section */
static int vhdx_parse_header(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    vhdx_header *header1;
    vhdx_header *header2;
    uint64_t h1_seq = 0;
    uint64_t h2_seq = 0;
    uint8_t *buffer;

    header1 = g_malloc(sizeof(vhdx_header));
    header2 = g_malloc(sizeof(vhdx_header));

    buffer = g_malloc(VHDX_HEADER_SIZE);

    s->headers[0] = header1;
    s->headers[1] = header2;

    ret = bdrv_pread(bs->file, VHDX_HEADER1_OFFSET, buffer, VHDX_HEADER_SIZE);
    if (ret < 0) {
        goto fail;
    }
    vhdx_fill_header(header1, buffer);

    vhdx_print_header(header1);

    if (vhdx_validate_checksum(buffer, VHDX_HEADER_SIZE, 4) == 0 &&
        header1->signature == VHDX_HDR_MAGIC) {
        printf("header1 is valid!\n");
        h1_seq = header1->sequence_number;
    }

    ret = bdrv_pread(bs->file, VHDX_HEADER2_OFFSET, buffer, VHDX_HEADER_SIZE);
    if (ret < 0) {
        goto fail;
    }
    vhdx_fill_header(header2, buffer);

    vhdx_print_header(header2);

    if (vhdx_validate_checksum(buffer, VHDX_HEADER_SIZE, 4) == 0 &&
        header2->signature == VHDX_HDR_MAGIC) {
        printf("header2 is valid!\n");
        h2_seq = header2->sequence_number;
    }

    if (h1_seq > h2_seq) {
        s->curr_header = 0;
    } else if (h2_seq > h1_seq) {
        s->curr_header = 1;
    } else {
        printf("NO VALID HEADER\n");
        ret = -1;
    }
    printf("current header is %d\n",s->curr_header);
    goto exit;

fail:
    g_free(header1);
    g_free(header2);
    s->headers[0] = NULL;
    s->headers[1] = NULL;
exit:
    g_free(buffer);
    return ret;
}

static int vhdx_open_region_tables(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    uint8_t *buffer;
    int offset = 0;
    vhdx_region_table_entry rt_entry;
    int i;

    /* We have to read the whole 64KB block, because the crc32 is over the
     * whole block */
    buffer = g_malloc(VHDX_HEADER_BLOCK_SIZE);

    printf("reading region tables...\n");
    ret = bdrv_pread(bs->file, VHDX_REGION_TABLE_OFFSET, buffer,
                    VHDX_HEADER_BLOCK_SIZE);
    if (ret < 0) {
        goto fail;
    }

    hdr_copy32(&s->rt.signature,   buffer, offset);
    hdr_copy32(&s->rt.checksum,    buffer, offset);
    hdr_copy32(&s->rt.entry_count, buffer, offset);
    hdr_copy32(&s->rt.reserved,    buffer, offset);

    if (vhdx_validate_checksum(buffer, VHDX_HEADER_BLOCK_SIZE, 4) ||
        s->rt.signature != VHDX_RT_MAGIC) {
        ret = -1;
        printf("region table checksum and/or magic failure\n");
        goto fail;
    }

    printf("Found %" PRId32 " region table entries\n", s->rt.entry_count);


    for (i = 0; i <s->rt.entry_count; i++) {
        hdr_copy_guid(rt_entry.guid, buffer, offset);

        hdr_copy64(&rt_entry.file_offset,   buffer, offset);
        hdr_copy32(&rt_entry.length,        buffer, offset);
        hdr_copy32(&rt_entry.bitfield.data, buffer, offset);

        /* see if we recognize the entry */
        if (guid_cmp(rt_entry.guid, bat_guid)) {
            s->bat_rt = rt_entry;
            printf("found BAT region table\n");
            continue;
        }

        if (guid_cmp(rt_entry.guid, metadata_guid)) {
            s->metadata_rt = rt_entry;
            printf("found Metadata region table\n");
            continue;
        }

        if (rt_entry.bitfield.bits.required) {
            /* cannot read vhdx file - required region table entry that
             * we do not understand.  per spec, we must fail to open */
            printf("Found unknown region table entry that is REQUIRED!\n");
            ret = -1;
            goto fail;
        }
    }

fail:
    g_free(buffer);
    return ret;
}


static int vhdx_parse_metadata(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    uint8_t *buffer;
    int offset = 0;
    int i = 0;
    vhdx_metadata_table_entry md_entry;

    buffer = g_malloc(VHDX_METADATA_TABLE_MAX_SIZE);

    printf("reading metadata at offset 0x%" PRIx64 "\n",s->metadata_rt.file_offset);
    ret = bdrv_pread(bs->file, s->metadata_rt.file_offset, buffer,
                     VHDX_METADATA_TABLE_MAX_SIZE);
    if (ret < 0) {
        goto fail_no_free;
    }
    hdr_copy64(&s->metadata_hdr.signature,   buffer, offset);
    hdr_copy16(&s->metadata_hdr.reserved,    buffer, offset);
    hdr_copy16(&s->metadata_hdr.entry_count, buffer, offset);
    hdr_copy(&s->metadata_hdr.reserved2, buffer,
             sizeof(s->metadata_hdr.reserved2), offset);

    if (s->metadata_hdr.signature != VHDX_METADATA_MAGIC) {
        ret = -1;
        printf("metadata header signature did not match: 0x%" PRIx64 "\n",
                s->metadata_hdr.signature);
        goto fail_no_free;
    }

    printf("metadata section has %" PRId16 " entries\n", s->metadata_hdr.entry_count);

    s->metadata_entries.present = 0;

    for (i = 0; i < s->metadata_hdr.entry_count; i++) {
        hdr_copy_guid(md_entry.item_id,     buffer, offset);
        hdr_copy32(&md_entry.offset,        buffer, offset);
        hdr_copy32(&md_entry.length,        buffer, offset);
        hdr_copy32(&md_entry.bitfield.data, buffer, offset);
        hdr_copy32(&md_entry.reserved2,     buffer, offset);

        if (guid_cmp(md_entry.item_id, file_param_guid)) {
            s->metadata_entries.file_parameters_entry = md_entry;
            s->metadata_entries.present |= META_FILE_PARAMETER_PRESENT;
            continue;
        }

        if (guid_cmp(md_entry.item_id, virtual_size_guid)) {
            s->metadata_entries.virtual_disk_size_entry = md_entry;
            s->metadata_entries.present |= META_VIRTUAL_DISK_SIZE_PRESENT;
            continue;
        }

        if (guid_cmp(md_entry.item_id, page83_guid)) {
            s->metadata_entries.page83_data_entry = md_entry;
            s->metadata_entries.present |= META_PAGE_83_PRESENT;
            continue;
        }

        if (guid_cmp(md_entry.item_id, logical_sector_guid)) {
            s->metadata_entries.logical_sector_size_entry = md_entry;
            s->metadata_entries.present |= META_LOGICAL_SECTOR_SIZE_PRESENT;
            continue;
        }

        if (guid_cmp(md_entry.item_id, phys_sector_guid)) {
            s->metadata_entries.phys_sector_size_entry = md_entry;
            s->metadata_entries.present |= META_PHYS_SECTOR_SIZE_PRESENT;
            continue;
        }

        if (guid_cmp(md_entry.item_id, parent_locator_guid)) {
            s->metadata_entries.parent_locator_entry = md_entry;
            s->metadata_entries.present |= META_PARENT_LOCATOR_PRESENT;
            continue;
        }

        if (md_entry.bitfield.bits.is_required) {
            /* cannot read vhdx file - required region table entry that
             * we do not understand.  per spec, we must fail to open */
            printf("Found unknown metadata table entry that is REQUIRED!\n");
            ret = -1;
            goto exit;
        }
    }

    if (s->metadata_entries.present != META_ALL_PRESENT) {
        printf("Did not find all required metadata entry fields\n");
        ret = -1;
        goto exit;
    }

    g_free(buffer);
    offset = 0;
    buffer = g_malloc(s->metadata_entries.file_parameters_entry.length);
    ret = bdrv_pread(bs->file,
                     s->metadata_entries.file_parameters_entry.offset
                                         + s->metadata_rt.file_offset,
                     buffer,
                     s->metadata_entries.file_parameters_entry.length);

    hdr_copy32(&s->params.block_size,    buffer, offset);
    hdr_copy32(&s->params.bitfield.data, buffer, offset);

    /* We now have the file parameters, so we can tell if this is a
     * differencing file (i.e.. has_parent), is dynamic or fixed
     * sized (leave_blocks_allocated), and the block size */

    /* The parent locator required iff the file parameters has_parent set */
    if (s->params.bitfield.bits.has_parent) {
        if (s->metadata_entries.present & ~META_PARENT_LOCATOR_PRESENT) {
            g_free(buffer);
            offset = 0;
            buffer = g_malloc(s->metadata_entries.parent_locator_entry.length);
            ret = bdrv_pread(bs->file,
                             s->metadata_entries.parent_locator_entry.offset,
                             buffer,
                             s->metadata_entries.parent_locator_entry.length);

            /* TODO: parse  parent locator fields */

        } else {
            printf("Did not find all required metadata entry fields\n");
            ret = -1;
            goto exit;
        }
    }
    /* determine virtual disk size, logical sector size,
     * and phys sector size */

    ret = bdrv_pread(bs->file,
                     s->metadata_entries.virtual_disk_size_entry.offset
                                           + s->metadata_rt.file_offset,
                     &s->virtual_disk_size,
                     sizeof(uint64_t));
    ret = bdrv_pread(bs->file,
                     s->metadata_entries.logical_sector_size_entry.offset
                                             + s->metadata_rt.file_offset,
                     &s->logical_sector_size,
                     sizeof(uint32_t));
    ret = bdrv_pread(bs->file,
                     s->metadata_entries.phys_sector_size_entry.offset
                                          + s->metadata_rt.file_offset,
                     &s->physical_sector_size,
                     sizeof(uint32_t));

    le64_to_cpus(&s->virtual_disk_size);
    le32_to_cpus(&s->logical_sector_size);
    le32_to_cpus(&s->physical_sector_size);

    printf("block size is %" PRId32 " MB\n", s->params.block_size/(1024*1024));
    printf("virtual disk size is %" PRId64 " MB\n",s->virtual_disk_size/(1024*1024));
    printf("logical sector size is %" PRId32 " bytes\n",s->logical_sector_size);

    /* TODO: can we support disks with logical sector sizes != 512? */

exit:
    g_free(buffer);
fail_no_free:
    return ret;
}

static int vhdx_open(BlockDriverState *bs, int flags)
{
    BDRVVHDXState *s = bs->opaque;
    int ret = 0;


    vhdx_parse_header(bs, s);
    vhdx_open_region_tables(bs, s);
    vhdx_parse_metadata(bs, s);

    /* the VHDX spec dictates that virtual_disk_size is always a multiple of
     * logical_sector_size */
    bs->total_sectors = s->virtual_disk_size / s->logical_sector_size;

    /* TODO */

    return ret;
}

static int vhdx_reopen_prepare(BDRVReopenState *state,
                               BlockReopenQueue *queue, Error **errp)
{
    return 0;
}



static int vhdx_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{
//    BDRVVHDXState *s = bs->opaque;
    int ret = 0;

    printf("%s:%d\n",__FILE__,__LINE__);
    /* TODO */

    return ret;
}

static coroutine_fn int vhdx_co_read(BlockDriverState *bs, int64_t sector_num,
                                    uint8_t *buf, int nb_sectors)
{
    int ret;
    BDRVVHDXState *s = bs->opaque;
    qemu_co_mutex_lock(&s->lock);
    ret = vhdx_read(bs, sector_num, buf, nb_sectors);
    qemu_co_mutex_unlock(&s->lock);

    printf("%s:%d\n",__FILE__,__LINE__);
    /* TODO */

    return ret;
}

static int vhdx_write(BlockDriverState *bs, int64_t sector_num,
    const uint8_t *buf, int nb_sectors)
{
//    BDRVVHDXState *s = bs->opaque;

    /* TODO */

    return 0;
}

static coroutine_fn int vhdx_co_write(BlockDriverState *bs, int64_t sector_num,
                                     const uint8_t *buf, int nb_sectors)
{
    int ret;
    BDRVVHDXState *s = bs->opaque;
    qemu_co_mutex_lock(&s->lock);
    ret = vhdx_write(bs, sector_num, buf, nb_sectors);
    qemu_co_mutex_unlock(&s->lock);

    /* TODO */

    return ret;
}


static int vhdx_create(const char *filename, QEMUOptionParameter *options)
{

    /* TODO */

   return 0;
}

static void vhdx_close(BlockDriverState *bs)
{
    BDRVVHDXState *s = bs->opaque;

    /* TODO */

    g_free(s->headers[0]);
    g_free(s->headers[1]);
}

static QEMUOptionParameter vhdx_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    {
        .name = BLOCK_OPT_SUBFMT,
        .type = OPT_STRING,
        .help =
            ""
    },
    { NULL }
};

static BlockDriver bdrv_vhdx = {
    .format_name    = "vhdx",
    .instance_size  = sizeof(BDRVVHDXState),

    .bdrv_probe             = vhdx_probe,
    .bdrv_open              = vhdx_open,
    .bdrv_close             = vhdx_close,
    .bdrv_reopen_prepare    = vhdx_reopen_prepare,
    .bdrv_create            = vhdx_create,
    .bdrv_read              = vhdx_co_read,
    .bdrv_write             = vhdx_co_write,
    .create_options         = vhdx_create_options,
};

static void bdrv_vhdx_init(void)
{
    bdrv_register(&bdrv_vhdx);
}

block_init(bdrv_vhdx_init);
