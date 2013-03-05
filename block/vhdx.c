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
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "qemu/crc32c.h"
#include "block/vhdx.h"


#define leguid_to_cpus(guid) do { \
    le32_to_cpus(&(guid)->data1); \
    le16_to_cpus(&(guid)->data2); \
    le16_to_cpus(&(guid)->data3); } while (0)

#define cpu_to_leguids(guid) do { \
    cpu_to_le32s(&(guid)->data1); \
    cpu_to_le16s(&(guid)->data2); \
    cpu_to_le16s(&(guid)->data3); } while (0)

/* Several metadata and region table data entries are identified by
 * guids in  a MS-specific GUID format. */


/* ------- Known Region Table GUIDs ---------------------- */
static const ms_guid bat_guid =      { .data1 = 0x2dc27766,
                                       .data2 = 0xf623,
                                       .data3 = 0x4200,
                                       .data4 = { 0x9d, 0x64, 0x11, 0x5e,
                                                  0x9b, 0xfd, 0x4a, 0x08} };

static const ms_guid metadata_guid = { .data1 = 0x8b7ca206,
                                       .data2 = 0x4790,
                                       .data3 = 0x4b9a,
                                       .data4 = { 0xb8, 0xfe, 0x57, 0x5f,
                                                  0x05, 0x0f, 0x88, 0x6e} };



/* ------- Known Metadata Entry GUIDs ---------------------- */
static const ms_guid file_param_guid =   { .data1 = 0xcaa16737,
                                           .data2 = 0xfa36,
                                           .data3 = 0x4d43,
                                           .data4 = { 0xb3, 0xb6, 0x33, 0xf0,
                                                      0xaa, 0x44, 0xe7, 0x6b} };

static const ms_guid virtual_size_guid = { .data1 = 0x2FA54224,
                                           .data2 = 0xcd1b,
                                           .data3 = 0x4876,
                                           .data4 = { 0xb2, 0x11, 0x5d, 0xbe,
                                                      0xd8, 0x3b, 0xf4, 0xb8} };

static const ms_guid page83_guid =       { .data1 = 0xbeca12ab,
                                           .data2 = 0xb2e6,
                                           .data3 = 0x4523,
                                           .data4 = { 0x93, 0xef, 0xc3, 0x09,
                                                      0xe0, 0x00, 0xc7, 0x46} };

static const ms_guid logical_sector_guid = {.data1 = 0x8141bf1d,
                                            .data2 = 0xa96f,
                                            .data3 = 0x4709,
                                           .data4 = { 0xba, 0x47, 0xf2, 0x33,
                                                      0xa8, 0xfa, 0xab, 0x5f} };

static const ms_guid phys_sector_guid =  { .data1 = 0xcda348c7,
                                           .data2 = 0x445d,
                                           .data3 = 0x4471,
                                           .data4 = { 0x9c, 0xc9, 0xe9, 0x88,
                                                      0x52, 0x51, 0xc5, 0x56} };

static const ms_guid parent_locator_guid = {.data1 = 0xa8d35f2d,
                                            .data2 = 0xb30b,
                                            .data3 = 0x454d,
                                           .data4 = { 0xab, 0xf7, 0xd3, 0xd8,
                                                      0x48, 0x34, 0xab, 0x0c} };

/* Each parent type must have a valid GUID; this is for parent images
 * of type 'VHDX'.  If we were to allow e.g. a QCOW2 parent, we would
 * need to make up our own QCOW2 GUID type */
static const ms_guid parent_vhdx_guid = { .data1 = 0xb04aefb7,
                                          .data2 = 0xd19e,
                                          .data3 = 0x4a81,
                                          .data4 = { 0xb7, 0x89, 0x25, 0xb8,
                                                     0xe9, 0x44, 0x59, 0x13} };


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


typedef struct vhdx_sector_info {
    uint32_t bat_idx;       /* BAT entry index */
    uint32_t sectors_avail; /* sectors available in payload block */
    uint32_t bytes_left;    /* bytes left in the block after data to r/w */
    uint32_t bytes_avail;   /* bytes available in payload block */
    uint64_t file_offset;   /* absolute offset in bytes, in file */
    uint64_t block_offset;  /* block offset, in bytes */
} vhdx_sector_info;



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
    uint32_t block_size;
    uint32_t block_size_bits;
    uint32_t sectors_per_block;
    uint32_t sectors_per_block_bits;

    uint64_t virtual_disk_size;
    uint32_t logical_sector_size;
    uint32_t physical_sector_size;

    uint64_t chunk_ratio;
    uint32_t chunk_ratio_bits;
    uint32_t logical_sector_size_bits;

    uint32_t bat_entries;
    vhdx_bat_entry *bat;
    uint64_t bat_offset;

    ms_guid session_guid;


    vhdx_parent_locator_header parent_header;
    vhdx_parent_locator_entry *parent_entries;

} BDRVVHDXState;

/* Calculates new checksum.
 *
 * Zero is substituted during crc calculation for the original crc field
 * crc_offset: byte offset in buf of the buffer crc
 * buf: buffer pointer
 * size: size of buffer (must be > crc_offset+4)
 */
static uint32_t vhdx_update_checksum(uint8_t *buf, size_t size, int crc_offset)
{
    uint32_t crc;

    assert(buf != NULL);
    assert(size > (crc_offset+4));

    memset(buf+crc_offset, 0, sizeof(crc));
    crc =  crc32c(0xffffffff, buf, size);
    memcpy(buf+crc_offset, &crc, sizeof(crc));

    return crc;
}

/* Validates the checksum of the buffer, with an in-place CRC.
 *
 * Zero is substituted during crc calculation for the original crc field,
 * and the crc field is restored afterwards.  But the buffer will be modifed
 * during the calculation, so this may not be not suitable for multi-threaded
 * use.
 *
 * crc_offset: byte offset in buf of the buffer crc
 * buf: buffer pointer
 * size: size of buffer (must be > crc_offset+4)
 *
 * returns true if checksum is valid, false otherwise
 */
static bool vhdx_checksum_is_valid(uint8_t *buf, size_t size, int crc_offset)
{
    uint32_t crc_orig;
    uint32_t crc;

    assert(buf != NULL);
    assert(size > (crc_offset+4));

    memcpy(&crc_orig, buf+crc_offset, sizeof(crc_orig));
    memset(buf+crc_offset, 0, sizeof(crc_orig));

    crc = crc32c(0xffffffff, buf, size);

    memcpy(buf+crc_offset, &crc_orig, sizeof(crc_orig));

    crc_orig = le32_to_cpu(crc_orig);
    return crc == crc_orig;
}

/*
 * This generates a UUID that is compliant with the MS GUIDs used
 * in the VHDX spec (and elsewhere).
 *
 * We can do this with uuid_generate if uuid.h is present,
 * however not all systems have uuid and the generation is
 * pretty straightforward for the DCE + random usage case
 *
 */
static void vhdx_guid_generate(ms_guid *guid)
{
    assert(guid != NULL);

    int i;

    guid->data1 = g_random_int();
    guid->data2 = g_random_int_range(0, 0xffff);
    guid->data3 = g_random_int_range(0, 0x0fff);
    guid->data3 |= 0x4000; /* denotes random algorithm */

    guid->data4[0] = g_random_int_range(0, 0x3f);
    guid->data4[0] |= 0x80; /* denotes DCE type */
    for (i = 1; i < sizeof(guid->data4); i++) {
        guid->data4[i] = g_random_int_range(0, 0xff);
    }
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


/* All VHDX structures on disk are little endian */
static void vhdx_header_le_import(vhdx_header *h)
{
    assert(h != NULL);

    le32_to_cpus(&h->signature);
    le32_to_cpus(&h->checksum);
    le64_to_cpus(&h->sequence_number);

    leguid_to_cpus(&h->file_write_guid);
    leguid_to_cpus(&h->data_write_guid);
    leguid_to_cpus(&h->log_guid);

    le16_to_cpus(&h->log_version);
    le16_to_cpus(&h->version);
    le32_to_cpus(&h->log_length);
    le64_to_cpus(&h->log_offset);
}

/* All VHDX structures on disk are little endian */
static void vhdx_header_le_export(vhdx_header *orig_h, vhdx_header *new_h)
{
    assert(orig_h != NULL);
    assert(new_h != NULL);

    new_h->signature       = cpu_to_le32(orig_h->signature);
    new_h->checksum        = cpu_to_le32(orig_h->checksum);
    new_h->sequence_number = cpu_to_le64(orig_h->sequence_number);

    memcpy(&new_h->file_write_guid, &orig_h->file_write_guid, sizeof(ms_guid));
    memcpy(&new_h->data_write_guid, &orig_h->data_write_guid, sizeof(ms_guid));
    memcpy(&new_h->log_guid,        &orig_h->log_guid,        sizeof(ms_guid));

    cpu_to_leguids(&new_h->file_write_guid);
    cpu_to_leguids(&new_h->data_write_guid);
    cpu_to_leguids(&new_h->log_guid);

    new_h->log_version     = cpu_to_le16(orig_h->log_version);
    new_h->version         = cpu_to_le16(orig_h->version);
    new_h->log_length      = cpu_to_le32(orig_h->log_length);
    new_h->log_offset      = cpu_to_le64(orig_h->log_offset);
}

/* Update the VHDX headers
 *
 * This follows the VHDX spec procedures for header updates.
 *
 *  - non-current header is updated with largest sequence number
 */
static int vhdx_update_header(BlockDriverState *bs, BDRVVHDXState *s, bool rw)
{
    int ret = 0;
    int hdr_idx = 0;
    uint64_t header_offset = VHDX_HEADER1_OFFSET;

    vhdx_header *active_header;
    vhdx_header *inactive_header;
    vhdx_header header_le;
    uint8_t *buffer;

    /* operate on the non-current header */
    if (s->curr_header == 0) {
        hdr_idx = 1;
        header_offset = VHDX_HEADER2_OFFSET;
    }

    active_header   = s->headers[s->curr_header];
    inactive_header = s->headers[hdr_idx];

    inactive_header->sequence_number = active_header->sequence_number + 1;

    /* a new file guid must be generate before any file write, including
     * headers */
    memcpy(&inactive_header->file_write_guid, &s->session_guid,
           sizeof(ms_guid));

    /* a new data guid only needs to be generate before any guest-visisble
     * writes, so update it if the image is opened r/w. */
    if (rw) {
        vhdx_guid_generate(&inactive_header->data_write_guid);
    }

    /* the header checksum is not over just the packed size of vhdx_header,
     * but rather over the entire 'reserved' range for the header, which is
     * 4KB (VHDX_HEADER_SIZE). */

    buffer = g_malloc(VHDX_HEADER_SIZE);
    /* we can't assume the extra reserved bytes are 0 */
    ret = bdrv_pread(bs->file, header_offset, buffer, VHDX_HEADER_SIZE);
    if (ret < 0) {
        goto fail;
    }
    /* overwrite the actual vhdx_header portion */
    memcpy(buffer, inactive_header, sizeof(vhdx_header));
    inactive_header->checksum = vhdx_update_checksum(buffer,
                                                     VHDX_HEADER_SIZE, 4);
    vhdx_header_le_export(inactive_header, &header_le);
    bdrv_pwrite_sync(bs->file, header_offset, &header_le, sizeof(vhdx_header));
    s->curr_header = hdr_idx;

fail:
    g_free(buffer);
    return ret;
}

/*
 * The VHDX spec calls for header updates to be performed twice, so that both
 * the current and non-current header have valid info
 */
static int vhdx_update_headers(BlockDriverState *bs, BDRVVHDXState *s, bool rw)
{
    int ret;

    ret = vhdx_update_header(bs, s, rw);
    if (ret < 0) {
        return ret;
    }
    ret = vhdx_update_header(bs, s, rw);
    return ret;
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

    /* We have to read the whole VHDX_HEADER_SIZE instead of
     * sizeof(vhdx_header), because the checksum is over the whole
     * region */
    ret = bdrv_pread(bs->file, VHDX_HEADER1_OFFSET, buffer, VHDX_HEADER_SIZE);
    if (ret < 0) {
        goto fail;
    }
    /* copy over just the relevant portion that we need */
    memcpy(header1, buffer, sizeof(vhdx_header));
    vhdx_header_le_import(header1);

    if (vhdx_checksum_is_valid(buffer, VHDX_HEADER_SIZE, 4) &&
        header1->signature == VHDX_HDR_MAGIC) {
        h1_seq = header1->sequence_number;
    }

    ret = bdrv_pread(bs->file, VHDX_HEADER2_OFFSET, buffer, VHDX_HEADER_SIZE);
    if (ret < 0) {
        goto fail;
    }
    /* copy over just the relevant portion that we need */
    memcpy(header2, buffer, sizeof(vhdx_header));
    vhdx_header_le_import(header2);

    if (vhdx_checksum_is_valid(buffer, VHDX_HEADER_SIZE, 4) &&
        header2->signature == VHDX_HDR_MAGIC) {
        h2_seq = header2->sequence_number;
    }

    if (h1_seq > h2_seq) {
        s->curr_header = 0;
    } else if (h2_seq > h1_seq) {
        s->curr_header = 1;
    } else {
        printf("NO VALID HEADER\n");
        ret = -EINVAL;
        goto fail;
    }

    ret = 0;

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

/* Parse the replay log.  Per the VHDX spec, if the log is present
 * it must be replayed prior to opening the file, even read-only.
 *
 * If read-only, we must replay the log in RAM (or refuse to open
 * a dirty VHDX file read-only */
static int vhdx_parse_log(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    int i;
    vhdx_header *hdr;

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

    if (hdr->log_length == 0) {
        goto exit;
    }

    /* there is a log present, but we don't support that yet */
    ret = -ENOTSUP;

exit:
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

    ret = bdrv_pread(bs->file, VHDX_REGION_TABLE_OFFSET, buffer,
                    VHDX_HEADER_BLOCK_SIZE);
    if (ret < 0) {
        goto fail;
    }
    memcpy(&s->rt, buffer, sizeof(s->rt));
    le32_to_cpus(&s->rt.signature);
    le32_to_cpus(&s->rt.checksum);
    le32_to_cpus(&s->rt.entry_count);
    le32_to_cpus(&s->rt.reserved);
    offset += sizeof(s->rt);

    if (!vhdx_checksum_is_valid(buffer, VHDX_HEADER_BLOCK_SIZE, 4) ||
        s->rt.signature != VHDX_RT_MAGIC) {
        ret = -EINVAL;
        goto fail;
    }

    for (i = 0; i < s->rt.entry_count; i++) {
        memcpy(&rt_entry, buffer+offset, sizeof(rt_entry));
        offset += sizeof(rt_entry);

        leguid_to_cpus(&rt_entry.guid);
        le64_to_cpus(&rt_entry.file_offset);
        le32_to_cpus(&rt_entry.length);
        le32_to_cpus(&rt_entry.data_bits);

        /* see if we recognize the entry */
        if (guid_eq(rt_entry.guid, bat_guid)) {
            s->bat_rt = rt_entry;
            continue;
        }

        if (guid_eq(rt_entry.guid, metadata_guid)) {
            s->metadata_rt = rt_entry;
            continue;
        }

        if (rt_entry.data_bits & VHDX_REGION_ENTRY_REQUIRED) {
            /* cannot read vhdx file - required region table entry that
             * we do not understand.  per spec, we must fail to open */
            ret = -ENOTSUP;
            goto fail;
        }
    }
    ret = 0;

fail:
    g_free(buffer);
    return ret;
}



/* Metadata initial parser
 *
 * This loads all the metadata entry fields.  This may cause additional
 * fields to be processed (e.g. parent locator, etc..).
 *
 * There are 5 Metadata items that are always required:
 *      - File Parameters (block size, has a parent)
 *      - Virtual Disk Size (size, in bytes, of the virtual drive)
 *      - Page 83 Data (scsi page 83 guid)
 *      - Logical Sector Size (logical sector size in bytes, either 512 or
 *                             4096.  We only support 512 currently)
 *      - Physical Sector Size (512 or 4096)
 *
 * Also, if the File Parameters indicate this is a differencing file,
 * we must also look for the Parent Locator metadata item.
 */
static int vhdx_parse_metadata(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    uint8_t *buffer;
    int offset = 0;
    int i = 0;
    uint32_t block_size, sectors_per_block, logical_sector_size;
    uint64_t chunk_ratio;
    vhdx_metadata_table_entry md_entry;

    buffer = g_malloc(VHDX_METADATA_TABLE_MAX_SIZE);

    ret = bdrv_pread(bs->file, s->metadata_rt.file_offset, buffer,
                     VHDX_METADATA_TABLE_MAX_SIZE);
    if (ret < 0) {
        goto fail_no_free;
    }
    memcpy(&s->metadata_hdr, buffer, sizeof(s->metadata_hdr));
    offset += sizeof(s->metadata_hdr);

    le64_to_cpus(&s->metadata_hdr.signature);
    le16_to_cpus(&s->metadata_hdr.reserved);
    le16_to_cpus(&s->metadata_hdr.entry_count);

    if (s->metadata_hdr.signature != VHDX_METADATA_MAGIC) {
        ret = -EINVAL;
        goto fail_no_free;
    }

    s->metadata_entries.present = 0;

    for (i = 0; i < s->metadata_hdr.entry_count; i++) {
        memcpy(&md_entry, buffer+offset, sizeof(md_entry));
        offset += sizeof(md_entry);

        leguid_to_cpus(&md_entry.item_id);
        le32_to_cpus(&md_entry.offset);
        le32_to_cpus(&md_entry.length);
        le32_to_cpus(&md_entry.data_bits);
        le32_to_cpus(&md_entry.reserved2);

        if (guid_eq(md_entry.item_id, file_param_guid)) {
            s->metadata_entries.file_parameters_entry = md_entry;
            s->metadata_entries.present |= META_FILE_PARAMETER_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, virtual_size_guid)) {
            s->metadata_entries.virtual_disk_size_entry = md_entry;
            s->metadata_entries.present |= META_VIRTUAL_DISK_SIZE_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, page83_guid)) {
            s->metadata_entries.page83_data_entry = md_entry;
            s->metadata_entries.present |= META_PAGE_83_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, logical_sector_guid)) {
            s->metadata_entries.logical_sector_size_entry = md_entry;
            s->metadata_entries.present |= META_LOGICAL_SECTOR_SIZE_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, phys_sector_guid)) {
            s->metadata_entries.phys_sector_size_entry = md_entry;
            s->metadata_entries.present |= META_PHYS_SECTOR_SIZE_PRESENT;
            continue;
        }

        if (guid_eq(md_entry.item_id, parent_locator_guid)) {
            s->metadata_entries.parent_locator_entry = md_entry;
            s->metadata_entries.present |= META_PARENT_LOCATOR_PRESENT;
            continue;
        }

        if (md_entry.data_bits & VHDX_META_FLAGS_IS_REQUIRED) {
            /* cannot read vhdx file - required region table entry that
             * we do not understand.  per spec, we must fail to open */
            ret = -ENOTSUP;
            goto exit;
        }
    }

    if (s->metadata_entries.present != META_ALL_PRESENT) {
        ret = -ENOTSUP;
        goto exit;
    }

    ret = bdrv_pread(bs->file,
                     s->metadata_entries.file_parameters_entry.offset
                                         + s->metadata_rt.file_offset,
                     &s->params,
                     sizeof(s->params));

    le32_to_cpus(&s->params.block_size);
    le32_to_cpus(&s->params.data_bits);


    /* We now have the file parameters, so we can tell if this is a
     * differencing file (i.e.. has_parent), is dynamic or fixed
     * sized (leave_blocks_allocated), and the block size */

    /* The parent locator required iff the file parameters has_parent set */
    if (s->params.data_bits & VHDX_PARAMS_HAS_PARENT) {
        if (s->metadata_entries.present & ~META_PARENT_LOCATOR_PRESENT) {
            /* TODO: parse  parent locator fields */
            ret = -ENOTSUP; /* temp, until differencing files are supported */
            goto exit;
        } else {
            /* if has_parent is set, but there is not parent locator present,
             * then that is an invalid combination */
            ret = -EINVAL;
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
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_pread(bs->file,
                     s->metadata_entries.logical_sector_size_entry.offset
                                             + s->metadata_rt.file_offset,
                     &s->logical_sector_size,
                     sizeof(uint32_t));
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_pread(bs->file,
                     s->metadata_entries.phys_sector_size_entry.offset
                                          + s->metadata_rt.file_offset,
                     &s->physical_sector_size,
                     sizeof(uint32_t));
    if (ret < 0) {
        goto exit;
    }

    le64_to_cpus(&s->virtual_disk_size);
    le32_to_cpus(&s->logical_sector_size);
    le32_to_cpus(&s->physical_sector_size);

    /* both block_size and sector_size are guaranteed powers of 2 */
    s->sectors_per_block = s->params.block_size / s->logical_sector_size;
    s->chunk_ratio = (VHDX_MAX_SECTORS_PER_BLOCK) *
                     (uint64_t)s->logical_sector_size /
                     (uint64_t)s->params.block_size;


    /* These values are ones we will want to use for division / multiplication
     * later on, and they are all guaranteed (per the spec) to be powers of 2,
     * so we can take advantage of that for shift operations during
     * reads/writes */
    logical_sector_size = s->logical_sector_size;
    while (logical_sector_size >>= 1) {
        s->logical_sector_size_bits++;
    }
    sectors_per_block = s->sectors_per_block;
    while (sectors_per_block >>= 1) {
        s->sectors_per_block_bits++;
    }
    chunk_ratio = s->chunk_ratio;
    while (chunk_ratio >>= 1) {
        s->chunk_ratio_bits++;
    }
    block_size = s->params.block_size;
    while (block_size >>= 1) {
        s->block_size_bits++;
    }

    if (s->logical_sector_size != BDRV_SECTOR_SIZE) {
        printf("VHDX error - QEMU only supports 512 byte sector sizes\n");
        ret = -ENOTSUP;
        goto exit;
    }

    ret = 0;

exit:
    g_free(buffer);
fail_no_free:
    return ret;
}

static int vhdx_open(BlockDriverState *bs, int flags)
{
    BDRVVHDXState *s = bs->opaque;
    int ret = 0;
    int i;

    s->bat = NULL;

    qemu_co_mutex_init(&s->lock);

    /* This is used for any header updates, for the file_write_guid.
     * The spec dictates that a new value should be used for the first
     * header update */
    vhdx_guid_generate(&s->session_guid);

    ret = vhdx_parse_header(bs, s);
    if (ret) {
        goto fail;
    }

    ret = vhdx_parse_log(bs, s);
    if (ret) {
        goto fail;
    }

    ret = vhdx_open_region_tables(bs, s);
    if (ret) {
        goto fail;
    }

    ret = vhdx_parse_metadata(bs, s);
    if (ret) {
        goto fail;
    }
    s->block_size = s->params.block_size;

    /* the VHDX spec dictates that virtual_disk_size is always a multiple of
     * logical_sector_size */
    bs->total_sectors = s->virtual_disk_size / s->logical_sector_size;

    s->bat_offset = s->bat_rt.file_offset;
    s->bat_entries = s->bat_rt.length / sizeof(vhdx_bat_entry);
    s->bat = g_malloc(s->bat_rt.length);

    ret = bdrv_pread(bs->file, s->bat_offset, s->bat, s->bat_rt.length);

    for (i = 0; i < s->bat_entries; i++) {
        le64_to_cpus(&s->bat[i]);
    }

    if (flags & BDRV_O_RDWR) {
        vhdx_update_headers(bs, s, false);
    }

    /* TODO: differencing files, write */

    return 0;
fail:
    g_free(s->bat);
    return ret;
}

static int vhdx_reopen_prepare(BDRVReopenState *state,
                               BlockReopenQueue *queue, Error **errp)
{
    return 0;
}


/*
 * Perform sector to block offset translations, to get various
 * sector and file offsets into the image.  See vhdx_sector_info
 */
static void vhdx_block_translate(BDRVVHDXState *s, int64_t sector_num,
                                 int nb_sectors, vhdx_sector_info *sinfo)
{
    uint32_t block_offset;

    sinfo->bat_idx = sector_num >> s->sectors_per_block_bits;
    /* effectively a modulo - this gives us the offset into the block
     * (in sector sizes) for our sector number */
    block_offset = sector_num - (sinfo->bat_idx << s->sectors_per_block_bits);
    /* the chunk ratio gives us the interleaving of the sector
     * bitmaps, so we need to advance our page block index by the
     * sector bitmaps entry number */
    sinfo->bat_idx += sinfo->bat_idx >> s->chunk_ratio_bits;

    /* the number of sectors we can read/write in this cycle */
    sinfo->sectors_avail = s->sectors_per_block - block_offset;

    sinfo->bytes_left = sinfo->sectors_avail << s->logical_sector_size_bits;

    if (sinfo->sectors_avail > nb_sectors) {
        sinfo->sectors_avail = nb_sectors;
    }

    sinfo->bytes_avail = sinfo->sectors_avail << s->logical_sector_size_bits;

    sinfo->file_offset = s->bat[sinfo->bat_idx] >> VHDX_BAT_FILE_OFF_BITS;

    sinfo->block_offset = block_offset << s->logical_sector_size_bits;

    /* The file offset must be past the header section, so must be > 0 */
    if (sinfo->file_offset == 0) {
        return;
    }

    /* block offset is the offset in vhdx logical sectors, in
     * the payload data block. Convert that to a byte offset
     * in the block, and add in the payload data block offset
     * in the file, in bytes, to get the final read address */

    sinfo->file_offset <<= 20;  /* now in bytes, rather than 1MB units */
    sinfo->file_offset += sinfo->block_offset;
}



static coroutine_fn int vhdx_co_readv(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    BDRVVHDXState *s = bs->opaque;
    int ret = 0;
    vhdx_sector_info sinfo;
    uint64_t bytes_done = 0;
    QEMUIOVector hd_qiov;

    qemu_iovec_init(&hd_qiov, qiov->niov);

    qemu_co_mutex_lock(&s->lock);

    while (nb_sectors > 0) {
        /* We are a differencing file, so we need to inspect the sector bitmap
         * to see if we have the data or not */
        if (s->params.data_bits & VHDX_PARAMS_HAS_PARENT) {
            /* not supported yet */
            ret = -ENOTSUP;
            goto exit;
        } else {
            vhdx_block_translate(s, sector_num, nb_sectors, &sinfo);

            qemu_iovec_reset(&hd_qiov);
            qemu_iovec_concat(&hd_qiov, qiov,  bytes_done, sinfo.bytes_avail);

            /* check the payload block state */
            switch (s->bat[sinfo.bat_idx] & VHDX_BAT_STATE_BIT_MASK) {
            case PAYLOAD_BLOCK_NOT_PRESENT: /* fall through */
            case PAYLOAD_BLOCK_UNDEFINED:   /* fall through */
            case PAYLOAD_BLOCK_UNMAPPED:    /* fall through */
            case PAYLOAD_BLOCK_ZERO:
                /* return zero */
                qemu_iovec_memset(&hd_qiov, 0, 0, sinfo.bytes_avail);
                break;
            case PAYLOAD_BLOCK_FULL_PRESENT:
                qemu_co_mutex_unlock(&s->lock);
                ret = bdrv_co_readv(bs->file,
                                    sinfo.file_offset >> BDRV_SECTOR_BITS,
                                    sinfo.sectors_avail, &hd_qiov);
                qemu_co_mutex_lock(&s->lock);
                if (ret < 0) {
                    goto exit;
                }
                break;
            case PAYLOAD_BLOCK_PARTIALLY_PRESENT:
                /* we don't yet support difference files, fall through
                 * to error */
            default:
                ret = -EIO;
                goto exit;
                break;
            }
            nb_sectors -= sinfo.sectors_avail;
            sector_num += sinfo.sectors_avail;
            bytes_done += sinfo.bytes_avail;
        }
    }
    ret = 0;
exit:
    qemu_co_mutex_unlock(&s->lock);
    qemu_iovec_destroy(&hd_qiov);
    return ret;
}



static coroutine_fn int vhdx_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    return -ENOTSUP;
}


static void vhdx_close(BlockDriverState *bs)
{
    BDRVVHDXState *s = bs->opaque;

    g_free(s->headers[0]);
    g_free(s->headers[1]);
    g_free(s->bat);
    g_free(s->parent_entries);
}

static BlockDriver bdrv_vhdx = {
    .format_name    = "vhdx",
    .instance_size  = sizeof(BDRVVHDXState),

    .bdrv_probe             = vhdx_probe,
    .bdrv_open              = vhdx_open,
    .bdrv_close             = vhdx_close,
    .bdrv_reopen_prepare    = vhdx_reopen_prepare,
    .bdrv_co_readv          = vhdx_co_readv,
    .bdrv_co_writev         = vhdx_co_writev,
};

static void bdrv_vhdx_init(void)
{
    bdrv_register(&bdrv_vhdx);
}

block_init(bdrv_vhdx_init);
