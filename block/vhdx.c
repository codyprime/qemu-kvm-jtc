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

/* Structures and fields present in the VHDX file */

/* The header section has the following blocks,
 * each block is 64KB:
 *
 * _____________________________________________________________________________
 * | File Id. |   Header 1    | Header 2   | Region Table |  Reserved (768KB)  |
 * |----------|---------------|------------|--------------|--------------------|
 * |          |               |            |              |                    |
 * 0.........64KB...........128KB........192KB..........256KB................1MB
 */

#define VHDX_HEADER_BLOCK_SIZE      (64*1024)

#define VHDX_FILE_ID_OFFSET         0
#define VHDX_HEADER1_OFFSET         (VHDX_HEADER_BLOCK_SIZE*1)
#define VHDX_HEADER2_OFFSET         (VHDX_HEADER_BLOCK_SIZE*2)
#define VHDX_REGION_TABLE_OFFSET    (VHDX_HEADER_BLOCK_SIZE*3)



/* ---- HEADER SECTION STRUCTURES ---- */

/* Important note: these structures are as defined in the VHDX specification,
 * including byte order and size.  However, without being packed structures,
 * they will not match 1:1 data read from disk.  Rather than use potentially
 * non-portable packed structures, data is copied from read buffers into
 * the structures below.  However, for reference, please refrain from
 * modifying these structures to something that does not represent the spec */

#define VHDX_FILE_ID_MAGIC 0x656C696678646876  /* 'vhdxfile' */
typedef struct vhdx_file_identifier {
    uint64_t    signature;              /* "vhdxfile" in ASCII */
    uint16_t    creator[256];           /* optional; utf-16 string to identify
                                           the vhdx file creator.  Diagnotistic
                                           only */
} vhdx_file_identifier;


/* the guid is a 16 byte unique ID - the definition for this used by
 * Microsoft is not just 16 bytes though - it is a structure that is defined,
 * so we need to follow it here so that endianness does not trip us up */

typedef struct ms_guid {
    uint32_t    data1;
    uint16_t    data2;
    uint16_t    data3;
    uint8_t     data4[8];
} ms_guid;

#define guid_cmp(a, b) \
    (memcmp(&(a), &(b), sizeof(ms_guid)) == 0)

#define VHDX_HEADER_SIZE (4*1024)   /* although the vhdx_header struct in disk
                                       is only 582 bytes, for purposes of crc
                                       the header is the first 4KB of the 64KB
                                       block */

#define VHDX_HDR_MAGIC 0x64616568   /* 'head' */
typedef struct vhdx_header {
    uint32_t    signature;              /* "head" in ASCII */
    uint32_t    checksum;               /* CRC-32C hash of the whole header */
    uint64_t    sequence_number;        /* Seq number of this header.  Each
                                           VHDX file has 2 of these headers,
                                           and only the header with the highest
                                           sequence number is valid */
    ms_guid     file_write_guid;       /* 128 bit unique identifier. Must be
                                           updated to new, unique value before
                                           the first modification is made to
                                           file */
    ms_guid     data_write_guid;        /* 128 bit unique identifier. Must be
                                           updated to new, unique value before
                                           the first modification is made to
                                           visible data.   Visbile data is
                                           defined as:
                                                    - system & user metadata
                                                    - raw block data
                                                    - disk size
                                                    - any change that will
                                                      cause the virtual disk
                                                      sector read to differ

                                           This does not need to change if
                                           blocks are re-arranged */
    ms_guid     log_guid;               /* 128 bit unique identifier. If zero,
                                           there is no valid log. If non-zero,
                                           log entries with this guid are
                                           valid. */
    uint16_t    log_version;            /* version of the log format. Mustn't be
                                           zero, unless log_guid is also zero */
    uint16_t    version;                /* version of th evhdx file.  Currently,
                                           only supported version is "1" */
    uint32_t    log_length;             /* length of the log.  Must be multiple
                                           of 1MB */
    uint64_t    log_offset;             /* byte offset in the file of the log.
                                           Must also be a multiple of 1MB */
} vhdx_header;

/* 4KB in packed data size, not to be used except for initial data read */
typedef struct vhdx_header_padded {
    vhdx_header header;
    uint8_t     reserved[502];          /* per the VHDX spec */
    uint8_t     reserved_[3514];        /* for the initial packed struct read */
} vhdx_header_padded;

/* Header for the region table block */
#define VHDX_RT_MAGIC 0x69676572  /* 'regi ' */
typedef struct vhdx_region_table_header {
    uint32_t    signature;              /* "regi" in ASCII */
    uint32_t    checksum;               /* CRC-32C hash of the 64KB table */
    uint32_t    entry_count;            /* number of valid entries */
    uint32_t    reserved;
} vhdx_region_table_header;


static const ms_guid bat_guid = { .data1 = 0x2dc27766,
                                  .data2 = 0xf623,
                                  .data3 = 0x4200,
                                  .data4 = { 0x9d, 0x64, 0x11, 0x5e,
                                             0x9b, 0xfd, 0x4a, 0x08}};

static const ms_guid metadata_guid = { .data1 = 0x8b7ca206,
                                       .data2 = 0x4790,
                                       .data3 = 0x4b9a,
                                       .data4 = { 0xb8, 0xfe, 0x57, 0x5f,
                                                  0x05, 0x0f, 0x88, 0x6e}};

/* Individual region table entry.  There may be a maximum of 2047 of these
 *
 *  There are two known region table properties.  Both are required.
 *  BAT (block allocation table):  2DC27766F62342009D64115E9BFD4A08
 *  Metadata:                      8B7CA20647904B9AB8FE575F050F886E
 */
typedef struct vhdx_region_table_entry {
    ms_guid     guid;                   /* 128-bit unique identifier */
    uint64_t    file_offset;            /* offset of the object in the file.
                                           Must be multiple of 1MB */
    uint32_t    length;                 /* length, in bytes, of the object */
    union vhdx_rt_bitfield {
        struct {
        uint32_t    required:1;        /* 1 if this region must be recognized
                                          in order to load the file */
        uint32_t    reserved:31;
        } bits;
        uint32_t data;
    } bitfield;
} vhdx_region_table_entry;









/* ---- LOG ENTRY STRUCTURES ---- */

#define VHDX_LOGE_MAGIC 0x65676F6C /* 'loge' */
typedef struct vhdx_log_entry_header {
    uint32_t    signature;              /* "loge" in ASCII */
    uint32_t    checksum;               /* CRC-32C hash of the 64KB table */
    uint32_t    entry_length;           /* length in bytes, multiple of 1MB */
    uint32_t    tail;                   /* byte offset of first log entry of a
                                           seq, where this entry is the last
                                           entry */
    uint64_t    sequence_number;        /* incremented with each log entry.
                                           May not be zero. */
    uint32_t    descriptor_count;       /* number of descriptors in this log
                                           entry, must be >= 0 */
    uint32_t    reserved;
    ms_guid     log_guid;               /* value of the log_guid from
                                           vhdx_header.  If not found in
                                           vhdx_header, it is invalid */
    uint64_t    flushed_file_offset;    /* see spec for full details - this
                                           sould be vhdx file size in bytes */
    uint64_t    last_file_offset;       /* size in bytes that all allocated
                                           file structures fit into */
} vhdx_log_entry_header;

#define VHDX_ZERO_MGIC 0x6F72657A /* 'zero' */
typedef struct vhdx_log_zero_descriptor {
    uint32_t    zero_signature;         /* "zero" in ASCII */
    uint32_t    reserver;
    uint64_t    zero_length;            /* length of the section to zero */
    uint64_t    file_offset;            /* file offset to write zeros - multiple
                                           of 4kB */
    uint64_t    sequence_number;        /* must match same field in
                                           vhdx_log_entry_header */
} vhdx_log_zero_descriptor;

#define VHDX_DATA_MAGIC 0x63736564 /* 'desc' */
typedef struct vhdx_log_data_descriptor {
    uint32_t    data_signature;         /* "desc" in ASCII */
    uint32_t    trailing_bytes;         /* bytes 4092-4096 of the data sector */
    uint64_t    leading_bytes;          /* bytes 0-7 of the data sector */
    uint64_t    file_offset;            /* file offset where the data described
                                           herein is written */
    uint64_t    sequence_number;        /* must match the sequence number field
                                           in entry header */
} vhdx_log_data_descriptor;

#define VHDX_DATAS_MAGIC 0x61746164 /* 'data' */
typedef struct vhdx_log_data_sector {
    uint32_t    data_signature;         /* "data" in ASCII */
    uint32_t    sequence_high;          /* 4 MSB of 8 byte sequence_number */
    uint8_t     data[4084];             /* raw data, bytes 8-4091 (inclusive).
                                           see the data descriptor field for the
                                           other mising bytes */
    uint32_t    sequence_low;           /* 4 LSB of 8 byte sequence_number */
} vhdx_log_data_sector;



#define PAYLOAD_BLOCK_NOT_PRESENT       0
#define PAYLOAD_BLOCK_UNDEFINED         1
#define PAYLOAD_BLOCK_ZERO              2
#define PAYLOAD_BLOCK_UNMAPPED          5
#define PAYLOAD_BLOCK_FULL_PRESENT      6
#define PAYLOAD_BLOCK_PARTIALLY_PRESENT 7

#define SB_BLOCK_NOT_PRESENT    0
#define SB_BLOCK_PRESENT        6

typedef struct vhdx_bat_entry {
    union vhdx_bat_bitfield {
        struct {
            uint64_t    state:3;           /* state of the block (see above) */
            uint64_t    reserved:17;
            uint64_t    file_offset_mb:44; /* offset within file in 1MB units */
        } bits;
        uint64_t data;
    } bitfield;
} vhdx_bat_entry;




/* ---- METADATA REGION STRUCTURES ---- */

#define VHDX_METADATA_ENTRY_SIZE 32
#define VHDX_METADATA_MAX_ENTRIES 2047  /* not including the header */
#define VHDX_METADATA_TABLE_MAX_SIZE \
    (VHDX_METADATA_ENTRY_SIZE * (VHDX_METADATA_MAX_ENTRIES+1))
#define VHDX_METADATA_MAGIC 0x617461646174656D /* 'metadata' */
typedef struct vhdx_metadata_table_header {
    uint64_t    signature;              /* "metadata" in ASCII */
    uint16_t    reserved;
    uint16_t    entry_count;            /* number table entries. <= 2047 */
    uint32_t    reserved2[5];
} vhdx_metadata_table_header;



static const ms_guid file_param_guid = { .data1 = 0xcaa16737,
                                         .data2 = 0xfa36,
                                         .data3 = 0x4d43,
                                         .data4 = { 0xb3, 0xb6, 0x33, 0xf0,
                                                    0xaa, 0x44, 0xe7, 0x6b}};

static const ms_guid virtual_size_guid = { .data1 = 0x2FA54224,
                                           .data2 = 0xcd1b,
                                           .data3 = 0x4876,
                                           .data4 = { 0xb2, 0x11, 0x5d, 0xbe,
                                                      0xd8, 0x3b, 0xf4, 0xb8}};

static const ms_guid page83_guid = { .data1 = 0xbeca12ab,
                                     .data2 = 0xb2e6,
                                     .data3 = 0x4523,
                                     .data4 = { 0x93, 0xef, 0xc3, 0x09,
                                                0xe0, 0x00, 0xc7, 0x46}};

static const ms_guid logical_sector_guid = {.data1 = 0x8141bf1d,
                                            .data2 = 0xa96f,
                                            .data3 = 0x4709,
                                            .data4 = { 0xba, 0x47, 0xf2, 0x33,
                                                       0xa8, 0xfa, 0xab, 0x5f}};

static const ms_guid phys_sector_guid = { .data1 = 0xcda348c7,
                                          .data2 = 0x445d,
                                          .data3 = 0x4471,
                                          .data4 = { 0x9c, 0xc9, 0xe9, 0x88,
                                                     0x52, 0x51, 0xc5, 0x56}};

static const ms_guid parent_locator_guid = {.data1 = 0xa8d35f2d,
                                            .data2 = 0xb30b,
                                            .data3 = 0x454d,
                                            .data4 = { 0xab, 0xf7, 0xd3, 0xd8,
                                                       0x48, 0x34, 0xab, 0x0c}};
typedef struct vhdx_metadata_table_entry {
    ms_guid     item_id;                /* 128-bit identifier for metadata */
    uint32_t    offset;                 /* byte offset of the metadata.  At
                                           least 64kB.  Relative to start of
                                           metadata region */
                                        /* note: if length = 0, so is offset */
    uint32_t    length;                 /* length of metadata. <= 1MB. */
    union vhdx_metadata_bitfield {
        struct {
            uint32_t    is_user:1;         /* 1: user metadata, 0: system
                                              metadata 1024 entries max can have
                                              this set */
            uint32_t    is_virtual_disk:1; /* See spec.  1: virtual disk
                                              metadata 0: file metadata */
            uint32_t    is_required:1;     /* 1: parser must understand this
                                              data */
            uint32_t    reserved:29;
        } bits;
        uint32_t data;
    } bitfield;
    uint32_t    reserved2;
} vhdx_metadata_table_entry;

typedef struct vhdx_file_parameters {
    uint32_t    block_size;             /* size of each payload block, always
                                           power of 2, <= 256MB and >= 1MB. */
    union _bitfield {
        struct {
            uint32_t    leave_blocks_allocated:1; /* if 1, do not change any
                                                     blocks to be
                                                     BLOCK_NOT_PRESENT.  For
                                                     fixed sized VHDX files */
            uint32_t    has_parent:1;            /* Has parent / backing file */
            uint32_t    reserved:30;
        } bits;
        uint64_t data;
    } bitfield;
} vhdx_file_parameters;

typedef struct vhdx_virtual_disk_size {
    uint64_t    virtual_disk_size;      /* Size of the virtual disk, in bytes.
                                           Must be multiple of the sector size,
                                           max of 64TB */
} vhdx_virtual_disk_size;

typedef struct vhdx_page83_data {
    uint8_t     page_83_data[16];       /* unique id for scsi devices that
                                           support page 0x83 */
} vhdx_page83_data;

typedef struct vhdx_virtual_disk_logical_sector_size {
    uint32_t    logical_sector_size;    /* virtual disk sector size (in bytes).
                                           Can only be 512 or 4096 bytes */
} vhdx_virtual_disk_logical_sector_size;

typedef struct vhdx_virtual_disk_physical_sector_size {
    uint32_t    physical_sector_size;   /* physical sector size (in bytes).
                                           Can only be 512 or 4096 bytes */
} vhdx_virtual_disk_physical_sector_size;

typedef struct vhdx_parent_locator_header {
    uint8_t     locator_type[16];       /* type of the parent virtual disk. */
    uint16_t    reserved;
    uint16_t    key_value_count;        /* number of key/value pairs for this
                                           locator */
} vhdx_parent_locator_header;

/* key and value strings are UNICODE strings, UTF-16 LE encoding, no NULs */
typedef struct vhdx_parent_locator_entry {
    uint32_t    key_offset;             /* offset in metadata for key, > 0 */
    uint32_t    value_offset;           /* offset in metadata for value, >0 */
    uint16_t    key_length;             /* length of entry key, > 0 */
    uint16_t    value_length;           /* length of entry value, > 0 */
} vhdx_parent_locator_entry;


/* ----- END VHDX SPECIFICATION STRUCTURES ---- */




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

    vhdx_metadata_table_entry file_parameters_entry;
    vhdx_metadata_table_entry virtual_disk_size_entry;
    vhdx_metadata_table_entry page83_data_entry;
    vhdx_metadata_table_entry logical_sector_size_entry;
    vhdx_metadata_table_entry phys_sector_size_entry;
    vhdx_metadata_table_entry parent_locator_entry;

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

#define vhdx_nop(x) do { (void)(x); } while (0)

/* Help macros to copy data from file buffers to header
 * structures, with proper endianness.  These help avoid
 * using packed structs */

/* Do not use directly, see macros below */
#define _hdr_copy(item, buf, size, offset, to_cpu) \
    memcpy((item), (buf)+(offset), (size));        \
    to_cpu((item));                                \
    (offset) += (size);

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

/* copies a defined msguid field, with correct endianness */
#define hdr_copy_guid(item, buf, offset)             \
        hdr_copy32(&(item).data1, (buf), (offset));  \
        hdr_copy16(&(item).data2, (buf), (offset));  \
        hdr_copy16(&(item).data3, (buf), (offset));  \
        hdr_copy(&(item).data4, (buf), sizeof((item).data4), (offset));


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
static int vhdx_open_header(BlockDriverState *bs, BDRVVHDXState *s)
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

    for (i = 0; i < s->metadata_hdr.entry_count; i++) {
        hdr_copy_guid(md_entry.item_id,     buffer, offset);
        hdr_copy32(&md_entry.offset,        buffer, offset);
        hdr_copy32(&md_entry.length,        buffer, offset);
        hdr_copy32(&md_entry.bitfield.data, buffer, offset);
        hdr_copy32(&md_entry.reserved2,     buffer, offset);

        if (guid_cmp(md_entry.item_id, file_param_guid)) {
            s->file_parameters_entry = md_entry;
            printf("file parameter metadata entry found!\n");
            continue;
        }

        if (guid_cmp(md_entry.item_id, virtual_size_guid)) {
            s->virtual_disk_size_entry = md_entry;
            printf("virtual size metadata entry found!\n");
            continue;
        }

        if (guid_cmp(md_entry.item_id, page83_guid)) {
            s->page83_data_entry = md_entry;
            printf("page 83 metadata entry found!\n");
            continue;
        }

        if (guid_cmp(md_entry.item_id, logical_sector_guid)) {
            s->logical_sector_size_entry = md_entry;
            printf("logical sector metadata entry found!\n");
            continue;
        }

        if (guid_cmp(md_entry.item_id, phys_sector_guid)) {
            s->phys_sector_size_entry = md_entry;
            printf("physical sector  metadata entry found!\n");
            continue;
        }

        if (guid_cmp(md_entry.item_id, parent_locator_guid)) {
            s->parent_locator_entry = md_entry;
            printf("parent locator metadata entry found!\n");
            continue;
        }

        if (md_entry.bitfield.bits.is_required) {
            /* cannot read vhdx file - required region table entry that
             * we do not understand.  per spec, we must fail to open */
            printf("Found unknown metadata table entry that is REQUIRED!\n");
            ret = -1;
            goto fail;
        }


    }

fail:
    g_free(buffer);
fail_no_free:
    return ret;
}

static int vhdx_open(BlockDriverState *bs, int flags)
{
    BDRVVHDXState *s = bs->opaque;
    int ret = 0;


    vhdx_open_header(bs, s);
    vhdx_open_region_tables(bs, s);
    vhdx_parse_metadata(bs, s);

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
