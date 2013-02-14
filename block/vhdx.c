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
 * | File Id. |   Header 1    | Header 2   | Region Table |  Reserverd (768KB) |
 * 0.........64KB...........128KB........192KB..........256KB................1MB
 * -----------------------------------------------------------------------------
 */

#define VHDX_HEADER_BLOCK_SIZE      (64*1024)

#define VHDX_FILE_ID_OFFSET         0
#define VHDX_HEADER1_OFFSET         (VHDX_HEADER_BLOCK_SIZE*1)
#define VHDX_HEADER2_OFFSET         (VHDX_HEADER_BLOCK_SIZE*2)
#define VHDX_REGION_TABLE_OFFSET    (VHDX_HEADER_BLOCK_SIZE*3)


/* ---- HEADER SECTION STRUCTURES ---- */

typedef struct vhdx_file_identifier {
    uint64_t    signature;              /* "vhdxfile" in ASCII */
    uint16_t    creator[256];           /* optional; utf-16 string to identify
                                           the vhdx file creator.  Diagnotistic
                                           only */
} vhdx_file_identifier;


#define VHDX_HEADER_SIZE (4*1024)   /* although the vhdx_header struct in disk
                                       is only 582 bytes, for purposes of crc
                                       the header is the first 4KB of the 64KB
                                       block */

typedef struct QEMU_PACKED vhdx_header {
    uint32_t    signature;              /* "head" in ASCII */
    uint32_t    checksum;               /* CRC-32C hash of the whole header */
    uint64_t    sequence_number;        /* Seq number of this header.  Each
                                           VHDX file has 2 of these headers,
                                           and only the header with the highest
                                           sequence number is valid */
    uint8_t     file_write_guid[16];    /* 128 bit unique identifier. Must be
                                           updated to new, unique value before
                                           the first modification is made to
                                           file */
    uint8_t     data_write_guid[16];    /* 128 bit unique identifier. Must be
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
    uint8_t     log_guid[16];           /* 128 bit unique identifier. If zero,
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
typedef struct QEMU_PACKED vhdx_header_padded {
    vhdx_header header;
    uint8_t     reserved[502];          /* per the VHDX spec */
    uint8_t     reserved_[3514];        /* for the initial packed struct read */
} vhdx_header_padded;

/* Header for the region table block */
typedef struct QEMU_PACKED vhdx_region_table_header {
    uint32_t    signature;              /* "regi" in ASCII */
    uint32_t    checksum;               /* CRC-32C hash of the 64KB table */
    uint32_t    entry_count;            /* number of valid entries */
    uint32_t    reserved;
} vhdx_region_table_header;

/* Individual region table entry.  There may be a maximum of 2047 of these
 *
 *  There are two known region table properties.  Both are required.
 *  BAT (block allocation table):  2DC27766F62342009D64115E9BFD4A08
 *  Metadata:                      8B7CA20647904B9AB8FE575F050F886E
 */
typedef struct QEMU_PACKED vhdx_region_table_entry {
    uint8_t     guid[16];               /* 128-bit unique identifier */
    uint64_t    file_offset;            /* offset of the object in the file.
                                           Must be multiple of 1MB */
    uint32_t    length;                 /* length, in bytes, of the object */
    uint32_t    required:1;             /* 1 if this region must be recognized
                                           in order to load the file */
    uint32_t    reserved:31;
} vhdx_region_table_entry;









/* ---- LOG ENTRY STRUCTURES ---- */

typedef struct QEMU_PACKED vhdx_log_entry_header {
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
    uint8_t     log_guid[16];           /* value of the log_guid from
                                           vhdx_header.  If not found in
                                           vhdx_header, it is invalid */
    uint64_t    flushed_file_offset;    /* see spec for full details - this
                                           sould be vhdx file size in bytes */
    uint64_t    last_file_offset;       /* size in bytes that all allocated
                                           file structures fit into */
} vhdx_log_entry_header;


typedef struct QEMU_PACKED vhdx_log_zero_descriptor {
    uint32_t    zero_signature;         /* "zero" in ASCII */
    uint32_t    reserver;
    uint64_t    zero_length;            /* length of the section to zero */
    uint64_t    file_offset;            /* file offset to write zeros - multiple
                                           of 4kB */
    uint64_t    sequence_number;        /* must match same field in
                                           vhdx_log_entry_header */
} vhdx_log_zero_descriptor;


typedef struct QEMU_PACKED vhdx_log_data_descriptor {
    uint32_t    data_signature;         /* "desc" in ASCII */
    uint32_t    trailing_bytes;         /* bytes 4092-4096 of the data sector */
    uint64_t    leading_bytes;          /* bytes 0-7 of the data sector */
    uint64_t    file_offset;            /* file offset where the data described
                                           herein is written */
    uint64_t    sequence_number;        /* must match the sequence number field
                                           in entry header */
} vhdx_log_data_descriptor;


typedef struct QEMU_PACKED vhdx_log_data_sector {
    uint32_t    data_signature;         /* "data" in ASCII */
    uint32_t    sequence_high;          /* 4 MSB of 8 byte sequence_number */
    uint8_t     data[4084];             /* raw data, bytes 8-4091 (inclusive).
                                           see the data descriptor field for the
                                           other mising bytes */
    uint32_t    sequence_low;           /* 4 LSB of 8 byte sequence_number */
} vhdx_log_data_sector;







/* ---- METADATA REGION STRUCTURES ---- */

typedef struct QEMU_PACKED vhdx_metadata_table_header {
    uint64_t    signature;              /* "metadata" in ASCII */
    uint16_t    reserved;
    uint16_t    entry_count;            /* number table entries. <= 2047 */
    uint32_t    reserved2[5];
} vhdx_metadata_table_header;

typedef struct QEMU_PACKED vhdx_metadata_table_entry {
    uint8_t     item_id[16];            /* 128-bit identifier for metadata */
    uint32_t    offset;                 /* byte offset of the metadata.  At
                                           least 64kB.  Relative to start of
                                           metadata region */
                                        /* note: if length = 0, so is offset */
    uint32_t    length;                 /* length of metadata. <= 1MB. */
    uint32_t    is_user:1;              /* 1: user metadata, 0: system metadata
                                           1024 entries max can have this set */
    uint32_t    is_virtual_disk:1;      /* See spec.  1: virtual disk metadata
                                                  0: file metadata */
    uint32_t    is_required:1;          /* 1: parser must understand this
                                           data */
    uint32_t    reserved:29;
    uint32_t    reserved2;
} vhdx_metadata_table_entry;

typedef struct QEMU_PACKED vhdx_virtual_disk_size {
    uint64_t    virtual_disk_size;      /* Size of the virtual disk, in bytes.
                                           Must be multiple of the sector size,
                                           max of 64TB */
} vhdx_virtual_disk_size;

typedef struct QEMU_PACKED vhdx_page83_data {
    uint8_t     page_83_data[16];       /* unique id for scsi devices that
                                           support page 0x83 */
} vhdx_page83_data;

typedef struct QEMU_PACKED vhdx_virtual_disk_logical_sector_size {
    uint32_t    logical_sector_size;    /* virtual disk sector size (in bytes).
                                           Can only be 512 or 4096 bytes */
} vhdx_virtual_disk_logical_sector_size;

typedef struct QEMU_PACKED vhdx_virtual_disk_physical_sector_size {
    uint32_t    physical_sector_size;   /* physical sector size (in bytes).
                                           Can only be 512 or 4096 bytes */
} vhdx_virtual_disk_physical_sector_size;

typedef struct QEMU_PACKED vhdx_parent_locator_header {
    uint8_t     locator_type[16];       /* type of the parent virtual disk. */
    uint16_t    reserved;
    uint16_t    key_value_count;        /* number of key/value pairs for this
                                           locator */
} vhdx_parent_locator_header;

/* key and value strings are UNICODE strings, UTF-16 LE encoding, no NULs */
typedef struct QEMU_PACKED vhdx_parent_locator_entry {
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
    uint8_t region_table_buf[VHDX_HEADER_BLOCK_SIZE];

    /* TODO */

} BDRVVHDXState;

#define vhdx_validate_checksum(block, size, old, valid)                    \
                (old) = (block)->checksum;                                 \
                printf("read checksum: %08" PRIx32 "\n",(old));            \
                (block)->checksum = 0;                                     \
                (valid) = (old) == vhdx_checksum((uint8_t *)(block), (size)) ? 1 : 0; \
                (block)->checksum = (old);
                

/* CRC-32C, Castagnoli polynomial, code 0x11EDC6F41 */
static uint32_t vhdx_checksum(uint8_t* buf, size_t size)
{
    uint32_t chksum;
    printf("computing checksum for length %zu\n", size);
    chksum =  crc32c(0, buf, size);
    printf("vhdx_checksum: %08" PRIx32 "\n", chksum);
    return chksum;
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

static void vhdx_unpack_header(vhdx_header *hdr, vhdx_header_padded *hdr_pad)
{
    hdr->signature = hdr_pad->header.signature;
    hdr->checksum = hdr_pad->header.checksum;
    hdr->sequence_number = hdr_pad->header.sequence_number;
    hdr->log_version = hdr_pad->header.log_version;
    hdr->version = hdr_pad->header.version;
    hdr->log_length = hdr_pad->header.log_length;
    hdr->log_offset = hdr_pad->header.log_offset;

    memcpy(hdr->file_write_guid, hdr_pad->header.file_write_guid,
           sizeof(hdr->file_write_guid));
    memcpy(hdr->data_write_guid, hdr_pad->header.data_write_guid,
           sizeof(hdr->data_write_guid));
    memcpy(hdr->log_guid,  hdr_pad->header.log_guid, sizeof(hdr->log_guid));

}

/* opens the specified header block from the VHDX file header section */
static int vhdx_open_header(BlockDriverState *bs, BDRVVHDXState *s)
{
    int ret = 0;
    uint32_t checksum_orig;
    int is_valid;
    vhdx_header *header1;
    vhdx_header *header2;
    uint64_t h1_seq = 0;
    uint64_t h2_seq = 0;
    vhdx_header *buffer;
   
    
    printf("%s:%d\n",__FILE__,__LINE__);
    header1 = g_malloc(sizeof(vhdx_header));
    header2 = g_malloc(sizeof(vhdx_header));

    buffer = g_malloc(sizeof(vhdx_header_padded));
    s->headers[0] = header1;
    s->headers[1] = header2;

    printf("header1 ptr = %016" PRIxPTR "\n", (uintptr_t) header1);
    ret = bdrv_pread(bs->file, VHDX_HEADER1_OFFSET, buffer, sizeof(vhdx_header_padded));
    if (ret < 0) {
    printf("%s:%d error: %s\n",__FILE__,__LINE__,strerror(-ret));
        goto fail;
    }
    vhdx_unpack_header(header1, (vhdx_header_padded *) buffer);
    vhdx_validate_checksum(buffer, sizeof(vhdx_header_padded), checksum_orig,
                           is_valid);
    if (is_valid) {
        h1_seq = header1->sequence_number;
    }

    ret = bdrv_pread(bs->file, VHDX_HEADER2_OFFSET, buffer, sizeof(vhdx_header_padded));
    if (ret < 0) {
    printf("%s:%d error: %s\n",__FILE__,__LINE__,strerror(-ret));
        goto fail;
    }
    vhdx_unpack_header(header1, (vhdx_header_padded *) buffer);
    vhdx_validate_checksum(buffer, sizeof(vhdx_header_padded), checksum_orig,
                           is_valid);
    if (is_valid) {
        h2_seq = header2->sequence_number;
    }

    if (h1_seq > h2_seq) {
        s->curr_header = 0;
    } else if (h2_seq < h1_seq) {
        s->curr_header = 1;
    } else {
        ret = -1;
    }
    printf("current header is %d\n",s->curr_header);
    goto exit;

fail:
    printf("%s:%d\n",__FILE__,__LINE__);
    g_free(header1);
    printf("%s:%d\n",__FILE__,__LINE__);
    g_free(header2);
    printf("%s:%d\n",__FILE__,__LINE__);
    s->headers[0] = NULL;
    s->headers[1] = NULL;
exit:
    g_free(buffer);
    return ret;
}


static int vhdx_open(BlockDriverState *bs, int flags)
{
    BDRVVHDXState *s = bs->opaque;
    int ret = 0;

    vhdx_open_header(bs, s);

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

    printf("%s:%d\n",__FILE__,__LINE__);
    g_free(s->headers[0]);
    printf("%s:%d\n",__FILE__,__LINE__);
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
