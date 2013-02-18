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

#ifndef BLOCK_VHDX_H
#define BLOCK_VHDX_H

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


/*
 * A note on the use of MS-GUID fields.  For more details on the GUID,
 * please see: https://en.wikipedia.org/wiki/Globally_unique_identifier.
 *
 * The VHDX specification only states that these are MS GUIDs, and which
 * bytes are data1-data4. It makes no mention of what algorithm should be used
 * to generate the GUID, nor what standard.  However, looking at the specified
 * known GUID fields, it appears the GUIDs are:
 *  Standard/DCE GUID type  (noted by 10b in the MSB of byte 0 of .data4)
 *  Random algorithm        (noted by 0x4XXX for .data3)
 */

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

#define guid_eq(a, b) \
    (memcmp(&(a), &(b), sizeof(ms_guid)) == 0)

#define VHDX_HEADER_SIZE (4*1024)   /* although the vhdx_header struct in disk
                                       is only 582 bytes, for purposes of crc
                                       the header is the first 4KB of the 64KB
                                       block */

#define VHDX_HDR_MAGIC 0x64616568   /* 'head' */
typedef struct QEMU_PACKED vhdx_header {
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
typedef struct QEMU_PACKED vhdx_header_padded {
    vhdx_header header;
    uint8_t     reserved[502];          /* per the VHDX spec */
    uint8_t     reserved_[3514];        /* for the initial packed struct read */
} vhdx_header_padded;

/* Header for the region table block */
#define VHDX_RT_MAGIC 0x69676572  /* 'regi ' */
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
#define VHDX_REGION_ENTRY_REQUIRED  0x01    /* if set, parser must understand
                                               this entry in order to open
                                               file */
typedef struct QEMU_PACKED vhdx_region_table_entry {
    ms_guid     guid;                   /* 128-bit unique identifier */
    uint64_t    file_offset;            /* offset of the object in the file.
                                           Must be multiple of 1MB */
    uint32_t    length;                 /* length, in bytes, of the object */
    uint32_t    data_bits;
} vhdx_region_table_entry;


/* ---- LOG ENTRY STRUCTURES ---- */

#define VHDX_LOGE_MAGIC 0x65676F6C /* 'loge' */
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
    ms_guid     log_guid;               /* value of the log_guid from
                                           vhdx_header.  If not found in
                                           vhdx_header, it is invalid */
    uint64_t    flushed_file_offset;    /* see spec for full details - this
                                           sould be vhdx file size in bytes */
    uint64_t    last_file_offset;       /* size in bytes that all allocated
                                           file structures fit into */
} vhdx_log_entry_header;

#define VHDX_ZERO_MGIC 0x6F72657A /* 'zero' */
typedef struct QEMU_PACKED vhdx_log_zero_descriptor {
    uint32_t    zero_signature;         /* "zero" in ASCII */
    uint32_t    reserver;
    uint64_t    zero_length;            /* length of the section to zero */
    uint64_t    file_offset;            /* file offset to write zeros - multiple
                                           of 4kB */
    uint64_t    sequence_number;        /* must match same field in
                                           vhdx_log_entry_header */
} vhdx_log_zero_descriptor;

#define VHDX_DATA_MAGIC 0x63736564 /* 'desc' */
typedef struct QEMU_PACKED vhdx_log_data_descriptor {
    uint32_t    data_signature;         /* "desc" in ASCII */
    uint32_t    trailing_bytes;         /* bytes 4092-4096 of the data sector */
    uint64_t    leading_bytes;          /* bytes 0-7 of the data sector */
    uint64_t    file_offset;            /* file offset where the data described
                                           herein is written */
    uint64_t    sequence_number;        /* must match the sequence number field
                                           in entry header */
} vhdx_log_data_descriptor;

#define VHDX_DATAS_MAGIC 0x61746164 /* 'data' */
typedef struct QEMU_PACKED vhdx_log_data_sector {
    uint32_t    data_signature;         /* "data" in ASCII */
    uint32_t    sequence_high;          /* 4 MSB of 8 byte sequence_number */
    uint8_t     data[4084];             /* raw data, bytes 8-4091 (inclusive).
                                           see the data descriptor field for the
                                           other mising bytes */
    uint32_t    sequence_low;           /* 4 LSB of 8 byte sequence_number */
} vhdx_log_data_sector;



/* block states - different state values depending on whether it is a
 * payload block, or a sector block. */

#define PAYLOAD_BLOCK_NOT_PRESENT       0
#define PAYLOAD_BLOCK_UNDEFINED         1
#define PAYLOAD_BLOCK_ZERO              2
#define PAYLOAD_BLOCK_UNMAPPED          5
#define PAYLOAD_BLOCK_FULL_PRESENT      6
#define PAYLOAD_BLOCK_PARTIALLY_PRESENT 7

#define SB_BLOCK_NOT_PRESENT    0
#define SB_BLOCK_PRESENT        6

/* per the spec */
#define VHDX_MAX_SECTORS_PER_BLOCK  (1<<23)

/* upper 44 bits are the file offset in 1MB units lower 3 bits are the state
   other bits are reserved */
#define VHDX_BAT_STATE_BIT_MASK 0x07
#define VHDX_BAT_FILE_OFF_BITS (64-44)
typedef uint64_t vhdx_bat_entry;

/* ---- METADATA REGION STRUCTURES ---- */

#define VHDX_METADATA_ENTRY_SIZE 32
#define VHDX_METADATA_MAX_ENTRIES 2047  /* not including the header */
#define VHDX_METADATA_TABLE_MAX_SIZE \
    (VHDX_METADATA_ENTRY_SIZE * (VHDX_METADATA_MAX_ENTRIES+1))
#define VHDX_METADATA_MAGIC 0x617461646174656D /* 'metadata' */
typedef struct QEMU_PACKED vhdx_metadata_table_header {
    uint64_t    signature;              /* "metadata" in ASCII */
    uint16_t    reserved;
    uint16_t    entry_count;            /* number table entries. <= 2047 */
    uint32_t    reserved2[5];
} vhdx_metadata_table_header;

#define VHDX_META_FLAGS_IS_USER         0x01    /* max 1024 entries */
#define VHDX_META_FLAGS_IS_VIRTUAL_DISK 0x02    /* virtual disk metadata if set,
                                                   otherwise file metdata */
#define VHDX_META_FLAGS_IS_REQUIRED     0x04    /* parse must understand this
                                                   entry to open the file */
typedef struct QEMU_PACKED vhdx_metadata_table_entry {
    ms_guid     item_id;                /* 128-bit identifier for metadata */
    uint32_t    offset;                 /* byte offset of the metadata.  At
                                           least 64kB.  Relative to start of
                                           metadata region */
                                        /* note: if length = 0, so is offset */
    uint32_t    length;                 /* length of metadata. <= 1MB. */
    uint32_t    data_bits;      /* least-significant 3 bits are flags, the
                                   rest are reserved (see above) */
    uint32_t    reserved2;
} vhdx_metadata_table_entry;

#define VHDX_PARAMS_LEAVE_BLOCKS_ALLOCED 0x01   /* Do not change any blocks to
                                                   be BLOCK_NOT_PRESENT.
                                                   If set indicates a fixed
                                                   size VHDX file */
#define VHDX_PARAMS_HAS_PARENT           0x02    /* has parent / backing file */
typedef struct QEMU_PACKED vhdx_file_parameters {
    uint32_t    block_size;             /* size of each payload block, always
                                           power of 2, <= 256MB and >= 1MB. */
    uint32_t data_bits;     /* least-significant 2 bits are flags, the rest
                               are reserved (see above) */
} vhdx_file_parameters;

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

#endif
