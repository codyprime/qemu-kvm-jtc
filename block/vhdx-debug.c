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
#include "block/vhdx.h"

#include <uuid/uuid.h>

#if (VHDX_DEBUG == 1)

void vhdx_print_header(VHDXHeader *h)
{
    int i;

    printf("\n===== VHDX Header ==========================================\n");
    printf("signature: 0x%" PRIx32 "\n", h->signature);
    printf("checksum: 0x%" PRIx32 "\n", h->checksum);
    printf("sequence_number: 0x%" PRIx64 "\n", h->sequence_number);
    printf("file_write_guid: %08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 "-",
            h->file_write_guid.data1,
            h->file_write_guid.data2,
            h->file_write_guid.data3);
    printf("%02" PRIx8 "%02" PRIx8 "-", h->file_write_guid.data4[0],
                                        h->file_write_guid.data4[1]);
    for (i = 2; i < 8; i++) {
        printf("%02" PRIx8, h->file_write_guid.data4[i]);
    }
    printf("\n");
    printf("data_write_guid: %08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 "-",
            h->data_write_guid.data1,
            h->data_write_guid.data2,
            h->data_write_guid.data3);
    printf("%02" PRIx8 "%02" PRIx8 "-", h->data_write_guid.data4[0],
                                        h->data_write_guid.data4[1]);
    for (i = 2; i < 8; i++) {
        printf("%02" PRIx8, h->data_write_guid.data4[i]);
    }
    printf("\n");
    printf("log_guid:        %08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 "-",
            h->log_guid.data1,
            h->log_guid.data2,
            h->log_guid.data3);
    printf("%02" PRIx8 "%02" PRIx8 "-", h->log_guid.data4[0],
                                        h->log_guid.data4[1]);
    for (i = 2; i < 8; i++) {
        printf("%02" PRIx8, h->log_guid.data4[i]);
    }
    printf("\n");

    printf("log_version: 0x%" PRIx16 "\n", h->log_version);
    printf("version: 0x%" PRIx16 "\n", h->version);
    printf("log_length: 0x%" PRIx32 "\n", h->log_length);
    printf("log_offset: 0x%" PRIx64 "\n", h->log_offset);
    printf("============================================================\n\n");
}


void vhdx_print_guid(MSGUID *guid)
{
    int i;
    printf("%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 "-",
            guid->data1,
            guid->data2,
            guid->data3);
    printf("%02" PRIx8 "%02" PRIx8 "-", guid->data4[0],
                                        guid->data4[1]);
    for (i = 2; i < 8; i++) {
        printf("%02" PRIx8, guid->data4[i]);
    }
    printf("\n");

}


void vhdx_log_hdr_print(VHDXLogEntryHeader *hdr, BDRVVHDXState *s)
{
    printf("hdr->signature: 0x%04x\n", hdr->signature);
    printf("hdr->checksum: 0x%04x\n", hdr->checksum);
    printf("hdr->entry_length: 0x%04x\n", hdr->entry_length);
    printf("hdr->tail: 0x%04x\n", hdr->tail);
    printf("hdr->sequence_number: 0x%" PRIx64 "\n", hdr->sequence_number);
    printf("hdr->descriptor_count: %" PRId32 "\n", hdr->descriptor_count);
    printf("hdr->flushed_file_offset: 0x%" PRIx64 "\n",
                     hdr->flushed_file_offset);
    printf("hdr->last_file_offset: 0x%" PRIx64 "\n", hdr->last_file_offset);
    printf("hdr->log_guid: ");
    vhdx_print_guid(&hdr->log_guid);
    printf("vhdx->log_guid: ");
    vhdx_print_guid(&s->headers[s->curr_header]->log_guid);
    printf("\n");

}
#endif
