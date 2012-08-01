/*
 * Hierarchical Bitmap Data Type
 *
 * Copyright Red Hat, Inc., 2012
 *
 * Author: Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#ifndef HBITMAP_H
#define HBITMAP_H 1

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include "bitops.h"

typedef struct HBitmap HBitmap;
typedef struct HBitmapIter HBitmapIter;

#define BITS_PER_LEVEL         (BITS_PER_LONG == 32 ? 5 : 6)

/* For 32-bit, the largest that fits in a 4 GiB address space.
 * For 64-bit, the number of sectors in 1 PiB.  Good luck, in
 * either case... :)
 */
#define HBITMAP_LOG_MAX_SIZE   (BITS_PER_LONG == 32 ? 34 : 41)

/* Leave an extra bit for a sentinel.  */
#define HBITMAP_LEVELS         ((HBITMAP_LOG_MAX_SIZE / BITS_PER_LEVEL) + 1)

struct HBitmapIter {
    HBitmap *hb;
    size_t pos;
    int granularity;
    unsigned long cur[HBITMAP_LEVELS];
};

int64_t hbitmap_iter_next(HBitmapIter *hbi);
void hbitmap_iter_init(HBitmapIter *hbi, HBitmap *hb, uint64_t first);
bool hbitmap_empty(HBitmap *hb);
uint64_t hbitmap_count(HBitmap *hb);
void hbitmap_set(HBitmap *hb, uint64_t start, uint64_t count);
void hbitmap_reset(HBitmap *hb, uint64_t start, uint64_t count);
bool hbitmap_get(HBitmap *hb, uint64_t item);
void hbitmap_free(HBitmap *hb);
HBitmap *hbitmap_alloc(uint64_t size, int granularity);

#endif
