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

#include "osdep.h"
#include "hbitmap.h"
#include "host-utils.h"
#include "trace.h"
#include <string.h>
#include <glib.h>
#include <assert.h>

/* HBitmaps provides an array of bits.  The bits are stored as usual in an
 * array of unsigned longs, but HBitmap is also optimized to provide fast
 * iteration over set bits; going from one bit to the next is O(logB n)
 * worst case, with B = sizeof(long) * CHAR_BIT: the result is low enough
 * that the number of levels is in fact fixed.
 *
 * In order to do this, it stacks multiple bitmaps with progressively coarser
 * granularity; in all levels except the last, bit N is set iff the N-th
 * unsigned long is nonzero in the immediately next level.  When iteration
 * completes on the last level it can examine the 2nd-last level to quickly
 * skip entire words, and even do so recursively to skip blocks of 64 words or
 * powers thereof (32 on 32-bit machines).
 *
 * Given an index in the bitmap, it can be split in group of bits like
 * this (for the 64-bit case):
 *
 *   bits 0-57 => word in the last bitmap     | bits 58-63 => bit in the word
 *   bits 0-51 => word in the 2nd-last bitmap | bits 52-57 => bit in the word
 *   bits 0-45 => word in the 3rd-last bitmap | bits 46-51 => bit in the word
 *
 * So it is easy to move up simply by shifting the index right by
 * log2(BITS_PER_LONG) bits.  To move down, you shift the index left
 * similarly, and add the word index within the group.  Iteration uses
 * ffs (find first set bit) to find the next word to examine; this
 * operation can be done in constant time in most current architectures.
 *
 * Setting or clearing a range of m bits on all levels, the work to perform
 * is O(m + m/W + m/W^2 + ...), which is O(m) like on a regular bitmap.
 *
 * When iterating on a bitmap, each bit (on any level) is only visited
 * once.  Hence, The total cost of visiting a bitmap with m bits in it is
 * the number of bits that are set in all bitmaps.  Unless the bitmap is
 * extremely sparse, this is also O(m + m/W + m/W^2 + ...), so the amortized
 * cost of advancing from one bit to the next is usually constant (worst case
 * O(logB n) as in the non-amortized complexity).
 */

struct HBitmap {
    /* Number of total bits in the bottom level.  */
    uint64_t size;

    /* Number of set bits in the bottom level.  */
    uint64_t count;

    /* A scaling factor.  When setting or resetting bits, the bitmap will
     * scale bit numbers right by this amount of bits.  When iterating,
     * the bitmap will scale bit numbers left by this amonut of bits.
     * Example of operations in a size-16, granularity-1 HBitmap:
     *
     *    initial state            00000000
     *    set(start=0, count=9)    11111000 (iter: 0, 2, 4, 6, 8)
     *    reset(start=1, count=3)  00111000 (iter: 4, 6, 8)
     *    set(start=9, count=2)    00111100 (iter: 4, 6, 8, 10)
     *    reset(start=5, count=5)  00000000
     */
    int granularity;

    /* A number of progressively less coarse bitmaps (i.e. level 0 is the
     * coarsest).  Each bit in level N represents a word in level N+1 that
     * has a set bit, except the last level where each bit represents the
     * actual bitmap.
     */
    unsigned long *levels[HBITMAP_LEVELS];
};

static int64_t hbi_next_internal(HBitmapIter *hbi)
{
    unsigned long cur = hbi->cur[HBITMAP_LEVELS - 1];
    size_t pos = hbi->pos;

    if (cur == 0) {
        HBitmap *hb = hbi->hb;
        int i = HBITMAP_LEVELS - 1;

        do {
            cur = hbi->cur[--i];
            pos >>= BITS_PER_LEVEL;
        } while (cur == 0);

        /* Check for end of iteration.  We only use up to
         * BITS_PER_LEVEL bits (actually less) in the level 0 bitmap,
         * and a sentinel is placed in hbitmap_alloc that ends the
         * above loop.
         */

        if (i == 0 && (cur & (BITS_PER_LONG - 1)) == 0) {
            return -1;
        }
        for (; i < HBITMAP_LEVELS - 1; i++) {
            /* Find least significant set bit in the word, use them
             * to add back shifted out bits to pos.
             */
            pos = (pos << BITS_PER_LEVEL) + ffsl(cur) - 1;
            hbi->cur[i] = cur & (cur - 1);

            /* Set up next level for iteration.  */
            cur = hb->levels[i + 1][pos];
        }

        hbi->pos = pos;
        hbi->cur[HBITMAP_LEVELS - 1] = cur & (cur - 1);
    } else {
        hbi->cur[HBITMAP_LEVELS - 1] &= cur - 1;
    }
    return ((uint64_t)pos << BITS_PER_LEVEL) + ffsl(cur) - 1;
}

static inline int popcountl(unsigned long l)
{
    return BITS_PER_LONG == 32 ? ctpop32(l) : ctpop64(l);
}

static int hbi_count_towards(HBitmapIter *hbi, uint64_t last)
{
    uint64_t next = hbi_next_internal(hbi);
    int n;

    /* Take it easy with the last few bits.  */
    if (next >= (last & -BITS_PER_LONG)) {
        return (next > last ? 0 : 1);
    }

    /* Process one word at a time, hbi_next_internal takes
     * care of skipping large all-zero blocks.  Sum one to
     * account for the value that was returned by next.
     */
    n = popcountl(hbi->cur[HBITMAP_LEVELS - 1]) + 1;
    hbi->cur[HBITMAP_LEVELS - 1] = 0;
    return n;
}

int64_t hbitmap_iter_next(HBitmapIter *hbi)
{
    int64_t next = hbi_next_internal(hbi);
    trace_hbitmap_iter_next(hbi->hb, hbi, next << hbi->granularity, next);

    return next << hbi->granularity;
}

void hbitmap_iter_init(HBitmapIter *hbi, HBitmap *hb, uint64_t first)
{
    int i, bit;
    size_t pos;

    hbi->hb = hb;
    pos = first;
    for (i = HBITMAP_LEVELS; --i >= 0; ) {
        bit = pos & (BITS_PER_LONG - 1);
        pos >>= BITS_PER_LEVEL;

        /* Drop bits representing items before first.  */
        hbi->cur[i] = hb->levels[i][pos] & ~((1UL << bit) - 1);

        /* We have already added level i+1, so the lowest set bit has
         * been processed.  Clear it.
         */
        if (i != HBITMAP_LEVELS - 1) {
            hbi->cur[i] &= ~(1UL << bit);
        }
    }

    hbi->pos = first >> BITS_PER_LEVEL;
    hbi->granularity = hb->granularity;
}

bool hbitmap_empty(HBitmap *hb)
{
    return hb->count == 0;
}

uint64_t hbitmap_count(HBitmap *hb)
{
    return hb->count << hb->granularity;
}

/* Count the number of set bits between start and end, not accounting for
 * the granularity.
 */
static int hb_count_between(HBitmap *hb, uint64_t start, uint64_t end)
{
    HBitmapIter hbi;
    uint64_t count = 0, more;

    hbitmap_iter_init(&hbi, hb, start);
    do {
        more = hbi_count_towards(&hbi, end);
        count += more;
    } while (more > 0);
    return count;
}

/* Setting starts at the last layer and propagates up if an element
 * changes from zero to non-zero.
 */
static inline bool hb_set_elem(unsigned long *elem, uint64_t start, uint64_t end)
{
    unsigned long mask;
    bool changed;

    assert((end & -BITS_PER_LONG) == (start & -BITS_PER_LONG));

    mask = 2UL << (end & (BITS_PER_LONG - 1));
    mask -= 1UL << (start & (BITS_PER_LONG - 1));
    changed = (*elem == 0);
    *elem |= mask;
    return changed;
}

/* The recursive workhorse (the depth is limited to HBITMAP_LEVELS)... */
static void hb_set_between(HBitmap *hb, int level, uint64_t start, uint64_t end)
{
    size_t pos = start >> BITS_PER_LEVEL;
    size_t endpos = end >> BITS_PER_LEVEL;
    bool changed = false;
    size_t i;

    i = pos;
    if (i < endpos) {
        uint64_t next = (start | (BITS_PER_LONG - 1)) + 1;
        changed |= hb_set_elem(&hb->levels[level][i], start, next - 1);
        for (;;) {
            start = next;
            next += BITS_PER_LONG;
            if (++i == endpos) {
                break;
            }
            changed |= (hb->levels[level][i] == 0);
            hb->levels[level][i] = ~0UL;
        }
    }
    changed |= hb_set_elem(&hb->levels[level][i], start, end);

    /* If there was any change in this layer, we may have to update
     * the one above.
     */
    if (level > 0 && changed) {
        return hb_set_between(hb, level - 1, pos, endpos);
    }
}

void hbitmap_set(HBitmap *hb, uint64_t start, uint64_t count)
{
    /* Compute range in the last layer.  */
    uint64_t last = start + count - 1;

    trace_hbitmap_set(hb, start, count,
                      start >> hb->granularity, last >> hb->granularity);

    start >>= hb->granularity;
    last >>= hb->granularity;
    count = last - start + 1;

    hb->count += count - hb_count_between(hb, start, last);
    hb_set_between(hb, HBITMAP_LEVELS - 1, start, last);
}

/* Resetting works the other way round: propagate up if the new
 * value is zero.
 */
static inline bool hb_reset_elem(unsigned long *elem, uint64_t start, uint64_t end)
{
    unsigned long mask;
    bool blanked;

    assert((end & -BITS_PER_LONG) == (start & -BITS_PER_LONG));

    mask = 2UL << (end & (BITS_PER_LONG - 1));
    mask -= 1UL << (start & (BITS_PER_LONG - 1));
    blanked = *elem != 0 && ((*elem & ~mask) == 0);
    *elem &= ~mask;
    return blanked;
}

/* The recursive workhorse (the depth is limited to HBITMAP_LEVELS)... */
static void hb_reset_between(HBitmap *hb, int level, uint64_t start, uint64_t end)
{
    size_t pos = start >> BITS_PER_LEVEL;
    size_t endpos = end >> BITS_PER_LEVEL;
    bool changed = false;
    size_t i;

    i = pos;
    if (i < endpos) {
        uint64_t next = (start | (BITS_PER_LONG - 1)) + 1;

	/* Here we need a more complex test than when setting bits.  Even if
	 * something was changed, we must not blank bits in the upper level
	 * unless the lower-level word became entirely zero.  So, remove pos
	 * from the upper-level range if bits remain set.
         */
        if (hb_reset_elem(&hb->levels[level][i], start, next - 1)) {
            changed = true;
        } else {
            pos++;
        }

        for (;;) {
            start = next;
            next += BITS_PER_LONG;
            if (++i == endpos) {
                break;
            }
            changed |= (hb->levels[level][i] != 0);
            hb->levels[level][i] = 0UL;
        }
    }

    /* Same as above, this time for endpos.  */
    if (hb_reset_elem(&hb->levels[level][i], start, end)) {
        changed = true;
    } else {
        endpos--;
    }

    if (level > 0 && changed) {
        return hb_reset_between(hb, level - 1, pos, endpos);
    }
}

void hbitmap_reset(HBitmap *hb, uint64_t start, uint64_t count)
{
    /* Compute range in the last layer.  */
    uint64_t last = start + count - 1;

    trace_hbitmap_reset(hb, start, count,
                        start >> hb->granularity, last >> hb->granularity);

    start >>= hb->granularity;
    last >>= hb->granularity;

    hb->count -= hb_count_between(hb, start, last);
    hb_reset_between(hb, HBITMAP_LEVELS - 1, start, last);
}

bool hbitmap_get(HBitmap *hb, uint64_t item)
{
    /* Compute position and bit in the last layer.  */
    uint64_t pos = item >> hb->granularity;
    unsigned long bit = 1UL << (pos & (BITS_PER_LONG - 1));

    return (hb->levels[HBITMAP_LEVELS - 1][pos >> BITS_PER_LEVEL] & bit) != 0;
}

void hbitmap_free(HBitmap *hb)
{
    int i;
    for (i = HBITMAP_LEVELS; --i >= 0; ) {
        g_free(hb->levels[i]);
    }
    g_free(hb);
}

HBitmap *hbitmap_alloc(uint64_t size, int granularity)
{
    HBitmap *hb = g_malloc0(sizeof (struct HBitmap));
    int i;

    assert(granularity >= 0 && granularity < 64);
    size = (size + (1ULL << granularity) - 1) >> granularity;
    assert(size <= ((uint64_t)1 << HBITMAP_LOG_MAX_SIZE));

    hb->size = size;
    hb->granularity = granularity;
    for (i = HBITMAP_LEVELS; --i >= 0; ) {
        size = MAX((size + BITS_PER_LONG - 1) >> BITS_PER_LEVEL, 1);
        hb->levels[i] = g_malloc0(size * sizeof(unsigned long));
    }

    /* Add a sentinel in the level 0 bitmap.  We only use up to
     * BITS_PER_LEVEL bits in level 0, so it's safe.
     */
    assert(size == 1);
    hb->levels[0][0] |= 1UL << (BITS_PER_LONG - 1);
    return hb;
}
