#ifndef BIT_UTIL_H
#define BIT_UTIL_H

#include <stdint.h>

#define ffs __builtin_ffs
#define ffsl __builtin_ffsl
#define ffsll __builtin_ffsll
#define popcount __builtin_popcount
#define popcountl __builtin_popcountl
#define popcountll __builtin_popcountll
#define fls generic_flsl
#define flsl generic_flsl
#define flsll generic_flsll

#define MAX_8BITS  0x00000000000000ff
#define MAX_16BITS 0x000000000000ffff
#define MAX_32BITS 0x00000000ffffffff
#define MAX_64BITS 0xffffffffffffffff

#define ROUNDUP8(x)  (((x) + 7ULL ) & (~7ULL ))
#define ROUNDUP16(x) (((x) + 15ULL) & (~15ULL))
#define ROUNDUP32(x) (((x) + 31ULL) & (~31ULL))
#define ROUNDUP64(x) (((x) + 63ULL) & (~63ULL))
#define POWERROUNDUP(x)                                    \
  ({                                                       \
    int fls_bit = generic_flsl(x);                        \
    fls_bit = (1UL << fls_bit) < x ? fls_bit - 1: fls_bit; \
    1UL << fls_bit;                                        \
  })
#define POWERROUNDUP64(x)                                   \
  ({                                                        \
    int fls_bit = flsll(x);                                 \
    fls_bit = (1ULL << fls_bit) < x ? fls_bit - 1: fls_bit; \
    1ULL << fls_bit;                                        \
  })


static inline int
generic_flsl(uint32_t x)
{
  int r = 32;
  if (!x) return 0;

  if (!(x & 0xffff0000u)) {
    x <<= 16;
    r -= 16;
  }
  if (!(x & 0xff000000u)) {
    x <<= 8;
    r -= 8;
  }
  if (!(x & 0xf0000000u)) {
    x <<= 4;
    r -= 4;
  }
  if (!(x & 0xc0000000u)) {
    x <<= 2;
    r -= 2;
  }
  if (!(x & 0x80000000u)) {
    x <<= 1;
    r -= 1;
  }
  return r;
}

static inline int
generic_flsll(uint64_t x)
{
  int r = 64;
  if (!x) return 0;

  if (!(x & 0xffffffff00000000u)) {
    x <<= 32;
    r -= 32;
  }
  if (!(x & 0xffff000000000000u)) {
    x <<= 16;
    r -= 16;
  }
  if (!(x & 0xff00000000000000u)) {
    x <<= 8;
    r -= 8;
  }
  if (!(x & 0xf000000000000000u)) {
    x <<= 4;
    r -= 4;
  }
  if (!(x & 0xc000000000000000u)) {
    x <<= 2;
    r -= 2;
  }
  if (!(x & 0x8000000000000000u)) {
    x <<= 1;
    r -= 1;
  }
  return r;
}

static inline uint8_t
kth_32bit(uint32_t val, uint8_t k)
{
  return (val >> k) & 1;
}

static inline uint8_t
kth_32bit_fleft(uint32_t val, uint8_t k)
{
  return (val >> (32 - k)) & 1;
}

static inline uint8_t
kth_64bit(uint64_t val, uint8_t k)
{
  return (val >> k) & 1;
}

static inline uint8_t
kth_64bit_fleft(uint64_t val, uint8_t k)
{
  return (val >> (64 -k)) & 1;
}

static inline uint8_t
kth_bit_ptr(uint8_t *ptr, uint64_t k)
{
  uint64_t byte_index = k >> 3; 
  uint8_t bit_index = k & 0b111; 
  ptr = (uint8_t*) ((uint64_t)ptr + byte_index);
  return ((*ptr) >> bit_index) & 1;
}



/** byte
 * uint64_t   a [           0          ]
 * uint32_t ptr [    1     ][    0     ] 
 * uin16_t  ptr [  3 ][  2 ][  1 ][  0 ]
 * uin8_t   ptr [7][6][5][4][3][2][1][0]
 */
#define KBITS_MASK_32(k) (k==32? (uint32_t) ~0UL  : ((1UL << k)-1))
#define KBITS_MASK_64(k) (k==64? (uint64_t) ~0ULL : ((1ULL << k)-1))

/**
 * from order    7 6 5 4 3 2 1 0        
 * uin8_t*  ptr [       0       ]
 */
static inline uint8_t
kbits_val_32(uint32_t val, uint8_t k, uint8_t from)
{
  return (uint8_t) ((val >> from) & KBITS_MASK_32(k));
}

static inline uint8_t
kbits_val_64(uint64_t val, uint8_t k, uint8_t from)
{
  return (uint8_t) ((val >> from) & KBITS_MASK_64(k));  
}

/**
 * from index    0 1 2 3 4 5 6 7
 * uin8_t*  ptr [       0       ]
 */
static inline uint32_t
kbits_val_32_fleft(uint32_t val, uint8_t k, uint8_t from)
{
  // == kbit_val_32(val, k, 32 - k -from)
  return (val << from) >> (32 - k);
}

static inline uint64_t
kbits_val_64_fleft(uint64_t val, uint8_t k, uint8_t from)
{
  return (val << from) >> (64 - k);
}

#endif
