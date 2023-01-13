#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint16_t entry_ct;
unsigned char mpers_filler_1[2];
mpers_ptr_t entries;
} ATTRIBUTE_PACKED m32_struct_unimapdesc;
#define MPERS_m32_struct_unimapdesc m32_struct_unimapdesc
