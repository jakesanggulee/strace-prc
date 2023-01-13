#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t index;
uint64_t id;
unsigned char name[24];
struct {
uint32_t numerator;
uint32_t denominator;
} ATTRIBUTE_PACKED frameperiod;
uint32_t framelines;
uint32_t reserved[4];
} ATTRIBUTE_PACKED m32_struct_v4l2_standard;
#define MPERS_m32_struct_v4l2_standard m32_struct_v4l2_standard
