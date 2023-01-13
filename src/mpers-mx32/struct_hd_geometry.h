#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
unsigned char heads;
unsigned char sectors;
uint16_t cylinders;
uint32_t start;
} ATTRIBUTE_PACKED mx32_struct_hd_geometry;
#define MPERS_mx32_struct_hd_geometry mx32_struct_hd_geometry
