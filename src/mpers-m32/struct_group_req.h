#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t gr_interface;
struct {
uint16_t ss_family;
char __ss_padding[122];
uint32_t __ss_align;
} ATTRIBUTE_PACKED gr_group;
} ATTRIBUTE_PACKED m32_struct_group_req;
#define MPERS_m32_struct_group_req m32_struct_group_req
