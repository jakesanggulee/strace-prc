#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int32_t ifc_len;
union {
mpers_ptr_t ifcu_buf;
mpers_ptr_t ifcu_req;
} ifc_ifcu;
} ATTRIBUTE_PACKED mx32_struct_ifconf;
#define MPERS_mx32_struct_ifconf mx32_struct_ifconf
