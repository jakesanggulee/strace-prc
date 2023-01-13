#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
mpers_ptr_t name;
int32_t nlen;
mpers_ptr_t oldval;
mpers_ptr_t oldlenp;
mpers_ptr_t newval;
uint32_t newlen;
uint32_t __unused[4];
} ATTRIBUTE_PACKED mx32_struct_sysctl_args;
#define MPERS_mx32_struct_sysctl_args mx32_struct_sysctl_args
