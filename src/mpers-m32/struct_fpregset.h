#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t cwd;
uint32_t swd;
uint32_t twd;
uint32_t fip;
uint32_t fcs;
uint32_t foo;
uint32_t fos;
uint32_t st_space[20];
} ATTRIBUTE_PACKED m32_struct_fpregset;
#define MPERS_m32_struct_fpregset m32_struct_fpregset
