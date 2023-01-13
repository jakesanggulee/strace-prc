#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint16_t cwd;
uint16_t swd;
uint16_t ftw;
uint16_t fop;
uint64_t rip;
uint64_t rdp;
uint32_t mxcsr;
uint32_t mxcr_mask;
uint32_t st_space[32];
uint32_t xmm_space[64];
uint32_t padding[24];
} ATTRIBUTE_PACKED mx32_struct_fpregset;
#define MPERS_mx32_struct_fpregset mx32_struct_fpregset
