#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t ebx;
uint32_t ecx;
uint32_t edx;
uint32_t esi;
uint32_t edi;
uint32_t ebp;
uint32_t eax;
uint32_t xds;
uint32_t xes;
uint32_t xfs;
uint32_t xgs;
uint32_t orig_eax;
uint32_t eip;
uint32_t xcs;
uint32_t eflags;
uint32_t esp;
uint32_t xss;
} ATTRIBUTE_PACKED m32_struct_prstatus_regset;
#define MPERS_m32_struct_prstatus_regset m32_struct_prstatus_regset
