#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint64_t r15;
uint64_t r14;
uint64_t r13;
uint64_t r12;
uint64_t rbp;
uint64_t rbx;
uint64_t r11;
uint64_t r10;
uint64_t r9;
uint64_t r8;
uint64_t rax;
uint64_t rcx;
uint64_t rdx;
uint64_t rsi;
uint64_t rdi;
uint64_t orig_rax;
uint64_t rip;
uint64_t cs;
uint64_t eflags;
uint64_t rsp;
uint64_t ss;
uint64_t fs_base;
uint64_t gs_base;
uint64_t ds;
uint64_t es;
uint64_t fs;
uint64_t gs;
} ATTRIBUTE_PACKED mx32_struct_prstatus_regset;
#define MPERS_mx32_struct_prstatus_regset mx32_struct_prstatus_regset
