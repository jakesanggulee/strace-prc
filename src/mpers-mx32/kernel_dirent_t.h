#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint64_t d_ino;
uint64_t d_off;
uint16_t d_reclen;
char d_name[1];
unsigned char mpers_end_filler_1[5];
} ATTRIBUTE_PACKED mx32_kernel_dirent_t;
#define MPERS_mx32_kernel_dirent_t mx32_kernel_dirent_t
