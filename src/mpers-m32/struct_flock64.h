#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int16_t l_type;
int16_t l_whence;
int64_t l_start;
int64_t l_len;
int32_t l_pid;
} ATTRIBUTE_PACKED m32_struct_flock64;
#define MPERS_m32_struct_flock64 m32_struct_flock64
