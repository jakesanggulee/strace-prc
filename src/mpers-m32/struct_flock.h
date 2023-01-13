#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int16_t l_type;
int16_t l_whence;
int32_t l_start;
int32_t l_len;
int32_t l_pid;
} ATTRIBUTE_PACKED m32_struct_flock;
#define MPERS_m32_struct_flock m32_struct_flock
