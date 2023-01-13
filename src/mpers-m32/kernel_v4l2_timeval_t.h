#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int64_t tv_sec;
int64_t tv_usec;
} ATTRIBUTE_PACKED m32_kernel_v4l2_timeval_t;
#define MPERS_m32_kernel_v4l2_timeval_t m32_kernel_v4l2_timeval_t
