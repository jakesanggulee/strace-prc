#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t type;
union {
uint64_t data[8];
} u;
uint32_t pending;
uint32_t sequence;
struct {
int64_t tv_sec;
int64_t tv_nsec;
} ATTRIBUTE_PACKED timestamp;
uint32_t id;
uint32_t reserved[8];
} ATTRIBUTE_PACKED m32_kernel_v4l2_event_t;
#define MPERS_m32_kernel_v4l2_event_t m32_kernel_v4l2_event_t
