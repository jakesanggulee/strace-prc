#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
mpers_ptr_t iov_base;
uint32_t iov_len;
} ATTRIBUTE_PACKED mx32_tracee_iovec;
#define MPERS_mx32_tracee_iovec mx32_tracee_iovec
