#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint64_t sec;
uint32_t nsec;
unsigned char mpers_end_filler_1[4];
} ATTRIBUTE_PACKED mx32_struct_btrfs_ioctl_timespec;
#define MPERS_mx32_struct_btrfs_ioctl_timespec mx32_struct_btrfs_ioctl_timespec
