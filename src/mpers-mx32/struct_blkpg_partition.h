#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int64_t start;
int64_t length;
int32_t pno;
char devname[64];
char volname[64];
unsigned char mpers_end_filler_1[4];
} ATTRIBUTE_PACKED mx32_struct_blkpg_partition;
#define MPERS_mx32_struct_blkpg_partition mx32_struct_blkpg_partition
