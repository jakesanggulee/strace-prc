#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int32_t used_ids;
unsigned char mpers_filler_1[4];
uint64_t shm_tot;
uint64_t shm_rss;
uint64_t shm_swp;
uint64_t swap_attempts;
uint64_t swap_successes;
} ATTRIBUTE_PACKED mx32_struct_shm_info_t;
#define MPERS_mx32_struct_shm_info_t mx32_struct_shm_info_t
