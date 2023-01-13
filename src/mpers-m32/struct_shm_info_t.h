#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int32_t used_ids;
uint32_t shm_tot;
uint32_t shm_rss;
uint32_t shm_swp;
uint32_t swap_attempts;
uint32_t swap_successes;
} ATTRIBUTE_PACKED m32_struct_shm_info_t;
#define MPERS_m32_struct_shm_info_t m32_struct_shm_info_t
