#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t shmmax;
uint32_t shmmin;
uint32_t shmmni;
uint32_t shmseg;
uint32_t shmall;
uint32_t __unused1;
uint32_t __unused2;
uint32_t __unused3;
uint32_t __unused4;
} ATTRIBUTE_PACKED m32_struct_shm_ipc_info_t;
#define MPERS_m32_struct_shm_ipc_info_t m32_struct_shm_ipc_info_t
