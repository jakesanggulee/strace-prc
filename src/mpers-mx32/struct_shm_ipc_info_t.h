#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint64_t shmmax;
uint64_t shmmin;
uint64_t shmmni;
uint64_t shmseg;
uint64_t shmall;
uint64_t __unused1;
uint64_t __unused2;
uint64_t __unused3;
uint64_t __unused4;
} ATTRIBUTE_PACKED mx32_struct_shm_ipc_info_t;
#define MPERS_mx32_struct_shm_ipc_info_t mx32_struct_shm_ipc_info_t
