#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
struct {
int32_t key;
uint32_t uid;
uint32_t gid;
uint32_t cuid;
uint32_t cgid;
uint16_t mode;
unsigned char __pad1[2];
uint16_t seq;
uint16_t __pad2;
uint32_t __unused1;
uint32_t __unused2;
} ATTRIBUTE_PACKED shm_perm;
uint32_t shm_segsz;
uint32_t shm_atime;
uint32_t shm_atime_high;
uint32_t shm_dtime;
uint32_t shm_dtime_high;
uint32_t shm_ctime;
uint32_t shm_ctime_high;
int32_t shm_cpid;
int32_t shm_lpid;
uint32_t shm_nattch;
uint32_t __unused4;
uint32_t __unused5;
} ATTRIBUTE_PACKED m32_shmid_ds_t;
#define MPERS_m32_shmid_ds_t m32_shmid_ds_t
