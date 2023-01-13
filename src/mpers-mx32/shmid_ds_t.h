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
uint32_t mode;
unsigned char __pad1[0];
uint16_t seq;
uint16_t __pad2;
unsigned char mpers_filler_1[4];
uint64_t __unused1;
uint64_t __unused2;
} ATTRIBUTE_PACKED shm_perm;
uint32_t shm_segsz;
unsigned char mpers_filler_2[4];
int64_t shm_atime;
int64_t shm_dtime;
int64_t shm_ctime;
int32_t shm_cpid;
int32_t shm_lpid;
uint64_t shm_nattch;
uint64_t __unused4;
uint64_t __unused5;
} ATTRIBUTE_PACKED mx32_shmid_ds_t;
#define MPERS_mx32_shmid_ds_t mx32_shmid_ds_t
