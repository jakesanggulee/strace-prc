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
} ATTRIBUTE_PACKED msg_perm;
int64_t msg_stime;
int64_t msg_rtime;
int64_t msg_ctime;
uint64_t msg_cbytes;
uint64_t msg_qnum;
uint64_t msg_qbytes;
int32_t msg_lspid;
int32_t msg_lrpid;
uint64_t __unused4;
uint64_t __unused5;
} ATTRIBUTE_PACKED mx32_msqid_ds_t;
#define MPERS_mx32_msqid_ds_t mx32_msqid_ds_t
