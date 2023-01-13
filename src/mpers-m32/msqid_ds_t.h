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
} ATTRIBUTE_PACKED msg_perm;
uint32_t msg_stime;
uint32_t msg_stime_high;
uint32_t msg_rtime;
uint32_t msg_rtime_high;
uint32_t msg_ctime;
uint32_t msg_ctime_high;
uint32_t msg_cbytes;
uint32_t msg_qnum;
uint32_t msg_qbytes;
int32_t msg_lspid;
int32_t msg_lrpid;
uint32_t __unused4;
uint32_t __unused5;
} ATTRIBUTE_PACKED m32_msqid_ds_t;
#define MPERS_m32_msqid_ds_t m32_msqid_ds_t
