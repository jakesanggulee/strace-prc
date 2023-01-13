#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
signed char qs_version;
unsigned char mpers_filler_1[1];
uint16_t qs_flags;
signed char qs_pad;
unsigned char mpers_filler_2[3];
struct {
uint64_t qfs_ino;
uint64_t qfs_nblks;
uint32_t qfs_nextents;
} ATTRIBUTE_PACKED qs_uquota;
struct {
uint64_t qfs_ino;
uint64_t qfs_nblks;
uint32_t qfs_nextents;
} ATTRIBUTE_PACKED qs_gquota;
uint32_t qs_incoredqs;
int32_t qs_btimelimit;
int32_t qs_itimelimit;
int32_t qs_rtbtimelimit;
uint16_t qs_bwarnlimit;
uint16_t qs_iwarnlimit;
} ATTRIBUTE_PACKED m32_fs_quota_stat_t;
#define MPERS_m32_fs_quota_stat_t m32_fs_quota_stat_t
