#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
struct {
int64_t tv_sec;
int64_t tv_usec;
} ATTRIBUTE_PACKED ru_utime;
struct {
int64_t tv_sec;
int64_t tv_usec;
} ATTRIBUTE_PACKED ru_stime;
int64_t ru_maxrss;
int64_t ru_ixrss;
int64_t ru_idrss;
int64_t ru_isrss;
int64_t ru_minflt;
int64_t ru_majflt;
int64_t ru_nswap;
int64_t ru_inblock;
int64_t ru_oublock;
int64_t ru_msgsnd;
int64_t ru_msgrcv;
int64_t ru_nsignals;
int64_t ru_nvcsw;
int64_t ru_nivcsw;
} ATTRIBUTE_PACKED mx32_kernel_rusage_t;
#define MPERS_mx32_kernel_rusage_t mx32_kernel_rusage_t
