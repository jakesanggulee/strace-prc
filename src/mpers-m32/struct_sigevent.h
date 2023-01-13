#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
union {
int32_t sival_int;
mpers_ptr_t sival_ptr;
} sigev_value;
int32_t sigev_signo;
int32_t sigev_notify;
union {
int32_t tid;
struct {
mpers_ptr_t function;
mpers_ptr_t attribute;
} ATTRIBUTE_PACKED sigev_thread;
} sigev_un;
} ATTRIBUTE_PACKED m32_struct_sigevent;
#define MPERS_m32_struct_sigevent m32_struct_sigevent
