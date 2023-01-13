#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int64_t actime;
int64_t modtime;
} ATTRIBUTE_PACKED mx32_utimbuf_t;
#define MPERS_mx32_utimbuf_t mx32_utimbuf_t
