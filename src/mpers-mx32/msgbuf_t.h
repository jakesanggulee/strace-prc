#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int64_t mtype;
char mtext[1];
unsigned char mpers_end_filler_1[7];
} ATTRIBUTE_PACKED mx32_msgbuf_t;
#define MPERS_mx32_msgbuf_t mx32_msgbuf_t
