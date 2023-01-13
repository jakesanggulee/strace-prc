#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int32_t mq_flags;
int32_t mq_maxmsg;
int32_t mq_msgsize;
int32_t mq_curmsgs;
int32_t __reserved[4];
} ATTRIBUTE_PACKED m32_mq_attr_t;
#define MPERS_m32_mq_attr_t m32_mq_attr_t
