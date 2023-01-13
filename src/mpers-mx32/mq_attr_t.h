#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int64_t mq_flags;
int64_t mq_maxmsg;
int64_t mq_msgsize;
int64_t mq_curmsgs;
int64_t __reserved[4];
} ATTRIBUTE_PACKED mx32_mq_attr_t;
#define MPERS_mx32_mq_attr_t mx32_mq_attr_t
