#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint16_t charcount;
uint16_t charheight;
mpers_ptr_t chardata;
} ATTRIBUTE_PACKED m32_struct_consolefontdesc;
#define MPERS_m32_struct_consolefontdesc m32_struct_consolefontdesc
