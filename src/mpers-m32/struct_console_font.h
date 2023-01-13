#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t width;
uint32_t height;
uint32_t charcount;
mpers_ptr_t data;
} ATTRIBUTE_PACKED m32_struct_console_font;
#define MPERS_m32_struct_console_font m32_struct_console_font
