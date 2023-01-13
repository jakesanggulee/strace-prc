#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
struct {
int32_t left;
int32_t top;
uint32_t width;
uint32_t height;
} ATTRIBUTE_PACKED w;
uint32_t field;
uint32_t chromakey;
mpers_ptr_t clips;
uint32_t clipcount;
mpers_ptr_t bitmap;
unsigned char global_alpha;
unsigned char mpers_end_filler_1[3];
} ATTRIBUTE_PACKED mx32_struct_v4l2_window;
#define MPERS_mx32_struct_v4l2_window mx32_struct_v4l2_window
