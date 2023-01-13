#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
int32_t pll_ctrl;
int32_t pll_value;
int32_t pll_max;
int32_t pll_min;
int32_t pll_posmult;
int32_t pll_negmult;
int32_t pll_clock;
} ATTRIBUTE_PACKED m32_struct_rtc_pll_info;
#define MPERS_m32_struct_rtc_pll_info m32_struct_rtc_pll_info
