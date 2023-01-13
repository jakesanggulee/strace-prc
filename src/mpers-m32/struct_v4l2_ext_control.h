#include <stdint.h>
#ifndef mpers_ptr_t_is_uint32_t
typedef uint32_t mpers_ptr_t;
#define mpers_ptr_t_is_uint32_t
#endif
typedef
struct {
uint32_t id;
uint32_t size;
uint32_t reserved2[1];
union {
int32_t value;
int64_t value64;
mpers_ptr_t string;
mpers_ptr_t p_u8;
mpers_ptr_t p_u16;
mpers_ptr_t p_u32;
mpers_ptr_t p_s32;
mpers_ptr_t p_s64;
mpers_ptr_t p_area;
mpers_ptr_t p_h264_sps;
mpers_ptr_t p_h264_pps;
mpers_ptr_t p_h264_scaling_matrix;
mpers_ptr_t p_h264_pred_weights;
mpers_ptr_t p_h264_slice_params;
mpers_ptr_t p_h264_decode_params;
mpers_ptr_t p_fwht_params;
mpers_ptr_t p_vp8_frame;
mpers_ptr_t p_mpeg2_sequence;
mpers_ptr_t p_mpeg2_picture;
mpers_ptr_t p_mpeg2_quantisation;
mpers_ptr_t p_vp9_compressed_hdr_probs;
mpers_ptr_t p_vp9_frame;
mpers_ptr_t p_hevc_sps;
mpers_ptr_t p_hevc_pps;
mpers_ptr_t p_hevc_slice_params;
mpers_ptr_t p_hevc_scaling_matrix;
mpers_ptr_t p_hevc_decode_params;
mpers_ptr_t ptr;
} ;
} ATTRIBUTE_PACKED m32_struct_v4l2_ext_control;
#define MPERS_m32_struct_v4l2_ext_control m32_struct_v4l2_ext_control
