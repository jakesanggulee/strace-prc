/*
 * Decode struct sg_req_info.
 *
 * Copyright (c) 2017-2021 Dmitry V. Levin <ldv@strace.io>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"

#ifdef HAVE_SCSI_SG_H


# include <scsi/sg.h>

typedef struct sg_req_info struct_sg_req_info;

#endif /* HAVE_SCSI_SG_H */

struct_sg_req_info mpers_target_var;
