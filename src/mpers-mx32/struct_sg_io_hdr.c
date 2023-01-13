/*
 * Copyright (c) 2007 Vladimir Nadvornik <nadvornik@suse.cz>
 * Copyright (c) 2007-2021 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2015 Bart Van Assche <bart.vanassche@sandisk.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"

#ifdef HAVE_SCSI_SG_H


# include <scsi/sg.h>

typedef struct sg_io_hdr struct_sg_io_hdr;

#endif /* HAVE_SCSI_SG_H */

struct_sg_io_hdr mpers_target_var;
