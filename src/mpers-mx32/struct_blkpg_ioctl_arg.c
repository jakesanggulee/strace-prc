/*
 * Copyright (c) 2009, 2010 Jeff Mahoney <jeffm@suse.com>
 * Copyright (c) 2011-2016 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2011-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/blkpg.h>
#include <linux/blkzoned.h>
#include <linux/blktrace_api.h>

typedef struct blkpg_ioctl_arg struct_blkpg_ioctl_arg;
typedef struct blkpg_partition struct_blkpg_partition;
typedef struct blk_user_trace_setup struct_blk_user_trace_setup;

struct_blkpg_ioctl_arg mpers_target_var;
