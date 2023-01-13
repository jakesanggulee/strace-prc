/*
 * Copyright (c) 2016 Jeff Mahoney <jeffm@suse.com>
 * Copyright (c) 2016-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <linux/btrfs_tree.h>

typedef struct btrfs_ioctl_dev_replace_args
	struct_btrfs_ioctl_dev_replace_args;
typedef struct btrfs_ioctl_send_args
	struct_btrfs_ioctl_send_args;
typedef struct btrfs_ioctl_received_subvol_args
	struct_btrfs_ioctl_received_subvol_args;
typedef struct btrfs_ioctl_timespec
	struct_btrfs_ioctl_timespec;
typedef struct btrfs_ioctl_vol_args_v2
	struct_btrfs_ioctl_vol_args_v2;

struct_btrfs_ioctl_vol_args_v2 mpers_target_var;
