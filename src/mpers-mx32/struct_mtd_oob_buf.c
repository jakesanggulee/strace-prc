/*
 * Copyright (c) 2012 Mike Frysinger <vapier@gentoo.org>
 * Copyright (c) 2012-2021 The strace developers.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <linux/ioctl.h>
#include <mtd/mtd-abi.h>

typedef struct mtd_oob_buf struct_mtd_oob_buf;

struct_mtd_oob_buf mpers_target_var;
