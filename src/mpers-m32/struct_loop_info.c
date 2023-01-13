/*
 * Copyright (c) 2012 The Chromium OS Authors.
 * Copyright (c) 2012-2021 The strace developers.
 * Written by Mike Frysinger <vapier@gentoo.org>.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <linux/loop.h>

typedef struct loop_info struct_loop_info;

struct_loop_info mpers_target_var;
