/*
 * Copyright (c) 2014-2016 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2016-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <linux/types.h>
#include <asm/statfs.h>
typedef struct statfs struct_statfs;
typedef struct statfs64 struct_statfs64;

struct_statfs mpers_target_var;
