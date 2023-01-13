/*
 * Copyright (c) 2015 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2015-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <linux/fcntl.h>
typedef struct flock struct_flock;
typedef struct flock64 struct_flock64;

struct_flock64 mpers_target_var;
