/*
 * Copyright (c) 2015-2021 Dmitry V. Levin <ldv@strace.io>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <linux/filter.h>
typedef struct sock_fprog struct_sock_fprog;

struct_sock_fprog mpers_target_var;
