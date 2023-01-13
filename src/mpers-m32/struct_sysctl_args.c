/*
 * Copyright (c) 2022 Dmitry V. Levin <ldv@strace.io>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"

#include <linux/sysctl.h>
typedef struct __sysctl_args struct_sysctl_args;
struct_sysctl_args mpers_target_var;
