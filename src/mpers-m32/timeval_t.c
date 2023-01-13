/*
 * Copyright (c) 2015-2017 Dmitry V. Levin <ldv@strace.io>
 * Copyright (c) 2016-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include "kernel_timeval.h"

typedef kernel_old_timeval_t timeval_t;

timeval_t mpers_target_var;
