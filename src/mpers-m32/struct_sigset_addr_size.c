/*
 * Copyright (c) 2018-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


typedef struct {
	sigset_t *sigmask;
	size_t sigsetsize;
} struct_sigset_addr_size;

struct_sigset_addr_size mpers_target_var;
