/*
 * Copyright (c) The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <sys/uio.h>
typedef struct iovec tracee_iovec;

tracee_iovec mpers_target_var;
