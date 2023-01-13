/*
 * Copyright (c) 2021 The strace developers.
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "ptrace.h"
#include "arch_prstatus_regset.h"
#include "arch_fpregset.h"

#if HAVE_ARCH_PRSTATUS_REGSET
#endif

#if HAVE_ARCH_FPREGSET
#endif

struct_prstatus_regset mpers_target_var;
