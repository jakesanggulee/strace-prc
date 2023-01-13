/*
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <sys/socket.h>
#include <net/if.h>

typedef struct ifconf struct_ifconf;
typedef struct ifreq struct_ifreq;

struct_ifconf mpers_target_var;
