/*
 * Copyright (c) 2014-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"


#include <utime.h>

typedef struct utimbuf utimbuf_t;

utimbuf_t mpers_target_var;
