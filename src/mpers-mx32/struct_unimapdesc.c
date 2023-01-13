/*
 * Support for decoding of personality-dependent VT ioctl commands.
 *
 * Copyright (c) 2019-2021 Eugene Syromyatnikov <evgsyr@gmail.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"

#include <linux/kd.h>


typedef struct unimapdesc struct_unimapdesc;
typedef struct consolefontdesc struct_consolefontdesc;
typedef struct console_font struct_console_font;
typedef struct console_font_op struct_console_font_op;

struct_unimapdesc mpers_target_var;
