/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 - 2016 Red Hat, Inc.
 */

#include "src/core/systemd/nm-default-systemd.h"

#include "nm-sd-adapt-core.h"

#include "fd-util.h"

/*****************************************************************************/

int
asynchronous_close(int fd)
{
    safe_close(fd);
    return -1;
}

/*****************************************************************************/
