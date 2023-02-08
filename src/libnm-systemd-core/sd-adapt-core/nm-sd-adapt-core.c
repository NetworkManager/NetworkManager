/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 - 2016 Red Hat, Inc.
 */

#include "libnm-systemd-core/nm-default-systemd-core.h"

#include "nm-sd-adapt-core.h"

#include "fd-util.h"
#include "sd-device.h"

/*****************************************************************************/

int
asynchronous_close(int fd)
{
    safe_close(fd);
    return -1;
}

/*****************************************************************************/

sd_device *
sd_device_ref(sd_device *self)
{
    g_return_val_if_fail(!self, self);
    return self;
}

sd_device *
sd_device_unref(sd_device *self)
{
    g_return_val_if_fail(!self, self);
    return self;
}
