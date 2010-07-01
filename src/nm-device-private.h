/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef NM_DEVICE_PRIVATE_H
#define NM_DEVICE_PRIVATE_H

#include "nm-device.h"

void nm_device_set_ip_iface (NMDevice *self, const char *iface);

void nm_device_activate_schedule_stage3_ip_config_start (NMDevice *device);

void nm_device_state_changed (NMDevice *device,
                              NMDeviceState state,
                              NMDeviceStateReason reason);

gboolean nm_device_hw_bring_up (NMDevice *self, gboolean wait, gboolean *no_firmware);

void nm_device_hw_take_down (NMDevice *self, gboolean block);

void nm_device_handle_autoip4_event (NMDevice *self,
                                     const char *event,
                                     const char *address);

gboolean nm_device_ip_config_should_fail (NMDevice *self, gboolean ip6);

gboolean nm_device_get_firmware_missing (NMDevice *self);

void nm_device_set_firmware_missing (NMDevice *self, gboolean missing);

#endif	/* NM_DEVICE_PRIVATE_H */
