/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2014 Red Hat, Inc.
 */

#include <NetworkManager.h>

#include "nm-default.h"

typedef struct {
	GDBusConnection *bus;
	GDBusProxy *proxy;
	GPid pid;
	int keepalive_fd;
} NMTestServiceInfo;

NMTestServiceInfo *nm_test_service_init (void);
void nm_test_service_cleanup (NMTestServiceInfo *info);

NMDevice *nm_test_service_add_device (NMTestServiceInfo *info,
                                      NMClient *client,
                                      const char *method,
                                      const char *ifname);

NMDevice * nm_test_service_add_wired_device (NMTestServiceInfo *sinfo,
                                             NMClient *client,
                                             const char *ifname,
                                             const char *hwaddr,
                                             const char **subchannels);

