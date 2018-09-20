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
 * Copyright (C) 2015-2018 Red Hat, Inc.
 */

#ifndef __NM_ACD_MANAGER__
#define __NM_ACD_MANAGER__

#include <netinet/in.h>

typedef struct _NMAcdManager NMAcdManager;

typedef struct {
	void (*probe_terminated_callback) (NMAcdManager *self,
	                                   gpointer user_data);
	GDestroyNotify user_data_destroy;
} NMAcdCallbacks;

NMAcdManager *nm_acd_manager_new (int ifindex,
                                  const guint8 *hwaddr,
                                  guint hwaddr_len,
                                  const NMAcdCallbacks *callbacks,
                                  gpointer user_data);

void nm_acd_manager_free (NMAcdManager *self);

gboolean nm_acd_manager_add_address (NMAcdManager *self, in_addr_t address);
gboolean nm_acd_manager_start_probe (NMAcdManager *self, guint timeout);
gboolean nm_acd_manager_check_address (NMAcdManager *self, in_addr_t address);
void nm_acd_manager_announce_addresses (NMAcdManager *self);

#endif /* __NM_ACD_MANAGER__ */
