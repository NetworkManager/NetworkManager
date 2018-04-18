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

#define NM_TYPE_ACD_MANAGER            (nm_acd_manager_get_type ())
#define NM_ACD_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACD_MANAGER, NMAcdManager))
#define NM_ACD_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_ACD_MANAGER, NMAcdManagerClass))
#define NM_IS_ACD_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACD_MANAGER))
#define NM_IS_ACD_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_ACD_MANAGER))
#define NM_ACD_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_ACD_MANAGER, NMAcdManagerClass))

#define NM_ACD_MANAGER_PROBE_TERMINATED  "probe-terminated"

typedef struct _NMAcdManagerClass NMAcdManagerClass;

GType nm_acd_manager_get_type (void);

NMAcdManager *nm_acd_manager_new (int ifindex, const guint8 *hwaddr, size_t hwaddr_len);
void nm_acd_manager_destroy (NMAcdManager *self);
gboolean nm_acd_manager_add_address (NMAcdManager *self, in_addr_t address);
gboolean nm_acd_manager_start_probe (NMAcdManager *self, guint timeout);
gboolean nm_acd_manager_check_address (NMAcdManager *self, in_addr_t address);
void nm_acd_manager_announce_addresses (NMAcdManager *self);
void nm_acd_manager_reset (NMAcdManager *self);

#endif /* __NM_ACD_MANAGER__ */
