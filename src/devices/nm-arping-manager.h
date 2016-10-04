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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_ARPING_MANAGER__
#define __NM_ARPING_MANAGER__

#include <netinet/in.h>

#define NM_TYPE_ARPING_MANAGER            (nm_arping_manager_get_type ())
#define NM_ARPING_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ARPING_MANAGER, NMArpingManager))
#define NM_ARPING_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_ARPING_MANAGER, NMArpingManagerClass))
#define NM_IS_ARPING_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ARPING_MANAGER))
#define NM_IS_ARPING_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_ARPING_MANAGER))
#define NM_ARPING_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_ARPING_MANAGER, NMArpingManagerClass))

#define NM_ARPING_MANAGER_PROBE_TERMINATED  "probe-terminated"

typedef struct _NMArpingManagerClass NMArpingManagerClass;

GType nm_arping_manager_get_type (void);

NMArpingManager *nm_arping_manager_new (int ifindex);
void nm_arping_manager_destroy (NMArpingManager *self);
gboolean nm_arping_manager_add_address (NMArpingManager *self, in_addr_t address);
gboolean nm_arping_manager_start_probe (NMArpingManager *self, guint timeout, GError **error);
gboolean nm_arping_manager_check_address (NMArpingManager *self, in_addr_t address);
void nm_arping_manager_announce_addresses (NMArpingManager *self);
void nm_arping_manager_reset (NMArpingManager *self);

#endif /* __NM_ARPING_MANAGER__ */
