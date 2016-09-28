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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_PPP_MANAGER_H__
#define __NETWORKMANAGER_PPP_MANAGER_H__


#include "nm-exported-object.h"
#include "nm-ppp-status.h"
#include "nm-act-request.h"
#include "nm-connection.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-pppd-plugin.h"
#include "NetworkManagerUtils.h"

#define NM_TYPE_PPP_MANAGER            (nm_ppp_manager_get_type ())
#define NM_PPP_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPP_MANAGER, NMPPPManager))
#define NM_PPP_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PPP_MANAGER, NMPPPManagerClass))
#define NM_IS_PPP_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PPP_MANAGER))
#define NM_IS_PPP_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PPP_MANAGER))
#define NM_PPP_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PPP_MANAGER, NMPPPManagerClass))

#define NM_PPP_MANAGER_PARENT_IFACE "parent-iface"

/* signals */
#define NM_PPP_MANAGER_STATE_CHANGED "state-changed"

typedef struct {
	NMExportedObject parent;
} NMPPPManager;

typedef struct {
	NMExportedObjectClass parent;

	/* Signals */
	void (*state_changed) (NMPPPManager *manager, NMPPPStatus status);
	void (*ip4_config) (NMPPPManager *manager, const char *iface, NMIP4Config *config);
	void (*ip6_config) (NMPPPManager *manager,
	                    const char *iface,
	                    const NMUtilsIPv6IfaceId *iid,
	                    NMIP6Config *config);
	void (*stats) (NMPPPManager *manager, guint32 in_bytes, guint32 out_bytes);
} NMPPPManagerClass;

GType nm_ppp_manager_get_type (void);

NMPPPManager *nm_ppp_manager_new (const char *iface);

gboolean nm_ppp_manager_start (NMPPPManager *manager,
                               NMActRequest *req,
                               const char *ppp_name,
                               guint32 timeout_secs,
                               GError **err);

void     nm_ppp_manager_stop        (NMPPPManager *manager,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data);
gboolean nm_ppp_manager_stop_finish (NMPPPManager *manager,
                                     GAsyncResult *res,
                                     GError **error);

#endif /* __NETWORKMANAGER_PPP_MANAGER_H__ */
