// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef __NM_PPP_MANAGER_CALL_H__
#define __NM_PPP_MANAGER_CALL_H__

#include "nm-ppp-manager.h"

NMPPPManager *      nm_ppp_manager_create      (const char *iface,
                                                GError **error);

void                nm_ppp_manager_set_route_parameters (NMPPPManager *ppp_manager,
                                                         guint32 ip4_route_table,
                                                         guint32 ip4_route_metric,
                                                         guint32 ip6_route_table,
                                                         guint32 ip6_route_metric);

gboolean            nm_ppp_manager_start       (NMPPPManager *self,
                                                NMActRequest *req,
                                                const char *ppp_name,
                                                guint32 timeout_secs,
                                                guint baud_override,
                                                GError **error);

NMPPPManagerStopHandle *nm_ppp_manager_stop (NMPPPManager *self,
                                             GCancellable *cancellable,
                                             NMPPPManagerStopCallback callback,
                                             gpointer user_data);

void nm_ppp_manager_stop_cancel (NMPPPManagerStopHandle *handle);

#endif /* __NM_PPP_MANAGER_CALL_H__ */
