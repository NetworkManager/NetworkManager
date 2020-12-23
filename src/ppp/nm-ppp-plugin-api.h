/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef __NM_PPP_PLUGIN_API_H__
#define __NM_PPP_PLUGIN_API_H__

#include "nm-ppp-manager.h"

typedef const struct {
    NMPPPManager *(*create)(const char *iface);

    void (*set_route_parameters)(NMPPPManager *manager,
                                 guint32       route_table_v4,
                                 guint32       route_metric_v4,
                                 guint32       route_table_v6,
                                 guint32       route_metric_v6);

    gboolean (*start)(NMPPPManager *manager,
                      NMActRequest *req,
                      const char *  ppp_name,
                      guint32       timeout_secs,
                      guint         baud_override,
                      GError **     err);

    NMPPPManagerStopHandle *(*stop)(NMPPPManager *           manager,
                                    GCancellable *           cancellable,
                                    NMPPPManagerStopCallback callback,
                                    gpointer                 user_data);

    void (*stop_cancel)(NMPPPManagerStopHandle *handle);

} NMPPPOps;

#endif /* __NM_PPP_PLUGIN_API_H__ */
