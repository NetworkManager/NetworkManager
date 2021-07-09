/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef __NM_WIMAX_NSP_H__
#define __NM_WIMAX_NSP_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_WIMAX_NSP (nm_wimax_nsp_get_type())
#define NM_WIMAX_NSP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_WIMAX_NSP, NMWimaxNsp))
#define NM_WIMAX_NSP_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_WIMAX_NSP, NMWimaxNspClass))
#define NM_IS_WIMAX_NSP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_WIMAX_NSP))
#define NM_IS_WIMAX_NSP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_WIMAX_NSP))
#define NM_WIMAX_NSP_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_WIMAX_NSP, NMWimaxNspClass))

#define NM_WIMAX_NSP_NAME           "name"
#define NM_WIMAX_NSP_SIGNAL_QUALITY "signal-quality"
#define NM_WIMAX_NSP_NETWORK_TYPE   "network-type"

/**
 * NMWimaxNsp:
 *
 * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
 */
typedef struct _NMWimaxNspClass NMWimaxNspClass;

GType nm_wimax_nsp_get_type(void);

NM_DEPRECATED_IN_1_22
const char *nm_wimax_nsp_get_name(NMWimaxNsp *nsp);
NM_DEPRECATED_IN_1_22
guint32 nm_wimax_nsp_get_signal_quality(NMWimaxNsp *nsp);
NM_DEPRECATED_IN_1_22
NMWimaxNspNetworkType nm_wimax_nsp_get_network_type(NMWimaxNsp *nsp);

NM_DEPRECATED_IN_1_22
GPtrArray *nm_wimax_nsp_filter_connections(NMWimaxNsp *nsp, const GPtrArray *connections);

NM_DEPRECATED_IN_1_22
gboolean nm_wimax_nsp_connection_valid(NMWimaxNsp *nsp, NMConnection *connection);

G_END_DECLS

#endif /* __NM_WIMAX_NSP_H__ */
