/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 Thomas Bechtold <thomasbechtold@jpberlin.de>
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_CONNECTIVITY_H__
#define __NETWORKMANAGER_CONNECTIVITY_H__

#include "nm-dbus-interface.h"

/*****************************************************************************/

static inline int
nm_connectivity_state_cmp(NMConnectivityState a, NMConnectivityState b)
{
    if (a == NM_CONNECTIVITY_PORTAL && b == NM_CONNECTIVITY_LIMITED)
        return 1;
    if (b == NM_CONNECTIVITY_PORTAL && a == NM_CONNECTIVITY_LIMITED)
        return -1;
    NM_CMP_DIRECT(a, b);
    return 0;
}

/*****************************************************************************/

#define NM_CONNECTIVITY_ERROR     ((NMConnectivityState) -1)
#define NM_CONNECTIVITY_FAKE      ((NMConnectivityState) -2)
#define NM_CONNECTIVITY_CANCELLED ((NMConnectivityState) -3)
#define NM_CONNECTIVITY_DISPOSING ((NMConnectivityState) -4)

#define NM_TYPE_CONNECTIVITY (nm_connectivity_get_type())
#define NM_CONNECTIVITY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_CONNECTIVITY, NMConnectivity))
#define NM_CONNECTIVITY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_CONNECTIVITY, NMConnectivityClass))
#define NM_IS_CONNECTIVITY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_CONNECTIVITY))
#define NM_IS_CONNECTIVITY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_CONNECTIVITY))
#define NM_CONNECTIVITY_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_CONNECTIVITY, NMConnectivityClass))

#define NM_CONNECTIVITY_CONFIG_CHANGED "config-changed"

typedef struct _NMConnectivityClass NMConnectivityClass;

GType nm_connectivity_get_type(void);

NMConnectivity *nm_connectivity_get(void);

const char *nm_connectivity_state_to_string(NMConnectivityState state);

gboolean nm_connectivity_check_enabled(NMConnectivity *self);

guint nm_connectivity_get_interval(NMConnectivity *self);

typedef struct _NMConnectivityCheckHandle NMConnectivityCheckHandle;

typedef void (*NMConnectivityCheckCallback)(NMConnectivity *           self,
                                            NMConnectivityCheckHandle *handle,
                                            NMConnectivityState        state,
                                            gpointer                   user_data);

NMConnectivityCheckHandle *nm_connectivity_check_start(NMConnectivity *            self,
                                                       int                         family,
                                                       NMPlatform *                platform,
                                                       int                         ifindex,
                                                       const char *                iface,
                                                       NMConnectivityCheckCallback callback,
                                                       gpointer                    user_data);

void nm_connectivity_check_cancel(NMConnectivityCheckHandle *handle);

#endif /* __NETWORKMANAGER_CONNECTIVITY_H__ */
