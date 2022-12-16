/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2006 - 2017 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SUPPLICANT_INTERFACE_H__
#define __NM_SUPPLICANT_INTERFACE_H__

#include "nm-supplicant-types.h"

#include "c-list/src/c-list.h"

/*
 * Supplicant interface states
 *   A mix of wpa_supplicant interface states and internal states.
 */
typedef enum {
    NM_SUPPLICANT_INTERFACE_STATE_INVALID = 0,

    NM_SUPPLICANT_INTERFACE_STATE_STARTING = 1,

    NM_SUPPLICANT_INTERFACE_STATE_DISABLED,
    NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED,
    NM_SUPPLICANT_INTERFACE_STATE_INACTIVE,
    NM_SUPPLICANT_INTERFACE_STATE_SCANNING,
    NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING,
    NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING,
    NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED,
    NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE,
    NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE,
    NM_SUPPLICANT_INTERFACE_STATE_COMPLETED,

    NM_SUPPLICANT_INTERFACE_STATE_DOWN,
} NMSupplicantInterfaceState;

static inline gboolean
nm_supplicant_interface_state_is_operational(NMSupplicantInterfaceState state)
{
    return state > NM_SUPPLICANT_INTERFACE_STATE_STARTING
           && state < NM_SUPPLICANT_INTERFACE_STATE_DOWN;
}

static inline gboolean
nm_supplicant_interface_state_is_associated(NMSupplicantInterfaceState state)
{
    return state >= NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING
           && state <= NM_SUPPLICANT_INTERFACE_STATE_COMPLETED;
}

typedef enum {
    NM_SUPPLICANT_AUTH_STATE_UNKNOWN,
    NM_SUPPLICANT_AUTH_STATE_STARTED,
    NM_SUPPLICANT_AUTH_STATE_SUCCESS,
    NM_SUPPLICANT_AUTH_STATE_FAILURE,
    _NM_SUPPLICANT_AUTH_STATE_NUM,
} NMSupplicantAuthState;

#define NM_TYPE_SUPPLICANT_INTERFACE (nm_supplicant_interface_get_type())
#define NM_SUPPLICANT_INTERFACE(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterface))
#define NM_SUPPLICANT_INTERFACE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfaceClass))
#define NM_IS_SUPPLICANT_INTERFACE(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SUPPLICANT_INTERFACE))
#define NM_IS_SUPPLICANT_INTERFACE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SUPPLICANT_INTERFACE))
#define NM_SUPPLICANT_INTERFACE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfaceClass))

#define NM_SUPPLICANT_INTERFACE_SUPPLICANT_MANAGER "supplicant-manager"
#define NM_SUPPLICANT_INTERFACE_DBUS_OBJECT_PATH   "dbus-object-path"
#define NM_SUPPLICANT_INTERFACE_IFINDEX            "ifindex"
#define NM_SUPPLICANT_INTERFACE_SCANNING           "scanning"
#define NM_SUPPLICANT_INTERFACE_CURRENT_BSS        "current-bss"
#define NM_SUPPLICANT_INTERFACE_P2P_GROUP_JOINED   "p2p-group-joined"
#define NM_SUPPLICANT_INTERFACE_P2P_GROUP_PATH     "p2p-group-path"
#define NM_SUPPLICANT_INTERFACE_P2P_GROUP_OWNER    "p2p-group-owner"
#define NM_SUPPLICANT_INTERFACE_DRIVER             "driver"
#define NM_SUPPLICANT_INTERFACE_P2P_AVAILABLE      "p2p-available"
#define NM_SUPPLICANT_INTERFACE_AUTH_STATE         "auth-state"

#define NM_SUPPLICANT_INTERFACE_STATE           "state"
#define NM_SUPPLICANT_INTERFACE_BSS_CHANGED     "bss-changed"
#define NM_SUPPLICANT_INTERFACE_PEER_CHANGED    "peer-changed"
#define NM_SUPPLICANT_INTERFACE_WPS_CREDENTIALS "wps-credentials"
#define NM_SUPPLICANT_INTERFACE_GROUP_STARTED   "group-started"
#define NM_SUPPLICANT_INTERFACE_GROUP_FINISHED  "group-finished"

typedef struct _NMSupplicantInterfaceClass NMSupplicantInterfaceClass;

struct _NMSupplicantInterfacePrivate;

struct _NMSupplicantInterface {
    GObject                               parent;
    CList                                 supp_lst;
    struct _NMSupplicantInterfacePrivate *_priv;
};

GType nm_supplicant_interface_get_type(void);

NMSupplicantInterface *nm_supplicant_interface_new(NMSupplicantManager *supplicant_manager,
                                                   NMRefString         *object_path,
                                                   int                  ifindex,
                                                   NMSupplicantDriver   driver);

NMRefString *nm_supplicant_interface_get_name_owner(NMSupplicantInterface *self);
NMRefString *nm_supplicant_interface_get_object_path(NMSupplicantInterface *iface);

void _nm_supplicant_interface_set_state_down(NMSupplicantInterface *self,
                                             gboolean               force_remove_from_supplicant,
                                             const char            *reason);

typedef void (*NMSupplicantInterfaceAssocCb)(NMSupplicantInterface *iface,
                                             GError                *error,
                                             gpointer               user_data);

void nm_supplicant_interface_assoc(NMSupplicantInterface       *self,
                                   NMSupplicantConfig          *cfg,
                                   NMSupplicantInterfaceAssocCb callback,
                                   gpointer                     user_data);

void nm_supplicant_interface_disconnect(NMSupplicantInterface *iface);

typedef void (*NMSupplicantInterfaceDisconnectCb)(NMSupplicantInterface *iface,
                                                  GError                *error,
                                                  gpointer               user_data);

void nm_supplicant_interface_disconnect_async(NMSupplicantInterface            *self,
                                              GCancellable                     *cancellable,
                                              NMSupplicantInterfaceDisconnectCb callback,
                                              gpointer                          user_data);

typedef void (*NMSupplicantInterfaceRequestScanCallback)(NMSupplicantInterface *self,
                                                         GCancellable          *cancellable,
                                                         gpointer               user_data);

void nm_supplicant_interface_request_scan(NMSupplicantInterface                   *self,
                                          GBytes *const                           *ssids,
                                          guint                                    ssids_len,
                                          GCancellable                            *cancellable,
                                          NMSupplicantInterfaceRequestScanCallback callback,
                                          gpointer                                 user_data);

NMSupplicantInterfaceState nm_supplicant_interface_get_state(NMSupplicantInterface *self);

const char *nm_supplicant_interface_state_to_string(NMSupplicantInterfaceState state);

gboolean nm_supplicant_interface_get_scanning(NMSupplicantInterface *self);

NMRefString *nm_supplicant_interface_get_current_bss(NMSupplicantInterface *self);

gint64 nm_supplicant_interface_get_last_scan(NMSupplicantInterface *self);

const char *nm_supplicant_interface_get_ifname(NMSupplicantInterface *self);

guint nm_supplicant_interface_get_max_scan_ssids(NMSupplicantInterface *self);

gboolean nm_supplicant_interface_get_p2p_available(NMSupplicantInterface *self);

gboolean nm_supplicant_interface_get_p2p_group_joined(NMSupplicantInterface *self);

const char *nm_supplicant_interface_get_p2p_group_path(NMSupplicantInterface *self);

gboolean nm_supplicant_interface_get_p2p_group_owner(NMSupplicantInterface *self);

gboolean nm_supplicant_interface_get_p2p_assigned_addr(NMSupplicantInterface *self,
                                                       in_addr_t             *assigned_addr,
                                                       guint8                *plen);

void nm_supplicant_interface_p2p_start_find(NMSupplicantInterface *self, guint timeout);
void nm_supplicant_interface_p2p_stop_find(NMSupplicantInterface *self);

void nm_supplicant_interface_p2p_connect(NMSupplicantInterface *self,
                                         const char            *peer,
                                         const char            *wps_method,
                                         const char            *wps_pin);
void nm_supplicant_interface_p2p_cancel_connect(NMSupplicantInterface *self);
void nm_supplicant_interface_p2p_disconnect(NMSupplicantInterface *self);

void nm_supplicant_interface_set_global_capabilities(NMSupplicantInterface *self,
                                                     NMSupplCapMask         value);

NMTernary nm_supplicant_interface_get_capability(NMSupplicantInterface *self, NMSupplCapType type);

NMSupplCapMask nm_supplicant_interface_get_capabilities(NMSupplicantInterface *self);

void nm_supplicant_interface_enroll_wps(NMSupplicantInterface *self,
                                        const char *const      type,
                                        const char            *bssid,
                                        const char            *pin);

void nm_supplicant_interface_cancel_wps(NMSupplicantInterface *self);

NMSupplicantAuthState nm_supplicant_interface_get_auth_state(NMSupplicantInterface *self);

void nm_supplicant_interface_set_bridge(NMSupplicantInterface *self, const char *bridge);

#endif /* __NM_SUPPLICANT_INTERFACE_H__ */
