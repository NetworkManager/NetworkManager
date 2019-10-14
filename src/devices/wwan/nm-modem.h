// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_MODEM_H__
#define __NETWORKMANAGER_MODEM_H__

#include "ppp/nm-ppp-manager.h"
#include "devices/nm-device.h"

#define NM_TYPE_MODEM            (nm_modem_get_type ())
#define NM_MODEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM, NMModem))
#define NM_MODEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_MODEM, NMModemClass))
#define NM_IS_MODEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM))
#define NM_IS_MODEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_MODEM))
#define NM_MODEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_MODEM, NMModemClass))

/* Properties */
#define NM_MODEM_UID             "uid"
#define NM_MODEM_PATH            "path"
#define NM_MODEM_DRIVER          "driver"
#define NM_MODEM_CONTROL_PORT    "control-port"
#define NM_MODEM_IP_IFINDEX      "ip-ifindex"
#define NM_MODEM_STATE           "state"
#define NM_MODEM_DEVICE_ID       "device-id"
#define NM_MODEM_SIM_ID          "sim-id"
#define NM_MODEM_IP_TYPES        "ip-types"   /* Supported IP types */
#define NM_MODEM_SIM_OPERATOR_ID "sim-operator-id"
#define NM_MODEM_OPERATOR_CODE   "operator-code"
#define NM_MODEM_APN             "apn"

/* Signals */
#define NM_MODEM_PPP_STATS         "ppp-stats"
#define NM_MODEM_PPP_FAILED        "ppp-failed"
#define NM_MODEM_PREPARE_RESULT    "prepare-result"
#define NM_MODEM_IP4_CONFIG_RESULT "ip4-config-result"
#define NM_MODEM_IP6_CONFIG_RESULT "ip6-config-result"
#define NM_MODEM_AUTH_REQUESTED    "auth-requested"
#define NM_MODEM_AUTH_RESULT       "auth-result"
#define NM_MODEM_REMOVED           "removed"
#define NM_MODEM_STATE_CHANGED     "state-changed"

typedef enum {
	NM_MODEM_IP_METHOD_UNKNOWN = 0,
	NM_MODEM_IP_METHOD_PPP,
	NM_MODEM_IP_METHOD_STATIC,
	NM_MODEM_IP_METHOD_AUTO,  /* DHCP and/or SLAAC */
} NMModemIPMethod;

/**
 * NMModemIPType:
 * @NM_MODEM_IP_TYPE_UNKNOWN: unknown or no IP support
 * @NM_MODEM_IP_TYPE_IPV4: IPv4-only bearers are supported
 * @NM_MODEM_IP_TYPE_IPV6: IPv6-only bearers are supported
 * @NM_MODEM_IP_TYPE_IPV4V6: dual-stack IPv4 + IPv6 bearers are supported
 *
 * Indicates what IP protocols the modem supports for an IP bearer.  Any
 * combination of flags is possible.  For example, (%NM_MODEM_IP_TYPE_IPV4 |
 * %NM_MODEM_IP_TYPE_IPV6) indicates that the modem supports IPv4 and IPv6
 * but not simultaneously on the same bearer.
 */
typedef enum {
	NM_MODEM_IP_TYPE_UNKNOWN = 0x0,
	NM_MODEM_IP_TYPE_IPV4 = 0x1,
	NM_MODEM_IP_TYPE_IPV6 = 0x2,
	NM_MODEM_IP_TYPE_IPV4V6 = 0x4
} NMModemIPType;

typedef enum {  /*< underscore_name=nm_modem_state >*/
	NM_MODEM_STATE_UNKNOWN       = 0,
	NM_MODEM_STATE_FAILED        = 1,
	NM_MODEM_STATE_INITIALIZING  = 2,
	NM_MODEM_STATE_LOCKED        = 3,
	NM_MODEM_STATE_DISABLED      = 4,
	NM_MODEM_STATE_DISABLING     = 5,
	NM_MODEM_STATE_ENABLING      = 6,
	NM_MODEM_STATE_ENABLED       = 7,
	NM_MODEM_STATE_SEARCHING     = 8,
	NM_MODEM_STATE_REGISTERED    = 9,
	NM_MODEM_STATE_DISCONNECTING = 10,
	NM_MODEM_STATE_CONNECTING    = 11,
	NM_MODEM_STATE_CONNECTED     = 12,

	_NM_MODEM_STATE_LAST0,
	_NM_MODEM_STATE_LAST = _NM_MODEM_STATE_LAST0 -1,
} NMModemState;

struct _NMModemPrivate;

struct _NMModem {
	GObject parent;
	struct _NMModemPrivate *_priv;
};

typedef struct _NMModem NMModem;

typedef void (*_NMModemDisconnectCallback) (NMModem *modem,
                                            GError *error,
                                            gpointer user_data);

typedef struct {
	GObjectClass parent;

	void     (*get_capabilities)               (NMModem *self,
	                                            NMDeviceModemCapabilities *modem_caps,
	                                            NMDeviceModemCapabilities *current_caps);

	gboolean (*get_user_pass)                  (NMModem *modem,
	                                            NMConnection *connection,
	                                            const char **user,
	                                            const char **pass);

	gboolean (*check_connection_compatible_with_modem) (NMModem *modem,
	                                                    NMConnection *connection,
	                                                    GError **error);

	gboolean (*complete_connection)            (NMModem *modem,
	                                            const char *iface,
	                                            NMConnection *connection,
	                                            NMConnection *const*existing_connections,
	                                            GError **error);

	NMActStageReturn (*modem_act_stage1_prepare) (NMModem *modem,
	                                              NMConnection *connection,
	                                              NMDeviceStateReason *out_failure_reason);

	NMActStageReturn (*static_stage3_ip4_config_start) (NMModem *self,
	                                                    NMActRequest *req,
	                                                    NMDeviceStateReason *out_failure_reason);

	/* Request the IP6 config; when the config returns the modem
	 * subclass should emit the ip6_config_result signal.
	 */
	NMActStageReturn (*stage3_ip6_config_request) (NMModem *self,
	                                               NMDeviceStateReason *out_failure_reason);

	void (*set_mm_enabled)                     (NMModem *self, gboolean enabled);

	void     (*disconnect)                     (NMModem *self,
	                                            gboolean warn,
	                                            GCancellable *cancellable,
	                                            _NMModemDisconnectCallback callback,
	                                            gpointer user_data);

	void     (*deactivate_cleanup)             (NMModem *self,
	                                            NMDevice *device,
	                                            gboolean stop_ppp_manager);

	gboolean (*owns_port)                      (NMModem *self, const char *iface);
} NMModemClass;

GType nm_modem_get_type (void);

gboolean nm_modem_is_claimed (NMModem *modem);
NMModem *nm_modem_claim (NMModem *modem);
void nm_modem_unclaim (NMModem *modem);

const char *nm_modem_get_path            (NMModem *modem);
const char *nm_modem_get_uid             (NMModem *modem);
const char *nm_modem_get_control_port    (NMModem *modem);
int         nm_modem_get_ip_ifindex      (NMModem *modem);
const char *nm_modem_get_driver          (NMModem *modem);
const char *nm_modem_get_device_id       (NMModem *modem);
const char *nm_modem_get_sim_id          (NMModem *modem);
const char *nm_modem_get_sim_operator_id (NMModem *modem);
gboolean    nm_modem_get_iid             (NMModem *modem, NMUtilsIPv6IfaceId *out_iid);
const char *nm_modem_get_operator_code   (NMModem *modem);
const char *nm_modem_get_apn             (NMModem *modem);

gboolean    nm_modem_set_data_port (NMModem *self,
                                    NMPlatform *platform,
                                    const char *data_port,
                                    NMModemIPMethod ip4_method,
                                    NMModemIPMethod ip6_method,
                                    guint timeout,
                                    GError **error);

gboolean    nm_modem_owns_port        (NMModem *modem, const char *iface);

void        nm_modem_get_capabilities (NMModem *self,
                                       NMDeviceModemCapabilities *modem_caps,
                                       NMDeviceModemCapabilities *current_caps);

gboolean nm_modem_check_connection_compatible (NMModem *self,
                                               NMConnection *connection,
                                               GError **error);

gboolean nm_modem_complete_connection (NMModem *self,
                                       const char *iface,
                                       NMConnection *connection,
                                       NMConnection *const*existing_connections,
                                       GError **error);

void nm_modem_get_route_parameters (NMModem *self,
                                    guint32 *out_ip4_route_table,
                                    guint32 *out_ip4_route_metric,
                                    guint32 *out_ip6_route_table,
                                    guint32 *out_ip6_route_metric);

void nm_modem_set_route_parameters (NMModem *self,
                                    guint32 ip4_route_table,
                                    guint32 ip4_route_metric,
                                    guint32 ip6_route_table,
                                    guint32 ip6_route_metric);

void nm_modem_set_route_parameters_from_device (NMModem *modem,
                                                NMDevice *device);

NMActStageReturn nm_modem_act_stage1_prepare (NMModem *modem,
                                              NMActRequest *req,
                                              NMDeviceStateReason *out_failure_reason);

void nm_modem_act_stage2_config (NMModem *modem);

NMActStageReturn nm_modem_stage3_ip4_config_start (NMModem *modem,
                                                   NMDevice *device,
                                                   NMDeviceClass *device_class,
                                                   NMDeviceStateReason *out_failure_reason);

NMActStageReturn nm_modem_stage3_ip6_config_start (NMModem *modem,
                                                   NMDevice *device,
                                                   NMDeviceStateReason *out_failure_reason);

void nm_modem_ip4_pre_commit (NMModem *modem, NMDevice *device, NMIP4Config *config);

void nm_modem_get_secrets (NMModem *modem,
                           const char *setting_name,
                           gboolean request_new,
                           const char *hint);

void nm_modem_deactivate (NMModem *modem, NMDevice *device);

typedef void (*NMModemDeactivateCallback) (NMModem *self,
                                           GError *error,
                                           gpointer user_data);

void     nm_modem_deactivate_async        (NMModem *self,
                                           NMDevice *device,
                                           GCancellable *cancellable,
                                           NMModemDeactivateCallback callback,
                                           gpointer user_data);

void nm_modem_device_state_changed (NMModem *modem,
                                    NMDeviceState new_state,
                                    NMDeviceState old_state);

void          nm_modem_set_mm_enabled (NMModem *self, gboolean enabled);

NMModemState  nm_modem_get_state (NMModem *self);
void          nm_modem_set_state (NMModem *self,
                                  NMModemState new_state,
                                  const char *reason);
void          nm_modem_set_prev_state (NMModem *self, const char *reason);
const char *  nm_modem_state_to_string (NMModemState state);

NMModemIPType nm_modem_get_supported_ip_types (NMModem *self);

/* For the modem-manager only */
void          nm_modem_emit_removed (NMModem *self);

void          nm_modem_emit_prepare_result (NMModem *self, gboolean success, NMDeviceStateReason reason);

void          nm_modem_emit_ppp_failed (NMModem *self, NMDeviceStateReason reason);

GArray       *nm_modem_get_connection_ip_type (NMModem *self,
                                               NMConnection *connection,
                                               GError **error);

/* For subclasses */
void nm_modem_emit_ip6_config_result (NMModem *self,
                                      NMIP6Config *config,
                                      GError *error);

const char *nm_modem_ip_type_to_string (NMModemIPType ip_type);

guint32 nm_modem_get_configured_mtu (NMDevice *self, NMDeviceMtuSource *out_source, gboolean *out_force);

void _nm_modem_set_operator_code (NMModem *self, const char *operator_code);
void _nm_modem_set_apn           (NMModem *self, const char *apn);

#endif /* __NETWORKMANAGER_MODEM_H__ */
