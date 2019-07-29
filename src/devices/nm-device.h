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
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_H__
#define __NETWORKMANAGER_DEVICE_H__

#include <netinet/in.h>

#include "nm-setting-connection.h"
#include "nm-dbus-object.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-rfkill-manager.h"
#include "NetworkManagerUtils.h"

typedef enum {
	NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
	NM_DEVICE_SYS_IFACE_STATE_ASSUME,
	NM_DEVICE_SYS_IFACE_STATE_MANAGED,

	/* the REMOVED state applies when the device is manually set to unmanaged
	 * or the link was externally removed. In both cases, we move the device
	 * to UNMANAGED state, without touching the link -- be it, because the link
	 * is already gone or because we want to release it (give it up).
	 */
	NM_DEVICE_SYS_IFACE_STATE_REMOVED,
} NMDeviceSysIfaceState;

typedef enum {
	NM_DEVICE_MTU_SOURCE_NONE,
	NM_DEVICE_MTU_SOURCE_PARENT,
	NM_DEVICE_MTU_SOURCE_IP_CONFIG,
	NM_DEVICE_MTU_SOURCE_CONNECTION,
} NMDeviceMtuSource;

static inline NMDeviceStateReason
nm_device_state_reason_check (NMDeviceStateReason reason)
{
	/* the device-state-reason serves mostly informational purpose during a state
	 * change. In some cases however, decisions are made based on the reason.
	 * I tend to think that interpreting the state reason to derive some behaviors
	 * is confusing, because the cause and effect are so far apart.
	 *
	 * This function is here to mark source that inspects the reason to make
	 * a decision -- contrary to places that set the reason. Thus, by grepping
	 * for nm_device_state_reason_check() you can find the "effect" to a certain
	 * reason.
	 */
	return reason;
}

#define NM_PENDING_ACTION_AUTOACTIVATE              "autoactivate"
#define NM_PENDING_ACTION_DHCP4                     "dhcp4"
#define NM_PENDING_ACTION_DHCP6                     "dhcp6"
#define NM_PENDING_ACTION_AUTOCONF6                 "autoconf6"
#define NM_PENDING_ACTION_RECHECK_AVAILABLE         "recheck-available"
#define NM_PENDING_ACTION_CARRIER_WAIT              "carrier-wait"
#define NM_PENDING_ACTION_WAITING_FOR_SUPPLICANT    "waiting-for-supplicant"
#define NM_PENDING_ACTION_WIFI_SCAN                 "wifi-scan"
#define NM_PENDING_ACTION_WAITING_FOR_COMPANION     "waiting-for-companion"
#define NM_PENDING_ACTION_LINK_INIT                 "link-init"

#define NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "queued-state-change-"
#define NM_PENDING_ACTIONPREFIX_ACTIVATION          "activation-"

/* Properties */
#define NM_DEVICE_UDI              "udi"
#define NM_DEVICE_IFACE            "interface"
#define NM_DEVICE_IP_IFACE         "ip-interface"
#define NM_DEVICE_DRIVER           "driver"
#define NM_DEVICE_DRIVER_VERSION   "driver-version"
#define NM_DEVICE_FIRMWARE_VERSION "firmware-version"
#define NM_DEVICE_CAPABILITIES     "capabilities"
#define NM_DEVICE_CARRIER          "carrier"
#define NM_DEVICE_IP4_ADDRESS      "ip4-address"
#define NM_DEVICE_IP4_CONFIG       "ip4-config"
#define NM_DEVICE_DHCP4_CONFIG     "dhcp4-config"
#define NM_DEVICE_IP6_CONFIG       "ip6-config"
#define NM_DEVICE_DHCP6_CONFIG     "dhcp6-config"
#define NM_DEVICE_STATE            "state"
#define NM_DEVICE_STATE_REASON     "state-reason"
#define NM_DEVICE_ACTIVE_CONNECTION "active-connection"
#define NM_DEVICE_DEVICE_TYPE      "device-type" /* ugh */
#define NM_DEVICE_LINK_TYPE        "link-type"
#define NM_DEVICE_MANAGED          "managed"
#define NM_DEVICE_AUTOCONNECT      "autoconnect"
#define NM_DEVICE_FIRMWARE_MISSING "firmware-missing"
#define NM_DEVICE_NM_PLUGIN_MISSING "nm-plugin-missing"
#define NM_DEVICE_AVAILABLE_CONNECTIONS "available-connections"
#define NM_DEVICE_PHYSICAL_PORT_ID "physical-port-id"
#define NM_DEVICE_MTU              "mtu"
#define NM_DEVICE_HW_ADDRESS       "hw-address"

/* "perm-hw-address" is exposed on D-Bus both for NMDeviceEthernet
 * and NMDeviceWifi. */
#define NM_DEVICE_PERM_HW_ADDRESS  "perm-hw-address"

#define NM_DEVICE_METERED          "metered"
#define NM_DEVICE_LLDP_NEIGHBORS  "lldp-neighbors"
#define NM_DEVICE_REAL             "real"

/* "parent" is exposed on D-Bus by subclasses like NMDeviceIPTunnel */
#define NM_DEVICE_PARENT           "parent"

/* the "slaves" property is internal in the parent class, but exposed
 * by the derived classes NMDeviceBond, NMDeviceBridge, NMDeviceTeam,
 * NMDeviceOvsBridge and NMDeviceOvsPort. */
#define NM_DEVICE_SLAVES           "slaves"         /* partially internal */

#define NM_DEVICE_TYPE_DESC        "type-desc"      /* Internal only */
#define NM_DEVICE_RFKILL_TYPE      "rfkill-type"    /* Internal only */
#define NM_DEVICE_IFINDEX          "ifindex"        /* Internal only */
#define NM_DEVICE_MASTER           "master"         /* Internal only */
#define NM_DEVICE_HAS_PENDING_ACTION "has-pending-action" /* Internal only */

/* Internal signals */
#define NM_DEVICE_AUTH_REQUEST          "auth-request"
#define NM_DEVICE_IP4_CONFIG_CHANGED    "ip4-config-changed"
#define NM_DEVICE_IP6_CONFIG_CHANGED    "ip6-config-changed"
#define NM_DEVICE_IP6_PREFIX_DELEGATED  "ip6-prefix-delegated"
#define NM_DEVICE_IP6_SUBNET_NEEDED     "ip6-subnet-needed"
#define NM_DEVICE_REMOVED               "removed"
#define NM_DEVICE_RECHECK_AUTO_ACTIVATE "recheck-auto-activate"
#define NM_DEVICE_RECHECK_ASSUME        "recheck-assume"
#define NM_DEVICE_STATE_CHANGED         "state-changed"
#define NM_DEVICE_LINK_INITIALIZED      "link-initialized"
#define NM_DEVICE_AUTOCONNECT_ALLOWED   "autoconnect-allowed"

#define NM_DEVICE_STATISTICS_REFRESH_RATE_MS "refresh-rate-ms"
#define NM_DEVICE_STATISTICS_TX_BYTES        "tx-bytes"
#define NM_DEVICE_STATISTICS_RX_BYTES        "rx-bytes"

#define NM_DEVICE_IP4_CONNECTIVITY           "ip4-connectivity"
#define NM_DEVICE_IP6_CONNECTIVITY           "ip6-connectivity"

#define NM_TYPE_DEVICE            (nm_device_get_type ())
#define NM_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE, NMDeviceClass))

typedef enum NMActStageReturn NMActStageReturn;

/* These flags affect whether a connection is considered available on a device
 * (check_connection_available()). The flags should have the meaning of relaxing
 * a condition, so that adding a flag might make a connection available that would
 * not be available otherwise. Adding a flag should never make a connection
 * not available if it would be available otherwise. */
typedef enum { /*< skip >*/
	NM_DEVICE_CHECK_CON_AVAILABLE_NONE                                  = 0,

	/* since NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST is a collection of flags with more fine grained
	 * parts, this flag in general indicates that this is a user-request. */
	_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST                     = (1L << 0),

	/* we also consider devices which have no carrier but are still waiting for the driver
	 * to detect carrier. Usually, such devices are not yet available, however for a user-request
	 * they are. They might fail later if carrier doesn't come. */
	_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER     = (1L << 1),

	/* usually, a profile is only available if the Wi-Fi AP is in range. For an
	 * explicit user request, we also consider profiles for APs that are not (yet)
	 * visible. */
	_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP           = (1L << 2),

	/* a device can be marked as unmanaged for various reasons. Some of these reasons
	 * are authoritative, others not. Non-authoritative reasons can be overruled by
	 * `nmcli device set $DEVICE managed yes`. Also, for an explicit user activation
	 * request we may want to consider the device as managed. This flag makes devices
	 * that are unmanaged appear available. */
	_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_OVERRULE_UNMANAGED  = (1L << 3),

	/* a collection of flags, that are commonly set for an explicit user-request. */
	NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST                      = _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST
	                                                                    | _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER
	                                                                    | _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP
	                                                                    | _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_OVERRULE_UNMANAGED,

	NM_DEVICE_CHECK_CON_AVAILABLE_ALL                                   = (1L << 4) - 1,
} NMDeviceCheckConAvailableFlags;

struct _NMDevicePrivate;

struct _NMDevice {
	NMDBusObject parent;
	struct _NMDevicePrivate *_priv;
	CList devices_lst;
};

/* The flags have an relaxing meaning, that means, specifying more flags, can make
 * a device appear more available. It can never make a device less available. */
typedef enum { /*< skip >*/
	NM_DEVICE_CHECK_DEV_AVAILABLE_NONE                                  = 0,

	/* the device is considered available, even if it has no carrier.
	 *
	 * For various device types (software devices) we ignore carrier based
	 * on the type. So, for them, this flag has no effect anyway. */
	_NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER                       = (1L << 0),

	NM_DEVICE_CHECK_DEV_AVAILABLE_FOR_USER_REQUEST                      = _NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER,

	NM_DEVICE_CHECK_DEV_AVAILABLE_ALL                                   = (1L << 1) - 1,
} NMDeviceCheckDevAvailableFlags;

typedef void (*NMDeviceDeactivateCallback) (NMDevice *self,
                                            GError *error,
                                            gpointer user_data);

typedef struct _NMDeviceClass {
	NMDBusObjectClass parent;

	struct _NMDeviceClass *default_type_description_klass;
	const char *default_type_description;

	const char *connection_type_supported;

	/* most device types, can only handle profiles of a particular type. This
	 * is the connection.type setting, as checked by nm_device_check_connection_compatible() */
	const char *connection_type_check_compatible;

	const NMLinkType *link_types;

	/* Whether the device type is a master-type. This depends purely on the
	 * type (NMDeviceClass), not the actual device instance. */
	bool is_master:1;

	void (*state_changed) (NMDevice *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);

	void            (* link_changed) (NMDevice *self,
	                                  const NMPlatformLink *pllink);

	/**
	 * create_and_realize():
	 * @self: the #NMDevice
	 * @connection: the #NMConnection being activated
	 * @parent: the parent #NMDevice, if any
	 * @out_plink: on success, a backing kernel network device if one exists.
	 *   The returned pointer is owned by platform and only valid until the
	 *   next platform operation.
	 * @error: location to store error, or %NULL
	 *
	 * Create any backing resources (kernel devices, etc) required for this
	 * device to activate @connection.  If the device is backed by a kernel
	 * network device, that device should be returned in @out_plink after
	 * being created.
	 *
	 * Returns: %TRUE on success, %FALSE on error
	 */
	gboolean        (*create_and_realize) (NMDevice *self,
	                                       NMConnection *connection,
	                                       NMDevice *parent,
	                                       const NMPlatformLink **out_plink,
	                                       GError **error);

	/**
	 * realize_start_notify():
	 * @self: the #NMDevice
	 * @pllink: the #NMPlatformLink if backed by a kernel netdevice
	 *
	 * Hook for derived classes to be notfied during realize_start_setup()
	 * and perform additional setup.
	 *
	 * The default implementation of NMDevice calls link_changed().
	 */
	void        (*realize_start_notify) (NMDevice *self,
	                                     const NMPlatformLink *pllink);

	/**
	 * unrealize():
	 * @self: the #NMDevice
	 *
	 * Remove the device backing resources.
	 */
	gboolean               (*unrealize) (NMDevice *self, GError **error);

	/**
	 * unrealize_notify():
	 * @self: the #NMDevice
	 *
	 * Hook for derived classes to clear any properties that depend on backing resources
	 * (kernel devices, etc). This is called by nm_device_unrealize() during unrealization.
	 */
	void            (*unrealize_notify)  (NMDevice *self);

	/* Hardware state (IFF_UP) */
	gboolean        (*can_unmanaged_external_down)  (NMDevice *self);

	/* Carrier state (IFF_LOWER_UP) */
	void            (*carrier_changed_notify) (NMDevice *, gboolean carrier);

	gboolean    (* get_ip_iface_identifier) (NMDevice *self, NMUtilsIPv6IfaceId *out_iid);

	NMDeviceCapabilities (* get_generic_capabilities) (NMDevice *self);

	gboolean    (* is_available) (NMDevice *self, NMDeviceCheckDevAvailableFlags flags);

	gboolean    (* get_enabled) (NMDevice *self);

	void        (* set_enabled) (NMDevice *self, gboolean enabled);

	/* let the subclass return additional NMPlatformRoutingRule (in form of NMPObject
	 * pointers) that shall be added to the rules provided by this device.
	 * The returned GPtrArray will be g_ptr_array_unref()'ed. The subclass may or
	 * may not keep an additional reference and return this array again and again. */
	GPtrArray *(*get_extra_rules) (NMDevice *self);

	/* allow derived classes to override the result of nm_device_autoconnect_allowed().
	 * If the value changes, the class should call nm_device_emit_recheck_auto_activate(),
	 * which emits NM_DEVICE_RECHECK_AUTO_ACTIVATE signal. */
	gboolean    (* get_autoconnect_allowed) (NMDevice *self);

	gboolean    (* can_auto_connect) (NMDevice *self,
	                                  NMSettingsConnection *sett_conn,
	                                  char **specific_object);

	guint32     (*get_configured_mtu) (NMDevice *self, NMDeviceMtuSource *out_source);

	/* allow the subclass to overwrite the routing table. This is mainly useful
	 * to change from partial mode (route-table=0) to full-sync mode (route-table=254). */
	guint32     (*coerce_route_table) (NMDevice *self,
	                                   int addr_family,
	                                   guint32 route_table,
	                                   gboolean is_user_config);

	const char *(*get_auto_ip_config_method) (NMDevice *self, int addr_family);

	/* Checks whether the connection is compatible with the device using
	 * only the devices type and characteristics.  Does not use any live
	 * network information like Wi-Fi scan lists etc.
	 */
	gboolean    (* check_connection_compatible) (NMDevice *self,
	                                             NMConnection *connection,
	                                             GError **error);

	/* Checks whether the connection is likely available to be activated,
	 * including any live network information like scan lists.  The connection
	 * is checked against the object defined by @specific_object, if given.
	 * Returns TRUE if the connection is available; FALSE if not.
	 *
	 * The passed @flags affect whether a connection is considered
	 * available or not. Adding more flags, means the connection is
	 * *more* available.
	 *
	 * Specifying @specific_object can only reduce the availability of a connection.
	 */
	gboolean    (* check_connection_available) (NMDevice *self,
	                                            NMConnection *connection,
	                                            NMDeviceCheckConAvailableFlags flags,
	                                            const char *specific_object,
	                                            GError **error);

	gboolean    (* complete_connection)         (NMDevice *self,
	                                             NMConnection *connection,
	                                             const char *specific_object,
	                                             NMConnection *const*existing_connections,
	                                             GError **error);

	NMActStageReturn    (* act_stage1_prepare)  (NMDevice *self,
	                                             NMDeviceStateReason *out_failure_reason);
	NMActStageReturn    (* act_stage2_config)   (NMDevice *self,
	                                             NMDeviceStateReason *out_failure_reason);
	NMActStageReturn    (* act_stage3_ip_config_start) (NMDevice *self,
	                                                    int addr_family,
	                                                    gpointer *out_config,
	                                                    NMDeviceStateReason *out_failure_reason);
	NMActStageReturn    (* act_stage4_ip_config_timeout)   (NMDevice *self,
	                                                        int addr_family,
	                                                        NMDeviceStateReason *out_failure_reason);

	void                (* ip4_config_pre_commit) (NMDevice *self, NMIP4Config *config);

	/* Async deactivating (in the DEACTIVATING phase) */
	void            (* deactivate_async)        (NMDevice *self,
	                                             GCancellable *cancellable,
	                                             NMDeviceDeactivateCallback callback,
	                                             gpointer user_data);

	void            (* deactivate_reset_hw_addr) (NMDevice *self);

	/* Sync deactivating (in the DISCONNECTED phase) */
	void            (* deactivate) (NMDevice *self);

	const char *(*get_type_description) (NMDevice *self);

	const char *(*get_s390_subchannels) (NMDevice *self);

	/* Update the connection with currently configured L2 settings */
	void            (* update_connection) (NMDevice *device, NMConnection *connection);

	gboolean (*master_update_slave_connection) (NMDevice *self,
	                                            NMDevice *slave,
	                                            NMConnection *connection,
	                                            GError **error);

	gboolean        (* enslave_slave) (NMDevice *self,
	                                   NMDevice *slave,
	                                   NMConnection *connection,
	                                   gboolean configure);

	void            (* release_slave) (NMDevice *self,
	                                   NMDevice *slave,
	                                   gboolean configure);

	void            (* parent_changed_notify) (NMDevice *self,
	                                           int old_ifindex,
	                                           NMDevice *old_parent,
	                                           int new_ifindex,
	                                           NMDevice *new_parent);

	/**
	 * component_added:
	 * @self: the #NMDevice
	 * @component: the component (device, modem, etc) which was added
	 *
	 * Notifies @self that a new component that a device might be interested
	 * in was detected by some device factory. It may include an object of
	 * %GObject subclass to help the devices decide whether it claims that
	 * particular object itself and the emitting factory should not.
	 *
	 * Returns: %TRUE if the component was claimed exclusively and no further
	 * devices should be notified of the new component.  %FALSE to indicate
	 * that the component was not exclusively claimed and other devices should
	 * be notified.
	 */
	gboolean        (* component_added) (NMDevice *self, GObject *component);

	gboolean        (* owns_iface) (NMDevice *self, const char *iface);

	NMConnection *  (* new_default_connection) (NMDevice *self);

	gboolean        (* unmanaged_on_quit) (NMDevice *self);

	gboolean        (* can_reapply_change) (NMDevice *self,
	                                        const char *setting_name,
	                                        NMSetting *s_old,
	                                        NMSetting *s_new,
	                                        GHashTable *diffs,
	                                        GError **error);

	void            (* reapply_connection) (NMDevice *self,
	                                        NMConnection *con_old,
	                                        NMConnection *con_new);

	guint32         (* get_dhcp_timeout) (NMDevice *self,
	                                      int addr_family);

	/* Controls, whether to call act_stage2_config() callback also for assuming
	 * a device or for external activations. In this case, act_stage2_config() must
	 * take care not to touch the device's configuration. */
	bool act_stage2_config_also_for_external_or_assume:1;
} NMDeviceClass;

typedef void (*NMDeviceAuthRequestFunc) (NMDevice *device,
                                         GDBusMethodInvocation *context,
                                         NMAuthSubject *subject,
                                         GError *error,
                                         gpointer user_data);

GType nm_device_get_type (void);

struct _NMDedupMultiIndex *nm_device_get_multi_index (NMDevice *self);
NMNetns *nm_device_get_netns (NMDevice *self);
NMPlatform *nm_device_get_platform (NMDevice *self);

const char *    nm_device_get_udi               (NMDevice *dev);
const char *    nm_device_get_iface             (NMDevice *dev);

static inline const char *
_nm_device_get_iface (NMDevice *device)
{
	/* like nm_device_get_iface(), but gracefully accept NULL without
	 * asserting. */
	return device ? nm_device_get_iface (device) : NULL;
}

int             nm_device_get_ifindex           (NMDevice *dev);
gboolean        nm_device_is_software           (NMDevice *dev);
gboolean        nm_device_is_real               (NMDevice *dev);
const char *    nm_device_get_ip_iface          (NMDevice *dev);
const char *    nm_device_get_ip_iface_from_platform (NMDevice *dev);
int             nm_device_get_ip_ifindex        (const NMDevice *dev);
const char *    nm_device_get_driver            (NMDevice *dev);
const char *    nm_device_get_driver_version    (NMDevice *dev);
const char *    nm_device_get_type_desc         (NMDevice *dev);
const char *    nm_device_get_type_description  (NMDevice *dev);
NMDeviceType    nm_device_get_device_type       (NMDevice *dev);
NMLinkType      nm_device_get_link_type         (NMDevice *dev);
NMMetered       nm_device_get_metered           (NMDevice *dev);

guint32         nm_device_get_route_table       (NMDevice *self, int addr_family);
guint32         nm_device_get_route_metric      (NMDevice *dev, int addr_family);

guint32         nm_device_get_route_metric_default (NMDeviceType device_type);

const char *    nm_device_get_hw_address        (NMDevice *dev);
const char *    nm_device_get_permanent_hw_address (NMDevice *self);
const char *    nm_device_get_permanent_hw_address_full (NMDevice *self,
                                                         gboolean force_freeze,
                                                         gboolean *out_is_fake);
const char *    nm_device_get_initial_hw_address (NMDevice *dev);

NMProxyConfig * nm_device_get_proxy_config      (NMDevice *dev);

NMDhcp4Config * nm_device_get_dhcp4_config      (NMDevice *dev);
NMDhcp6Config * nm_device_get_dhcp6_config      (NMDevice *dev);
NMIP4Config *   nm_device_get_ip4_config        (NMDevice *dev);
void            nm_device_replace_vpn4_config   (NMDevice *dev,
                                                 NMIP4Config *old,
                                                 NMIP4Config *config);

NMIP6Config *   nm_device_get_ip6_config        (NMDevice *dev);
void            nm_device_replace_vpn6_config   (NMDevice *dev,
                                                 NMIP6Config *old,
                                                 NMIP6Config *config);

void            nm_device_capture_initial_config (NMDevice *dev);

int             nm_device_parent_get_ifindex    (NMDevice *dev);
NMDevice       *nm_device_parent_get_device     (NMDevice *dev);
void            nm_device_parent_set_ifindex    (NMDevice *self,
                                                 int parent_ifindex);
gboolean        nm_device_parent_notify_changed (NMDevice *self,
                                                 NMDevice *change_candidate,
                                                 gboolean device_removed);

const char     *nm_device_parent_find_for_connection (NMDevice *self,
                                                      const char *current_setting_parent);

/* Master */
gboolean        nm_device_is_master             (NMDevice *dev);

/* Slave */
NMDevice *      nm_device_get_master            (NMDevice *dev);

NMActRequest *  nm_device_get_act_request       (NMDevice *dev);
NMSettingsConnection *nm_device_get_settings_connection (NMDevice *dev);
NMConnection *  nm_device_get_settings_connection_get_connection (NMDevice *self);
NMConnection *  nm_device_get_applied_connection (NMDevice *dev);
gboolean        nm_device_has_unmodified_applied_connection (NMDevice *self,
                                                             NMSettingCompareFlags compare_flags);
NMActivationStateFlags nm_device_get_activation_state_flags (NMDevice *self);

gpointer /* (NMSetting *) */ nm_device_get_applied_setting   (NMDevice *dev,
                                                              GType setting_type);

void            nm_device_removed               (NMDevice *self, gboolean unconfigure_ip_config);

gboolean        nm_device_ignore_carrier_by_default (NMDevice *self);

gboolean        nm_device_is_available          (NMDevice *dev, NMDeviceCheckDevAvailableFlags flags);
gboolean        nm_device_has_carrier           (NMDevice *dev);

NMConnection * nm_device_generate_connection (NMDevice *self,
                                              NMDevice *master,
                                              gboolean *out_maybe_later,
                                              GError **error);

gboolean nm_device_master_update_slave_connection (NMDevice *master,
                                                   NMDevice *slave,
                                                   NMConnection *connection,
                                                   GError **error);

gboolean nm_device_can_auto_connect (NMDevice *self,
                                     NMSettingsConnection *sett_conn,
                                     char **specific_object);

gboolean nm_device_complete_connection (NMDevice *device,
                                        NMConnection *connection,
                                        const char *specific_object,
                                        NMConnection *const*existing_connections,
                                        GError **error);

gboolean nm_device_check_connection_compatible (NMDevice *device,
                                                NMConnection *connection,
                                                GError **error);

gboolean nm_device_check_slave_connection_compatible (NMDevice *device, NMConnection *connection);

gboolean nm_device_unmanage_on_quit (NMDevice *self);

gboolean nm_device_spec_match_list (NMDevice *device, const GSList *specs);
int      nm_device_spec_match_list_full (NMDevice *self, const GSList *specs, int no_match_value);

gboolean nm_device_is_activating (NMDevice *dev);
gboolean nm_device_autoconnect_allowed (NMDevice *self);

NMDeviceState nm_device_get_state (NMDevice *device);

gboolean nm_device_get_enabled (NMDevice *device);

void nm_device_set_enabled (NMDevice *device, gboolean enabled);

RfKillType nm_device_get_rfkill_type (NMDevice *device);

/* IPv6 prefix delegation */

void nm_device_request_ip6_prefixes (NMDevice *self, int needed_prefixes);

gboolean nm_device_needs_ip6_subnet (NMDevice *self);

void nm_device_use_ip6_subnet (NMDevice *self, const NMPlatformIP6Address *subnet);

void nm_device_copy_ip6_dns_config (NMDevice *self, NMDevice *from_device);

/**
 * NMUnmanagedFlags:
 * @NM_UNMANAGED_NONE: placeholder value
 * @NM_UNMANAGED_SLEEPING: %TRUE when unmanaged because NM is sleeping.
 * @NM_UNMANAGED_QUITTING: %TRUE when unmanaged because NM is shutting down.
 * @NM_UNMANAGED_PARENT: %TRUE when unmanaged due to parent device being unmanaged
 * @NM_UNMANAGED_BY_TYPE: %TRUE for unmanaging device by type, like loopback.
 * @NM_UNMANAGED_PLATFORM_INIT: %TRUE when unmanaged because platform link not
 *   yet initialized. Unrealized device are also unmanaged for this reason.
 * @NM_UNMANAGED_USER_EXPLICIT: %TRUE when unmanaged by explicit user decision
 *   (e.g. via a D-Bus command)
 * @NM_UNMANAGED_USER_SETTINGS: %TRUE when unmanaged by user decision via
 *   the settings plugin (for example keyfile.unmanaged-devices or ifcfg-rh's
 *   NM_CONTROLLED=no). Although this is user-configuration (provided from
 *   the settings plugins, such as NM_CONTROLLED=no in ifcfg-rh), it cannot
 *   be overruled and is authoritative. That is because users may depend on
 *   dropping a ifcfg-rh file to ensure the device is unmanaged.
 * @NM_UNMANAGED_USER_CONF: %TRUE when unmanaged by user decision via
 *   the NetworkManager.conf ("unmanaged" in the [device] section).
 *   Contray to @NM_UNMANAGED_USER_SETTINGS, this can be overwritten via
 *   D-Bus.
 * @NM_UNMANAGED_BY_DEFAULT: %TRUE for certain device types where we unmanage
 *   them by default
 * @NM_UNMANAGED_USER_UDEV: %TRUE when unmanaged by user decision (via UDev rule)
 * @NM_UNMANAGED_EXTERNAL_DOWN: %TRUE when unmanaged because !IFF_UP and not created by NM
 * @NM_UNMANAGED_IS_SLAVE: indicates that the device is enslaved. Note that
 *   setting the NM_UNMANAGED_IS_SLAVE to %TRUE makes no sense, this flag has only
 *   meaning to set a slave device as managed if the parent is managed too.
 */
typedef enum { /*< skip >*/
	NM_UNMANAGED_NONE          = 0,

	/* these flags are authoritative. If one of them is set,
	 * the device cannot be managed. */
	NM_UNMANAGED_SLEEPING      = (1LL <<  0),
	NM_UNMANAGED_QUITTING      = (1LL <<  1),
	NM_UNMANAGED_PARENT        = (1LL <<  2),
	NM_UNMANAGED_BY_TYPE       = (1LL <<  3),
	NM_UNMANAGED_PLATFORM_INIT = (1LL <<  4),
	NM_UNMANAGED_USER_EXPLICIT = (1LL <<  5),
	NM_UNMANAGED_USER_SETTINGS = (1LL <<  6),

	/* These flags can be non-effective and be overwritten
	 * by other flags. */
	NM_UNMANAGED_BY_DEFAULT    = (1LL <<  8),
	NM_UNMANAGED_USER_CONF     = (1LL <<  9),
	NM_UNMANAGED_USER_UDEV     = (1LL << 10),
	NM_UNMANAGED_EXTERNAL_DOWN = (1LL << 11),
	NM_UNMANAGED_IS_SLAVE      = (1LL << 12),

} NMUnmanagedFlags;

typedef enum {
	NM_UNMAN_FLAG_OP_SET_MANAGED        = FALSE,
	NM_UNMAN_FLAG_OP_SET_UNMANAGED      = TRUE,
	NM_UNMAN_FLAG_OP_FORGET             = 2,
} NMUnmanFlagOp;

const char *nm_unmanaged_flags2str (NMUnmanagedFlags flags, char *buf, gsize len);

gboolean nm_device_get_managed (NMDevice *device, gboolean for_user_request);
NMUnmanagedFlags nm_device_get_unmanaged_mask (NMDevice *device, NMUnmanagedFlags flag);
NMUnmanagedFlags nm_device_get_unmanaged_flags (NMDevice *device, NMUnmanagedFlags flag);
void nm_device_set_unmanaged_flags (NMDevice *device,
                                    NMUnmanagedFlags flags,
                                    NMUnmanFlagOp set_op);
void nm_device_set_unmanaged_by_flags (NMDevice *device,
                                       NMUnmanagedFlags flags,
                                       NMUnmanFlagOp set_op,
                                       NMDeviceStateReason reason);
void nm_device_set_unmanaged_by_flags_queue (NMDevice *self,
                                             NMUnmanagedFlags flags,
                                             NMUnmanFlagOp set_op,
                                             NMDeviceStateReason reason);
void nm_device_set_unmanaged_by_user_settings (NMDevice *self);
void nm_device_set_unmanaged_by_user_udev (NMDevice *self);
void nm_device_set_unmanaged_by_user_conf (NMDevice *self);
void nm_device_set_unmanaged_by_quitting (NMDevice *device);

gboolean nm_device_check_unrealized_device_managed (NMDevice *self);

gboolean nm_device_is_nm_owned (NMDevice *device);

gboolean nm_device_has_capability (NMDevice *self, NMDeviceCapabilities caps);

/*****************************************************************************/

void nm_device_assume_state_get (NMDevice *self,
                                 gboolean *out_assume_state_guess_assume,
                                 const char **out_assume_state_connection_uuid);
void nm_device_assume_state_reset (NMDevice *self);

/*****************************************************************************/

gboolean nm_device_realize_start      (NMDevice *device,
                                       const NMPlatformLink *plink,
                                       gboolean assume_state_guess_assume,
                                       const char *assume_state_connection_uuid,
                                       gboolean set_nm_owned,
                                       NMUnmanFlagOp unmanaged_user_explicit,
                                       gboolean *out_compatible,
                                       GError **error);
void     nm_device_realize_finish     (NMDevice *self,
                                       const NMPlatformLink *plink);
gboolean nm_device_create_and_realize (NMDevice *self,
                                       NMConnection *connection,
                                       NMDevice *parent,
                                       GError **error);
gboolean nm_device_unrealize          (NMDevice *device,
                                       gboolean remove_resources,
                                       GError **error);

void nm_device_update_from_platform_link (NMDevice *self,
                                          const NMPlatformLink *plink);

typedef enum {
	NM_DEVICE_AUTOCONNECT_BLOCKED_NONE                  = 0,

	NM_DEVICE_AUTOCONNECT_BLOCKED_USER                  = (1LL <<  0),

	NM_DEVICE_AUTOCONNECT_BLOCKED_WRONG_PIN             = (1LL <<  1),
	NM_DEVICE_AUTOCONNECT_BLOCKED_MANUAL_DISCONNECT     = (1LL <<  2),
	NM_DEVICE_AUTOCONNECT_BLOCKED_SIM_MISSING           = (1LL <<  3),
	NM_DEVICE_AUTOCONNECT_BLOCKED_INIT_FAILED           = (1LL <<  4),

	_NM_DEVICE_AUTOCONNECT_BLOCKED_LAST,

	NM_DEVICE_AUTOCONNECT_BLOCKED_ALL                   = (((_NM_DEVICE_AUTOCONNECT_BLOCKED_LAST - 1) << 1) - 1),

	NM_DEVICE_AUTOCONNECT_BLOCKED_INTERNAL              = NM_DEVICE_AUTOCONNECT_BLOCKED_ALL & ~NM_DEVICE_AUTOCONNECT_BLOCKED_USER,
} NMDeviceAutoconnectBlockedFlags;

NMDeviceAutoconnectBlockedFlags nm_device_autoconnect_blocked_get (NMDevice *device, NMDeviceAutoconnectBlockedFlags mask);

void nm_device_autoconnect_blocked_set_full (NMDevice *device, NMDeviceAutoconnectBlockedFlags mask, NMDeviceAutoconnectBlockedFlags values);

static inline void
nm_device_autoconnect_blocked_set (NMDevice *device, NMDeviceAutoconnectBlockedFlags mask)
{
	nm_device_autoconnect_blocked_set_full (device, mask, mask);
}

static inline void
nm_device_autoconnect_blocked_unset (NMDevice *device, NMDeviceAutoconnectBlockedFlags mask)
{
	nm_device_autoconnect_blocked_set_full (device, mask, NM_DEVICE_AUTOCONNECT_BLOCKED_NONE);
}

void nm_device_emit_recheck_auto_activate (NMDevice *device);

NMDeviceSysIfaceState nm_device_sys_iface_state_get (NMDevice *device);

gboolean nm_device_sys_iface_state_is_external (NMDevice *self);
gboolean nm_device_sys_iface_state_is_external_or_assume (NMDevice *self);

void nm_device_sys_iface_state_set (NMDevice *device, NMDeviceSysIfaceState sys_iface_state);

void nm_device_state_changed (NMDevice *device,
                              NMDeviceState state,
                              NMDeviceStateReason reason);

void nm_device_queue_state   (NMDevice *self,
                              NMDeviceState state,
                              NMDeviceStateReason reason);

gboolean nm_device_get_firmware_missing (NMDevice *self);

void nm_device_disconnect_active_connection (NMActiveConnection *active,
                                             NMDeviceStateReason device_reason,
                                             NMActiveConnectionStateReason active_reason);

void nm_device_queue_activation (NMDevice *device, NMActRequest *req);

gboolean nm_device_supports_vlans (NMDevice *device);

gboolean nm_device_add_pending_action    (NMDevice *device, const char *action, gboolean assert_not_yet_pending);
gboolean nm_device_remove_pending_action (NMDevice *device, const char *action, gboolean assert_is_pending);
const char *nm_device_has_pending_action_reason (NMDevice *device);

static inline gboolean
nm_device_has_pending_action (NMDevice *device)
{
	return !!nm_device_has_pending_action_reason (device);
}

NMSettingsConnection *nm_device_get_best_connection (NMDevice *device,
                                                     const char *specific_object,
                                                     GError **error);

gboolean   nm_device_check_connection_available (NMDevice *device,
                                                 NMConnection *connection,
                                                 NMDeviceCheckConAvailableFlags flags,
                                                 const char *specific_object,
                                                 GError **error);

gboolean nm_device_notify_component_added (NMDevice *device, GObject *component);

gboolean nm_device_owns_iface (NMDevice *device, const char *iface);

NMConnection *nm_device_new_default_connection (NMDevice *self);

const NMPObject *nm_device_get_best_default_route (NMDevice *self,
                                                   int addr_family);

void nm_device_spawn_iface_helper (NMDevice *self);

gboolean nm_device_reapply (NMDevice *self,
                            NMConnection *connection,
                            GError **error);
void nm_device_reapply_settings_immediately (NMDevice *self);

void nm_device_update_firewall_zone (NMDevice *self);
void nm_device_update_metered (NMDevice *self);
void nm_device_reactivate_ip4_config (NMDevice *device,
                                      NMSettingIPConfig *s_ip4_old,
                                      NMSettingIPConfig *s_ip4_new);
void nm_device_reactivate_ip6_config (NMDevice *device,
                                      NMSettingIPConfig *s_ip6_old,
                                      NMSettingIPConfig *s_ip6_new);

gboolean nm_device_update_hw_address (NMDevice *self);
void nm_device_update_initial_hw_address (NMDevice *self);
void nm_device_update_permanent_hw_address (NMDevice *self, gboolean force_freeze);
void nm_device_update_dynamic_ip_setup (NMDevice *self);
guint nm_device_get_supplicant_timeout (NMDevice *self);

gboolean nm_device_auth_retries_try_next (NMDevice *self);

gboolean nm_device_hw_addr_get_cloned (NMDevice *self,
                                       NMConnection *connection,
                                       gboolean is_wifi,
                                       char **hwaddr,
                                       gboolean *preserve,
                                       GError **error);

typedef struct _NMDeviceConnectivityHandle NMDeviceConnectivityHandle;

typedef void (*NMDeviceConnectivityCallback) (NMDevice *self,
                                              NMDeviceConnectivityHandle *handle,
                                              NMConnectivityState state,
                                              GError *error,
                                              gpointer user_data);

void nm_device_check_connectivity_update_interval (NMDevice *self);

NMDeviceConnectivityHandle *nm_device_check_connectivity (NMDevice *self,
                                                          int addr_family,
                                                          NMDeviceConnectivityCallback callback,
                                                          gpointer user_data);

void nm_device_check_connectivity_cancel (NMDeviceConnectivityHandle *handle);

NMConnectivityState nm_device_get_connectivity_state (NMDevice *self, int addr_family);

typedef struct _NMBtVTableNetworkServer NMBtVTableNetworkServer;
struct _NMBtVTableNetworkServer {
	gboolean (*is_available) (const NMBtVTableNetworkServer *vtable,
	                          const char *addr);
	gboolean (*register_bridge) (const NMBtVTableNetworkServer *vtable,
	                             const char *addr,
	                             NMDevice *device);
	gboolean (*unregister_bridge) (const NMBtVTableNetworkServer *vtable,
	                               NMDevice *device);
};

const char *nm_device_state_to_str (NMDeviceState state);
const char *nm_device_state_reason_to_str (NMDeviceStateReason reason);

#endif /* __NETWORKMANAGER_DEVICE_H__ */
