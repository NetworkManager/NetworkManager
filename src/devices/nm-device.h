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
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_H__
#define __NETWORKMANAGER_DEVICE_H__

#include <netinet/in.h>

#include "nm-exported-object.h"
#include "nm-dbus-interface.h"
#include "nm-default.h"
#include "nm-connection.h"
#include "nm-rfkill-manager.h"
#include "NetworkManagerUtils.h"

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
#define NM_DEVICE_METERED          "metered"
#define NM_DEVICE_LLDP_NEIGHBORS  "lldp-neighbors"
#define NM_DEVICE_REAL             "real"

/* the "slaves" property is internal in the parent class, but exposed
 * by the derived classes NMDeviceBond, NMDeviceBridge and NMDeviceTeam.
 * It is thus important that the property name matches. */
#define NM_DEVICE_SLAVES           "slaves"         /* partially internal */

#define NM_DEVICE_TYPE_DESC        "type-desc"      /* Internal only */
#define NM_DEVICE_RFKILL_TYPE      "rfkill-type"    /* Internal only */
#define NM_DEVICE_IFINDEX          "ifindex"        /* Internal only */
#define NM_DEVICE_IS_MASTER        "is-master"      /* Internal only */
#define NM_DEVICE_MASTER           "master"         /* Internal only */
#define NM_DEVICE_HAS_PENDING_ACTION "has-pending-action" /* Internal only */

/* Internal signals */
#define NM_DEVICE_AUTH_REQUEST          "auth-request"
#define NM_DEVICE_IP4_CONFIG_CHANGED    "ip4-config-changed"
#define NM_DEVICE_IP6_CONFIG_CHANGED    "ip6-config-changed"
#define NM_DEVICE_REMOVED               "removed"
#define NM_DEVICE_RECHECK_AUTO_ACTIVATE "recheck-auto-activate"
#define NM_DEVICE_RECHECK_ASSUME        "recheck-assume"
#define NM_DEVICE_STATE_CHANGED         "state-changed"
#define NM_DEVICE_LINK_INITIALIZED      "link-initialized"

G_BEGIN_DECLS

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

	_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST                     = (1L << 0),
	_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER     = (1L << 1),
	_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP           = (1L << 2),
	NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST                      = _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST
	                                                                    | _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER
	                                                                    | _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_IGNORE_AP,

	NM_DEVICE_CHECK_CON_AVAILABLE_ALL                                   = (1L << 3) - 1,
} NMDeviceCheckConAvailableFlags;

struct _NMDevicePrivate;

struct _NMDevice {
	NMExportedObject parent;

	/* private */
	struct _NMDevicePrivate *priv;
};

/* The flags have an relaxing meaning, that means, specifying more flags, can make
 * a device appear more available. It can never make a device less available. */
typedef enum { /*< skip >*/
	NM_DEVICE_CHECK_DEV_AVAILABLE_NONE                                  = 0,

	_NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER                       = (1L << 0),
	NM_DEVICE_CHECK_DEV_AVAILABLE_FOR_USER_REQUEST                      = _NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER,

	NM_DEVICE_CHECK_DEV_AVAILABLE_ALL                                   = (1L << 1) - 1,
} NMDeviceCheckDevAvailableFlags;

typedef struct {
	NMExportedObjectClass parent;

	const char *connection_type;
	const NMLinkType *link_types;

	void (*state_changed) (NMDevice *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);

	void            (* link_changed) (NMDevice *self, NMPlatformLink *info);

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
	 * @plink: the #NMPlatformLink if backed by a kernel netdevice
	 *
	 * Hook for derived classes to be notfied during realize_start_setup()
	 * and perform additional setup.
	 */
	void        (*realize_start_notify) (NMDevice *self, const NMPlatformLink *plink);

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
	gboolean        (*is_up)                        (NMDevice *self);
	gboolean        (*bring_up)                     (NMDevice *self, gboolean *no_firmware);
	gboolean        (*take_down)                    (NMDevice *self);

	/* Carrier state (IFF_LOWER_UP) */
	void            (*carrier_changed) (NMDevice *, gboolean carrier);

	gboolean    (* get_ip_iface_identifier) (NMDevice *self, NMUtilsIPv6IfaceId *out_iid);

	NMDeviceCapabilities (* get_generic_capabilities) (NMDevice *self);

	gboolean    (* is_available) (NMDevice *self, NMDeviceCheckDevAvailableFlags flags);

	gboolean    (* get_enabled) (NMDevice *self);

	void        (* set_enabled) (NMDevice *self, gboolean enabled);

	gboolean    (* can_auto_connect) (NMDevice *self,
	                                  NMConnection *connection,
	                                  char **specific_object);

	/* Checks whether the connection is compatible with the device using
	 * only the devices type and characteristics.  Does not use any live
	 * network information like WiFi scan lists etc.
	 */
	gboolean    (* check_connection_compatible) (NMDevice *self, NMConnection *connection);

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
	                                            const char *specific_object);

	gboolean    (* complete_connection)         (NMDevice *self,
	                                             NMConnection *connection,
	                                             const char *specific_object,
	                                             const GSList *existing_connections,
	                                             GError **error);

	NMActStageReturn    (* act_stage1_prepare)  (NMDevice *self,
	                                             NMDeviceStateReason *reason);
	NMActStageReturn    (* act_stage2_config)   (NMDevice *self,
	                                             NMDeviceStateReason *reason);
	NMActStageReturn    (* act_stage3_ip4_config_start) (NMDevice *self,
	                                                     NMIP4Config **out_config,
	                                                     NMDeviceStateReason *reason);
	NMActStageReturn    (* act_stage3_ip6_config_start) (NMDevice *self,
	                                                     NMIP6Config **out_config,
	                                                     NMDeviceStateReason *reason);
	NMActStageReturn    (* act_stage4_ip4_config_timeout)   (NMDevice *self,
	                                                         NMDeviceStateReason *reason);
	NMActStageReturn    (* act_stage4_ip6_config_timeout)   (NMDevice *self,
	                                                         NMDeviceStateReason *reason);

	/* Called right before IP config is set; use for setting MTU etc */
	void                (* ip4_config_pre_commit) (NMDevice *self, NMIP4Config *config);
	void                (* ip6_config_pre_commit) (NMDevice *self, NMIP6Config *config);

	/* Async deactivating (in the DEACTIVATING phase) */
	void            (* deactivate_async)        (NMDevice *self,
	                                             GCancellable *cancellable,
	                                             GAsyncReadyCallback callback,
	                                             gpointer user_data);
	gboolean        (* deactivate_async_finish) (NMDevice *self,
	                                             GAsyncResult *res,
	                                             GError **error);

	/* Sync deactivating (in the DISCONNECTED phase) */
	void            (* deactivate) (NMDevice *self);

	const char *(*get_type_description) (NMDevice *self);

	NMMatchSpecMatchType (* spec_match_list)   (NMDevice *self, const GSList *specs);

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

	gboolean        (* have_any_ready_slaves) (NMDevice *self,
	                                           const GSList *slaves);

	void            (* notify_new_device_added) (NMDevice *self, NMDevice *new_device);

	/**
	 * component_added:
	 * @self: the #NMDevice
	 * @component: the component (device, modem, etc) which was added
	 *
	 * Notifies @self that a new component was added to the Manager.  This
	 * may include any kind of %GObject subclass, and the device is expected
	 * to match only specific components they care about, like %NMModem objects
	 * or %NMDevice objects.
	 *
	 * Returns: %TRUE if the component was claimed exclusively and no further
	 * devices should be notified of the new component.  %FALSE to indicate
	 * that the component was not exclusively claimed and other devices should
	 * be notified.
	 */
	gboolean        (* component_added) (NMDevice *self, GObject *component);

	gboolean        (* owns_iface) (NMDevice *self, const char *iface);

	NMConnection *  (* new_default_connection) (NMDevice *self);
} NMDeviceClass;

typedef void (*NMDeviceAuthRequestFunc) (NMDevice *device,
                                         GDBusMethodInvocation *context,
                                         NMAuthSubject *subject,
                                         GError *error,
                                         gpointer user_data);

GType nm_device_get_type (void);

const char *    nm_device_get_udi               (NMDevice *dev);
const char *    nm_device_get_iface             (NMDevice *dev);
int             nm_device_get_ifindex           (NMDevice *dev);
gboolean        nm_device_is_software           (NMDevice *dev);
gboolean        nm_device_is_real               (NMDevice *dev);
const char *    nm_device_get_ip_iface          (NMDevice *dev);
int             nm_device_get_ip_ifindex        (NMDevice *dev);
const char *    nm_device_get_driver            (NMDevice *dev);
const char *    nm_device_get_driver_version    (NMDevice *dev);
const char *    nm_device_get_type_desc         (NMDevice *dev);
const char *    nm_device_get_type_description  (NMDevice *dev);
NMDeviceType    nm_device_get_device_type       (NMDevice *dev);
NMLinkType      nm_device_get_link_type         (NMDevice *dev);
NMMetered       nm_device_get_metered           (NMDevice *dev);

int             nm_device_get_priority          (NMDevice *dev);
guint32         nm_device_get_ip4_route_metric  (NMDevice *dev);
guint32         nm_device_get_ip6_route_metric  (NMDevice *dev);

const char *    nm_device_get_hw_address        (NMDevice *dev);
const char *    nm_device_get_permanent_hw_address (NMDevice *dev);
const char *    nm_device_get_initial_hw_address (NMDevice *dev);

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

/* Master */
gboolean        nm_device_is_master             (NMDevice *dev);

/* Slave */
NMDevice *      nm_device_get_master            (NMDevice *dev);

NMActRequest *  nm_device_get_act_request       (NMDevice *dev);
NMSettingsConnection *nm_device_get_settings_connection (NMDevice *dev);
NMConnection *  nm_device_get_applied_connection (NMDevice *dev);
gboolean        nm_device_has_unmodified_applied_connection (NMDevice *self,
                                                             NMSettingCompareFlags compare_flags);
NMSetting *     nm_device_get_applied_setting   (NMDevice *dev, GType setting_type);

void            nm_device_removed               (NMDevice *self, gboolean unconfigure_ip_config);

gboolean        nm_device_is_available          (NMDevice *dev, NMDeviceCheckDevAvailableFlags flags);
gboolean        nm_device_has_carrier           (NMDevice *dev);

NMConnection * nm_device_generate_connection (NMDevice *self, NMDevice *master);

gboolean nm_device_master_update_slave_connection (NMDevice *master,
                                                   NMDevice *slave,
                                                   NMConnection *connection,
                                                   GError **error);

gboolean nm_device_can_auto_connect (NMDevice *self,
                                     NMConnection *connection,
                                     char **specific_object);

gboolean nm_device_complete_connection (NMDevice *device,
                                        NMConnection *connection,
                                        const char *specific_object,
                                        const GSList *existing_connection,
                                        GError **error);

gboolean nm_device_check_connection_compatible (NMDevice *device, NMConnection *connection);
gboolean nm_device_check_slave_connection_compatible (NMDevice *device, NMConnection *connection);

gboolean nm_device_uses_assumed_connection (NMDevice *device);

gboolean nm_device_can_assume_active_connection (NMDevice *device);

gboolean nm_device_spec_match_list (NMDevice *device, const GSList *specs);

gboolean nm_device_is_activating (NMDevice *dev);
gboolean nm_device_autoconnect_allowed (NMDevice *self);

NMDeviceState nm_device_get_state (NMDevice *device);

gboolean nm_device_get_enabled (NMDevice *device);

void nm_device_set_enabled (NMDevice *device, gboolean enabled);

RfKillType nm_device_get_rfkill_type (NMDevice *device);

/**
 * NMUnmanagedFlags:
 * @NM_UNMANAGED_NONE: placeholder value
 * @NM_UNMANAGED_SLEEPING: %TRUE when unmanaged because NM is sleeping.
 * @NM_UNMANAGED_QUITTING: %TRUE when unmanaged because NM is shutting down.
 * @NM_UNMANAGED_PARENT: %TRUE when unmanaged due to parent device being unmanaged
 * @NM_UNMANAGED_LOOPBACK: %TRUE for unmanaging loopback device
 * @NM_UNMANAGED_PLATFORM_INIT: %TRUE when unmanaged because platform link not
 *   yet initialized. Unrealized device are also unmanaged for this reason.
 * @NM_UNMANAGED_USER_EXPLICIT: %TRUE when unmanaged by explicit user decision
 *   (e.g. via a D-Bus command)
 * @NM_UNMANAGED_USER_SETTINGS: %TRUE when unmanaged by user decision via
 *   the settings plugin (for example keyfile.unmanaged-devices or ifcfg-rh's
 *   NM_CONTROLLED=no)
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

	/* these flags are authorative. If one of them is set,
	 * the device cannot be managed. */
	NM_UNMANAGED_SLEEPING      = (1LL <<  0),
	NM_UNMANAGED_QUITTING      = (1LL <<  1),
	NM_UNMANAGED_PARENT        = (1LL <<  2),
	NM_UNMANAGED_LOOPBACK      = (1LL <<  3),
	NM_UNMANAGED_PLATFORM_INIT = (1LL <<  4),
	NM_UNMANAGED_USER_EXPLICIT = (1LL <<  5),
	NM_UNMANAGED_USER_SETTINGS = (1LL <<  6),

	/* These flags can be non-effective and be overwritten
	 * by other flags. */
	NM_UNMANAGED_BY_DEFAULT    = (1LL <<  8),
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
void nm_device_set_unmanaged_by_user_config (NMDevice *self, const GSList *unmanaged_specs);
void nm_device_set_unmanaged_by_user_udev (NMDevice *self);
void nm_device_set_unmanaged_by_quitting (NMDevice *device);

gboolean nm_device_get_is_nm_owned (NMDevice *device);

gboolean nm_device_has_capability (NMDevice *self, NMDeviceCapabilities caps);

gboolean nm_device_realize_start      (NMDevice *device,
                                       const NMPlatformLink *plink,
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

gboolean nm_device_get_autoconnect (NMDevice *device);
void nm_device_set_autoconnect (NMDevice *device, gboolean autoconnect);
void nm_device_emit_recheck_auto_activate (NMDevice *device);

void nm_device_state_changed (NMDevice *device,
                              NMDeviceState state,
                              NMDeviceStateReason reason);

void nm_device_queue_state   (NMDevice *self,
                              NMDeviceState state,
                              NMDeviceStateReason reason);

gboolean nm_device_get_firmware_missing (NMDevice *self);
gboolean nm_device_get_nm_plugin_missing (NMDevice *self);
void     nm_device_set_nm_plugin_missing (NMDevice *self,
                                          gboolean missing);

void nm_device_steal_connection (NMDevice *device, NMSettingsConnection *connection);

void nm_device_queue_activation (NMDevice *device, NMActRequest *req);

gboolean nm_device_supports_vlans (NMDevice *device);

gboolean nm_device_add_pending_action    (NMDevice *device, const char *action, gboolean assert_not_yet_pending);
gboolean nm_device_remove_pending_action (NMDevice *device, const char *action, gboolean assert_is_pending);
gboolean nm_device_has_pending_action    (NMDevice *device);

NMSettingsConnection *nm_device_get_best_connection (NMDevice *device,
                                                     const char *specific_object,
                                                     GError **error);

gboolean   nm_device_check_connection_available (NMDevice *device,
                                                 NMConnection *connection,
                                                 NMDeviceCheckConAvailableFlags flags,
                                                 const char *specific_object);

void     nm_device_notify_new_device_added (NMDevice *self, NMDevice *new_device);
gboolean nm_device_notify_component_added (NMDevice *device, GObject *component);

gboolean nm_device_owns_iface (NMDevice *device, const char *iface);

NMConnection *nm_device_new_default_connection (NMDevice *self);

const NMPlatformIP4Route *nm_device_get_ip4_default_route (NMDevice *self, gboolean *out_is_assumed);
const NMPlatformIP6Route *nm_device_get_ip6_default_route (NMDevice *self, gboolean *out_is_assumed);

void nm_device_spawn_iface_helper (NMDevice *self);

void nm_device_reapply_settings_immediately (NMDevice *self);

void nm_device_update_firewall_zone (NMDevice *self);
void nm_device_update_metered (NMDevice *self);
void nm_device_reactivate_ip4_config (NMDevice *device,
                                      NMSettingIPConfig *s_ip4_old,
                                      NMSettingIPConfig *s_ip4_new);
void nm_device_reactivate_ip6_config (NMDevice *device,
                                      NMSettingIPConfig *s_ip6_old,
                                      NMSettingIPConfig *s_ip6_new);

void nm_device_update_hw_address (NMDevice *self);
void nm_device_update_initial_hw_address (NMDevice *self);
void nm_device_update_dynamic_ip_setup (NMDevice *self);

G_END_DECLS

#endif /* NM_DEVICE_H */
