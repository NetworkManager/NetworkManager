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

#include <config.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <netlink/route/addr.h>

#include "libgsystem.h"
#include "nm-glib-compat.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "nm-platform.h"
#include "nm-rdisc.h"
#include "nm-lndp-rdisc.h"
#include "nm-dhcp-manager.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-connection.h"
#include "nm-dnsmasq-manager.h"
#include "nm-dhcp4-config.h"
#include "nm-rfkill-manager.h"
#include "nm-firewall-manager.h"
#include "nm-properties-changed-signal.h"
#include "nm-enum-types.h"
#include "nm-settings-connection.h"
#include "nm-connection-provider.h"
#include "nm-posix-signals.h"
#include "nm-manager-auth.h"
#include "nm-dbus-glib-types.h"
#include "nm-dispatcher.h"
#include "nm-config-device.h"
#include "nm-config.h"
#include "nm-dns-manager.h"

#include "nm-device-bridge.h"
#include "nm-device-bond.h"
#include "nm-device-team.h"

static void impl_device_disconnect (NMDevice *device, DBusGMethodInvocation *context);

#include "nm-device-glue.h"

static void nm_device_config_device_interface_init (NMConfigDeviceInterface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMDevice, nm_device, G_TYPE_OBJECT,
                                  G_IMPLEMENT_INTERFACE (NM_TYPE_CONFIG_DEVICE, nm_device_config_device_interface_init))

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

enum {
	STATE_CHANGED,
	AUTOCONNECT_ALLOWED,
	AUTH_REQUEST,
	IP4_CONFIG_CHANGED,
	IP6_CONFIG_CHANGED,
	REMOVED,
	RECHECK_AUTO_ACTIVATE,
	RECHECK_ASSUME,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_PLATFORM_DEVICE,
	PROP_UDI,
	PROP_IFACE,
	PROP_IP_IFACE,
	PROP_DRIVER,
	PROP_DRIVER_VERSION,
	PROP_FIRMWARE_VERSION,
	PROP_CAPABILITIES,
	PROP_CARRIER,
	PROP_MTU,
	PROP_IP4_ADDRESS,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,
	PROP_STATE,
	PROP_STATE_REASON,
	PROP_ACTIVE_CONNECTION,
	PROP_DEVICE_TYPE,
	PROP_MANAGED,
	PROP_AUTOCONNECT,
	PROP_FIRMWARE_MISSING,
	PROP_TYPE_DESC,
	PROP_RFKILL_TYPE,
	PROP_IFINDEX,
	PROP_AVAILABLE_CONNECTIONS,
	PROP_PHYSICAL_PORT_ID,
	PROP_IS_MASTER,
	PROP_MASTER,
	PROP_HW_ADDRESS,
	PROP_HAS_PENDING_ACTION,
	LAST_PROP
};

/***********************************************************/

#define PENDING_ACTION_DHCP4 "dhcp4"
#define PENDING_ACTION_DHCP6 "dhcp6"
#define PENDING_ACTION_AUTOCONF6 "autoconf6"

typedef enum {
	IP_NONE = 0,
	IP_WAIT,
	IP_CONF,
	IP_DONE,
	IP_FAIL
} IpState;

typedef struct {
	NMDeviceState state;
	NMDeviceStateReason reason;
	guint id;
} QueuedState;

typedef struct {
	NMDevice *slave;
	gboolean enslaved;
	gboolean configure;
	guint watch_id;
} SlaveInfo;

typedef struct {
	guint log_domain;
	guint timeout;
	guint watch;
	GPid pid;
} PingInfo;

typedef struct {
	NMDevice *device;
	guint idle_add_id;
	int ifindex;
} DeleteOnDeactivateData;

typedef struct {
	gboolean in_state_changed;

	NMDeviceState state;
	NMDeviceStateReason state_reason;
	QueuedState   queued_state;
	guint queued_ip_config_id;
	GSList *pending_actions;

	char *        udi;
	char *        path;
	char *        iface;   /* may change, could be renamed by user */
	int           ifindex;
	gboolean      is_software;
	char *        ip_iface;
	int           ip_ifindex;
	NMDeviceType  type;
	char *        type_desc;
	guint32       capabilities;
	char *        driver;
	char *        driver_version;
	char *        firmware_version;
	RfKillType    rfkill_type;
	gboolean      firmware_missing;
	GHashTable *  available_connections;
	guint8        hw_addr[NM_UTILS_HWADDR_LEN_MAX];
	guint         hw_addr_len;
	char *        physical_port_id;

	NMUnmanagedFlags        unmanaged_flags;
	gboolean                is_nm_owned; /* whether the device is a device owned and created by NM */
	DeleteOnDeactivateData *delete_on_deactivate_data; /* data for scheduled cleanup when deleting link (g_idle_add) */

	guint32         ip4_address;

	NMActRequest *  queued_act_request;
	NMActRequest *  act_request;
	guint           act_source_id;
	gpointer        act_source_func;
	guint           act_source6_id;
	gpointer        act_source6_func;
	guint           recheck_assume_id;
	struct {
		guint               call_id;
		NMDeviceState       post_state;
		NMDeviceStateReason post_state_reason;
	}               dispatcher;

	/* Link stuff */
	guint           link_connected_id;
	guint           link_disconnected_id;
	guint           carrier_defer_id;
	gboolean        carrier;
	guint           carrier_wait_id;
	gboolean        ignore_carrier;
	guint32         mtu;

	/* Generic DHCP stuff */
	guint32         dhcp_timeout;
	GByteArray *    dhcp_anycast_address;

	/* IP4 configuration info */
	NMIP4Config *   ip4_config;     /* Combined config from VPN, settings, and device */
	IpState         ip4_state;
	NMIP4Config *   dev_ip4_config; /* Config from DHCP, PPP, LLv4, etc */
	NMIP4Config *   ext_ip4_config; /* Stuff added outside NM */

	/* DHCPv4 tracking */
	NMDHCPClient *  dhcp4_client;
	gulong          dhcp4_state_sigid;
	gulong          dhcp4_timeout_sigid;
	NMDHCP4Config * dhcp4_config;
	NMIP4Config *   vpn4_config;  /* routes added by a VPN which uses this device */

	guint           arp_round2_id;
	PingInfo        gw_ping;

	/* dnsmasq stuff for shared connections */
	NMDnsMasqManager *dnsmasq_manager;
	gulong            dnsmasq_state_id;

	/* Firewall Manager */
	NMFirewallManager *fw_manager;
	DBusGProxyCall    *fw_call;

	/* avahi-autoipd stuff */
	GPid    aipd_pid;
	guint   aipd_watch;
	guint   aipd_timeout;

	/* IP6 configuration info */
	NMIP6Config *  ip6_config;
	IpState        ip6_state;
	NMIP6Config *  vpn6_config;  /* routes added by a VPN which uses this device */
	NMIP6Config *  ext_ip6_config; /* Stuff added outside NM */

	NMRDisc *      rdisc;
	gulong         rdisc_config_changed_sigid;
	NMSettingIP6ConfigPrivacy rdisc_use_tempaddr;
	/* IP6 config from autoconf */
	NMIP6Config *  ac_ip6_config;

	guint          linklocal6_timeout_id;

	GHashTable *   ip6_saved_properties;

	NMDHCPClient *  dhcp6_client;
	NMRDiscDHCPLevel dhcp6_mode;
	gulong          dhcp6_state_sigid;
	gulong          dhcp6_timeout_sigid;
	NMDHCP6Config * dhcp6_config;
	/* IP6 config from DHCP */
	NMIP6Config *   dhcp6_ip6_config;

	/* allow autoconnect feature */
	gboolean        autoconnect;

	/* master interface for bridge/bond/team slave */
	NMDevice *      master;
	gboolean        enslaved;
	guint           master_ready_id;

	/* slave management */
	gboolean        is_master;
	GSList *        slaves;    /* list of SlaveInfo */

	NMConnectionProvider *con_provider;
} NMDevicePrivate;

static gboolean nm_device_set_ip4_config (NMDevice *dev,
                                          NMIP4Config *config,
                                          gboolean commit,
                                          NMDeviceStateReason *reason);
static gboolean ip4_config_merge_and_apply (NMDevice *self,
                                            NMIP4Config *config,
                                            gboolean commit,
                                            NMDeviceStateReason *out_reason);

static gboolean nm_device_set_ip6_config (NMDevice *dev,
                                          NMIP6Config *config,
                                          gboolean commit,
                                          NMDeviceStateReason *reason);

static gboolean nm_device_master_add_slave (NMDevice *dev, NMDevice *slave, gboolean configure);
static void nm_device_slave_notify_enslave (NMDevice *dev, gboolean success);
static void nm_device_slave_notify_release (NMDevice *dev, NMDeviceStateReason reason);

static void addrconf6_start_with_link_ready (NMDevice *self);

static gboolean nm_device_get_default_unmanaged (NMDevice *device);

static void _set_state_full (NMDevice *device,
                             NMDeviceState state,
                             NMDeviceStateReason reason,
                             gboolean quitting);

/***********************************************************/

static GQuark
nm_device_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-device-error");
	return quark;
}

#define NM_DEVICE_ERROR (nm_device_error_quark ())

/***********************************************************/

#define QUEUED_PREFIX "queued state change to "

static const char *state_table[] = {
	[NM_DEVICE_STATE_UNKNOWN]      = QUEUED_PREFIX "unknown",
	[NM_DEVICE_STATE_UNMANAGED]    = QUEUED_PREFIX "unmanaged",
	[NM_DEVICE_STATE_UNAVAILABLE]  = QUEUED_PREFIX "unavailable",
	[NM_DEVICE_STATE_DISCONNECTED] = QUEUED_PREFIX "disconnected",
	[NM_DEVICE_STATE_PREPARE]      = QUEUED_PREFIX "prepare",
	[NM_DEVICE_STATE_CONFIG]       = QUEUED_PREFIX "config",
	[NM_DEVICE_STATE_NEED_AUTH]    = QUEUED_PREFIX "need-auth",
	[NM_DEVICE_STATE_IP_CONFIG]    = QUEUED_PREFIX "ip-config",
	[NM_DEVICE_STATE_IP_CHECK]     = QUEUED_PREFIX "ip-check",
	[NM_DEVICE_STATE_SECONDARIES]  = QUEUED_PREFIX "secondaries",
	[NM_DEVICE_STATE_ACTIVATED]    = QUEUED_PREFIX "activated",
	[NM_DEVICE_STATE_DEACTIVATING] = QUEUED_PREFIX "deactivating",
	[NM_DEVICE_STATE_FAILED]       = QUEUED_PREFIX "failed",
};

static const char *
queued_state_to_string (NMDeviceState state)
{
	if (state >= 0 && state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return state_table[NM_DEVICE_STATE_UNKNOWN];
}

static const char *
state_to_string (NMDeviceState state)
{
	return queued_state_to_string (state) + strlen (QUEUED_PREFIX);
}

static const char *reason_table[] = {
	[NM_DEVICE_STATE_REASON_NONE]                     = "none",
	[NM_DEVICE_STATE_REASON_NOW_MANAGED]              = "managed",
	[NM_DEVICE_STATE_REASON_NOW_UNMANAGED]            = "unmanaged",
	[NM_DEVICE_STATE_REASON_CONFIG_FAILED]            = "config-failed",
	[NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE]    = "ip-config-unavailable",
	[NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED]        = "ip-config-expired",
	[NM_DEVICE_STATE_REASON_NO_SECRETS]               = "no-secrets",
	[NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT]    = "supplicant-disconnect",
	[NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED] = "supplicant-config-failed",
	[NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED]        = "supplicant-failed",
	[NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT]       = "supplicant-timeout",
	[NM_DEVICE_STATE_REASON_PPP_START_FAILED]         = "ppp-start-failed",
	[NM_DEVICE_STATE_REASON_PPP_DISCONNECT]           = "ppp-disconnect",
	[NM_DEVICE_STATE_REASON_PPP_FAILED]               = "ppp-failed",
	[NM_DEVICE_STATE_REASON_DHCP_START_FAILED]        = "dhcp-start-failed",
	[NM_DEVICE_STATE_REASON_DHCP_ERROR]               = "dhcp-error",
	[NM_DEVICE_STATE_REASON_DHCP_FAILED]              = "dhcp-failed",
	[NM_DEVICE_STATE_REASON_SHARED_START_FAILED]      = "sharing-start-failed",
	[NM_DEVICE_STATE_REASON_SHARED_FAILED]            = "sharing-failed",
	[NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED]      = "autoip-start-failed",
	[NM_DEVICE_STATE_REASON_AUTOIP_ERROR]             = "autoip-error",
	[NM_DEVICE_STATE_REASON_AUTOIP_FAILED]            = "autoip-failed",
	[NM_DEVICE_STATE_REASON_MODEM_BUSY]               = "modem-busy",
	[NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE]       = "modem-no-dialtone",
	[NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER]         = "modem-no-carrier",
	[NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT]       = "modem-dial-timeout",
	[NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED]        = "modem-dial-failed",
	[NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED]        = "modem-init-failed",
	[NM_DEVICE_STATE_REASON_GSM_APN_FAILED]           = "gsm-apn-failed",
	[NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING] = "gsm-registration-idle",
	[NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED]  = "gsm-registration-denied",
	[NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT] = "gsm-registration-timeout",
	[NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED]  = "gsm-registration-failed",
	[NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED]     = "gsm-pin-check-failed",
	[NM_DEVICE_STATE_REASON_FIRMWARE_MISSING]         = "firmware-missing",
	[NM_DEVICE_STATE_REASON_REMOVED]                  = "removed",
	[NM_DEVICE_STATE_REASON_SLEEPING]                 = "sleeping",
	[NM_DEVICE_STATE_REASON_CONNECTION_REMOVED]       = "connection-removed",
	[NM_DEVICE_STATE_REASON_USER_REQUESTED]           = "user-requested",
	[NM_DEVICE_STATE_REASON_CARRIER]                  = "carrier-changed",
	[NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED]       = "connection-assumed",
	[NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE]     = "supplicant-available",
	[NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND]          = "modem-not-found",
	[NM_DEVICE_STATE_REASON_BT_FAILED]                = "bluetooth-failed",
	[NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED]     = "gsm-sim-not-inserted",
	[NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED]     = "gsm-sim-pin-required",
	[NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED]     = "gsm-sim-puk-required",
	[NM_DEVICE_STATE_REASON_GSM_SIM_WRONG]            = "gsm-sim-wrong",
	[NM_DEVICE_STATE_REASON_INFINIBAND_MODE]          = "infiniband-mode",
	[NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED]        = "dependency-failed",
	[NM_DEVICE_STATE_REASON_BR2684_FAILED]            = "br2684-bridge-failed",
	[NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE] = "modem-manager-unavailable",
	[NM_DEVICE_STATE_REASON_SSID_NOT_FOUND]           = "ssid-not-found",
	[NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED] = "secondary-connection-failed",
	[NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED]          = "dcb-fcoe-failed",
	[NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED]     = "teamd-control-failed",
	[NM_DEVICE_STATE_REASON_MODEM_FAILED]             = "modem-failed",
	[NM_DEVICE_STATE_REASON_MODEM_AVAILABLE]          = "modem-available",
	[NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT]        = "sim-pin-incorrect",
};

static const char *
reason_to_string (NMDeviceStateReason reason)
{
	if (reason >= 0 && reason < G_N_ELEMENTS (reason_table))
		return reason_table[reason];
	return reason_table[NM_DEVICE_STATE_REASON_UNKNOWN];
}

/***********************************************************/

static inline gboolean
nm_device_ipv6_sysctl_set (NMDevice *self, const char *property, const char *value)
{
	return nm_platform_sysctl_set (nm_utils_ip6_property_path (nm_device_get_ip_iface (self), property), value);
}

static gboolean
device_has_capability (NMDevice *device, NMDeviceCapabilities caps)
{
	return !!(NM_DEVICE_GET_PRIVATE (device)->capabilities & caps);
}

/***********************************************************/

void
nm_device_dbus_export (NMDevice *device)
{
	static guint32 devcount = 0;
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE (device);
	g_return_if_fail (priv->path == NULL);

	priv->path = g_strdup_printf ("/org/freedesktop/NetworkManager/Devices/%d", devcount++);
	nm_log_info (LOGD_DEVICE, "(%s): exported as %s", priv->iface, priv->path);
	nm_dbus_manager_register_object (nm_dbus_manager_get (), priv->path, device);
}

const char *
nm_device_get_path (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->path;
}

const char *
nm_device_get_udi (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->udi;
}

const char *
nm_device_get_iface (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->iface;
}

int
nm_device_get_ifindex (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, 0);

	return NM_DEVICE_GET_PRIVATE (self)->ifindex;
}

gboolean
nm_device_is_software (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	return priv->is_software;
}

const char *
nm_device_get_ip_iface (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (self != NULL, NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);
	/* If it's not set, default to iface */
	return priv->ip_iface ? priv->ip_iface : priv->iface;
}

int
nm_device_get_ip_ifindex (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (self != NULL, 0);

	priv = NM_DEVICE_GET_PRIVATE (self);
	/* If it's not set, default to iface */
	return priv->ip_iface ? priv->ip_ifindex : priv->ifindex;
}

void
nm_device_set_ip_iface (NMDevice *self, const char *iface)
{
	NMDevicePrivate *priv;
	char *old_ip_iface;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (!g_strcmp0 (iface, priv->ip_iface))
		return;

	old_ip_iface = priv->ip_iface;
	priv->ip_ifindex = 0;

	priv->ip_iface = g_strdup (iface);
	if (priv->ip_iface) {
		priv->ip_ifindex = nm_platform_link_get_ifindex (priv->ip_iface);
		if (priv->ip_ifindex > 0) {
			if (!nm_platform_link_is_up (priv->ip_ifindex))
				nm_platform_link_set_up (priv->ip_ifindex);
		} else {
			/* Device IP interface must always be a kernel network interface */
			nm_log_warn (LOGD_HW, "(%s): failed to look up interface index", iface);
		}
	}

	/* We don't care about any saved values from the old iface */
	g_hash_table_remove_all (priv->ip6_saved_properties);

	/* Emit change notification */
	if (g_strcmp0 (old_ip_iface, priv->ip_iface))
		g_object_notify (G_OBJECT (self), NM_DEVICE_IP_IFACE);
	g_free (old_ip_iface);
}

const char *
nm_device_get_driver (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->driver;
}

const char *
nm_device_get_driver_version (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->driver_version;
}

NMDeviceType
nm_device_get_device_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_TYPE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->type;
}


/**
 * nm_device_get_priority():
 * @dev: the #NMDevice
 *
 * Returns: the device's routing priority.  Lower numbers means a "better"
 *  device, eg higher priority.
 */
int
nm_device_get_priority (NMDevice *dev)
{
	g_return_val_if_fail (NM_IS_DEVICE (dev), 100);

	/* Device 'priority' is used for two things:
	 *
	 * a) two devices on the same IP subnet: the "better" (ie, lower number)
	 *     device is the default outgoing device for that subnet
	 * b) default route: the "better" device gets the default route.  This can
	 *     always be modified by setting a connection to never-default=TRUE, in
	 *     which case that device will never take the default route when
	 *     it's using that connection.
	 */

	switch (nm_device_get_device_type (dev)) {
	case NM_DEVICE_TYPE_ETHERNET:
		return 1;
	case NM_DEVICE_TYPE_INFINIBAND:
		return 2;
	case NM_DEVICE_TYPE_ADSL:
		return 3;
	case NM_DEVICE_TYPE_WIMAX:
		return 4;
	case NM_DEVICE_TYPE_BOND:
		return 5;
	case NM_DEVICE_TYPE_TEAM:
		return 6;
	case NM_DEVICE_TYPE_VLAN:
		return 7;
	case NM_DEVICE_TYPE_MODEM:
		return 8;
	case NM_DEVICE_TYPE_BT:
		return 9;
	case NM_DEVICE_TYPE_WIFI:
		return 10;
	case NM_DEVICE_TYPE_OLPC_MESH:
		return 11;
	default:
		return 20;
	}
}

const char *
nm_device_get_type_desc (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->type_desc;
}

gboolean
nm_device_has_carrier (NMDevice *device)
{
	return NM_DEVICE_GET_PRIVATE (device)->carrier;
}

NMActRequest *
nm_device_get_act_request (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->act_request;
}

NMConnection *
nm_device_get_connection (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	return priv->act_request ? nm_act_request_get_connection (priv->act_request) : NULL;
}

RfKillType
nm_device_get_rfkill_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_PRIVATE (self)->rfkill_type;
}

static const char *
nm_device_get_physical_port_id (NMDevice *device)
{
	return NM_DEVICE_GET_PRIVATE (device)->physical_port_id;
}

/***********************************************************/

static gboolean
nm_device_uses_generated_connection (NMDevice *self)
{
	NMConnection *connection;

	connection = nm_device_get_connection (self);
	if (!connection)
		return FALSE;
	return nm_settings_connection_get_nm_generated (NM_SETTINGS_CONNECTION (connection));
}

static SlaveInfo *
find_slave_info (NMDevice *self, NMDevice *slave)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	SlaveInfo *info;
	GSList *iter;

	for (iter = priv->slaves; iter; iter = g_slist_next (iter)) {
		info = iter->data;
		if (info->slave == slave)
			return info;
	}
	return NULL;
}

static void
free_slave_info (SlaveInfo *info)
{
	g_signal_handler_disconnect (info->slave, info->watch_id);
	g_clear_object (&info->slave);
	memset (info, 0, sizeof (*info));
	g_free (info);
}

/**
 * nm_device_enslave_slave:
 * @dev: the master device
 * @slave: the slave device to enslave
 * @connection: (allow-none): the slave device's connection
 *
 * If @dev is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function enslaves @slave.
 *
 * Returns: %TRUE on success, %FALSE on failure or if this device cannot enslave
 *  other devices.
 */
static gboolean
nm_device_enslave_slave (NMDevice *dev, NMDevice *slave, NMConnection *connection)
{
	SlaveInfo *info;
	gboolean success = FALSE;
	gboolean configure;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (dev)->enslave_slave != NULL, FALSE);

	info = find_slave_info (dev, slave);
	if (!info)
		return FALSE;

	if (info->enslaved)
		success = TRUE;
	else {
		configure = (info->configure && connection != NULL);
		if (configure)
			g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

		success = NM_DEVICE_GET_CLASS (dev)->enslave_slave (dev, slave, connection, configure);
		info->enslaved = success;
	}

	nm_device_slave_notify_enslave (info->slave, success);

	/* Ensure the device's hardware address is up-to-date; it often changes
	 * when slaves change.
	 */
	nm_device_update_hw_address (dev);

	/* Restart IP configuration if we're waiting for slaves.  Do this
	 * after updating the hardware address as IP config may need the
	 * new address.
	 */
	if (success) {
		if (NM_DEVICE_GET_PRIVATE (dev)->ip4_state == IP_WAIT)
			nm_device_activate_stage3_ip4_start (dev);

		if (NM_DEVICE_GET_PRIVATE (dev)->ip6_state == IP_WAIT)
			nm_device_activate_stage3_ip6_start (dev);
	}

	return success;
}

/**
 * nm_device_release_one_slave:
 * @dev: the master device
 * @slave: the slave device to release
 * @configure: whether @dev needs to actually release @slave
 * @reason: the state change reason for the @slave
 *
 * If @dev is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function releases the previously enslaved @slave and/or
 * updates the state of @dev and @slave to reflect its release.
 *
 * Returns: %TRUE on success, %FALSE on failure, if this device cannot enslave
 *  other devices, or if @slave was never enslaved.
 */
static gboolean
nm_device_release_one_slave (NMDevice *dev, NMDevice *slave, gboolean configure, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	SlaveInfo *info;
	gboolean success = FALSE;

	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (dev)->release_slave != NULL, FALSE);

	info = find_slave_info (dev, slave);
	if (!info)
		return FALSE;
	priv->slaves = g_slist_remove (priv->slaves, info);

	if (info->enslaved) {
		success = NM_DEVICE_GET_CLASS (dev)->release_slave (dev, slave, configure);
		/* The release_slave() implementation logs success/failure (in the
		 * correct device-specific log domain), so we don't have to do anything.
		 */
	}

	if (!configure) {
		g_warn_if_fail (reason == NM_DEVICE_STATE_REASON_NONE);
		reason = NM_DEVICE_STATE_REASON_NONE;
	} else if (reason == NM_DEVICE_STATE_REASON_NONE) {
		g_warn_if_reached ();
		reason = NM_DEVICE_STATE_REASON_UNKNOWN;
	}
	nm_device_slave_notify_release (info->slave, reason);

	free_slave_info (info);

	/* Ensure the device's hardware address is up-to-date; it often changes
	 * when slaves change.
	 */
	nm_device_update_hw_address (dev);

	return success;
}

static void
carrier_changed (NMDevice *device, gboolean carrier)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if (!nm_device_get_managed (device))
		return;

	nm_device_recheck_available_connections (device);

	/* ignore-carrier devices ignore all carrier-down events */
	if (priv->ignore_carrier && !carrier)
		return;

	if (priv->is_master) {
		/* Bridge/bond/team carrier does not affect its own activation,
		 * but when carrier comes on, if there are slaves waiting,
		 * it will restart them.
		 */
		if (!carrier)
			return;

		if (nm_device_activate_ip4_state_in_wait (device))
			nm_device_activate_stage3_ip4_start (device);
		if (nm_device_activate_ip6_state_in_wait (device))
			nm_device_activate_stage3_ip6_start (device);

		return;
	} else if (nm_device_get_enslaved (device) && !carrier) {
		/* Slaves don't deactivate when they lose carrier; for
		 * bonds/teams in particular that would be actively
		 * counterproductive.
		 */
		return;
	}

	if (carrier) {
		g_warn_if_fail (priv->state >= NM_DEVICE_STATE_UNAVAILABLE);

		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_queue_state (device, NM_DEVICE_STATE_DISCONNECTED,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		} else if (priv->state == NM_DEVICE_STATE_DISCONNECTED) {
			/* If the device is already in DISCONNECTED state without a carrier
			 * (probably because it is tagged for carrier ignore) ensure that
			 * when the carrier appears, auto connections are rechecked for
			 * the device.
			 */
			nm_device_emit_recheck_auto_activate (device);
		}
	} else {
		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			if (nm_device_queued_state_peek (device) >= NM_DEVICE_STATE_DISCONNECTED)
				nm_device_queued_state_clear (device);
		} else if (priv->state >= NM_DEVICE_STATE_DISCONNECTED) {
			nm_device_queue_state (device, NM_DEVICE_STATE_UNAVAILABLE,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		}
	}
}

#define LINK_DISCONNECT_DELAY 4

static gboolean
link_disconnect_action_cb (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	nm_log_dbg (LOGD_DEVICE, "(%s): link disconnected (calling deferred action) (id=%u)",
	             nm_device_get_iface (device), priv->carrier_defer_id);

	priv->carrier_defer_id = 0;

	nm_log_info (LOGD_DEVICE, "(%s): link disconnected (calling deferred action)",
	             nm_device_get_iface (device));

	NM_DEVICE_GET_CLASS (device)->carrier_changed (device, FALSE);

	return FALSE;
}

static void
link_disconnect_action_cancel (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->carrier_defer_id) {
		g_source_remove (priv->carrier_defer_id);
		nm_log_dbg (LOGD_DEVICE, "(%s): link disconnected (canceling deferred action) (id=%u)",
		            nm_device_get_iface (self), priv->carrier_defer_id);
		priv->carrier_defer_id = 0;
	}
}

void
nm_device_set_carrier (NMDevice *device, gboolean carrier)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (device);
	NMDeviceState state = nm_device_get_state (device);
	const char *iface = nm_device_get_iface (device);

	if (priv->carrier == carrier)
		return;

	priv->carrier = carrier;
	g_object_notify (G_OBJECT (device), NM_DEVICE_CARRIER);

	if (priv->carrier) {
		nm_log_info (LOGD_DEVICE, "(%s): link connected", iface);
		link_disconnect_action_cancel (device);
		klass->carrier_changed (device, TRUE);

		if (priv->carrier_wait_id) {
			g_source_remove (priv->carrier_wait_id);
			priv->carrier_wait_id = 0;
			nm_device_remove_pending_action (device, "carrier wait", TRUE);
		}
	} else if (state <= NM_DEVICE_STATE_DISCONNECTED) {
		nm_log_info (LOGD_DEVICE, "(%s): link disconnected", iface);
		klass->carrier_changed (device, FALSE);
	} else {
		nm_log_info (LOGD_DEVICE, "(%s): link disconnected (deferring action for %d seconds)",
		             iface, LINK_DISCONNECT_DELAY);
		priv->carrier_defer_id = g_timeout_add_seconds (LINK_DISCONNECT_DELAY,
		                                                link_disconnect_action_cb, device);
		nm_log_dbg (LOGD_DEVICE, "(%s): link disconnected (deferring action for %d seconds) (id=%u)",
		             iface, LINK_DISCONNECT_DELAY, priv->carrier_defer_id);
	}
}

static void
update_for_ip_ifname_change (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	g_hash_table_remove_all (priv->ip6_saved_properties);

	if (priv->dhcp4_client) {
		if (!nm_device_dhcp4_renew (device, FALSE)) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_DHCP_FAILED);
			return;
		}
	}
	if (priv->dhcp6_client) {
		if (!nm_device_dhcp6_renew (device, FALSE)) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_DHCP_FAILED);
			return;
		}
	}
	if (priv->rdisc) {
		/* FIXME: todo */
	}
	if (priv->dnsmasq_manager) {
		/* FIXME: todo */
	}
}

static void
device_link_changed (NMDevice *device, NMPlatformLink *info)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (device);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	gboolean ip_ifname_changed = FALSE;

	if (info->udi && g_strcmp0 (info->udi, priv->udi)) {
		/* Update UDI to what udev gives us */
		g_free (priv->udi);
		priv->udi = g_strdup (info->udi);
		g_object_notify (G_OBJECT (device), NM_DEVICE_UDI);
	}

	/* Update MTU if it has changed. */
	if (priv->mtu != info->mtu) {
		priv->mtu = info->mtu;
		g_object_notify (G_OBJECT (device), NM_DEVICE_MTU);
	}

	if (info->name[0] && strcmp (priv->iface, info->name) != 0) {
		nm_log_info (LOGD_DEVICE, "(%s): interface index %d renamed iface from '%s' to '%s'",
		             priv->iface, priv->ifindex, priv->iface, info->name);
		g_free (priv->iface);
		priv->iface = g_strdup (info->name);

		/* If the device has no explicit ip_iface, then changing iface changes ip_iface too. */
		ip_ifname_changed = !priv->ip_iface;

		g_object_notify (G_OBJECT (device), NM_DEVICE_IFACE);
		if (ip_ifname_changed)
			g_object_notify (G_OBJECT (device), NM_DEVICE_IP_IFACE);

		/* Re-match available connections against the new interface name */
		nm_device_recheck_available_connections (device);

		/* Let any connections that use the new interface name have a chance
		 * to auto-activate on the device.
		 */
		nm_device_emit_recheck_auto_activate (device);
	}

	/* Update slave status for external changes */
	if (info->master && !priv->enslaved) {
		NMDevice *master;

		master = nm_manager_get_device_by_ifindex (nm_manager_get (), info->master);
		if (master && NM_DEVICE_GET_CLASS (master)->enslave_slave) {
			g_clear_object (&priv->master);
			priv->master = g_object_ref (master);
			nm_device_master_add_slave (master, device, FALSE);
			nm_device_enslave_slave (master, device, NULL);
		} else if (master) {
			nm_log_info (LOGD_DEVICE, "(%s): enslaved to non-master-type device %s; ignoring",
			             nm_device_get_iface (device),
			             nm_device_get_iface (master));
		} else {
			nm_log_warn (LOGD_DEVICE, "(%s): enslaved to unknown device %d %s",
			             nm_device_get_iface (device),
			             info->master,
			             nm_platform_link_get_name (info->master));
		}
	} else if (priv->enslaved && !info->master)
		nm_device_release_one_slave (priv->master, device, FALSE, NM_DEVICE_STATE_REASON_NONE);

	if (klass->link_changed)
		klass->link_changed (device, info);


	/* Update DHCP, etc, if needed */
	if (ip_ifname_changed)
		update_for_ip_ifname_change (device);
}

static void
device_ip_link_changed (NMDevice *device, NMPlatformLink *info)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if (info->name[0] && g_strcmp0 (priv->ip_iface, info->name)) {
		nm_log_info (LOGD_DEVICE, "(%s): interface index %d renamed ip_iface (%d) from '%s' to '%s'",
		             priv->iface, priv->ifindex, nm_device_get_ip_ifindex (device),
		             priv->ip_iface, info->name);
		g_free (priv->ip_iface);
		priv->ip_iface = g_strdup (info->name);

		g_object_notify (G_OBJECT (device), NM_DEVICE_IP_IFACE);
		update_for_ip_ifname_change (device);
	}
}

static void
link_changed_cb (NMPlatform *platform, int ifindex, NMPlatformLink *info, NMPlatformSignalChangeType change_type, NMPlatformReason reason, NMDevice *device)
{
	if (change_type != NM_PLATFORM_SIGNAL_CHANGED)
		return;

	/* We don't filter by 'reason' because we are interested in *all* link
	 * changes. For example a call to nm_platform_link_set_up() may result
	 * in an internal carrier change (i.e. we ask the kernel to set IFF_UP
	 * and it results in also setting IFF_LOWER_UP.
	 */

	if (ifindex == nm_device_get_ifindex (device))
		device_link_changed (device, info);
	else if (ifindex == nm_device_get_ip_ifindex (device))
		device_ip_link_changed (device, info);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	/* Update carrier from link event if applicable. */
	if (   device_has_capability (device, NM_DEVICE_CAP_CARRIER_DETECT)
	    && !device_has_capability (device, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
		nm_device_set_carrier (device, info->connected);
}

/**
 * nm_device_notify_component_added():
 * @device: the #NMDevice
 * @component: the component being added by a plugin
 *
 * Called by the manager to notify the device that a new component has
 * been found.  The device implementation should return %TRUE if it
 * wishes to claim the component, or %FALSE if it cannot.
 *
 * Returns: %TRUE to claim the component, %FALSE if the component cannot be
 * claimed.
 */
gboolean
nm_device_notify_component_added (NMDevice *device, GObject *component)
{
	if (NM_DEVICE_GET_CLASS (device)->component_added)
		return NM_DEVICE_GET_CLASS (device)->component_added (device, component);
	return FALSE;
}

/**
 * nm_device_owns_iface():
 * @device: the #NMDevice
 * @iface: an interface name
 *
 * Called by the manager to ask if the device or any of its components owns
 * @iface.  For example, a WWAN implementation would return %TRUE for an
 * ethernet interface name that was owned by the WWAN device's modem component,
 * because that ethernet interface is controlled by the WWAN device and cannot
 * be used independently of the WWAN device.
 *
 * Returns: %TRUE if @device or it's components owns the interface name,
 * %FALSE if not
 */
gboolean
nm_device_owns_iface (NMDevice *device, const char *iface)
{
	if (NM_DEVICE_GET_CLASS (device)->owns_iface)
		return NM_DEVICE_GET_CLASS (device)->owns_iface (device, iface);
	return FALSE;
}

static void
slave_state_changed (NMDevice *slave,
                     NMDeviceState slave_new_state,
                     NMDeviceState slave_old_state,
                     NMDeviceStateReason reason,
                     NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean release = FALSE;

	nm_log_dbg (LOGD_DEVICE, "(%s): slave %s state change %d (%s) -> %d (%s)",
	            nm_device_get_iface (self),
	            nm_device_get_iface (slave),
	            slave_old_state,
	            state_to_string (slave_old_state),
	            slave_new_state,
	            state_to_string (slave_new_state));

	/* Don't try to enslave slaves until the master is ready */
	if (priv->state < NM_DEVICE_STATE_CONFIG)
		return;

	if (slave_new_state == NM_DEVICE_STATE_IP_CONFIG)
		nm_device_enslave_slave (self, slave, nm_device_get_connection (slave));
	else if (slave_new_state > NM_DEVICE_STATE_ACTIVATED)
		release = TRUE;
	else if (   slave_new_state <= NM_DEVICE_STATE_DISCONNECTED
	         && slave_old_state > NM_DEVICE_STATE_DISCONNECTED) {
		/* Catch failures due to unavailable or unmanaged */
		release = TRUE;
	}

	if (release) {
		nm_device_release_one_slave (self, slave, TRUE, reason);
		/* Bridge/bond/team interfaces are left up until manually deactivated */
		if (priv->slaves == NULL && priv->state == NM_DEVICE_STATE_ACTIVATED) {
			nm_log_dbg (LOGD_DEVICE, "(%s): last slave removed; remaining activated",
			            nm_device_get_iface (self));
		}
	}
}

/**
 * nm_device_master_add_slave:
 * @dev: the master device
 * @slave: the slave device to enslave
 * @configure: pass %TRUE if the slave should be configured by the master, or
 * %FALSE if it is already configured outside NetworkManager
 *
 * If @dev is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function adds @slave to the slave list for later enslavement.
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
static gboolean
nm_device_master_add_slave (NMDevice *dev, NMDevice *slave, gboolean configure)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	SlaveInfo *info;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (dev)->enslave_slave != NULL, FALSE);

	if (configure)
		g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

	if (!find_slave_info (dev, slave)) {
		info = g_malloc0 (sizeof (SlaveInfo));
		info->slave = g_object_ref (slave);
		info->configure = configure;
		info->watch_id = g_signal_connect (slave, "state-changed",
		                                   G_CALLBACK (slave_state_changed), dev);
		priv->slaves = g_slist_append (priv->slaves, info);
	}

	return TRUE;
}


/**
 * nm_device_master_get_slaves:
 * @dev: the master device
 *
 * Returns: any slaves of which @device is the master.  Caller owns returned list.
 */
GSList *
nm_device_master_get_slaves (NMDevice *dev)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	GSList *slaves = NULL, *iter;

	for (iter = priv->slaves; iter; iter = g_slist_next (iter))
		slaves = g_slist_prepend (slaves, ((SlaveInfo *) iter->data)->slave);

	return slaves;
}

/**
 * nm_device_master_get_slave_by_ifindex:
 * @dev: the master device
 * @ifindex: the slave's interface index
 *
 * Returns: the slave with the given @ifindex of which @device is the master,
 *   or %NULL if no device with @ifindex is a slave of @device.
 */
NMDevice *
nm_device_master_get_slave_by_ifindex (NMDevice *dev, int ifindex)
{
	GSList *iter;

	for (iter = NM_DEVICE_GET_PRIVATE (dev)->slaves; iter; iter = g_slist_next (iter)) {
		SlaveInfo *info = iter->data;

		if (nm_device_get_ip_ifindex (info->slave) == ifindex)
			return info->slave;
	}
	return NULL;
}

/**
 * nm_device_master_check_slave_physical_port:
 * @dev: the master device
 * @slave: a slave device
 * @log_domain: domain to log a warning in
 *
 * Checks if @dev already has a slave with the same #NMDevice:physical-port-id
 * as @slave, and logs a warning if so.
 */
void
nm_device_master_check_slave_physical_port (NMDevice *dev, NMDevice *slave,
                                            guint64 log_domain)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	const char *slave_physical_port_id, *existing_physical_port_id;
	SlaveInfo *info;
	GSList *iter;

	slave_physical_port_id = nm_device_get_physical_port_id (slave);
	if (!slave_physical_port_id)
		return;

	for (iter = priv->slaves; iter; iter = iter->next) {
		info = iter->data;
		if (info->slave == slave)
			continue;

		existing_physical_port_id = nm_device_get_physical_port_id (info->slave);
		if (!g_strcmp0 (slave_physical_port_id, existing_physical_port_id)) {
			nm_log_warn (log_domain, "(%s): slave %s shares a physical port with existing slave %s",
			             nm_device_get_ip_iface (dev),
			             nm_device_get_ip_iface (slave),
			             nm_device_get_ip_iface (info->slave));
			/* Since this function will get called for every slave, we only have
			 * to warn about the first match we find; if there are other matches
			 * later in the list, we will have already warned about them matching
			 * @existing earlier.
			 */
			return;
		}
	}
}

/* release all slaves */
static void
nm_device_master_release_slaves (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason reason;

	/* Don't release the slaves if this connection doesn't belong to NM. */
	if (nm_device_uses_generated_connection (self))
		return;

	reason = priv->state_reason;
	if (priv->state == NM_DEVICE_STATE_FAILED)
		reason = NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED;

	while (priv->slaves) {
		SlaveInfo *info = priv->slaves->data;

		nm_device_release_one_slave (self, info->slave, TRUE, reason);
	}
}

/**
 * nm_device_get_master:
 * @dev: the device
 *
 * If @dev has been enslaved by another device, this returns that
 * device. Otherwise it returns %NULL. (In particular, note that if
 * @dev is in the process of activating as a slave, but has not yet
 * been enslaved by its master, this will return %NULL.)
 *
 * Returns: (transfer none): @dev's master, or %NULL
 */
NMDevice *
nm_device_get_master (NMDevice *dev)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);

	if (priv->enslaved)
		return priv->master;
	else
		return NULL;
}

/**
 * nm_device_slave_notify_enslave:
 * @dev: the slave device
 * @success: whether the enslaving operation succeeded
 *
 * Notifies a slave that either it has been enslaved, or else its master tried
 * to enslave it and failed.
 */
static void
nm_device_slave_notify_enslave (NMDevice *dev, gboolean success)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	NMConnection *connection = nm_device_get_connection (dev);
	gboolean activating = (priv->state == NM_DEVICE_STATE_IP_CONFIG);

	g_assert (priv->master);

	if (!priv->enslaved) {
		if (success) {
			if (activating) {
				nm_log_info (LOGD_DEVICE,
				             "Activation (%s) connection '%s' enslaved, continuing activation",
				             nm_device_get_iface (dev),
				             nm_connection_get_id (connection));
			} else {
				nm_log_info (LOGD_DEVICE,
				             "(%s): enslaved to %s",
				             nm_device_get_iface (dev),
				             nm_device_get_iface (priv->master));
			}

			priv->enslaved = TRUE;
			g_object_notify (G_OBJECT (dev), NM_DEVICE_MASTER);
		} else if (activating) {
			nm_log_warn (LOGD_DEVICE,
			             "Activation (%s) connection '%s' could not be enslaved",
			             nm_device_get_iface (dev),
			             nm_connection_get_id (connection));
		}
	}

	if (activating) {
		priv->ip4_state = IP_DONE;
		priv->ip6_state = IP_DONE;
		nm_device_queue_state (dev,
		                       success ? NM_DEVICE_STATE_SECONDARIES : NM_DEVICE_STATE_FAILED,
		                       NM_DEVICE_STATE_REASON_NONE);
	} else
		nm_device_queue_recheck_assume (dev);
}

/**
 * nm_device_slave_notify_release:
 * @dev: the slave device
 * @reason: the reason associated with the state change
 *
 * Notifies a slave that it has been released, and why.
 */
static void
nm_device_slave_notify_release (NMDevice *dev, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	NMConnection *connection = nm_device_get_connection (dev);
	NMDeviceState new_state;
	const char *master_status;

	if (   reason != NM_DEVICE_STATE_REASON_NONE
	    && priv->state > NM_DEVICE_STATE_DISCONNECTED
	    && priv->state <= NM_DEVICE_STATE_ACTIVATED) {
		if (reason == NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED) {
			new_state = NM_DEVICE_STATE_FAILED;
			master_status = "failed";
		} else if (reason == NM_DEVICE_STATE_REASON_USER_REQUESTED) {
			new_state = NM_DEVICE_STATE_DEACTIVATING;
			master_status = "deactivated by user request";
		} else {
			new_state = NM_DEVICE_STATE_DISCONNECTED;
			master_status = "deactivated";
		}

		nm_log_dbg (LOGD_DEVICE,
		            "Activation (%s) connection '%s' master %s",
		            nm_device_get_iface (dev),
		            nm_connection_get_id (connection),
		            master_status);

		nm_device_queue_state (dev, new_state, reason);
	} else {
		nm_log_info (LOGD_DEVICE,
		             "(%s): released from master %s",
		             nm_device_get_iface (dev),
		             nm_device_get_iface (priv->master));
	}

	if (priv->enslaved) {
		priv->enslaved = FALSE;
		g_object_notify (G_OBJECT (dev), NM_DEVICE_MASTER);
	}
}

/**
 * nm_device_get_enslaved:
 * @device: the #NMDevice
 *
 * Returns: %TRUE if the device is enslaved to a master device (eg bridge or
 * bond or team), %FALSE if not
 */
gboolean
nm_device_get_enslaved (NMDevice *device)
{
	return NM_DEVICE_GET_PRIVATE (device)->enslaved;
}

static gboolean
is_available (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	return priv->carrier || priv->ignore_carrier;
}

/**
 * nm_device_is_available:
 * @self: the #NMDevice
 *
 * Checks if @self would currently be capable of activating a
 * connection. In particular, it checks that the device is ready (eg,
 * is not missing firmware), that it has carrier (if necessary), and
 * that any necessary external software (eg, ModemManager,
 * wpa_supplicant) is available.
 *
 * @self can only be in a state higher than
 * %NM_DEVICE_STATE_UNAVAILABLE when nm_device_is_available() returns
 * %TRUE. (But note that it can still be %NM_DEVICE_STATE_UNMANAGED
 * when it is available.)
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
nm_device_is_available (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->firmware_missing)
		return FALSE;

	return NM_DEVICE_GET_CLASS (self)->is_available (self);
}

gboolean
nm_device_get_enabled (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (NM_DEVICE_GET_CLASS (self)->get_enabled)
		return NM_DEVICE_GET_CLASS (self)->get_enabled (self);
	return TRUE;
}

void
nm_device_set_enabled (NMDevice *self, gboolean enabled)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	if (NM_DEVICE_GET_CLASS (self)->set_enabled)
		NM_DEVICE_GET_CLASS (self)->set_enabled (self, enabled);
}

gboolean
nm_device_get_autoconnect (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return NM_DEVICE_GET_PRIVATE (device)->autoconnect;
}

static gboolean
autoconnect_allowed_accumulator (GSignalInvocationHint *ihint,
                                 GValue *return_accu,
                                 const GValue *handler_return, gpointer data)
{
	if (!g_value_get_boolean (handler_return))
		g_value_set_boolean (return_accu, FALSE);
	return TRUE;
}

gboolean
nm_device_autoconnect_allowed (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GValue instance = G_VALUE_INIT;
	GValue retval = G_VALUE_INIT;

	g_value_init (&instance, G_TYPE_OBJECT);
	g_value_set_object (&instance, self);

	g_value_init (&retval, G_TYPE_BOOLEAN);
	if (priv->autoconnect)
		g_value_set_boolean (&retval, TRUE);
	else
		g_value_set_boolean (&retval, FALSE);

	/* Use g_signal_emitv() rather than g_signal_emit() to avoid the return
	 * value being changed if no handlers are connected */
	g_signal_emitv (&instance, signals[AUTOCONNECT_ALLOWED], 0, &retval);
	g_value_unset (&instance);
	return g_value_get_boolean (&retval);
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMConnection *connection,
                  char **specific_object)
{
	NMSettingConnection *s_con;

	s_con = nm_connection_get_setting_connection (connection);
	if (!nm_setting_connection_get_autoconnect (s_con))
		return FALSE;

	return nm_device_connection_is_available (device, connection, FALSE);
}

static gboolean
device_has_config (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	/* Check for IP configuration. */
	if (priv->ip4_config && nm_ip4_config_get_num_addresses (priv->ip4_config))
		return TRUE;
	if (priv->ip6_config && nm_ip6_config_get_num_addresses (priv->ip6_config))
		return TRUE;

	/* The existence of a software device is good enough. */
	if (nm_device_is_software (device))
		return TRUE;

	/* Slaves are also configured by definition */
	if (nm_platform_link_get_master (priv->ifindex) > 0)
		return TRUE;

	return FALSE;
}

NMConnection *
nm_device_generate_connection (NMDevice *device)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (device);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	const char *ifname = nm_device_get_iface (device);
	int ifindex = nm_device_get_ifindex (device);
	NMConnection *connection;
	NMSetting *s_con;
	NMSetting *s_ip4;
	NMSetting *s_ip6;
	gs_free char *uuid = NULL;
	gs_free char *name = NULL;
	int master_ifindex = 0;
	const char *ip4_method, *ip6_method;
	GError *error = NULL;

	/* If update_connection() is not implemented, just fail. */
	if (!klass->update_connection)
		return NULL;

	/* Return NULL if device is unconfigured. */
	if (!device_has_config (device)) {
		nm_log_dbg (LOGD_DEVICE, "(%s): device has no existing configuration", ifname);
		return NULL;
	}

	if (ifindex)
		master_ifindex = nm_platform_link_get_master (ifindex);
	if (master_ifindex) {
		NMDevice *master;

		master = nm_manager_get_device_by_ifindex (nm_manager_get (), master_ifindex);
		if (!master || !nm_device_get_act_request (master)) {
			nm_log_dbg (LOGD_DEVICE, "(%s): cannot generate connection for slave before its master (%s)",
			            ifname, nm_platform_link_get_name (master_ifindex));
			return NULL;
		}
	}

	connection = nm_connection_new ();
	s_con = nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	name = g_strdup_printf ("%s", ifname);

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, name,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, ifname,
	              NM_SETTING_CONNECTION_TIMESTAMP, (guint64) time (NULL),
	              NULL);
	if (klass->connection_type)
		g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, klass->connection_type, NULL);
	nm_connection_add_setting (connection, s_con);

	/* If the device is a slave, update various slave settings */
	if (master_ifindex) {
		const char *master_iface = nm_platform_link_get_name (master_ifindex);
		const char *slave_type = NULL;
		gboolean success = FALSE;

		switch (nm_platform_link_get_type (master_ifindex)) {
		case NM_LINK_TYPE_BRIDGE:
			slave_type = NM_SETTING_BRIDGE_SETTING_NAME;
			success = nm_bridge_update_slave_connection (device, connection);
			break;
		case NM_LINK_TYPE_BOND:
			slave_type = NM_SETTING_BOND_SETTING_NAME;
			success = TRUE;
			break;
		case NM_LINK_TYPE_TEAM:
			slave_type = NM_SETTING_TEAM_SETTING_NAME;
			success = nm_team_update_slave_connection (device, connection);
			break;
		default:
			g_warn_if_reached ();
			break;
		}

		if (!success)
			nm_log_err (LOGD_DEVICE, "(%s): failed to read slave configuration", ifname);

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, master_iface,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, slave_type,
		              NULL);
	} else {
		/* Only regular and master devices get IP configuration; slaves do not */
		s_ip4 = nm_ip4_config_create_setting (priv->ip4_config);
		nm_connection_add_setting (connection, s_ip4);

		s_ip6 = nm_ip6_config_create_setting (priv->ip6_config);
		nm_connection_add_setting (connection, s_ip6);
	}

	klass->update_connection (device, connection);

	/* Check the connection in case of update_connection() bug. */
	if (!nm_connection_verify (connection, &error)) {
		nm_log_err (LOGD_DEVICE, "(%s): Generated connection does not verify: %s",
		            nm_device_get_iface (device), error->message);
		g_clear_error (&error);
		g_object_unref (connection);
		return NULL;
	}

	/* Ignore the connection if it has no IP configuration,
	 * no slave configuration, and is not a master interface.
	 */
	ip4_method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ip6_method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (   g_strcmp0 (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0
	    && g_strcmp0 (ip6_method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0
	    && !nm_setting_connection_get_master (NM_SETTING_CONNECTION (s_con))) {
		nm_log_dbg (LOGD_DEVICE, "(%s): ignoring generated connection (no IP and not slave)", ifname);
		g_object_unref (connection);
		connection = NULL;
	}

	return connection;
}

/**
 * nm_device_get_best_auto_connection:
 * @dev: an #NMDevice
 * @connections: (element-type #NMConnection): a list of connections
 * @specific_object: (out) (transfer full): on output, the path of an
 *   object associated with the returned connection, to be passed to
 *   nm_manager_activate_connection(), or %NULL.
 *
 * Looks through @connections to see if there is a connection that can
 * be auto-activated on @dev right now. This requires, at a minimum,
 * that the connection be compatible with @dev, and that it have the
 * #NMSettingConnection:autoconnect property set. Some devices impose
 * additional requirements. (Eg, a Wi-Fi connection can only be
 * activated if its SSID was seen in the last scan.)
 *
 * Returns: an auto-activatable #NMConnection, or %NULL if none are
 * available.
 */

NMConnection *
nm_device_get_best_auto_connection (NMDevice *dev,
                                    GSList *connections,
                                    char **specific_object)
{
	GSList *iter;

	g_return_val_if_fail (NM_IS_DEVICE (dev), NULL);
	g_return_val_if_fail (specific_object != NULL, NULL);
	g_return_val_if_fail (*specific_object == NULL, NULL);

	for (iter = connections; iter; iter = iter->next) {
		NMConnection *connection = NM_CONNECTION (iter->data);

		if (NM_DEVICE_GET_CLASS (dev)->can_auto_connect (dev, connection, specific_object))
			return connection;
	}

	return NULL;
}

gboolean
nm_device_complete_connection (NMDevice *self,
                               NMConnection *connection,
                               const char *specific_object,
                               const GSList *existing_connections,
                               GError **error)
{
	gboolean success = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	if (!NM_DEVICE_GET_CLASS (self)->complete_connection) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CONNECTION_INVALID,
		             "Device class %s had no complete_connection method",
		             G_OBJECT_TYPE_NAME (self));
		return FALSE;
	}

	success = NM_DEVICE_GET_CLASS (self)->complete_connection (self,
	                                                           connection,
	                                                           specific_object,
	                                                           existing_connections,
	                                                           error);
	if (success)
		success = nm_connection_verify (connection, error);

	return success;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *config_iface, *device_iface;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	config_iface = nm_setting_connection_get_interface_name (s_con);
	device_iface = nm_device_get_iface (device);
	if (config_iface && strcmp (config_iface, device_iface) != 0)
		return FALSE;

	return TRUE;
}

/**
 * nm_device_check_connection_compatible:
 * @device: an #NMDevice
 * @connection: an #NMConnection
 *
 * Checks if @connection could potentially be activated on @device.
 * This means only that @device has the proper capabilities, and that
 * @connection is not locked to some other device. It does not
 * necessarily mean that @connection could be activated on @device
 * right now. (Eg, it might refer to a Wi-Fi network that is not
 * currently available.)
 *
 * Returns: #TRUE if @connection could potentially be activated on
 *   @device.
 */
gboolean
nm_device_check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	return NM_DEVICE_GET_CLASS (device)->check_connection_compatible (device, connection);
}

static gboolean
string_in_list (const char *str, const char **array, gsize array_len)
{
	gsize i;

	for (i = 0; i < array_len; i++) {
		if (strcmp (str, array[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

/**
 * nm_device_can_assume_connections:
 * @device: #NMDevice instance
 *
 * This is a convenience function to determine whether connection assumption
 * is available for this device.
 *
 * Returns: %TRUE if the device is capable of assuming connections, %FALSE if not
 */
static gboolean
nm_device_can_assume_connections (NMDevice *device)
{
	return !!NM_DEVICE_GET_CLASS (device)->update_connection;
}

/**
 * nm_device_can_assume_active_connection:
 * @device: #NMDevice instance
 *
 * This is a convenience function to determine whether the device's active
 * connection can be assumed if NetworkManager restarts.  This method returns
 * %TRUE if and only if the device can assume connections, and the device has
 * an active connection, and that active connection can be assumed.
 *
 * Returns: %TRUE if the device's active connection can be assumed, or %FALSE
 * if there is no active connection or the active connection cannot be
 * assumed.
 */
gboolean
nm_device_can_assume_active_connection (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMConnection *connection;
	const char *method;
	const char *assumable_ip6_methods[] = {
		NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		NM_SETTING_IP6_CONFIG_METHOD_DHCP,
		NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
		NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	};
	const char *assumable_ip4_methods[] = {
		NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
		NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	};

	if (!nm_device_can_assume_connections (device))
		return FALSE;

	connection = nm_device_get_connection (device);
	if (!connection)
		return FALSE;

	/* Can't assume connections that aren't yet configured
	 * FIXME: what about bridges/bonds waiting for slaves?
	 */
	if (priv->state < NM_DEVICE_STATE_IP_CONFIG)
		return FALSE;
	if (priv->ip4_state != IP_DONE && priv->ip6_state != IP_DONE)
		return FALSE;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (!string_in_list (method, assumable_ip6_methods, G_N_ELEMENTS (assumable_ip6_methods)))
		return FALSE;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (!string_in_list (method, assumable_ip4_methods, G_N_ELEMENTS (assumable_ip4_methods)))
		return FALSE;

	return TRUE;
}

static gboolean
nm_device_emit_recheck_assume (gpointer self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->recheck_assume_id = 0;
	if (!nm_device_get_act_request (self) && (priv->ip4_config || priv->ip6_config))
		g_signal_emit (self, signals[RECHECK_ASSUME], 0);
	return G_SOURCE_REMOVE;
}

void
nm_device_queue_recheck_assume (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (nm_device_can_assume_connections (self) && !priv->recheck_assume_id)
		priv->recheck_assume_id = g_idle_add (nm_device_emit_recheck_assume, self);
}

void
nm_device_emit_recheck_auto_activate (NMDevice *self)
{
	g_signal_emit (self, signals[RECHECK_AUTO_ACTIVATE], 0);
}

static void
dnsmasq_state_changed_cb (NMDnsMasqManager *manager, guint32 status, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	switch (status) {
	case NM_DNSMASQ_STATUS_DEAD:
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
		break;
	default:
		break;
	}
}

static void
activation_source_clear (NMDevice *self, gboolean remove_source, int family)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint *act_source_id;
	gpointer *act_source_func;

	if (family == AF_INET6) {
		act_source_id = &priv->act_source6_id;
		act_source_func = &priv->act_source6_func;
	} else {
		act_source_id = &priv->act_source_id;
		act_source_func = &priv->act_source_func;
	}

	if (*act_source_id) {
		if (remove_source)
			g_source_remove (*act_source_id);
		*act_source_id = 0;
		*act_source_func = NULL;
	}
}

static void
activation_source_schedule (NMDevice *self, GSourceFunc func, int family)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint *act_source_id;
	gpointer *act_source_func;

	if (family == AF_INET6) {
		act_source_id = &priv->act_source6_id;
		act_source_func = &priv->act_source6_func;
	} else {
		act_source_id = &priv->act_source_id;
		act_source_func = &priv->act_source_func;
	}

	if (*act_source_id) {
		nm_log_err (LOGD_DEVICE, "activation stage already scheduled");
	}

	/* Don't bother rescheduling the same function that's about to
	 * run anyway.  Fixes issues with crappy wireless drivers sending
	 * streams of associate events before NM has had a chance to process
	 * the first one.
	 */
	if (!*act_source_id || (*act_source_func != func)) {
		activation_source_clear (self, TRUE, family);
		*act_source_id = g_idle_add (func, self);
		*act_source_func = func;
	}
}

gboolean
nm_device_ip_config_should_fail (NMDevice *self, gboolean ip6)
{
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;

	g_return_val_if_fail (self != NULL, TRUE);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* Fail the connection if the failed IP method is required to complete */
	if (ip6) {
		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (!nm_setting_ip6_config_get_may_fail (s_ip6))
			return TRUE;
	} else {
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (!nm_setting_ip4_config_get_may_fail (s_ip4))
			return TRUE;
	}

	return FALSE;
}

static void
master_ready_cb (NMActiveConnection *active,
                 GParamSpec *pspec,
                 NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActiveConnection *master;

	g_assert (priv->state == NM_DEVICE_STATE_PREPARE);

	/* Notify a master device that it has a new slave */
	g_assert (nm_active_connection_get_master_ready (active));
	master = nm_active_connection_get_master (active);

	priv->master = g_object_ref (nm_active_connection_get_device (master));
	nm_device_master_add_slave (priv->master,
	                            self,
	                            nm_active_connection_get_assumed (active) ? FALSE : TRUE);

	nm_log_dbg (LOGD_DEVICE, "(%s): master connection ready; master device %s",
	            nm_device_get_iface (self),
	            nm_device_get_iface (priv->master));

	if (priv->master_ready_id) {
		g_signal_handler_disconnect (active, priv->master_ready_id);
		priv->master_ready_id = 0;
	}

	nm_device_activate_schedule_stage2_device_config (self);
}

static NMActStageReturn
act_stage1_prepare (NMDevice *self, NMDeviceStateReason *reason)
{
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*
 * nm_device_activate_stage1_device_prepare
 *
 * Prepare for device activation
 *
 */
static gboolean
nm_device_activate_stage1_device_prepare (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMActiveConnection *active = NM_ACTIVE_CONNECTION (priv->act_request);

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	priv->ip4_state = priv->ip6_state = IP_NONE;

	/* Notify the new ActiveConnection along with the state change */
	g_object_notify (G_OBJECT (self), NM_DEVICE_ACTIVE_CONNECTION);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 1 of 5 (Device Prepare) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE, NM_DEVICE_STATE_REASON_NONE);

	/* Assumed connections were already set up outside NetworkManager */
	if (!nm_active_connection_get_assumed (active)) {
		ret = NM_DEVICE_GET_CLASS (self)->act_stage1_prepare (self, &reason);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
			goto out;
		} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
			goto out;
		}
		g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);
	}

	if (nm_active_connection_get_master (active)) {
		/* If the master connection is ready for slaves, attach ourselves */
		if (nm_active_connection_get_master_ready (active))
			master_ready_cb (active, NULL, self);
		else {
			nm_log_dbg (LOGD_DEVICE, "(%s): waiting for master connection to become ready",
			            nm_device_get_iface (self));

			/* Attach a signal handler and wait for the master connection to begin activating */
			g_assert (priv->master_ready_id == 0);
			priv->master_ready_id = g_signal_connect (active,
			                                          "notify::" NM_ACTIVE_CONNECTION_INT_MASTER_READY,
			                                          (GCallback) master_ready_cb,
			                                          self);
			/* Postpone */
		}
	} else
		nm_device_activate_schedule_stage2_device_config (self);

out:
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 1 of 5 (Device Prepare) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage1_device_prepare
 *
 * Prepare a device for activation
 *
 */
void
nm_device_activate_schedule_stage1_device_prepare (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_stage1_device_prepare, 0);

	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 1 of 5 (Device Prepare) scheduled...",
	             nm_device_get_iface (self));
}

static NMActStageReturn
act_stage2_config (NMDevice *dev, NMDeviceStateReason *reason)
{
	/* Nothing to do */
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*
 * nm_device_activate_stage2_device_config
 *
 * Determine device parameters and set those on the device, ie
 * for wireless devices, set SSID, keys, etc.
 *
 */
static gboolean
nm_device_activate_stage2_device_config (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface;
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	gboolean no_firmware = FALSE;
	NMActiveConnection *active = NM_ACTIVE_CONNECTION (priv->act_request);
	GSList *iter;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 2 of 5 (Device Configure) starting...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	/* Assumed connections were already set up outside NetworkManager */
	if (!nm_active_connection_get_assumed (active)) {
		if (!nm_device_bring_up (self, FALSE, &no_firmware)) {
			if (no_firmware)
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_FIRMWARE_MISSING);
			else
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
			goto out;
		}

		ret = NM_DEVICE_GET_CLASS (self)->act_stage2_config (self, &reason);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
			goto out;
		else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
			goto out;
		}
		g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);
	}

	/* If we have slaves that aren't yet enslaved, do that now */
	for (iter = priv->slaves; iter; iter = g_slist_next (iter)) {
		SlaveInfo *info = iter->data;
		NMDeviceState slave_state = nm_device_get_state (info->slave);

		if (slave_state == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_enslave_slave (self, info->slave, nm_device_get_connection (info->slave));
		else if (   nm_device_uses_generated_connection (self)
		         && slave_state <= NM_DEVICE_STATE_DISCONNECTED)
			nm_device_queue_recheck_assume (info->slave);
	}

	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 2 of 5 (Device Configure) successful.", iface);

	nm_device_activate_schedule_stage3_ip_config_start (self);

out:
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 2 of 5 (Device Configure) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage2_device_config
 *
 * Schedule setup of the hardware device
 *
 */
void
nm_device_activate_schedule_stage2_device_config (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_stage2_device_config, 0);

	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 2 of 5 (Device Configure) scheduled...",
	         nm_device_get_iface (self));
}

/*********************************************/
/* avahi-autoipd stuff */

static void
aipd_timeout_remove (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->aipd_timeout) {
		g_source_remove (priv->aipd_timeout);
		priv->aipd_timeout = 0;
	}
}

static void
aipd_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->aipd_watch) {
		g_source_remove (priv->aipd_watch);
		priv->aipd_watch = 0;
	}

	if (priv->aipd_pid > 0) {
		kill (priv->aipd_pid, SIGKILL);

		/* ensure the child is reaped */
		nm_log_dbg (LOGD_AUTOIP4, "waiting for avahi-autoipd pid %d to exit", priv->aipd_pid);
		waitpid (priv->aipd_pid, NULL, 0);
		nm_log_dbg (LOGD_AUTOIP4, "avahi-autoip pid %d cleaned up", priv->aipd_pid);

		priv->aipd_pid = -1;
	}

	aipd_timeout_remove (self);
}

static NMIP4Config *
aipd_get_ip4_config (NMDevice *self, guint32 lla)
{
	NMIP4Config *config = NULL;
	NMPlatformIP4Address address;
	NMPlatformIP4Route route;

	config = nm_ip4_config_new ();
	g_assert (config);

	memset (&address, 0, sizeof (address));
	address.address = lla;
	address.plen = 16;
	address.source = NM_PLATFORM_SOURCE_IP4LL;
	nm_ip4_config_add_address (config, &address);

	/* Add a multicast route for link-local connections: destination= 224.0.0.0, netmask=240.0.0.0 */
	memset (&route, 0, sizeof (route));
	route.network = htonl (0xE0000000L);
	route.plen = 4;
	route.source = NM_PLATFORM_SOURCE_IP4LL;
	route.metric = nm_device_get_priority (self);
	nm_ip4_config_add_route (config, &route);

	return config;
}

#define IPV4LL_NETWORK (htonl (0xA9FE0000L))
#define IPV4LL_NETMASK (htonl (0xFFFF0000L))

void
nm_device_handle_autoip4_event (NMDevice *self,
                                const char *event,
                                const char *address)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection = NULL;
	const char *iface, *method;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	g_return_if_fail (event != NULL);

	if (priv->act_request == NULL)
		return;

	connection = nm_act_request_get_connection (priv->act_request);
	g_assert (connection);

	/* Ignore if the connection isn't an AutoIP connection */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL) != 0)
		return;

	iface = nm_device_get_iface (self);

	if (strcmp (event, "BIND") == 0) {
		guint32 lla;
		NMIP4Config *config;

		if (inet_pton (AF_INET, address, &lla) <= 0) {
			nm_log_err (LOGD_AUTOIP4, "(%s): invalid address %s received from avahi-autoipd.",
			            iface, address);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_AUTOIP_ERROR);
			return;
		}

		if ((lla & IPV4LL_NETMASK) != IPV4LL_NETWORK) {
			nm_log_err (LOGD_AUTOIP4, "(%s): invalid address %s received from avahi-autoipd (not link-local).",
			            iface, address);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_AUTOIP_ERROR);
			return;
		}

		config = aipd_get_ip4_config (self, lla);
		if (config == NULL) {
			nm_log_err (LOGD_AUTOIP4, "failed to get autoip config");
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
			return;
		}

		if (priv->ip4_state == IP_CONF) {
			aipd_timeout_remove (self);
			nm_device_activate_schedule_ip4_config_result (self, config);
		} else if (priv->ip4_state == IP_DONE) {
			if (!ip4_config_merge_and_apply (self, config, TRUE, &reason)) {
				nm_log_err (LOGD_AUTOIP4, "(%s): failed to update IP4 config for autoip change.",
							nm_device_get_iface (self));
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
			}
		} else
			g_assert_not_reached ();

		g_object_unref (config);
	} else {
		nm_log_warn (LOGD_AUTOIP4, "(%s): autoip address %s no longer valid because '%s'.",
		            iface, address, event);

		/* The address is gone; terminate the connection or fail activation */
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
	}
}

static void
aipd_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState state;
	const char *iface;

	if (!priv->aipd_watch)
		return;
	priv->aipd_watch = 0;

	iface = nm_device_get_iface (self);

	if (WIFEXITED (status)) {
		nm_log_dbg (LOGD_AUTOIP4, "(%s): avahi-autoipd exited with error code %d",
		            iface, WEXITSTATUS (status));
	} else if (WIFSTOPPED (status)) {
		nm_log_warn (LOGD_AUTOIP4, "(%s): avahi-autoipd stopped unexpectedly with signal %d",
		            iface, WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_warn (LOGD_AUTOIP4, "(%s): avahi-autoipd died with signal %d",
		             iface, WTERMSIG (status));
	} else {
		nm_log_warn (LOGD_AUTOIP4, "(%s): avahi-autoipd died from an unknown cause", iface);
	}

	aipd_cleanup (self);

	state = nm_device_get_state (self);
	if (nm_device_is_activating (self) || (state == NM_DEVICE_STATE_ACTIVATED))
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_AUTOIP_FAILED);
}

static gboolean
aipd_timeout_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->aipd_timeout) {
		nm_log_info (LOGD_AUTOIP4, "(%s): avahi-autoipd timed out.", nm_device_get_iface (self));
		priv->aipd_timeout = 0;
		aipd_cleanup (self);

		if (priv->ip4_state == IP_CONF)
			nm_device_activate_schedule_ip4_config_timeout (self);
	}

	return FALSE;
}

static void
aipd_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point.
	 * Give child it's own program group for signal
	 * separation.
	 */
	pid_t pid = getpid ();
	setpgid (pid, pid);

	/*
	 * We blocked signals in main(). We need to restore original signal
	 * mask for avahi-autoipd here so that it can receive signals.
	 */
	nm_unblock_posix_signals (NULL);
}

/* default to installed helper, but can be modified for testing */
const char *nm_device_autoipd_helper_path = LIBEXECDIR "/nm-avahi-autoipd.action";

static NMActStageReturn
aipd_start (NMDevice *self, NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface = nm_device_get_iface (self);
	char *argv[6], *cmdline;
	const char **aipd_binary = NULL;
	static const char *aipd_paths[] = {
		"/usr/sbin/avahi-autoipd",
		"/usr/local/sbin/avahi-autoipd",
		NULL
	};
	int i = 0;
	GError *error = NULL;

	aipd_cleanup (self);

	/* Find avahi-autoipd */
	aipd_binary = aipd_paths;
	while (*aipd_binary != NULL) {
		if (g_file_test (*aipd_binary, G_FILE_TEST_EXISTS))
			break;
		aipd_binary++;
	}

	if (!*aipd_binary) {
		nm_log_warn (LOGD_DEVICE | LOGD_AUTOIP4,
		             "Activation (%s) Stage 3 of 5 (IP Configure Start) failed"
		             " to start avahi-autoipd: not found", iface);
		*reason = NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	argv[i++] = (char *) (*aipd_binary);
	argv[i++] = "--script";
	argv[i++] = (char *) nm_device_autoipd_helper_path;

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_AUTOIP4))
		argv[i++] = "--debug";
	argv[i++] = (char *) nm_device_get_ip_iface (self);
	argv[i++] = NULL;

	cmdline = g_strjoinv (" ", argv);
	nm_log_dbg (LOGD_AUTOIP4, "running: %s", cmdline);
	g_free (cmdline);

	if (!g_spawn_async ("/", argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                    &aipd_child_setup, NULL, &(priv->aipd_pid), &error)) {
		nm_log_warn (LOGD_DEVICE | LOGD_AUTOIP4,
		             "Activation (%s) Stage 3 of 5 (IP Configure Start) failed"
		             " to start avahi-autoipd: %s",
		             iface,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		aipd_cleanup (self);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	nm_log_info (LOGD_DEVICE | LOGD_AUTOIP4,
	             "Activation (%s) Stage 3 of 5 (IP Configure Start) started"
	             " avahi-autoipd...", iface);

	/* Monitor the child process so we know when it dies */
	priv->aipd_watch = g_child_watch_add (priv->aipd_pid, aipd_watch_cb, self);

	/* Start a timeout to bound the address attempt */
	priv->aipd_timeout = g_timeout_add_seconds (20, aipd_timeout_cb, self);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*********************************************/
/* DHCPv4 stuff */

static void
dhcp4_cleanup (NMDevice *self, gboolean stop, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dhcp4_client) {
		/* Stop any ongoing DHCP transaction on this device */
		if (priv->dhcp4_state_sigid) {
			g_signal_handler_disconnect (priv->dhcp4_client, priv->dhcp4_state_sigid);
			priv->dhcp4_state_sigid = 0;
		}

		if (priv->dhcp4_timeout_sigid) {
			g_signal_handler_disconnect (priv->dhcp4_client, priv->dhcp4_timeout_sigid);
			priv->dhcp4_timeout_sigid = 0;
		}

		nm_device_remove_pending_action (self, PENDING_ACTION_DHCP4, FALSE);

		if (stop)
			nm_dhcp_client_stop (priv->dhcp4_client, release);

		g_clear_object (&priv->dhcp4_client);
	}

	if (priv->dhcp4_config) {
		g_clear_object (&priv->dhcp4_config);
		g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP4_CONFIG);
	}
}

static void
dhcp4_add_option_cb (gpointer key, gpointer value, gpointer user_data)
{
	nm_dhcp4_config_add_option (NM_DHCP4_CONFIG (user_data),
	                            (const char *) key,
	                            (const char *) value);
}

static gboolean
ip4_config_merge_and_apply (NMDevice *self,
                            NMIP4Config *config,
                            gboolean commit,
                            NMDeviceStateReason *out_reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	gboolean success;
	NMIP4Config *composite;

	/* Merge all the configs into the composite config */
	if (config) {
		g_clear_object (&priv->dev_ip4_config);
		priv->dev_ip4_config = g_object_ref (config);
	}

	composite = nm_ip4_config_new ();
	if (priv->dev_ip4_config)
		nm_ip4_config_merge (composite, priv->dev_ip4_config);
	if (priv->vpn4_config)
		nm_ip4_config_merge (composite, priv->vpn4_config);
	if (priv->ext_ip4_config)
		nm_ip4_config_merge (composite, priv->ext_ip4_config);

	/* Merge user overrides into the composite config */
	connection = nm_device_get_connection (self);
	if (connection) {
		nm_ip4_config_merge_setting (composite,
		                             nm_connection_get_setting_ip4_config (connection),
		                             nm_device_get_priority (self));
	}

	/* Allow setting MTU etc */
	if (commit) {
		if (NM_DEVICE_GET_CLASS (self)->ip4_config_pre_commit)
			NM_DEVICE_GET_CLASS (self)->ip4_config_pre_commit (self, composite);
	}

	success = nm_device_set_ip4_config (self, composite, commit, out_reason);
	g_object_unref (composite);
	return success;
}

static void
dhcp4_lease_change (NMDevice *self, NMIP4Config *config)
{
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	g_return_if_fail (config != NULL);

	if (!ip4_config_merge_and_apply (self, config, TRUE, &reason)) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to update IPv4 config for DHCP change.",
		             nm_device_get_ip_iface (self));
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
	} else {
		/* Notify dispatcher scripts of new DHCP4 config */
		nm_dispatcher_call (DISPATCHER_ACTION_DHCP4_CHANGE,
		                    nm_device_get_connection (self),
		                    self,
		                    NULL,
		                    NULL,
		                    NULL);
	}
}

static void
dhcp4_fail (NMDevice *device, gboolean timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	nm_dhcp4_config_reset (priv->dhcp4_config);

	if (timeout || (priv->ip4_state == IP_CONF))
		nm_device_activate_schedule_ip4_config_timeout (device);
	else if (priv->ip4_state == IP_FAIL)
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
}

static void
dhcp4_state_changed (NMDHCPClient *client,
                     NMDHCPState state,
                     gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMIP4Config *config;

	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == FALSE);

	nm_log_dbg (LOGD_DHCP4, "(%s): new DHCPv4 client state %d",
	            nm_device_get_iface (device), state);

	switch (state) {
	case DHC_BOUND4:     /* lease obtained */
	case DHC_RENEW4:     /* lease renewed */
	case DHC_REBOOT:     /* have valid lease, but now obtained a different one */
	case DHC_REBIND4:    /* new, different lease */
		config = nm_dhcp_client_get_ip4_config (priv->dhcp4_client, FALSE);
		if (!config) {
			nm_log_warn (LOGD_DHCP4, "(%s): failed to get IPv4 config in response to DHCP event.",
					     nm_device_get_ip_iface (device));
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
			break;
		}

		/* Update the DHCP4 config object with new DHCP options */
		nm_dhcp4_config_reset (priv->dhcp4_config);
		nm_dhcp_client_foreach_option (priv->dhcp4_client,
			                           dhcp4_add_option_cb,
			                           priv->dhcp4_config);
		g_object_notify (G_OBJECT (device), NM_DEVICE_DHCP4_CONFIG);

		if (priv->ip4_state == IP_CONF)
			nm_device_activate_schedule_ip4_config_result (device, config);
		else if (priv->ip4_state == IP_DONE)
			dhcp4_lease_change (device, config);
		g_object_unref (config);

		break;
	case DHC_TIMEOUT: /* timed out contacting DHCP server */
		dhcp4_fail (device, TRUE);
		break;
	case DHC_END: /* dhclient exited normally */
	case DHC_FAIL: /* all attempts to contact server timed out, sleeping */
	case DHC_ABEND: /* dhclient exited abnormally */
		/* dhclient quit and can't get/renew a lease; so kill the connection */
		dhcp4_fail (device, FALSE);
		break;
	default:
		break;
	}
}

static void
dhcp4_timeout (NMDHCPClient *client, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	g_return_if_fail (nm_device_get_act_request (device) != NULL);
	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == FALSE);

	nm_dhcp_client_stop (client, FALSE);
	dhcp4_fail (device, TRUE);
}

static NMActStageReturn
dhcp4_start (NMDevice *self,
             NMConnection *connection,
             NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingIP4Config *s_ip4;
	GByteArray *tmp = NULL;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);

	/* Clear old exported DHCP options */
	if (priv->dhcp4_config)
		g_object_unref (priv->dhcp4_config);
	priv->dhcp4_config = nm_dhcp4_config_new ();

	if (priv->hw_addr_len) {
		tmp = g_byte_array_sized_new (priv->hw_addr_len);
		g_byte_array_append (tmp, priv->hw_addr, priv->hw_addr_len);
	}

	/* Begin DHCP on the interface */
	g_warn_if_fail (priv->dhcp4_client == NULL);
	priv->dhcp4_client = nm_dhcp_manager_start_ip4 (nm_dhcp_manager_get (),
	                                                nm_device_get_ip_iface (self),
	                                                tmp,
	                                                nm_connection_get_uuid (connection),
	                                                nm_device_get_priority (self),
	                                                s_ip4,
	                                                priv->dhcp_timeout,
	                                                priv->dhcp_anycast_address);

	if (tmp)
		g_byte_array_free (tmp, TRUE);

	if (!priv->dhcp4_client) {
		*reason = NM_DEVICE_STATE_REASON_DHCP_START_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	priv->dhcp4_state_sigid = g_signal_connect (priv->dhcp4_client,
	                                            NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
	                                            G_CALLBACK (dhcp4_state_changed),
	                                            self);
	priv->dhcp4_timeout_sigid = g_signal_connect (priv->dhcp4_client,
	                                              NM_DHCP_CLIENT_SIGNAL_TIMEOUT,
	                                              G_CALLBACK (dhcp4_timeout),
	                                              self);

	nm_device_add_pending_action (self, PENDING_ACTION_DHCP4, TRUE);

	/* DHCP devices will be notified by the DHCP manager when stuff happens */
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

gboolean
nm_device_dhcp4_renew (NMDevice *self, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMDeviceStateReason reason;
	NMConnection *connection;

	g_return_val_if_fail (priv->dhcp4_client != NULL, FALSE);

	nm_log_info (LOGD_DHCP4, "(%s): DHCPv4 lease renewal requested",
	             nm_device_get_iface (self));

	/* Terminate old DHCP instance and release the old lease */
	dhcp4_cleanup (self, TRUE, release);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* Start DHCP again on the interface */
	ret = dhcp4_start (self, connection, &reason);

	return (ret != NM_ACT_STAGE_RETURN_FAILURE);
}

/*********************************************/

static GHashTable *shared_ips = NULL;

static void
release_shared_ip (gpointer data)
{
	g_hash_table_remove (shared_ips, data);
}

static gboolean
reserve_shared_ip (NMSettingIP4Config *s_ip4, NMPlatformIP4Address *address)
{
	if (G_UNLIKELY (shared_ips == NULL))
		shared_ips = g_hash_table_new (g_direct_hash, g_direct_equal);

	memset (address, 0, sizeof (*address));

	if (s_ip4 && nm_setting_ip4_config_get_num_addresses (s_ip4)) {
		/* Use the first user-supplied address */
		NMIP4Address *user = nm_setting_ip4_config_get_address (s_ip4, 0);

		g_assert (user);
		address->address = nm_ip4_address_get_address (user);
		address->plen = nm_ip4_address_get_prefix (user);
	} else {
		/* Find an unused address in the 10.42.x.x range */
		guint32 start = (guint32) ntohl (0x0a2a0001); /* 10.42.0.1 */
		guint32 count = 0;

		while (g_hash_table_lookup (shared_ips, GUINT_TO_POINTER (start + count))) {
			count += ntohl (0x100);
			if (count > ntohl (0xFE00)) {
				nm_log_err (LOGD_SHARING, "ran out of shared IP addresses!");
				return FALSE;
			}
		}
		address->address = start + count;
		address->plen = 24;

		g_hash_table_insert (shared_ips,
		                     GUINT_TO_POINTER (address->address),
		                     GUINT_TO_POINTER (TRUE));
	}

	return TRUE;
}

static NMIP4Config *
shared4_new_config (NMDevice *self, NMConnection *connection, NMDeviceStateReason *reason)
{
	NMIP4Config *config = NULL;
	NMPlatformIP4Address address;

	g_return_val_if_fail (self != NULL, NULL);

	if (!reserve_shared_ip (nm_connection_get_setting_ip4_config (connection), &address)) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NULL;
	}

	config = nm_ip4_config_new ();
	address.source = NM_PLATFORM_SOURCE_SHARED;
	nm_ip4_config_add_address (config, &address);

	/* Remove the address lock when the object gets disposed */
	g_object_set_data_full (G_OBJECT (config), "shared-ip",
	                        GUINT_TO_POINTER (address.address),
	                        release_shared_ip);

	return config;
}

/*********************************************/

static gboolean
have_any_ready_slaves (NMDevice *device, const GSList *slaves)
{
	const GSList *iter;

	/* Any enslaved slave is "ready" in the generic case as it's
	 * at least >= NM_DEVCIE_STATE_IP_CONFIG and has had Layer 2
	 * properties set up.
	 */
	for (iter = slaves; iter; iter = g_slist_next (iter)) {
		if (nm_device_get_enslaved (iter->data))
			return TRUE;
	}
	return FALSE;
}

static gboolean
ip4_requires_slaves (NMConnection *connection)
{
	const char *method;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	return strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0;
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *self,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *method;
	GSList *slaves;
	gboolean ready_slaves;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (priv->master)
		g_assert_cmpstr (method, ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);

	if (   strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) != 0
	    && priv->is_master
	    && !priv->carrier) {
		nm_log_info (LOGD_IP4 | LOGD_DEVICE,
		             "(%s): IPv4 config waiting until carrier is on",
		             nm_device_get_ip_iface (self));
		return NM_ACT_STAGE_RETURN_WAIT;
	}

	if (priv->is_master && ip4_requires_slaves (connection)) {
		/* If the master has no ready slaves, and depends on slaves for
		 * a successful IPv4 attempt, then postpone IPv4 addressing.
		 */
		slaves = nm_device_master_get_slaves (self);
		ready_slaves = NM_DEVICE_GET_CLASS (self)->have_any_ready_slaves (self, slaves);
		g_slist_free (slaves);

		if (ready_slaves == FALSE) {
			nm_log_info (LOGD_DEVICE | LOGD_IP4,
			             "(%s): IPv4 config waiting until slaves are ready",
			             nm_device_get_ip_iface (self));
			return NM_ACT_STAGE_RETURN_WAIT;
		}
	}

	/* Start IPv4 addressing based on the method requested */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0)
		ret = dhcp4_start (self, connection, reason);
	else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL) == 0)
		ret = aipd_start (self, reason);
	else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0) {
		/* Use only IPv4 config from the connection data */
		*out_config = nm_ip4_config_new ();
		g_assert (*out_config);
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0) {
		*out_config = shared4_new_config (self, connection, reason);
		if (*out_config) {
			priv->dnsmasq_manager = nm_dnsmasq_manager_new (nm_device_get_ip_iface (self));
			ret = NM_ACT_STAGE_RETURN_SUCCESS;
		} else
			ret = NM_ACT_STAGE_RETURN_FAILURE;
	} else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0) {
		/* Nothing to do... */
		ret = NM_ACT_STAGE_RETURN_STOP;
	} else {
		nm_log_warn (LOGD_IP4, "(%s): unhandled IPv4 config method '%s'; will fail",
		             nm_device_get_ip_iface (self), method);
	}

	return ret;
}

/*********************************************/
/* DHCPv6 stuff */

static void
dhcp6_cleanup (NMDevice *self, gboolean stop, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_NONE;
	g_clear_object (&priv->dhcp6_ip6_config);

	if (priv->dhcp6_client) {
		if (priv->dhcp6_state_sigid) {
			g_signal_handler_disconnect (priv->dhcp6_client, priv->dhcp6_state_sigid);
			priv->dhcp6_state_sigid = 0;
		}

		if (priv->dhcp6_timeout_sigid) {
			g_signal_handler_disconnect (priv->dhcp6_client, priv->dhcp6_timeout_sigid);
			priv->dhcp6_timeout_sigid = 0;
		}

		nm_device_remove_pending_action (self, PENDING_ACTION_DHCP6, FALSE);

		if (stop)
			nm_dhcp_client_stop (priv->dhcp6_client, release);

		g_clear_object (&priv->dhcp6_client);
	}

	if (priv->dhcp6_config) {
		g_clear_object (&priv->dhcp6_config);
		g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP6_CONFIG);
	}
}

static void
dhcp6_add_option_cb (gpointer key, gpointer value, gpointer user_data)
{
	nm_dhcp6_config_add_option (NM_DHCP6_CONFIG (user_data),
	                            (const char *) key,
	                            (const char *) value);
}

static gboolean
ip6_config_merge_and_apply (NMDevice *self,
                            gboolean commit,
                            NMDeviceStateReason *out_reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	gboolean success;
	NMIP6Config *composite;

	/* If no config was passed in, create a new one */
	composite = nm_ip6_config_new ();
	g_assert (composite);

	/* Merge all the IP configs into the composite config */
	if (priv->ac_ip6_config)
		nm_ip6_config_merge (composite, priv->ac_ip6_config);
	if (priv->dhcp6_ip6_config)
		nm_ip6_config_merge (composite, priv->dhcp6_ip6_config);
	if (priv->vpn6_config)
		nm_ip6_config_merge (composite, priv->vpn6_config);
	if (priv->ext_ip6_config)
		nm_ip6_config_merge (composite, priv->ext_ip6_config);

	/* Merge user overrides into the composite config */
	connection = nm_device_get_connection (self);
	if (connection) {
		nm_ip6_config_merge_setting (composite,
		                             nm_connection_get_setting_ip6_config (connection),
		                             nm_device_get_priority (self));
	}

	nm_ip6_config_addresses_sort (composite,
	    priv->rdisc ? priv->rdisc_use_tempaddr : NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

	success = nm_device_set_ip6_config (self, composite, commit, out_reason);
	g_object_unref (composite);
	return success;
}

static void
dhcp6_lease_change (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMConnection *connection;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	if (priv->dhcp6_ip6_config == NULL) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to get DHCPv6 config for rebind",
		             nm_device_get_ip_iface (device));
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
		return;
	}

	g_assert (priv->dhcp6_client);  /* sanity check */

	connection = nm_device_get_connection (device);
	g_assert (connection);

	/* Apply the updated config */
	if (ip6_config_merge_and_apply (device, TRUE, &reason) == FALSE) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to update IPv6 config in response to DHCP event.",
		             nm_device_get_ip_iface (device));
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
	} else {
		/* Notify dispatcher scripts of new DHCPv6 config */
		nm_dispatcher_call (DISPATCHER_ACTION_DHCP6_CHANGE, connection, device, NULL, NULL, NULL);
	}
}

static void
dhcp6_fail (NMDevice *device, gboolean timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	nm_dhcp6_config_reset (priv->dhcp6_config);

	if (timeout || (priv->ip6_state == IP_CONF))
		nm_device_activate_schedule_ip6_config_timeout (device);
	else if (priv->ip6_state == IP_FAIL)
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
}

static void
dhcp6_state_changed (NMDHCPClient *client,
                     NMDHCPState state,
                     gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == TRUE);

	nm_log_dbg (LOGD_DHCP6, "(%s): new DHCPv6 client state %d",
	            nm_device_get_iface (device), state);

	switch (state) {
	case DHC_BOUND6:
	case DHC_RENEW6:     /* lease renewed */
	case DHC_REBOOT:     /* have valid lease, but now obtained a different one */
	case DHC_REBIND6:    /* new, different lease */
		g_clear_object (&priv->dhcp6_ip6_config);
		priv->dhcp6_ip6_config = nm_dhcp_client_get_ip6_config (priv->dhcp6_client, FALSE);

		/* Update the DHCP6 config object with new DHCP options */
		nm_dhcp6_config_reset (priv->dhcp6_config);
		if (priv->dhcp6_ip6_config) {
			nm_dhcp_client_foreach_option (priv->dhcp6_client,
			                               dhcp6_add_option_cb,
			                               priv->dhcp6_config);
		}
		g_object_notify (G_OBJECT (device), NM_DEVICE_DHCP6_CONFIG);

		if (priv->ip6_state == IP_CONF) {
			if (priv->dhcp6_ip6_config == NULL) {
				/* FIXME: Initial DHCP failed; should we fail IPv6 entirely then? */
				nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_DHCP_FAILED);
				break;
			}
			nm_device_activate_schedule_ip6_config_result (device);
		} else if (priv->ip6_state == IP_DONE)
			dhcp6_lease_change (device);
		break;
	case DHC_TIMEOUT: /* timed out contacting DHCP server */
		dhcp6_fail (device, TRUE);
		break;
	case DHC_END: /* dhclient exited normally */
		/* In IPv6 info-only mode, the client doesn't handle leases so it
		 * may exit right after getting a response from the server.  That's
		 * normal.  In that case we just ignore the exit.
		 */
		if (priv->dhcp6_mode == NM_RDISC_DHCP_LEVEL_OTHERCONF)
			break;
		/* Otherwise, fall through */
	case DHC_FAIL: /* all attempts to contact server timed out, sleeping */
	case DHC_ABEND: /* dhclient exited abnormally */
		/* dhclient quit and can't get/renew a lease; so kill the connection */
		dhcp6_fail (device, FALSE);
		break;
	default:
		break;
	}
}

static void
dhcp6_timeout (NMDHCPClient *client, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	g_return_if_fail (nm_device_get_act_request (device) != NULL);
	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == TRUE);

	nm_dhcp_client_stop (client, FALSE);
	if (priv->dhcp6_mode == NM_RDISC_DHCP_LEVEL_MANAGED)
		dhcp6_fail (device, TRUE);
	else {
		/* not a hard failure; just live with the RA info */
		nm_dhcp6_config_reset (priv->dhcp6_config);
		if (priv->dhcp6_ip6_config)
			g_object_unref (priv->dhcp6_ip6_config);
		priv->dhcp6_ip6_config = NULL;

		if (priv->ip6_state == IP_CONF)
			nm_device_activate_schedule_ip6_config_result (device);
	}
}

static NMActStageReturn
dhcp6_start (NMDevice *self,
             NMConnection *connection,
             guint32 dhcp_opt,
             NMDeviceStateReason *reason)
{
	NMSettingIP6Config *s_ip6;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	GByteArray *tmp = NULL;

	if (!connection) {
		connection = nm_device_get_connection (self);
		g_assert (connection);
	}

	/* Begin a DHCP transaction on the interface */

	/* Clear old exported DHCP options */
	if (priv->dhcp6_config)
		g_object_unref (priv->dhcp6_config);
	priv->dhcp6_config = nm_dhcp6_config_new ();

	g_warn_if_fail (priv->dhcp6_ip6_config == NULL);
	if (priv->dhcp6_ip6_config) {
		g_object_unref (priv->dhcp6_ip6_config);
		priv->dhcp6_ip6_config = NULL;
	}

	if (priv->hw_addr_len) {
		tmp = g_byte_array_sized_new (priv->hw_addr_len);
		g_byte_array_append (tmp, priv->hw_addr, priv->hw_addr_len);
	}

	priv->dhcp6_client = nm_dhcp_manager_start_ip6 (nm_dhcp_manager_get (),
	                                                nm_device_get_ip_iface (self),
	                                                tmp,
	                                                nm_connection_get_uuid (connection),
	                                                nm_device_get_priority (self),
	                                                nm_connection_get_setting_ip6_config (connection),
	                                                priv->dhcp_timeout,
	                                                priv->dhcp_anycast_address,
	                                                (dhcp_opt == NM_RDISC_DHCP_LEVEL_OTHERCONF) ? TRUE : FALSE);
	if (tmp)
		g_byte_array_free (tmp, TRUE);

	if (priv->dhcp6_client) {
		priv->dhcp6_state_sigid = g_signal_connect (priv->dhcp6_client,
		                                            NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
		                                            G_CALLBACK (dhcp6_state_changed),
		                                            self);
		priv->dhcp6_timeout_sigid = g_signal_connect (priv->dhcp6_client,
		                                              NM_DHCP_CLIENT_SIGNAL_TIMEOUT,
		                                              G_CALLBACK (dhcp6_timeout),
		                                              self);

		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (!nm_setting_ip6_config_get_may_fail (s_ip6) ||
		    !strcmp (nm_setting_ip6_config_get_method (s_ip6), NM_SETTING_IP6_CONFIG_METHOD_DHCP))
			nm_device_add_pending_action (self, PENDING_ACTION_DHCP6, TRUE);

		/* DHCP devices will be notified by the DHCP manager when stuff happens */
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		*reason = NM_DEVICE_STATE_REASON_DHCP_START_FAILED;
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

gboolean
nm_device_dhcp6_renew (NMDevice *self, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMDeviceStateReason reason;
	NMConnection *connection;

	g_return_val_if_fail (priv->dhcp6_client != NULL, FALSE);

	nm_log_info (LOGD_DHCP6, "(%s): DHCPv6 lease renewal requested",
	             nm_device_get_iface (self));

	/* Terminate old DHCP instance and release the old lease */
	dhcp6_cleanup (self, TRUE, release);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* Start DHCP again on the interface */
	ret = dhcp6_start (self, connection, priv->dhcp6_mode, &reason);

	return (ret != NM_ACT_STAGE_RETURN_FAILURE);
}

/******************************************/

static gboolean
linklocal6_config_is_ready (const NMIP6Config *ip6_config)
{
	int i;

	if (!ip6_config)
		return FALSE;

	for (i = 0; i < nm_ip6_config_get_num_addresses (ip6_config); i++) {
		const NMPlatformIP6Address *addr = nm_ip6_config_get_address (ip6_config, i);

		if (IN6_IS_ADDR_LINKLOCAL (&addr->address) &&
		    !(addr->flags & IFA_F_TENTATIVE))
			return TRUE;
	}

	return FALSE;
}

static void
linklocal6_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->linklocal6_timeout_id) {
		g_source_remove (priv->linklocal6_timeout_id);
		priv->linklocal6_timeout_id = 0;
	}
}

static gboolean
linklocal6_timeout_cb (gpointer user_data)
{
	NMDevice *self = user_data;

	linklocal6_cleanup (self);

	nm_log_dbg (LOGD_DEVICE, "[%s] linklocal6: waiting for link-local addresses failed due to timeout",
	             nm_device_get_iface (self));

	nm_device_activate_schedule_ip6_config_timeout (self);
	return G_SOURCE_REMOVE;
}

static void
linklocal6_complete (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	const char *method;

	g_assert (priv->linklocal6_timeout_id);
	g_assert (linklocal6_config_is_ready (priv->ip6_config));

	linklocal6_cleanup (self);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	nm_log_dbg (LOGD_DEVICE, "[%s] linklocal6: waiting for link-local addresses successful, continue with method %s",
	             nm_device_get_iface (self), method);

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0)
		addrconf6_start_with_link_ready (self);
	else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0)
		nm_device_activate_schedule_ip6_config_result (self);
	else
		g_return_if_fail (FALSE);
}

static NMActStageReturn
linklocal6_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	const char *method;

	linklocal6_cleanup (self);

	if (linklocal6_config_is_ready (priv->ip6_config))
		return NM_ACT_STAGE_RETURN_SUCCESS;

	connection = nm_device_get_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	nm_log_dbg (LOGD_DEVICE, "[%s] linklocal6: starting IPv6 with method '%s', but the device has no link-local addresses configured. Wait.",
	            nm_device_get_iface (self), method);

	priv->linklocal6_timeout_id = g_timeout_add_seconds (5, linklocal6_timeout_cb, self);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/******************************************/

static void
print_support_extended_ifa_flags (NMSettingIP6ConfigPrivacy use_tempaddr)
{
	static gint8 warn = 0;
	static gint8 s_libnl = -1, s_kernel;

	if (warn >= 2)
		return;

	if (s_libnl == -1) {
		s_libnl = !!nm_platform_check_support_libnl_extended_ifa_flags ();
		s_kernel = !!nm_platform_check_support_kernel_extended_ifa_flags ();

		if (s_libnl && s_kernel) {
			nm_log_dbg (LOGD_IP6, "kernel and libnl support extended IFA_FLAGS (needed by NM for IPv6 private addresses)");
			warn = 2;
			return;
		}
	}

	if (   use_tempaddr != NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR
	    && use_tempaddr != NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR) {
		if (warn == 0) {
			nm_log_dbg (LOGD_IP6, "%s%s%s %s not support extended IFA_FLAGS (needed by NM for IPv6 private addresses)",
			                      !s_kernel ? "kernel" : "",
			                      !s_kernel && !s_libnl ? " and " : "",
			                      !s_libnl ? "libnl" : "",
			                      !s_kernel && !s_libnl ? "do" : "does");
			warn = 1;
		}
		return;
	}

	if (!s_libnl && !s_kernel) {
		nm_log_warn (LOGD_IP6, "libnl and the kernel do not support extended IFA_FLAGS needed by NM for "
		                       "IPv6 private addresses. This feature is not available");
	} else if (!s_libnl) {
		nm_log_warn (LOGD_IP6, "libnl does not support extended IFA_FLAGS needed by NM for "
		                       "IPv6 private addresses. This feature is not available");
	} else if (!s_kernel) {
		nm_log_warn (LOGD_IP6, "The kernel does not support extended IFA_FLAGS needed by NM for "
		                       "IPv6 private addresses. This feature is not available");
	}

	warn = 2;
}

static void
rdisc_config_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMConnection *connection;
	int i;
	NMDeviceStateReason reason;
	static int system_support = -1;
	guint ifa_flags = 0x00;

	if (system_support == -1) {
		/*
		 * Check, if both libnl and the kernel are recent enough,
		 * to help user space handling RA. If it's not supported,
		 * we have no ipv6-privacy and must add autoconf addresses
		 * as /128. The reason for the /128 is to prevent the kernel
		 * from adding a prefix route for this address.
		 **/
		system_support = nm_platform_check_support_libnl_extended_ifa_flags () &&
		                 nm_platform_check_support_kernel_extended_ifa_flags ();
	}

	if (system_support)
		ifa_flags = IFA_F_NOPREFIXROUTE;
	if (priv->rdisc_use_tempaddr == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR
	    || priv->rdisc_use_tempaddr == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR)
	{
		/* without system_support, this flag will be ignored. Still set it, doesn't seem to do any harm. */
		ifa_flags |= IFA_F_MANAGETEMPADDR;
	}

	g_return_if_fail (priv->act_request);
	connection = nm_device_get_connection (device);
	g_assert (connection);

	if (!priv->ac_ip6_config)
		priv->ac_ip6_config = nm_ip6_config_new ();

	if (changed & NM_RDISC_CONFIG_GATEWAYS) {
		/* Use the first gateway as ordered in router discovery cache. */
		if (rdisc->gateways->len) {
			NMRDiscGateway *gateway = &g_array_index (rdisc->gateways, NMRDiscGateway, 0);

			nm_ip6_config_set_gateway (priv->ac_ip6_config, &gateway->address);
		} else
			nm_ip6_config_set_gateway (priv->ac_ip6_config, NULL);
	}

	if (changed & NM_RDISC_CONFIG_ADDRESSES) {
		/* Rebuild address list from router discovery cache. */
		nm_ip6_config_reset_addresses (priv->ac_ip6_config);

		/* rdisc->addresses contains at most max_addresses entries.
		 * This is different from what the kernel does, which
		 * also counts static and temporary addresses when checking
		 * max_addresses.
		 **/
		for (i = 0; i < rdisc->addresses->len; i++) {
			NMRDiscAddress *discovered_address = &g_array_index (rdisc->addresses, NMRDiscAddress, i);
			NMPlatformIP6Address address;

			memset (&address, 0, sizeof (address));
			address.address = discovered_address->address;
			address.plen = system_support ? 64 : 128;
			address.timestamp = discovered_address->timestamp;
			address.lifetime = discovered_address->lifetime;
			address.preferred = discovered_address->preferred;
			if (address.preferred > address.lifetime)
				address.preferred = address.lifetime;
			address.source = NM_PLATFORM_SOURCE_RDISC;
			address.flags = ifa_flags;

			nm_ip6_config_add_address (priv->ac_ip6_config, &address);
		}
	}

	if (changed & NM_RDISC_CONFIG_ROUTES) {
		/* Rebuild route list from router discovery cache. */
		nm_ip6_config_reset_routes (priv->ac_ip6_config);

		for (i = 0; i < rdisc->routes->len; i++) {
			NMRDiscRoute *discovered_route = &g_array_index (rdisc->routes, NMRDiscRoute, i);
			NMPlatformIP6Route route;

			/* Only accept non-default routes.  The router has no idea what the
			 * local configuration or user preferences are, so sending routes
			 * with a prefix length of 0 is quite rude and thus ignored.
			 */
			if (discovered_route->plen > 0) {
				memset (&route, 0, sizeof (route));
				route.network = discovered_route->network;
				route.plen = discovered_route->plen;
				route.gateway = discovered_route->gateway;
				route.source = NM_PLATFORM_SOURCE_RDISC;
				route.metric = nm_device_get_priority (device);

				nm_ip6_config_add_route (priv->ac_ip6_config, &route);
			}
		}
	}

	if (changed & NM_RDISC_CONFIG_DNS_SERVERS) {
		/* Rebuild DNS server list from router discovery cache. */
		nm_ip6_config_reset_nameservers (priv->ac_ip6_config);

		for (i = 0; i < rdisc->dns_servers->len; i++) {
			NMRDiscDNSServer *discovered_server = &g_array_index (rdisc->dns_servers, NMRDiscDNSServer, i);

			nm_ip6_config_add_nameserver (priv->ac_ip6_config, &discovered_server->address);
		}
	}

	if (changed & NM_RDISC_CONFIG_DNS_DOMAINS) {
		/* Rebuild domain list from router discovery cache. */
		nm_ip6_config_reset_domains (priv->ac_ip6_config);

		for (i = 0; i < rdisc->dns_domains->len; i++) {
			NMRDiscDNSDomain *discovered_domain = &g_array_index (rdisc->dns_domains, NMRDiscDNSDomain, i);

			nm_ip6_config_add_domain (priv->ac_ip6_config, discovered_domain->domain);
		}
	}

	if (changed & NM_RDISC_CONFIG_DHCP_LEVEL) {
		dhcp6_cleanup (device, TRUE, TRUE);

		priv->dhcp6_mode = rdisc->dhcp_level;

		switch (priv->dhcp6_mode) {
		case NM_RDISC_DHCP_LEVEL_NONE:
			break;
		default:
			nm_log_info (LOGD_DEVICE | LOGD_DHCP6,
			             "Activation (%s) Stage 3 of 5 (IP Configure Start) starting DHCPv6"
			             " as requested by IPv6 router...",
			             priv->iface);
			switch (dhcp6_start (device, connection, priv->dhcp6_mode, &reason)) {
			case NM_ACT_STAGE_RETURN_SUCCESS:
				g_warn_if_reached ();
				break;
			case NM_ACT_STAGE_RETURN_POSTPONE:
				return;
			default:
				nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
				return;
			}
		}
	}

	if (changed & NM_RDISC_CONFIG_HOP_LIMIT) {
		char val[16];

		g_snprintf (val, sizeof (val), "%d", rdisc->hop_limit);
		nm_device_ipv6_sysctl_set (device, "hop_limit", val);
	}

	nm_device_activate_schedule_ip6_config_result (device);
}

static gboolean
addrconf6_start (NMDevice *self, NMSettingIP6ConfigPrivacy use_tempaddr)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMActStageReturn ret;
	const char *ip_iface = nm_device_get_ip_iface (self);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	g_warn_if_fail (priv->ac_ip6_config == NULL);
	if (priv->ac_ip6_config) {
		g_object_unref (priv->ac_ip6_config);
		priv->ac_ip6_config = NULL;
	}

	priv->rdisc = nm_lndp_rdisc_new (nm_device_get_ip_ifindex (self), ip_iface);
	if (!priv->rdisc) {
		nm_log_err (LOGD_IP6, "(%s): failed to start router discovery.", ip_iface);
		return FALSE;
	}

	priv->rdisc_use_tempaddr = use_tempaddr;
	print_support_extended_ifa_flags (use_tempaddr);

	if (!nm_setting_ip6_config_get_may_fail (nm_connection_get_setting_ip6_config (connection)))
		nm_device_add_pending_action (self, PENDING_ACTION_AUTOCONF6, TRUE);

	/* ensure link local is ready... */
	ret = linklocal6_start (self);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS)
		addrconf6_start_with_link_ready (self);
	else
		g_return_val_if_fail (ret == NM_ACT_STAGE_RETURN_POSTPONE, TRUE);

	return TRUE;
}

static void
addrconf6_start_with_link_ready (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_assert (priv->rdisc);

	/* FIXME: what if interface has no lladdr, like PPP? */
	if (priv->hw_addr_len)
		nm_rdisc_set_lladdr (priv->rdisc, (const char *) priv->hw_addr, priv->hw_addr_len);

	nm_device_ipv6_sysctl_set (self, "accept_ra", "1");
	nm_device_ipv6_sysctl_set (self, "accept_ra_defrtr", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_pinfo", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_rtr_pref", "0");

	priv->rdisc_config_changed_sigid = g_signal_connect (priv->rdisc, NM_RDISC_CONFIG_CHANGED,
	                                                     G_CALLBACK (rdisc_config_changed), self);

	nm_rdisc_start (priv->rdisc);
}

static void
addrconf6_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->rdisc_config_changed_sigid) {
		g_signal_handler_disconnect (priv->rdisc,
		                             priv->rdisc_config_changed_sigid);
		priv->rdisc_config_changed_sigid = 0;
	}

	nm_device_remove_pending_action (self, PENDING_ACTION_AUTOCONF6, FALSE);

	g_clear_object (&priv->ac_ip6_config);
	g_clear_object (&priv->rdisc);
}

/******************************************/

static const char *ip6_properties_to_save[] = {
	"accept_ra",
	"accept_ra_defrtr",
	"accept_ra_pinfo",
	"accept_ra_rtr_pref",
	"disable_ipv6",
	"hop_limit",
	"use_tempaddr",
};

static void
save_ip6_properties (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *ifname = nm_device_get_ip_iface (self);
	char *value;
	int i;

	g_hash_table_remove_all (priv->ip6_saved_properties);

	for (i = 0; i < G_N_ELEMENTS (ip6_properties_to_save); i++) {
		value = nm_platform_sysctl_get (nm_utils_ip6_property_path (ifname, ip6_properties_to_save[i]));
		if (value) {
			g_hash_table_insert (priv->ip6_saved_properties,
			                     (char *) ip6_properties_to_save[i],
			                     value);
		}
	}
}

static void
restore_ip6_properties (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, priv->ip6_saved_properties);
	while (g_hash_table_iter_next (&iter, &key, &value))
		nm_device_ipv6_sysctl_set (self, key, value);
}

static NMSettingIP6ConfigPrivacy
use_tempaddr_clamp (NMSettingIP6ConfigPrivacy use_tempaddr)
{
	switch (use_tempaddr) {
	case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		return use_tempaddr;
	default:
		return NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
	}
}

/* Get net.ipv6.conf.default.use_tempaddr value from /etc/sysctl.conf or
 * /lib/sysctl.d/sysctl.conf
 */
static NMSettingIP6ConfigPrivacy
ip6_use_tempaddr (void)
{
	char *contents = NULL;
	const char *group_name = "[forged_group]\n";
	char *sysctl_data = NULL;
	GKeyFile *keyfile;
	GError *error = NULL;
	gint tmp;
	NMSettingIP6ConfigPrivacy ret = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;

	/* Read file contents to a string. */
	if (!g_file_get_contents ("/etc/sysctl.conf", &contents, NULL, NULL))
		if (!g_file_get_contents ("/lib/sysctl.d/sysctl.conf", &contents, NULL, NULL))
			return NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;

	/* Prepend a group so that we can use GKeyFile parser. */
	sysctl_data = g_strdup_printf ("%s%s", group_name, contents);

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_data (keyfile, sysctl_data, -1, G_KEY_FILE_NONE, NULL))
		goto done;

	tmp = g_key_file_get_integer (keyfile, "forged_group", "net.ipv6.conf.default.use_tempaddr", &error);
	if (error == NULL)
		ret = use_tempaddr_clamp (tmp);

done:
	g_free (contents);
	g_free (sysctl_data);
	g_clear_error (&error);
	g_key_file_free (keyfile);

	return ret;
}

static gboolean
ip6_requires_slaves (NMConnection *connection)
{
	const char *method;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	/* SLAAC, DHCP, and Link-Local depend on connectivity (and thus slaves)
	 * to complete addressing.  SLAAC and DHCP obviously need a peer to
	 * provide a prefix, while Link-Local must perform DAD on the local link.
	 */
	return    strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	       || strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0
	       || strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0;
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *self,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *ip_iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMConnection *connection;
	const char *method;
	NMSettingIP6ConfigPrivacy ip6_privacy = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
	const char *ip6_privacy_str = "0\n";
	GSList *slaves;
	gboolean ready_slaves;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ip_iface = nm_device_get_ip_iface (self);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (priv->master)
		g_assert_cmpstr (method, ==, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);

	if (   strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) != 0
	    && priv->is_master
	    && !priv->carrier) {
		nm_log_info (LOGD_IP6 | LOGD_DEVICE,
		             "(%s): IPv6 config waiting until carrier is on", ip_iface);
		return NM_ACT_STAGE_RETURN_WAIT;
	}

	if (priv->is_master && ip6_requires_slaves (connection)) {
		/* If the master has no ready slaves, and depends on slaves for
		 * a successful IPv6 attempt, then postpone IPv6 addressing.
		 */
		slaves = nm_device_master_get_slaves (self);
		ready_slaves = NM_DEVICE_GET_CLASS (self)->have_any_ready_slaves (self, slaves);
		g_slist_free (slaves);

		if (ready_slaves == FALSE) {
			nm_log_info (LOGD_DEVICE | LOGD_IP6,
			             "(%s): IPv6 config waiting until slaves are ready",
			             ip_iface);
			return NM_ACT_STAGE_RETURN_WAIT;
		}
	}

	priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_NONE;

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0) {
		if (!priv->master)
			restore_ip6_properties (self);
		return NM_ACT_STAGE_RETURN_STOP;
	}

	/* Re-enable IPv6 on the interface */
	nm_device_ipv6_sysctl_set (self, "disable_ipv6", "0");

	/* Enable/disable IPv6 Privacy Extensions.
	 * If a global value is configured by sysadmin (e.g. /etc/sysctl.conf),
	 * use that value instead of per-connection value.
	 */
	ip6_privacy = ip6_use_tempaddr ();
	if (ip6_privacy == NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN) {
		NMSettingIP6Config *s_ip6 = nm_connection_get_setting_ip6_config (connection);

		if (s_ip6)
			ip6_privacy = nm_setting_ip6_config_get_ip6_privacy (s_ip6);
	}
	ip6_privacy = use_tempaddr_clamp (ip6_privacy);

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0) {
		if (!addrconf6_start (self, ip6_privacy)) {
			/* IPv6 might be disabled; allow IPv4 to proceed */
			ret = NM_ACT_STAGE_RETURN_STOP;
		} else
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0) {
		ret = linklocal6_start (self);
		if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
			/* New blank config; LL address is already in priv->ext_ip6_config */
			*out_config = nm_ip6_config_new ();
			g_assert (*out_config);
		}
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0) {
		priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_MANAGED;
		ret = dhcp6_start (self, connection, priv->dhcp6_mode, reason);
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0) {
		/* New blank config */
		*out_config = nm_ip6_config_new ();
		g_assert (*out_config);

		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else {
		nm_log_warn (LOGD_IP6, "(%s): unhandled IPv6 config method '%s'; will fail",
		             nm_device_get_ip_iface (self), method);
	}

	/* Other methods (shared) aren't implemented yet */

	switch (ip6_privacy) {
	case NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN:
	case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
		ip6_privacy_str = "0";
	break;
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		ip6_privacy_str = "1";
	break;
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
		ip6_privacy_str = "2";
	break;
	}
	nm_device_ipv6_sysctl_set (self, "use_tempaddr", ip6_privacy_str);

	return ret;
}

/**
 * nm_device_activate_stage3_ip4_start:
 * @self: the device
 *
 * Try starting IPv4 configuration.
 */
gboolean
nm_device_activate_stage3_ip4_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMIP4Config *ip4_config = NULL;

	g_assert (priv->ip4_state == IP_WAIT);

	priv->ip4_state = IP_CONF;
	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip4_config_start (self, &ip4_config, &reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
		g_assert (ip4_config);
		nm_device_activate_schedule_ip4_config_result (self, ip4_config);
		g_object_unref (ip4_config);
	} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		return FALSE;
	} else if (ret == NM_ACT_STAGE_RETURN_STOP) {
		/* Early finish */
		priv->ip4_state = IP_FAIL;
	} else if (ret == NM_ACT_STAGE_RETURN_WAIT) {
		/* Wait for something to try IP config again */
		priv->ip4_state = IP_WAIT;
	} else
		g_assert (ret == NM_ACT_STAGE_RETURN_POSTPONE);

	return TRUE;
}

/**
 * nm_device_activate_stage3_ip6_start:
 * @self: the device
 *
 * Try starting IPv6 configuration.
 */
gboolean
nm_device_activate_stage3_ip6_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMIP6Config *ip6_config = NULL;

	g_assert (priv->ip6_state == IP_WAIT);

	priv->ip6_state = IP_CONF;
	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip6_config_start (self, &ip6_config, &reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
		g_assert (ip6_config);
		/* Here we get a static IPv6 config, like for Shared where it's
		 * autogenerated or from modems where it comes from ModemManager.
		 */
		g_warn_if_fail (priv->ac_ip6_config == NULL);
		priv->ac_ip6_config = ip6_config;
		nm_device_activate_schedule_ip6_config_result (self);
	} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		return FALSE;
	} else if (ret == NM_ACT_STAGE_RETURN_STOP) {
		/* Early finish */
		priv->ip6_state = IP_FAIL;
	} else if (ret == NM_ACT_STAGE_RETURN_WAIT) {
		/* Wait for something to try IP config again */
		priv->ip6_state = IP_WAIT;
	} else
		g_assert (ret == NM_ACT_STAGE_RETURN_POSTPONE);

	return TRUE;
}

/*
 * nm_device_activate_stage3_ip_config_start
 *
 * Begin automatic/manual IP configuration
 *
 */
static gboolean
nm_device_activate_stage3_ip_config_start (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface;
	NMActiveConnection *master;
	NMDevice *master_device;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	priv->ip4_state = priv->ip6_state = IP_WAIT;

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 3 of 5 (IP Configure Start) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	/* Device should be up before we can do anything with it */
	if (!nm_platform_link_is_up (nm_device_get_ip_ifindex (self))) {
		nm_log_warn (LOGD_DEVICE, "(%s): interface %s not up for IP configuration",
		             iface, nm_device_get_ip_iface (self));
	}

	/* If the device is a slave, then we don't do any IP configuration but we
	 * use the IP config stage to indicate to the master we're ready for
	 * enslavement.  If the master is already activating, it will have tried to
	 * enslave us when we changed state to IP_CONFIG, causing us to queue a
	 * transition to SECONDARIES (or FAILED if the enslavement failed), with
	 * our IP states set to IP_DONE either way.  If the master isn't yet
	 * activating, then they'll still be in IP_WAIT.  Either way, we bail out
	 * of IP config here.
	 */
	master = nm_active_connection_get_master (NM_ACTIVE_CONNECTION (priv->act_request));
	if (master) {
		master_device = nm_active_connection_get_device (master);
		if (priv->ip4_state == IP_WAIT && priv->ip6_state == IP_WAIT) {
			nm_log_info (LOGD_DEVICE, "Activation (%s) connection '%s' waiting on master '%s'",
			             nm_device_get_iface (self),
			             nm_connection_get_id (nm_device_get_connection (self)),
			             master_device ? nm_device_get_iface (master_device) : "(unknown)");
		}
		goto out;
	}

	/* IPv4 */
	if (!nm_device_activate_stage3_ip4_start (self))
		goto out;

	/* IPv6 */
	if (!nm_device_activate_stage3_ip6_start (self))
		goto out;

	if (priv->ip4_state == IP_FAIL && priv->ip6_state == IP_FAIL) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	}

out:
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 3 of 5 (IP Configure Start) complete.", iface);
	return FALSE;
}


static void
fw_change_zone_cb (GError *error, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->fw_call = NULL;

	if (error) {
		/* FIXME: fail the device activation? */
	}

	activation_source_schedule (self, nm_device_activate_stage3_ip_config_start, 0);

	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 3 of 5 (IP Configure Start) scheduled.",
	             nm_device_get_iface (self));
}

/*
 * nm_device_activate_schedule_stage3_ip_config_start
 *
 * Schedule IP configuration start
 */
void
nm_device_activate_schedule_stage3_ip_config_start (NMDevice *self)
{
	NMDevicePrivate *priv;
	NMConnection *connection;
	NMSettingConnection *s_con = NULL;
	const char *zone;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	/* Add the interface to the specified firewall zone */
	connection = nm_device_get_connection (self);
	g_assert (connection);
	s_con = nm_connection_get_setting_connection (connection);

	zone = nm_setting_connection_get_zone (s_con);
	nm_log_dbg (LOGD_DEVICE, "Activation (%s) setting firewall zone '%s'",
	            nm_device_get_iface (self), zone ? zone : "default");
	priv->fw_call = nm_firewall_manager_add_or_change_zone (priv->fw_manager,
	                                                        nm_device_get_ip_iface (self),
	                                                        zone,
	                                                        FALSE,
	                                                        fw_change_zone_cb,
	                                                        self);
}

static NMActStageReturn
act_stage4_ip4_config_timeout (NMDevice *self, NMDeviceStateReason *reason)
{
	if (nm_device_ip_config_should_fail (self, FALSE)) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}
	return NM_ACT_STAGE_RETURN_SUCCESS;
}


/*
 * nm_device_activate_stage4_ip4_config_timeout
 *
 * Time out on retrieving the IPv4 config.
 *
 */
static gboolean
nm_device_activate_ip4_config_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE | LOGD_IP4,
	             "Activation (%s) Stage 4 of 5 (IPv4 Configure Timeout) started...",
	             iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip4_config_timeout (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	priv->ip4_state = IP_FAIL;

	/* If IPv4 failed and IPv6 failed, the activation fails */
	if (priv->ip6_state == IP_FAIL)
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);

out:
	nm_log_info (LOGD_DEVICE | LOGD_IP4,
	             "Activation (%s) Stage 4 of 5 (IPv4 Configure Timeout) complete.",
	             iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_ip4_config_timeout
 *
 * Deal with a timeout of the IPv4 configuration
 *
 */
void
nm_device_activate_schedule_ip4_config_timeout (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_ip4_config_timeout, AF_INET);

	nm_log_info (LOGD_DEVICE | LOGD_IP4,
	             "Activation (%s) Stage 4 of 5 (IPv4 Configure Timeout) scheduled...",
	             nm_device_get_iface (self));
}


static NMActStageReturn
act_stage4_ip6_config_timeout (NMDevice *self, NMDeviceStateReason *reason)
{
	if (nm_device_ip_config_should_fail (self, TRUE)) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}


/*
 * nm_device_activate_ip6_config_timeout
 *
 * Time out on retrieving the IPv6 config.
 *
 */
static gboolean
nm_device_activate_ip6_config_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET6);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE | LOGD_IP6,
	             "Activation (%s) Stage 4 of 5 (IPv6 Configure Timeout) started...",
	             iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip6_config_timeout (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

	priv->ip6_state = IP_FAIL;

	/* If IPv6 failed and IPv4 failed, the activation fails */
	if (priv->ip4_state == IP_FAIL)
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);

out:
	nm_log_info (LOGD_DEVICE | LOGD_IP6,
	             "Activation (%s) Stage 4 of 5 (IPv6 Configure Timeout) complete.",
	             iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_ip6_config_timeout
 *
 * Deal with a timeout of the IPv6 configuration
 *
 */
void
nm_device_activate_schedule_ip6_config_timeout (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_ip6_config_timeout, AF_INET6);

	nm_log_info (LOGD_DEVICE | LOGD_IP6,
	             "Activation (%s) Stage 4 of 5 (IPv6 Configure Timeout) scheduled...",
	             nm_device_get_iface (self));
}

static void
share_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);

	nm_unblock_posix_signals (NULL);
}

static gboolean
share_init (void)
{
	int status;
	char *modules[] = { "ip_tables", "iptable_nat", "nf_nat_ftp", "nf_nat_irc",
	                    "nf_nat_sip", "nf_nat_tftp", "nf_nat_pptp", "nf_nat_h323",
	                    NULL };
	char **iter;

	if (!nm_platform_sysctl_set ("/proc/sys/net/ipv4/ip_forward", "1")) {
		nm_log_err (LOGD_SHARING, "Error starting IP forwarding: (%d) %s",
					errno, strerror (errno));
		return FALSE;
	}

	if (!nm_platform_sysctl_set ("/proc/sys/net/ipv4/ip_dynaddr", "1")) {
		nm_log_err (LOGD_SHARING, "error starting IP forwarding: (%d) %s",
					errno, strerror (errno));
	}

	for (iter = modules; *iter; iter++) {
		char *argv[3] = { "/sbin/modprobe", *iter, NULL };
		char *envp[1] = { NULL };
		GError *error = NULL;

		if (!g_spawn_sync ("/", argv, envp, G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
		                   share_child_setup, NULL, NULL, NULL, &status, &error)) {
			nm_log_err (LOGD_SHARING, "error loading NAT module %s: (%d) %s",
			            *iter, error ? error->code : 0,
			            (error && error->message) ? error->message : "unknown");
			if (error)
				g_error_free (error);
		}
	}

	return TRUE;
}

static void
add_share_rule (NMActRequest *req, const char *table, const char *fmt, ...)
{
	va_list args;
	char *cmd;

	va_start (args, fmt);
	cmd = g_strdup_vprintf (fmt, args);
	va_end (args);

	nm_act_request_add_share_rule (req, table, cmd);
	g_free (cmd);
}

static gboolean
start_sharing (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	GError *error = NULL;
	char str_addr[INET_ADDRSTRLEN + 1];
	char str_mask[INET_ADDRSTRLEN + 1];
	guint32 netmask, network;
	const NMPlatformIP4Address *ip4_addr;
	const char *ip_iface;

	g_return_val_if_fail (config != NULL, FALSE);

	ip_iface = nm_device_get_ip_iface (self);

	ip4_addr = nm_ip4_config_get_address (config, 0);
	if (!ip4_addr || !ip4_addr->address)
		return FALSE;

	netmask = nm_utils_ip4_prefix_to_netmask (ip4_addr->plen);
	if (!inet_ntop (AF_INET, &netmask, str_mask, sizeof (str_mask)))
		return FALSE;

	network = ip4_addr->address & netmask;
	if (!inet_ntop (AF_INET, &network, str_addr, sizeof (str_addr)))
		return FALSE;

	if (!share_init ())
		return FALSE;

	req = nm_device_get_act_request (self);
	g_assert (req);

	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol tcp --destination-port 53 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol udp --destination-port 53 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol tcp --destination-port 67 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol udp --destination-port 67 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "FORWARD --in-interface %s --jump REJECT", ip_iface);
	add_share_rule (req, "filter", "FORWARD --out-interface %s --jump REJECT", ip_iface);
	add_share_rule (req, "filter", "FORWARD --in-interface %s --out-interface %s --jump ACCEPT", ip_iface, ip_iface);
	add_share_rule (req, "filter", "FORWARD --source %s/%s --in-interface %s --jump ACCEPT", str_addr, str_mask, ip_iface);
	add_share_rule (req, "filter", "FORWARD --destination %s/%s --out-interface %s --match state --state ESTABLISHED,RELATED --jump ACCEPT", str_addr, str_mask, ip_iface);
	add_share_rule (req, "nat", "POSTROUTING --source %s/%s ! --destination %s/%s --jump MASQUERADE", str_addr, str_mask, str_addr, str_mask);

	nm_act_request_set_shared (req, TRUE);

	if (!nm_dnsmasq_manager_start (priv->dnsmasq_manager, config, &error)) {
		nm_log_err (LOGD_SHARING, "(%s/%s): failed to start dnsmasq: %s",
		            nm_device_get_iface (self), ip_iface,
		            (error && error->message) ? error->message : "(unknown)");
		g_error_free (error);
		nm_act_request_set_shared (req, FALSE);
		return FALSE;
	}

	priv->dnsmasq_state_id = g_signal_connect (priv->dnsmasq_manager, "state-changed",
	                                           G_CALLBACK (dnsmasq_state_changed_cb),
	                                           self);
	return TRUE;
}

static void
send_arps (NMDevice *self, const char *mode_arg)
{
	const char *argv[] = { "/sbin/arping", mode_arg, "-q", "-I", nm_device_get_ip_iface (self), "-c", "1", NULL, NULL };
	int ip_arg = G_N_ELEMENTS (argv) - 2;
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	int i, num;
	NMIP4Address *addr;
	guint32 ipaddr;
	GError *error = NULL;

	connection = nm_device_get_connection (self);
	if (!connection)
		return;
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return;
	num = nm_setting_ip4_config_get_num_addresses (s_ip4);

	for (i = 0; i < num; i++) {
		addr = nm_setting_ip4_config_get_address (s_ip4, i);
		ipaddr = nm_ip4_address_get_address (addr);
		argv[ip_arg] = (char *) nm_utils_inet4_ntop (ipaddr, NULL);

		nm_log_dbg (LOGD_DEVICE | LOGD_IP4,
		            "Running arping %s -I %s %s",
		            mode_arg, nm_device_get_iface (self), argv[ip_arg]);
		g_spawn_async (NULL, (char **) argv, NULL,
		               G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
		               nm_unblock_posix_signals,
		               NULL, NULL, &error);
		if (error) {
			nm_log_warn (LOGD_DEVICE | LOGD_IP4,
			             "Could not send ARP for local address %s: %s",
			             argv[ip_arg], error->message);
			g_clear_error (&error);
		}
	}
}

static gboolean
arp_announce_round2 (gpointer self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->arp_round2_id = 0;

	if (   priv->state >= NM_DEVICE_STATE_IP_CONFIG
	    && priv->state <= NM_DEVICE_STATE_ACTIVATED)
		send_arps (self, "-U");

	return G_SOURCE_REMOVE;
}

static void
arp_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->arp_round2_id) {
		g_source_remove (priv->arp_round2_id);
		priv->arp_round2_id = 0;
	}
}

static void
arp_announce (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	int num;

	arp_cleanup (self);

	/* We only care about manually-configured addresses; DHCP- and autoip-configured
	 * ones should already have been seen on the network at this point.
	 */
	connection = nm_device_get_connection (self);
	if (!connection)
		return;
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return;
	num = nm_setting_ip4_config_get_num_addresses (s_ip4);
	if (num == 0)
		return;

	send_arps (self, "-A");
	priv->arp_round2_id = g_timeout_add_seconds (2, arp_announce_round2, self);
}

static gboolean
nm_device_activate_ip4_config_commit (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	const char *iface, *method;
	NMConnection *connection;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 5 of 5 (IPv4 Commit) started...",
	             iface);

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Device should be up before we can do anything with it */
	if (!nm_platform_link_is_up (nm_device_get_ip_ifindex (self))) {
		nm_log_warn (LOGD_DEVICE, "(%s): interface %s not up for IP configuration",
		             iface, nm_device_get_ip_iface (self));
	}

	/* NULL to use the existing priv->dev_ip4_config */
	if (!ip4_config_merge_and_apply (self, NULL, TRUE, &reason)) {
		nm_log_info (LOGD_DEVICE | LOGD_IP4,
			         "Activation (%s) Stage 5 of 5 (IPv4 Commit) failed",
					 iface);
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}

	/* Start IPv4 sharing if we need it */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);

	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0) {
		if (!start_sharing (self, priv->ip4_config)) {
			nm_log_warn (LOGD_SHARING, "Activation (%s) Stage 5 of 5 (IPv4 Commit) start sharing failed.", iface);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
			goto out;
		}
	}

	/* If IPv4 wasn't the first to complete, and DHCP was used, then ensure
	 * dispatcher scripts get the DHCP lease information.
	 */
	if (   priv->dhcp4_client
	    && nm_device_activate_ip4_state_in_conf (self)
	    && (nm_device_get_state (self) > NM_DEVICE_STATE_IP_CONFIG)) {
		/* Notify dispatcher scripts of new DHCP4 config */
		nm_dispatcher_call (DISPATCHER_ACTION_DHCP4_CHANGE,
		                    nm_device_get_connection (self),
		                    self,
		                    NULL,
		                    NULL,
		                    NULL);
	}

	arp_announce (self);

	/* Enter the IP_CHECK state if this is the first method to complete */
	priv->ip4_state = IP_DONE;

	nm_device_remove_pending_action (self, PENDING_ACTION_DHCP4, FALSE);

	if (nm_device_get_state (self) == NM_DEVICE_STATE_IP_CONFIG)
		nm_device_state_changed (self, NM_DEVICE_STATE_IP_CHECK, NM_DEVICE_STATE_REASON_NONE);

out:
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 5 of 5 (IPv4 Commit) complete.",
	             iface);

	return FALSE;
}

void
nm_device_activate_schedule_ip4_config_result (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (NM_IS_IP4_CONFIG (config));
	priv = NM_DEVICE_GET_PRIVATE (self);

	g_clear_object (&priv->dev_ip4_config);
	priv->dev_ip4_config = g_object_ref (config);

	activation_source_schedule (self, nm_device_activate_ip4_config_commit, AF_INET);

	nm_log_info (LOGD_DEVICE | LOGD_IP4,
		         "Activation (%s) Stage 5 of 5 (IPv4 Configure Commit) scheduled...",
		         nm_device_get_iface (self));
}

gboolean
nm_device_activate_ip4_state_in_conf (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip4_state == IP_CONF;
}

gboolean
nm_device_activate_ip4_state_in_wait (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip4_state == IP_WAIT;
}

static gboolean
nm_device_activate_ip6_config_commit (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint level = (priv->ip6_state == IP_DONE) ? LOGL_DEBUG : LOGL_INFO;
	NMActRequest *req;
	const char *iface;
	NMConnection *connection;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET6);

	iface = nm_device_get_iface (self);
	nm_log (LOGD_DEVICE, level, "Activation (%s) Stage 5 of 5 (IPv6 Commit) started...", iface);

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Device should be up before we can do anything with it */
	g_warn_if_fail (nm_platform_link_is_up (nm_device_get_ip_ifindex (self)));

	/* Allow setting MTU etc */
	if (NM_DEVICE_GET_CLASS (self)->ip6_config_pre_commit)
		NM_DEVICE_GET_CLASS (self)->ip6_config_pre_commit (self);

	if (ip6_config_merge_and_apply (self, TRUE, &reason)) {
		/* If IPv6 wasn't the first IP to complete, and DHCP was used,
		 * then ensure dispatcher scripts get the DHCP lease information.
		 */
		if (   priv->dhcp6_client
		    && nm_device_activate_ip6_state_in_conf (self)
		    && (nm_device_get_state (self) > NM_DEVICE_STATE_IP_CONFIG)) {
			/* Notify dispatcher scripts of new DHCP6 config */
			nm_dispatcher_call (DISPATCHER_ACTION_DHCP6_CHANGE,
			                    nm_device_get_connection (self),
			                    self,
			                    NULL,
			                    NULL,
			                    NULL);
		}

		/* Enter the IP_CHECK state if this is the first method to complete */
		priv->ip6_state = IP_DONE;

		nm_device_remove_pending_action (self, PENDING_ACTION_DHCP6, FALSE);
		nm_device_remove_pending_action (self, PENDING_ACTION_AUTOCONF6, FALSE);

		if (nm_device_get_state (self) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_state_changed (self, NM_DEVICE_STATE_IP_CHECK, NM_DEVICE_STATE_REASON_NONE);
	} else {
		nm_log_warn (LOGD_DEVICE | LOGD_IP6,
			         "Activation (%s) Stage 5 of 5 (IPv6 Commit) failed",
					 iface);
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
	}

	nm_log (LOGD_DEVICE, level, "Activation (%s) Stage 5 of 5 (IPv6 Commit) complete.", iface);

	return FALSE;
}

void
nm_device_activate_schedule_ip6_config_result (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint level = (priv->ip6_state == IP_DONE) ? LOGL_DEBUG : LOGL_INFO;

	g_return_if_fail (NM_IS_DEVICE (self));

	activation_source_schedule (self, nm_device_activate_ip6_config_commit, AF_INET6);

	nm_log (LOGD_DEVICE | LOGD_IP6, level,
		    "Activation (%s) Stage 5 of 5 (IPv6 Commit) scheduled...",
		    nm_device_get_iface (self));
}

gboolean
nm_device_activate_ip6_state_in_conf (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip6_state == IP_CONF;
}

gboolean
nm_device_activate_ip6_state_in_wait (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip6_state == IP_WAIT;
}

static void
clear_act_request (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->act_request)
		return;

	nm_active_connection_set_default (NM_ACTIVE_CONNECTION (priv->act_request), FALSE);

	if (priv->master_ready_id) {
		g_signal_handler_disconnect (priv->act_request, priv->master_ready_id);
		priv->master_ready_id = 0;
	}

	g_clear_object (&priv->act_request);
	g_object_notify (G_OBJECT (self), NM_DEVICE_ACTIVE_CONNECTION);
}

static void
dnsmasq_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->dnsmasq_manager)
		return;

	if (priv->dnsmasq_state_id) {
		g_signal_handler_disconnect (priv->dnsmasq_manager, priv->dnsmasq_state_id);
		priv->dnsmasq_state_id = 0;
	}

	nm_dnsmasq_manager_stop (priv->dnsmasq_manager);
	g_object_unref (priv->dnsmasq_manager);
	priv->dnsmasq_manager = NULL;
}

static void
_update_ip4_address (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	struct ifreq req;
	guint32 new_address;
	int fd;

	g_return_if_fail (self  != NULL);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_IP4, "couldn't open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_ip_iface (self), IFNAMSIZ);
	if (ioctl (fd, SIOCGIFADDR, &req) == 0) {
		new_address = ((struct sockaddr_in *)(&req.ifr_addr))->sin_addr.s_addr;
		if (new_address != priv->ip4_address)
			priv->ip4_address = new_address;
	}
	close (fd);
}

gboolean
nm_device_get_is_nm_owned (NMDevice *device)
{
	return NM_DEVICE_GET_PRIVATE (device)->is_nm_owned;
}

void
nm_device_set_nm_owned (NMDevice *device)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	NM_DEVICE_GET_PRIVATE (device)->is_nm_owned = TRUE;
}

/*
 * delete_on_deactivate_link_delete
 *
 * Function will be queued with g_idle_add to call
 * nm_platform_link_delete for the underlying resources
 * of the device.
 */
static gboolean
delete_on_deactivate_link_delete (gpointer user_data)
{
	DeleteOnDeactivateData *data = user_data;

	if (data->device) {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (data->device);

		g_object_remove_weak_pointer (G_OBJECT (data->device), (void **) &data->device);
		priv->delete_on_deactivate_data = NULL;
	}

	nm_log_dbg (LOGD_DEVICE, "delete_on_deactivate: cleanup and delete virtual link #%d (id=%u)",
	                         data->ifindex, data->idle_add_id);
	nm_platform_link_delete (data->ifindex);
	g_free (data);
	return FALSE;
}

static void
delete_on_deactivate_unschedule (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->delete_on_deactivate_data) {
		DeleteOnDeactivateData *data = priv->delete_on_deactivate_data;

		priv->delete_on_deactivate_data = NULL;

		g_source_remove (data->idle_add_id);
		g_object_remove_weak_pointer (G_OBJECT (self), (void **) &data->device);
		nm_log_dbg (LOGD_DEVICE, "delete_on_deactivate: cancel cleanup and delete virtual link #%d (id=%u)",
		                         data->ifindex, data->idle_add_id);
		g_free (data);
	}
}

static void
delete_on_deactivate_check_and_schedule (NMDevice *self, int ifindex)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	DeleteOnDeactivateData *data;

	if (ifindex <= 0)
		return;
	if (!priv->is_nm_owned)
		return;
	if (!nm_device_is_software (self))
		return;
	if (nm_device_get_state (self) == NM_DEVICE_STATE_UNMANAGED)
		return;
	if (nm_device_get_state (self) == NM_DEVICE_STATE_UNAVAILABLE)
		return;
	delete_on_deactivate_unschedule (self); /* always cancel and reschedule */

	data = g_new (DeleteOnDeactivateData, 1);
	g_object_add_weak_pointer (G_OBJECT (self), (void **) &data->device);
	data->device = self;
	data->ifindex = ifindex;
	data->idle_add_id = g_idle_add (delete_on_deactivate_link_delete, data);
	priv->delete_on_deactivate_data = data;

	nm_log_dbg (LOGD_DEVICE, "delete_on_deactivate: schedule cleanup and delete virtual link #%d for [%s] (id=%u)",
	                         ifindex, nm_device_get_iface (self), data->idle_add_id);
}

static void
disconnect_cb (NMDevice *device,
               DBusGMethodInvocation *context,
               GError *error,
               gpointer user_data)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	GError *local = NULL;

	if (error) {
		dbus_g_method_return_error (context, error);
		return;
	}

	/* Authorized */
	if (priv->state <= NM_DEVICE_STATE_DISCONNECTED) {
		local = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "Device is not active");
		dbus_g_method_return_error (context, local);
		g_error_free (local);
	} else {
		priv->autoconnect = FALSE;

		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
		dbus_g_method_return (context);
	}
}

static void
impl_device_disconnect (NMDevice *device, DBusGMethodInvocation *context)
{
	NMConnection *connection;
	GError *error = NULL;

	if (NM_DEVICE_GET_PRIVATE (device)->act_request == NULL) {
		error = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "This device is not active");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	connection = nm_device_get_connection (device);
	g_assert (connection);

	/* Ask the manager to authenticate this request for us */
	g_signal_emit (device, signals[AUTH_REQUEST], 0,
	               context,
	               connection,
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               disconnect_cb,
	               NULL);
}

static void
_device_activate (NMDevice *self, NMActRequest *req)
{
	NMDevicePrivate *priv;
	NMConnection *connection;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv = NM_DEVICE_GET_PRIVATE (self);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	nm_log_info (LOGD_DEVICE, "Activation (%s) starting connection '%s'",
	             nm_device_get_iface (self),
	             nm_connection_get_id (connection));

	delete_on_deactivate_unschedule (self);

	/* Move default unmanaged devices to DISCONNECTED state here */
	if (nm_device_get_default_unmanaged (self) && priv->state == NM_DEVICE_STATE_UNMANAGED) {
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_NOW_MANAGED);
	}

	/* note: don't notify D-Bus of the new AC here, but do it later when
	 * changing state to PREPARE so that the two properties change together.
	 */
	priv->act_request = g_object_ref (req);

	nm_device_activate_schedule_stage1_device_prepare (self);
}

void
nm_device_queue_activation (NMDevice *self, NMActRequest *req)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->act_request) {
		/* Just activate immediately */
		_device_activate (self, req);
		return;
	}

	/* supercede any already-queued request */
	g_clear_object (&priv->queued_act_request);
	priv->queued_act_request = g_object_ref (req);

	/* Deactivate existing activation request first */
	nm_log_info (LOGD_DEVICE, "(%s): disconnecting for new activation request.",
	             nm_device_get_iface (self));
	nm_device_state_changed (self,
	                         NM_DEVICE_STATE_DEACTIVATING,
	                         NM_DEVICE_STATE_REASON_NONE);
}

/*
 * nm_device_is_activating
 *
 * Return whether or not the device is currently activating itself.
 *
 */
gboolean
nm_device_is_activating (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	state = nm_device_get_state (device);
	if (state >= NM_DEVICE_STATE_PREPARE && state <= NM_DEVICE_STATE_SECONDARIES)
		return TRUE;

	/* There's a small race between the time when stage 1 is scheduled
	 * and when the device actually sets STATE_PREPARE when the activation
	 * handler is actually run.  If there's an activation handler scheduled
	 * we're activating anyway.
	 */
	return priv->act_source_id ? TRUE : FALSE;
}

/* IP Configuration stuff */

NMDHCP4Config *
nm_device_get_dhcp4_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->dhcp4_config;
}

NMIP4Config *
nm_device_get_ip4_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->ip4_config;
}


static gboolean
nm_device_set_ip4_config (NMDevice *self,
                          NMIP4Config *new_config,
                          gboolean commit,
                          NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	NMIP4Config *old_config = NULL;
	gboolean has_changes = FALSE;
	gboolean success = TRUE;
	NMDeviceStateReason reason_local = NM_DEVICE_STATE_REASON_NONE;
	int ip_ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);
	ip_ifindex = nm_device_get_ip_ifindex (self);

	old_config = priv->ip4_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config) {
		success = nm_ip4_config_commit (new_config, ip_ifindex);
		if (!success)
			reason_local = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	}

	if (new_config) {
		if (old_config) {
			/* has_changes is set only on relevant changes, because when the configuration changes,
			 * this causes a re-read and reset. This should only happen for relevant changes */
			nm_ip4_config_replace (old_config, new_config, &has_changes);
			if (has_changes) {
				nm_log_dbg (LOGD_IP4, "(%s): update IP4Config instance (%s)",
				            ip_iface, nm_ip4_config_get_dbus_path (old_config));
			}
		} else {
			has_changes = TRUE;
			priv->ip4_config = g_object_ref (new_config);

			if (success && !nm_ip4_config_get_dbus_path (new_config)) {
				/* Export over D-Bus */
				nm_ip4_config_export (new_config);
			}

			nm_log_dbg (LOGD_IP4, "(%s): set IP4Config instance (%s)",
			            ip_iface, nm_ip4_config_get_dbus_path (new_config));
		}
	} else if (old_config) {
		has_changes = TRUE;
		priv->ip4_config = NULL;
		nm_log_dbg (LOGD_IP4, "(%s): clear IP4Config instance (%s)",
		            ip_iface, nm_ip4_config_get_dbus_path (old_config));
		/* Device config is invalid if combined config is invalid */
		g_clear_object (&priv->dev_ip4_config);
	}

	if (has_changes) {
		_update_ip4_address (self);

		if (old_config != priv->ip4_config)
			g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_CONFIG);
		g_signal_emit (self, signals[IP4_CONFIG_CHANGED], 0, priv->ip4_config, old_config);

		if (old_config != priv->ip4_config && old_config)
			g_object_unref (old_config);

		if (nm_device_uses_generated_connection (self)) {
			NMConnection *connection = nm_device_get_connection (self);
			NMSetting *s_ip4;

			g_object_freeze_notify (G_OBJECT (connection));
			nm_connection_remove_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
			s_ip4 = nm_ip4_config_create_setting (priv->ip4_config);
			nm_connection_add_setting (connection, s_ip4);
			g_object_thaw_notify (G_OBJECT (connection));
		}

		nm_device_queue_recheck_assume (self);
	}

	if (reason)
		*reason = reason_local;

	return success;
}

void
nm_device_set_vpn4_config (NMDevice *device, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if (priv->vpn4_config == config)
		return;

	g_clear_object (&priv->vpn4_config);
	if (config)
		priv->vpn4_config = g_object_ref (config);

	/* NULL to use existing configs */
	if (!ip4_config_merge_and_apply (device, NULL, TRUE, NULL)) {
		nm_log_warn (LOGD_IP4, "(%s): failed to set VPN routes for device",
			         nm_device_get_ip_iface (device));
	}
}

static gboolean
nm_device_set_ip6_config (NMDevice *self,
                          NMIP6Config *new_config,
                          gboolean commit,
                          NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	NMIP6Config *old_config = NULL;
	gboolean has_changes = FALSE;
	gboolean success = TRUE;
	NMDeviceStateReason reason_local = NM_DEVICE_STATE_REASON_NONE;
	int ip_ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);
	ip_ifindex = nm_device_get_ip_ifindex (self);

	old_config = priv->ip6_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config) {
		success = nm_ip6_config_commit (new_config, ip_ifindex);
		if (!success)
			reason_local = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	}

	if (new_config) {
		if (old_config) {
			/* has_changes is set only on relevant changes, because when the configuration changes,
			 * this causes a re-read and reset. This should only happen for relevant changes */
			nm_ip6_config_replace (old_config, new_config, &has_changes);
			if (has_changes) {
				nm_log_dbg (LOGD_IP6, "(%s): update IP6Config instance (%s)",
				            ip_iface, nm_ip6_config_get_dbus_path (old_config));
			}
		} else {
			has_changes = TRUE;
			priv->ip6_config = g_object_ref (new_config);

			if (success && !nm_ip6_config_get_dbus_path (new_config)) {
				/* Export over D-Bus */
				nm_ip6_config_export (new_config);
			}

			nm_log_dbg (LOGD_IP4, "(%s): set IP6Config instance (%s)",
			            ip_iface, nm_ip6_config_get_dbus_path (new_config));
		}
	} else if (old_config) {
		has_changes = TRUE;
		priv->ip6_config = NULL;
		nm_log_dbg (LOGD_IP6, "(%s): clear IP6Config instance (%s)",
		            ip_iface, nm_ip6_config_get_dbus_path (old_config));
	}

	if (has_changes) {
		if (old_config != priv->ip6_config)
			g_object_notify (G_OBJECT (self), NM_DEVICE_IP6_CONFIG);
		g_signal_emit (self, signals[IP6_CONFIG_CHANGED], 0, priv->ip6_config, old_config);

		if (old_config != priv->ip6_config && old_config)
			g_object_unref (old_config);

		if (nm_device_uses_generated_connection (self)) {
			NMConnection *connection = nm_device_get_connection (self);
			NMSetting *s_ip6;

			g_object_freeze_notify (G_OBJECT (connection));
			nm_connection_remove_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
			s_ip6 = nm_ip6_config_create_setting (priv->ip6_config);
			nm_connection_add_setting (connection, s_ip6);
			g_object_thaw_notify (G_OBJECT (connection));
		}

		nm_device_queue_recheck_assume (self);
	}

	if (reason)
		*reason = reason_local;

	return success;
}

void
nm_device_set_vpn6_config (NMDevice *device, NMIP6Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if (priv->vpn6_config == config)
		return;

	g_clear_object (&priv->vpn6_config);
	if (config)
		priv->vpn6_config = g_object_ref (config);

	/* NULL to use existing configs */
	if (!ip6_config_merge_and_apply (device, TRUE, NULL)) {
		nm_log_warn (LOGD_IP6, "(%s): failed to set VPN routes for device",
			         nm_device_get_ip_iface (device));
	}
}

NMDHCP6Config *
nm_device_get_dhcp6_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->dhcp6_config;
}

NMIP6Config *
nm_device_get_ip6_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->ip6_config;
}

/****************************************************************/

static void
dispatcher_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dispatcher.call_id) {
		nm_dispatcher_call_cancel (priv->dispatcher.call_id);
		priv->dispatcher.call_id = 0;
		priv->dispatcher.post_state = NM_DEVICE_STATE_UNKNOWN;
		priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
	}
}

static void
dispatcher_complete_proceed_state (guint call_id, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (call_id == priv->dispatcher.call_id);

	priv->dispatcher.call_id = 0;
	nm_device_queue_state (self, priv->dispatcher.post_state,
	                       priv->dispatcher.post_state_reason);
	priv->dispatcher.post_state = NM_DEVICE_STATE_UNKNOWN;
	priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
}

/****************************************************************/

static void
ip_check_pre_up (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dispatcher.call_id != 0) {
		g_warn_if_reached ();
		dispatcher_cleanup (self);
	}

	priv->dispatcher.post_state = NM_DEVICE_STATE_SECONDARIES;
	priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
	if (!nm_dispatcher_call (DISPATCHER_ACTION_PRE_UP,
	                         nm_device_get_connection (self),
	                         self,
	                         dispatcher_complete_proceed_state,
	                         self,
	                         &priv->dispatcher.call_id)) {
		/* Just proceed on errors */
		dispatcher_complete_proceed_state (0, self);
	}
}

static void
ip_check_gw_ping_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->gw_ping.watch) {
		g_source_remove (priv->gw_ping.watch);
		priv->gw_ping.watch = 0;
	}
	if (priv->gw_ping.timeout) {
		g_source_remove (priv->gw_ping.timeout);
		priv->gw_ping.timeout = 0;
	}

	if (priv->gw_ping.pid) {
		guint count = 20;
		int status;

		kill (priv->gw_ping.pid, SIGKILL);
		do {
			if (waitpid (priv->gw_ping.pid, &status, WNOHANG) != 0)
				break;
			g_usleep (G_USEC_PER_SEC / 20);
		} while (count--);

		priv->gw_ping.pid = 0;
	}
}

static void
ip_check_ping_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface;
	guint log_domain = priv->gw_ping.log_domain;

	if (!priv->gw_ping.watch)
		return;
	priv->gw_ping.watch = 0;
	priv->gw_ping.pid = 0;

	iface = nm_device_get_iface (self);

	if (WIFEXITED (status)) {
		if (WEXITSTATUS (status) == 0)
			nm_log_dbg (log_domain, "(%s): gateway ping succeeded", iface);
		else {
			nm_log_warn (log_domain, "(%s): gateway ping failed with error code %d",
				         iface, WEXITSTATUS (status));
		}
	} else
		nm_log_warn (log_domain, "(%s): ping stopped unexpectedly with status %d", iface, status);

	/* We've got connectivity, proceed to pre_up */
	ip_check_gw_ping_cleanup (self);
	ip_check_pre_up (self);
}

static gboolean
ip_check_ping_timeout_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->gw_ping.timeout = 0;

	nm_log_warn (priv->gw_ping.log_domain, "(%s): gateway ping timed out",
	             nm_device_get_iface (self));

	ip_check_gw_ping_cleanup (self);
	ip_check_pre_up (self);
	return FALSE;
}

static gboolean
spawn_ping (NMDevice *self,
            guint log_domain,
            const char *binary,
            const char *address,
            guint timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *args[] = { binary, "-I", nm_device_get_ip_iface (self), "-c", "1", "-w", NULL, address, NULL };
	GError *error = NULL;
	char *str_timeout, *cmd;
	gboolean success;

	g_return_val_if_fail (priv->gw_ping.watch == 0, FALSE);
	g_return_val_if_fail (priv->gw_ping.timeout == 0, FALSE);

	args[6] = str_timeout = g_strdup_printf ("%u", timeout);

	if (nm_logging_enabled (LOGL_DEBUG, log_domain)) {
		cmd = g_strjoinv (" ", (gchar **) args);
		nm_log_dbg (log_domain, "(%s): running '%s'",
		            nm_device_get_iface (self),
		            cmd);
		g_free (cmd);
	}

	success = g_spawn_async ("/",
	                         (gchar **) args,
	                         NULL,
	                         G_SPAWN_DO_NOT_REAP_CHILD,
	                         nm_unblock_posix_signals,
	                         NULL,
	                         &priv->gw_ping.pid,
	                         &error);
	if (success) {
		priv->gw_ping.log_domain = log_domain;
		priv->gw_ping.watch = g_child_watch_add (priv->gw_ping.pid, ip_check_ping_watch_cb, self);
		priv->gw_ping.timeout = g_timeout_add_seconds (timeout + 1, ip_check_ping_timeout_cb, self);
	} else {
		nm_log_warn (log_domain, "could not spawn %s: %s", binary, error->message);
		g_clear_error (&error);
	}

	g_free (str_timeout);
	return success;
}

static void
nm_device_start_ip_check (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingConnection *s_con;
	guint timeout = 0;
	const char *ping_binary = NULL;
	char buf[INET6_ADDRSTRLEN] = { 0 };
	guint log_domain = LOGD_IP4;

	/* Shouldn't be any active ping here, since IP_CHECK happens after the
	 * first IP method completes.  Any subsequently completing IP method doesn't
	 * get checked.
	 */
	g_assert (!priv->gw_ping.watch);
	g_assert (!priv->gw_ping.timeout);
	g_assert (!priv->gw_ping.pid);
	g_assert (priv->ip4_state == IP_DONE || priv->ip6_state == IP_DONE);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	timeout = nm_setting_connection_get_gateway_ping_timeout (s_con);

	if (timeout) {
		if (priv->ip4_state == IP_DONE) {
			guint gw = 0;

			ping_binary = "/usr/bin/ping";
			log_domain = LOGD_IP4;

			gw = nm_ip4_config_get_gateway (priv->ip4_config);
			if (gw && !inet_ntop (AF_INET, &gw, buf, sizeof (buf)))
				buf[0] = '\0';
		} else if (priv->ip6_config && priv->ip6_state == IP_DONE) {
			const struct in6_addr *gw = NULL;

			ping_binary = "/usr/bin/ping6";
			log_domain = LOGD_IP6;

			gw = nm_ip6_config_get_gateway (priv->ip6_config);
			if (gw && !inet_ntop (AF_INET6, gw, buf, sizeof (buf)))
				buf[0] = '\0';
		}
	}

	if (buf[0])
		spawn_ping (self, log_domain, ping_binary, buf, timeout);

	/* If no ping was started, just advance to pre_up */
	if (!priv->gw_ping.pid)
		ip_check_pre_up (self);
}

/****************************************************************/

static gboolean
carrier_wait_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	NM_DEVICE_GET_PRIVATE (self)->carrier_wait_id = 0;
	nm_device_remove_pending_action (self, "carrier wait", TRUE);
	return G_SOURCE_REMOVE;
}

static gboolean
nm_device_is_up (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (NM_DEVICE_GET_CLASS (self)->is_up)
		return NM_DEVICE_GET_CLASS (self)->is_up (self);

	return TRUE;
}

static gboolean
is_up (NMDevice *device)
{
	int ifindex = nm_device_get_ip_ifindex (device);

	return ifindex > 0 ? nm_platform_link_is_up (ifindex) : TRUE;
}

gboolean
nm_device_bring_up (NMDevice *self, gboolean block, gboolean *no_firmware)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean device_is_up = FALSE;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	nm_log_dbg (LOGD_HW, "(%s): bringing up device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->bring_up) {
		if (!NM_DEVICE_GET_CLASS (self)->bring_up (self, no_firmware))
			return FALSE;
	}

	device_is_up = nm_device_is_up (self);
	if (block && !device_is_up) {
		int ifindex = nm_device_get_ip_ifindex (self);
		gint64 wait_until = nm_utils_get_monotonic_timestamp_us () + 10000 /* microseconds */;

		do {
			g_usleep (200);
			if (!nm_platform_link_refresh (ifindex))
				return FALSE;
			device_is_up = nm_device_is_up (self);
		} while (!device_is_up && nm_utils_get_monotonic_timestamp_us () < wait_until);
	}

	if (!device_is_up) {
		if (block)
			nm_log_warn (LOGD_HW, "(%s): device not up after timeout!", nm_device_get_iface (self));
		else
			nm_log_dbg (LOGD_HW, "(%s): device not up immediately", nm_device_get_iface (self));
		return FALSE;
	}

	/* Devices that support carrier detect must be IFF_UP to report carrier
	 * changes; so after setting the device IFF_UP we must suppress startup
	 * complete (via a pending action) until either the carrier turns on, or
	 * a timeout is reached.
	 */
	if (device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)) {
		if (priv->carrier_wait_id) {
			g_source_remove (priv->carrier_wait_id);
			nm_device_remove_pending_action (self, "carrier wait", TRUE);
		}
		priv->carrier_wait_id = g_timeout_add_seconds (5, carrier_wait_timeout, self);
		nm_device_add_pending_action (self, "carrier wait", TRUE);
	}

	/* Can only get HW address of some devices when they are up */
	nm_device_update_hw_address (self);

	_update_ip4_address (self);
	return TRUE;
}

static void
check_carrier (NMDevice *device)
{
	int ifindex = nm_device_get_ip_ifindex (device);

	if (!device_has_capability (device, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
		nm_device_set_carrier (device, nm_platform_link_is_connected (ifindex));
}

static gboolean
bring_up (NMDevice *device, gboolean *no_firmware)
{
	int ifindex = nm_device_get_ip_ifindex (device);
	gboolean result;

	if (ifindex <= 0) {
		if (no_firmware)
			*no_firmware = FALSE;
		return TRUE;
	}

	result = nm_platform_link_set_up (ifindex);
	if (no_firmware)
		*no_firmware = nm_platform_get_error () == NM_PLATFORM_ERROR_NO_FIRMWARE;

	/* Store carrier immediately. */
	if (result && device_has_capability (device, NM_DEVICE_CAP_CARRIER_DETECT))
		check_carrier (device);

	return result;
}

void
nm_device_take_down (NMDevice *self, gboolean block)
{
	gboolean device_is_up;

	g_return_if_fail (NM_IS_DEVICE (self));

	nm_log_dbg (LOGD_HW, "(%s): taking down device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->take_down) {
		if (!NM_DEVICE_GET_CLASS (self)->take_down (self))
			return;
	}

	device_is_up = nm_device_is_up (self);
	if (block && device_is_up) {
		int ifindex = nm_device_get_ip_ifindex (self);
		gint64 wait_until = nm_utils_get_monotonic_timestamp_us () + 10000 /* microseconds */;

		do {
			g_usleep (200);
			if (!nm_platform_link_refresh (ifindex))
				return;
			device_is_up = nm_device_is_up (self);
		} while (device_is_up && nm_utils_get_monotonic_timestamp_us () < wait_until);
	}

	if (device_is_up) {
		if (block)
			nm_log_warn (LOGD_HW, "(%s): device not down after timeout!", nm_device_get_iface (self));
		else
			nm_log_dbg (LOGD_HW, "(%s): device not down immediately", nm_device_get_iface (self));
	}
}

static gboolean
take_down (NMDevice *device)
{
	int ifindex = nm_device_get_ip_ifindex (device);

	if (ifindex > 0)
		return nm_platform_link_set_down (ifindex);

	/* devices without ifindex are always up. */
	nm_log_dbg (LOGD_HW, "(%s): cannot take down device without ifindex", nm_device_get_iface (device));
	return FALSE;
}

void
nm_device_set_firmware_missing (NMDevice *self, gboolean new_missing)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->firmware_missing != new_missing) {
		priv->firmware_missing = new_missing;
		g_object_notify (G_OBJECT (self), NM_DEVICE_FIRMWARE_MISSING);
	}
}

gboolean
nm_device_get_firmware_missing (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->firmware_missing;
}

static NMIP4Config *
find_ip4_lease_config (NMDevice *device,
                       NMConnection *connection,
                       NMIP4Config *ext_ip4_config)
{
	const char *ip_iface = nm_device_get_ip_iface (device);
	GSList *leases, *liter;
	NMIP4Config *found = NULL;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (ext_ip4_config), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	leases = nm_dhcp_manager_get_lease_ip_configs (nm_dhcp_manager_get (),
	                                               ip_iface,
	                                               nm_connection_get_uuid (connection),
	                                               FALSE);
	for (liter = leases; liter && !found; liter = liter->next) {
		NMIP4Config *lease_config = liter->data;
		const NMPlatformIP4Address *address = nm_ip4_config_get_address (lease_config, 0);
		guint32 gateway = nm_ip4_config_get_gateway (lease_config);

		g_assert (address);
		if (!nm_ip4_config_address_exists (ext_ip4_config, address))
			continue;
		if (gateway != nm_ip4_config_get_gateway (ext_ip4_config))
			continue;
		found = g_object_ref (lease_config);
	}

	g_slist_free_full (leases, g_object_unref);
	return found;
}

static void
capture_lease_config (NMDevice *device,
                      NMIP4Config *ext_ip4_config,
                      NMIP4Config **out_ip4_config,
                      NMIP6Config *ext_ip6_config,
                      NMIP6Config **out_ip6_config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	const GSList *connections, *citer;
	guint i;
	gboolean dhcp_used = FALSE;

	/* Ensure at least one address on the device has a non-infinite lifetime,
	 * otherwise DHCP cannot possibly be active on the device right now.
	 */
	if (ext_ip4_config && out_ip4_config) {
		for (i = 0; i < nm_ip4_config_get_num_addresses (ext_ip4_config); i++) {
			const NMPlatformIP4Address *addr = nm_ip4_config_get_address (ext_ip4_config, i);

			if (addr->lifetime != NM_PLATFORM_LIFETIME_PERMANENT) {
				dhcp_used = TRUE;
				break;
			}
		}
	} else if (ext_ip6_config && out_ip6_config) {
		for (i = 0; i < nm_ip6_config_get_num_addresses (ext_ip6_config); i++) {
			const NMPlatformIP6Address *addr = nm_ip6_config_get_address (ext_ip6_config, i);

			if (addr->lifetime != NM_PLATFORM_LIFETIME_PERMANENT) {
				dhcp_used = TRUE;
				break;
			}
		}
	} else {
		g_return_if_fail (   (ext_ip6_config && out_ip6_config)
		                  || (ext_ip4_config && out_ip4_config));
	}

	if (!dhcp_used)
		return;

	connections = nm_connection_provider_get_connections (priv->con_provider);
	for (citer = connections; citer; citer = citer->next) {
		NMConnection *candidate = citer->data;
		const char *method;

		if (!nm_device_check_connection_compatible (device, candidate))
			continue;

		/* IPv4 leases */
		method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP4_CONFIG);
		if (out_ip4_config && strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0) {
			*out_ip4_config = find_ip4_lease_config (device, candidate, ext_ip4_config);
			if (*out_ip4_config)
				return;
		}

		/* IPv6 leases */
		method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP6_CONFIG);
		if (out_ip6_config && strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0) {
			/* FIXME: implement find_ip6_lease_config() */
		}
	}
}

static void
update_ip_config (NMDevice *self, gboolean initial)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ifindex;
	gboolean linklocal6_just_completed = FALSE;
	gboolean capture_resolv_conf;
	NMDnsManagerResolvConfMode resolv_conf_mode;

	ifindex = nm_device_get_ip_ifindex (self);
	if (!ifindex)
		return;

	resolv_conf_mode = nm_dns_manager_get_resolv_conf_mode (nm_dns_manager_get ());
	capture_resolv_conf = initial && (resolv_conf_mode == NM_DNS_MANAGER_RESOLV_CONF_EXPLICIT);

	/* IPv4 */
	g_clear_object (&priv->ext_ip4_config);
	priv->ext_ip4_config = nm_ip4_config_capture (ifindex, capture_resolv_conf);

	if (priv->ext_ip4_config) {
		if (initial) {
			g_clear_object (&priv->dev_ip4_config);
			capture_lease_config (self, priv->ext_ip4_config, &priv->dev_ip4_config, NULL, NULL);
		}
		if (priv->dev_ip4_config)
			nm_ip4_config_subtract (priv->ext_ip4_config, priv->dev_ip4_config);
		if (priv->vpn4_config)
			nm_ip4_config_subtract (priv->ext_ip4_config, priv->vpn4_config);

		ip4_config_merge_and_apply (self, NULL, FALSE, NULL);
	}

	/* IPv6 */
	g_clear_object (&priv->ext_ip6_config);
	priv->ext_ip6_config = nm_ip6_config_capture (ifindex, capture_resolv_conf, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
	if (priv->ext_ip6_config) {

		/* Check this before modifying ext_ip6_config */
		linklocal6_just_completed = priv->linklocal6_timeout_id &&
		                            linklocal6_config_is_ready (priv->ext_ip6_config);

		if (priv->ac_ip6_config)
			nm_ip6_config_subtract (priv->ext_ip6_config, priv->ac_ip6_config);
		if (priv->dhcp6_ip6_config)
			nm_ip6_config_subtract (priv->ext_ip6_config, priv->dhcp6_ip6_config);
		if (priv->vpn6_config)
			nm_ip6_config_subtract (priv->ext_ip6_config, priv->vpn6_config);

		ip6_config_merge_and_apply (self, FALSE, NULL);
	}

	if (linklocal6_just_completed) {
		/* linklocal6 is ready now, do the state transition... we are also
		 * invoked as g_idle_add, so no problems with reentrance doing it now.
		 */
		linklocal6_complete (self);
	}
}

void
nm_device_capture_initial_config (NMDevice *dev)
{
	update_ip_config (dev, TRUE);
}

static gboolean
queued_ip_config_change (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* Wait for any queued state changes */
	if (priv->queued_state.id)
		return TRUE;

	priv->queued_ip_config_id = 0;
	update_ip_config (self, FALSE);
	return FALSE;
}

static void
device_ip_changed (NMPlatform *platform, int ifindex, gpointer platform_object, NMPlatformSignalChangeType change_type, NMPlatformReason reason, gpointer user_data)
{
	NMDevice *self = user_data;

	if (nm_device_get_ip_ifindex (self) == ifindex) {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

		if (!priv->queued_ip_config_id)
			priv->queued_ip_config_id = g_idle_add (queued_ip_config_change, self);

		nm_log_dbg (LOGD_DEVICE, "(%s): queued IP config change",
		            nm_device_get_iface (self));
	}
}

static void
nm_device_queued_ip_config_change_clear (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->queued_ip_config_id) {
		nm_log_dbg (LOGD_DEVICE, "(%s): clearing queued IP config change",
		            nm_device_get_iface (self));
		g_source_remove (priv->queued_ip_config_id);
		priv->queued_ip_config_id = 0;
	}
}

/**
 * nm_device_get_managed():
 * @device: the #NMDevice
 *
 * Returns: %TRUE if the device is managed
 */
gboolean
nm_device_get_managed (NMDevice *device)
{
	NMDevicePrivate *priv;
	gboolean managed;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (device);

	/* Return the composite of all managed flags.  However, if the device
	 * is a default-unmanaged device, and would be managed except for the
	 * default-unmanaged flag (eg, only NM_UNMANAGED_DEFAULT is set) then
	 * the device is managed whenever it's not in the UNMANAGED state.
	 */
	managed = !(priv->unmanaged_flags & ~NM_UNMANAGED_DEFAULT);
	if (managed && (priv->unmanaged_flags & NM_UNMANAGED_DEFAULT))
		managed = (priv->state > NM_DEVICE_STATE_UNMANAGED);

	return managed;
}

/**
 * nm_device_get_unmanaged_flag():
 * @device: the #NMDevice
 *
 * Returns: %TRUE if the device is unmanaged for @flag.
 */
gboolean
nm_device_get_unmanaged_flag (NMDevice *device, NMUnmanagedFlags flag)
{
	return NM_DEVICE_GET_PRIVATE (device)->unmanaged_flags & flag;
}

/**
 * nm_device_get_default_unmanaged():
 * @device: the #NMDevice
 *
 * Returns: %TRUE if the device is by default unmanaged
 */
static gboolean
nm_device_get_default_unmanaged (NMDevice *device)
{
	return nm_device_get_unmanaged_flag (device, NM_UNMANAGED_DEFAULT);
}

void
nm_device_set_unmanaged (NMDevice *device,
                         NMUnmanagedFlags flag,
                         gboolean unmanaged,
                         NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	gboolean was_managed, now_managed;

	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (flag <= NM_UNMANAGED_LAST);

	priv = NM_DEVICE_GET_PRIVATE (device);

	was_managed = nm_device_get_managed (device);
	if (unmanaged)
		priv->unmanaged_flags |= flag;
	else
		priv->unmanaged_flags &= ~flag;
	now_managed = nm_device_get_managed (device);

	if (was_managed != now_managed) {
		nm_log_dbg (LOGD_DEVICE, "(%s): now %s",
			        nm_device_get_iface (device),
			        unmanaged ? "unmanaged" : "managed");

		g_object_notify (G_OBJECT (device), NM_DEVICE_MANAGED);

		if (unmanaged)
			nm_device_state_changed (device, NM_DEVICE_STATE_UNMANAGED, reason);
		else
			nm_device_state_changed (device, NM_DEVICE_STATE_UNAVAILABLE, reason);
	}
}

void
nm_device_set_unmanaged_quitting (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	/* It's OK to block here because we're quitting */
	if (nm_device_is_activating (device) || priv->state == NM_DEVICE_STATE_ACTIVATED)
		_set_state_full (device, NM_DEVICE_STATE_DEACTIVATING, NM_DEVICE_STATE_REASON_REMOVED, TRUE);

	nm_device_set_unmanaged (device,
	                         NM_UNMANAGED_INTERNAL,
	                         TRUE,
	                         NM_DEVICE_STATE_REASON_REMOVED);
}

/**
 * nm_device_set_initial_unmanaged_flag():
 * @device: the #NMDevice
 * @flag: an #NMUnmanagedFlag
 * @unmanaged: %TRUE or %FALSE to set or clear @flag
 *
 * Like nm_device_set_unmanaged() but must be set before the device is exported
 * and does not trigger state changes.  Should only be used when initializing
 * a device.
 */
void
nm_device_set_initial_unmanaged_flag (NMDevice *device,
                                      NMUnmanagedFlags flag,
                                      gboolean unmanaged)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (flag <= NM_UNMANAGED_LAST);

	priv = NM_DEVICE_GET_PRIVATE (device);
	g_return_if_fail (priv->path == NULL);

	if (unmanaged)
		priv->unmanaged_flags |= flag;
	else
		priv->unmanaged_flags &= ~flag;
}

void
nm_device_set_dhcp_timeout (NMDevice *device, guint32 timeout)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	NM_DEVICE_GET_PRIVATE (device)->dhcp_timeout = timeout;
}

void
nm_device_set_dhcp_anycast_address (NMDevice *device, guint8 *addr)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (priv->dhcp_anycast_address) {
		g_byte_array_free (priv->dhcp_anycast_address, TRUE);
		priv->dhcp_anycast_address = NULL;
	}

	if (addr) {
		priv->dhcp_anycast_address = g_byte_array_sized_new (ETH_ALEN);
		g_byte_array_append (priv->dhcp_anycast_address, addr, ETH_ALEN);
	}
}

/**
 * nm_device_connection_is_available():
 * @device: the #NMDevice
 * @connection: the #NMConnection to check for availability
 * @allow_device_override: set to %TRUE to let the device do specific checks
 *
 * Check if @connection is available to be activated on @device.  Normally this
 * only checks if the connection is in @device's AvailableConnections property.
 * If @allow_device_override is %TRUE then the device is asked to do specific
 * checks that may bypass the AvailableConnections property.
 *
 * Returns: %TRUE if @connection can be activated on @device
 */
gboolean
nm_device_connection_is_available (NMDevice *device,
                                   NMConnection *connection,
                                   gboolean allow_device_override)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	gboolean available = FALSE;

	if (nm_device_get_default_unmanaged (device) && (priv->state == NM_DEVICE_STATE_UNMANAGED)) {
		/* default-unmanaged  devices in UNMANAGED state have no available connections
		 * so we must manually check whether the connection is available here.
		 */
		if (   nm_device_check_connection_compatible (device, connection)
		    && NM_DEVICE_GET_CLASS (device)->check_connection_available (device, connection, NULL))
			return TRUE;
	}

	available = !!g_hash_table_lookup (priv->available_connections, connection);
	if (!available && allow_device_override) {
		/* FIXME: hack for hidden WiFi becuase clients didn't consistently
		 * set the 'hidden' property to indicate hidden SSID networks.  If
		 * activating but the network isn't available let the device recheck
		 * availability.
		 */
		if (   nm_device_check_connection_compatible (device, connection)
		    && NM_DEVICE_GET_CLASS (device)->check_connection_available_wifi_hidden)
			available = NM_DEVICE_GET_CLASS (device)->check_connection_available_wifi_hidden (device, connection);
	}

	return available;
}

static void
_signal_available_connections_changed (NMDevice *device)
{
	g_object_notify (G_OBJECT (device), NM_DEVICE_AVAILABLE_CONNECTIONS);
}

static void
_clear_available_connections (NMDevice *device, gboolean do_signal)
{
	g_hash_table_remove_all (NM_DEVICE_GET_PRIVATE (device)->available_connections);
	if (do_signal == TRUE)
		_signal_available_connections_changed (device);
}

static gboolean
_try_add_available_connection (NMDevice *self, NMConnection *connection)
{
	if (nm_device_get_state (self) < NM_DEVICE_STATE_DISCONNECTED)
		return FALSE;

	if (nm_device_check_connection_compatible (self, connection)) {
		if (NM_DEVICE_GET_CLASS (self)->check_connection_available (self, connection, NULL)) {
			g_hash_table_insert (NM_DEVICE_GET_PRIVATE (self)->available_connections,
			                     g_object_ref (connection),
			                     GUINT_TO_POINTER (1));
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
_del_available_connection (NMDevice *device, NMConnection *connection)
{
	return g_hash_table_remove (NM_DEVICE_GET_PRIVATE (device)->available_connections, connection);
}

static gboolean
connection_requires_carrier (NMConnection *connection)
{
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	const char *method;
	gboolean ip4_carrier_wanted = FALSE, ip6_carrier_wanted = FALSE;
	gboolean ip4_used = FALSE, ip6_used = FALSE;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (   strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) != 0
	    && strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) != 0) {
		ip4_carrier_wanted = TRUE;

		/* If IPv4 wants a carrier and cannot fail, the whole connection
		 * requires a carrier regardless of the IPv6 method.
		 */
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (s_ip4 && !nm_setting_ip4_config_get_may_fail (s_ip4))
			return TRUE;
	}
	ip4_used = (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) != 0);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (   strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) != 0
	    && strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) != 0) {
		ip6_carrier_wanted = TRUE;

		/* If IPv6 wants a carrier and cannot fail, the whole connection
		 * requires a carrier regardless of the IPv4 method.
		 */
		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (s_ip6 && !nm_setting_ip6_config_get_may_fail (s_ip6))
			return TRUE;
	}
	ip6_used = (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) != 0);

	/* If an IP version wants a carrier and and the other IP version isn't
	 * used, the connection requires carrier since it will just fail without one.
	 */
	if (ip4_carrier_wanted && !ip6_used)
		return TRUE;
	if (ip6_carrier_wanted && !ip4_used)
		return TRUE;

	/* If both want a carrier, the whole connection wants a carrier */
	return ip4_carrier_wanted && ip6_carrier_wanted;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            const char *specific_object)
{
	/* Connections which require a network connection are not available when
	 * the device has no carrier, even with ignore-carrer=TRUE.
	 */
	if (NM_DEVICE_GET_PRIVATE (device)->carrier == FALSE)
		return connection_requires_carrier (connection) ? FALSE : TRUE;

	return TRUE;
}

void
nm_device_recheck_available_connections (NMDevice *device)
{
	NMDevicePrivate *priv;
	const GSList *connections, *iter;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE(device);

	if (priv->con_provider) {
		_clear_available_connections (device, FALSE);

		connections = nm_connection_provider_get_connections (priv->con_provider);
		for (iter = connections; iter; iter = g_slist_next (iter))
			_try_add_available_connection (device, NM_CONNECTION (iter->data));

		_signal_available_connections_changed (device);
	}
}

/**
 * nm_device_get_available_connections:
 * @device: the #NMDevice
 * @specific_object: a specific object path if any
 *
 * Returns a list of connections available to activate on the device, taking
 * into account any device-specific details given by @specific_object (like
 * WiFi access point path).
 *
 * Returns: caller-owned #GPtrArray of #NMConnections
 */
GPtrArray *
nm_device_get_available_connections (NMDevice *device, const char *specific_object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	GHashTableIter iter;
	guint num_available;
	NMConnection *connection = NULL;
	GPtrArray *array = NULL;

	num_available = g_hash_table_size (priv->available_connections);
	if (num_available > 0) {
		array = g_ptr_array_sized_new (num_available);
		g_hash_table_iter_init (&iter, priv->available_connections);
		while (g_hash_table_iter_next (&iter, (gpointer) &connection, NULL)) {
			/* If a specific object is given, only include connections that are
			 * compatible with it.
			 */
			if (   !specific_object
			    || NM_DEVICE_GET_CLASS (device)->check_connection_available (device, connection, specific_object))
				g_ptr_array_add (array, connection);
		}
	}
	return array;
}

static void
cp_connection_added (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data)
{
	if (_try_add_available_connection (NM_DEVICE (user_data), connection))
		_signal_available_connections_changed (NM_DEVICE (user_data));
}

static void
cp_connection_removed (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data)
{
	if (_del_available_connection (NM_DEVICE (user_data), connection))
		_signal_available_connections_changed (NM_DEVICE (user_data));
}

static void
cp_connection_updated (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data)
{
	gboolean added, deleted;

	/* FIXME: don't remove it from the hash if it's just going to get re-added */
	deleted = _del_available_connection (NM_DEVICE (user_data), connection);
	added = _try_add_available_connection (NM_DEVICE (user_data), connection);

	/* Only signal if the connection was removed OR added, but not both */
	if (added != deleted)
		_signal_available_connections_changed (NM_DEVICE (user_data));
}

gboolean
nm_device_supports_vlans (NMDevice *device)
{
	return nm_platform_link_supports_vlans (nm_device_get_ifindex (device));
}

/**
 * nm_device_add_pending_action():
 * @device: the #NMDevice to add the pending action to
 * @action: a static string that identifies the action
 * @assert_not_yet_pending: if %TRUE, assert that the @action is currently not yet pending.
 * Otherwise, ignore duplicate scheduling of the same action silently.
 *
 * Adds a pending action to the device.
 *
 * Returns: %TRUE if the action was added (and not already added before). %FALSE
 * if the same action is already scheduled. In the latter case, the action was not scheduled
 * a second time.
 */
gboolean
nm_device_add_pending_action (NMDevice *device, const char *action, gboolean assert_not_yet_pending)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	GSList *iter;
	guint count = 0;

	g_return_val_if_fail (action, FALSE);

	/* Check if the action is already pending. Cannot add duplicate actions */
	for (iter = priv->pending_actions; iter; iter = iter->next) {
		if (!strcmp (action, iter->data)) {
			if (assert_not_yet_pending) {
				nm_log_warn (LOGD_DEVICE, "(%s): add_pending_action (%d): '%s' already pending",
				             nm_device_get_iface (device),
				             count + g_slist_length (iter),
				             action);
				g_return_val_if_reached (FALSE);
			} else {
				nm_log_dbg (LOGD_DEVICE, "(%s): add_pending_action (%d): '%s' already pending (expected)",
				            nm_device_get_iface (device),
				            count + g_slist_length (iter),
				            action);
			}
			return FALSE;
		}
		count++;
	}

	priv->pending_actions = g_slist_append (priv->pending_actions, g_strdup (action));
	count++;

	nm_log_dbg (LOGD_DEVICE, "(%s): add_pending_action (%d): '%s'",
	            nm_device_get_iface (device),
	            count,
	            action);

	if (count == 1)
		g_object_notify (G_OBJECT (device), NM_DEVICE_HAS_PENDING_ACTION);

	return TRUE;
}

/**
 * nm_device_remove_pending_action():
 * @device: the #NMDevice to remove the pending action from
 * @action: a static string that identifies the action
 * @assert_is_pending: if %TRUE, assert that the @action is pending.
 * If %FALSE, don't do anything if the current action is not pending and
 * return %FALSE.
 *
 * Removes a pending action previously added by nm_device_add_pending_action().
 *
 * Returns: whether the @action was pending and is now removed.
 */
gboolean
nm_device_remove_pending_action (NMDevice *device, const char *action, gboolean assert_is_pending)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	GSList *iter;
	guint count = 0;

	g_return_val_if_fail (action, FALSE);

	for (iter = priv->pending_actions; iter; iter = iter->next) {
		if (!strcmp (action, iter->data)) {
			nm_log_dbg (LOGD_DEVICE, "(%s): remove_pending_action (%d): '%s'",
			            nm_device_get_iface (device),
			            count + g_slist_length (iter->next), /* length excluding 'iter' */
			            action);
			g_free (iter->data);
			priv->pending_actions = g_slist_delete_link (priv->pending_actions, iter);
			if (priv->pending_actions == NULL)
				g_object_notify (G_OBJECT (device), NM_DEVICE_HAS_PENDING_ACTION);
			return TRUE;
		}
		count++;
	}

	if (assert_is_pending) {
		nm_log_warn (LOGD_DEVICE, "(%s): remove_pending_action (%d): '%s' not pending",
		             nm_device_get_iface (device),
		             count,
		             action);
		g_return_val_if_reached (FALSE);
	} else {
		nm_log_dbg (LOGD_DEVICE, "(%s): remove_pending_action (%d): '%s' not pending (expected)",
		             nm_device_get_iface (device),
		             count,
		             action);
	}
	return FALSE;
}

gboolean
nm_device_has_pending_action (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	return !!priv->pending_actions;
}

/***********************************************************/

static void
_cleanup_generic_pre (NMDevice *self, gboolean deconfigure)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* Clean up when device was deactivated during call to firewall */
	if (priv->fw_manager) {
		NMConnection *connection;

		if (priv->fw_call) {
			nm_firewall_manager_cancel_call (priv->fw_manager, priv->fw_call);
			priv->fw_call = NULL;
		}

		connection = nm_device_get_connection (self);
		if (deconfigure && connection) {
			nm_firewall_manager_remove_from_zone (priv->fw_manager,
			                                      nm_device_get_ip_iface (self),
			                                      NULL);
		}
	}

	ip_check_gw_ping_cleanup (self);

	/* Break the activation chain */
	activation_source_clear (self, TRUE, AF_INET);
	activation_source_clear (self, TRUE, AF_INET6);

	/* Clear any queued transitions */
	nm_device_queued_state_clear (self);
	nm_device_queued_ip_config_change_clear (self);

	priv->ip4_state = priv->ip6_state = IP_NONE;

	dhcp4_cleanup (self, deconfigure, FALSE);
	arp_cleanup (self);
	dhcp6_cleanup (self, deconfigure, FALSE);
	linklocal6_cleanup (self);
	addrconf6_cleanup (self);
	dnsmasq_cleanup (self);
	aipd_cleanup (self);
}

static void
_cleanup_generic_post (NMDevice *self, gboolean deconfigure)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason ignored = NM_DEVICE_STATE_REASON_NONE;

	/* Clean up IP configs; this does not actually deconfigure the
	 * interface; the caller must flush routes and addresses explicitly.
	 */
	nm_device_set_ip4_config (self, NULL, TRUE, &ignored);
	nm_device_set_ip6_config (self, NULL, TRUE, &ignored);
	g_clear_object (&priv->dev_ip4_config);
	g_clear_object (&priv->ext_ip4_config);
	g_clear_object (&priv->vpn4_config);
	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->ac_ip6_config);
	g_clear_object (&priv->ext_ip6_config);
	g_clear_object (&priv->vpn6_config);
	g_clear_object (&priv->ip6_config);

	clear_act_request (self);

	/* Clear legacy IPv4 address property */
	if (priv->ip4_address) {
		priv->ip4_address = 0;
		g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_ADDRESS);
	}

	if (deconfigure) {
		/* Check if the device was deactivated, and if so, delete_link.
		 * Don't call delete_link synchronously because we are currently
		 * handling a state change -- which is not reentrant. */
		delete_on_deactivate_check_and_schedule (self, nm_device_get_ip_ifindex (self));
	}

	/* ip_iface should be cleared after flushing all routes and addreses, since
	 * those are identified by ip_iface, not by iface (which might be a tty
	 * or ATM device).
	 */
	nm_device_set_ip_iface (self, NULL);
}

/*
 * nm_device_cleanup
 *
 * Remove a device's routing table entries and IP addresses.
 *
 */
static void
nm_device_cleanup (NMDevice *self, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (reason == NM_DEVICE_STATE_REASON_NOW_MANAGED) {
		nm_log_info (LOGD_DEVICE, "(%s): preparing device",
		             nm_device_get_iface (self));
	} else {
		nm_log_info (LOGD_DEVICE, "(%s): deactivating device (reason '%s') [%d]",
		             nm_device_get_iface (self), reason_to_string (reason), reason);
	}

	/* Save whether or not we tried IPv6 for later */
	priv = NM_DEVICE_GET_PRIVATE (self);

	_cleanup_generic_pre (self, TRUE);

	/* Turn off kernel IPv6 */
	nm_device_ipv6_sysctl_set (self, "disable_ipv6", "1");
	nm_device_ipv6_sysctl_set (self, "accept_ra", "0");
	nm_device_ipv6_sysctl_set (self, "use_tempaddr", "0");

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate)
		NM_DEVICE_GET_CLASS (self)->deactivate (self);

	/* master: release slaves */
	nm_device_master_release_slaves (self);

	/* slave: mark no longer enslaved */
	g_clear_object (&priv->master);
	priv->enslaved = FALSE;
	g_object_notify (G_OBJECT (self), NM_DEVICE_MASTER);

	/* Take out any entries in the routing table and any IP address the device had. */
	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex > 0) {
		nm_platform_route_flush (ifindex);
		nm_platform_address_flush (ifindex);
	}

	_cleanup_generic_post (self, TRUE);
}

/***********************************************************/

static gboolean
ip_config_valid (NMDeviceState state)
{
	return (state == NM_DEVICE_STATE_UNMANAGED) ||
	        (state >= NM_DEVICE_STATE_IP_CHECK &&
	         state <= NM_DEVICE_STATE_DEACTIVATING);
}

static void
notify_ip_properties (NMDevice *device)
{
	g_object_notify (G_OBJECT (device), NM_DEVICE_IP_IFACE);
	g_object_notify (G_OBJECT (device), NM_DEVICE_IP4_CONFIG);
	g_object_notify (G_OBJECT (device), NM_DEVICE_DHCP4_CONFIG);
	g_object_notify (G_OBJECT (device), NM_DEVICE_IP6_CONFIG);
	g_object_notify (G_OBJECT (device), NM_DEVICE_DHCP6_CONFIG);
}

static void
_set_state_full (NMDevice *device,
                 NMDeviceState state,
                 NMDeviceStateReason reason,
                 gboolean quitting)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMDeviceState old_state;
	NMActRequest *req;
	gboolean no_firmware = FALSE;
	NMConnection *connection;

	/* Track re-entry */
	g_warn_if_fail (priv->in_state_changed == FALSE);
	priv->in_state_changed = TRUE;

	g_return_if_fail (NM_IS_DEVICE (device));

	/* Do nothing if state isn't changing, but as a special case allow
	 * re-setting UNAVAILABLE if the device is missing firmware so that we
	 * can retry device initialization.
	 */
	if (   (priv->state == state)
	    && !(state == NM_DEVICE_STATE_UNAVAILABLE && priv->firmware_missing)) {
		priv->in_state_changed = FALSE;
		return;
	}

	old_state = priv->state;
	priv->state = state;
	priv->state_reason = reason;

	nm_log_info (LOGD_DEVICE, "(%s): device state change: %s -> %s (reason '%s') [%d %d %d]",
	             nm_device_get_iface (device),
	             state_to_string (old_state),
	             state_to_string (state),
	             reason_to_string (reason),
	             old_state,
	             state,
	             reason);

	/* Clear any queued transitions */
	nm_device_queued_state_clear (device);

	dispatcher_cleanup (device);

	/* Cache the activation request for the dispatcher */
	req = priv->act_request ? g_object_ref (priv->act_request) : NULL;

	if (state <= NM_DEVICE_STATE_UNAVAILABLE) {
		_clear_available_connections (device, TRUE);
		g_clear_object (&priv->queued_act_request);
	}

	/* Update the available connections list when a device first becomes available */
	if (   state >= NM_DEVICE_STATE_DISCONNECTED
	    && old_state < NM_DEVICE_STATE_DISCONNECTED)
		nm_device_recheck_available_connections (device);

	/* Handle the new state here; but anything that could trigger
	 * another state change should be done below.
	 */
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		nm_device_set_firmware_missing (device, FALSE);
		if (old_state > NM_DEVICE_STATE_UNMANAGED) {
			/* Clean up if the device is now unmanaged but was activated */
			if (nm_device_get_act_request (device))
				nm_device_cleanup (device, reason);
			nm_device_take_down (device, TRUE);
			restore_ip6_properties (device);
		}
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state == NM_DEVICE_STATE_UNMANAGED) {
			save_ip6_properties (device);
			if (reason != NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED) {
				nm_device_ipv6_sysctl_set (device, "disable_ipv6", "1");
				nm_device_ipv6_sysctl_set (device, "accept_ra_defrtr", "0");
				nm_device_ipv6_sysctl_set (device, "accept_ra_pinfo", "0");
				nm_device_ipv6_sysctl_set (device, "accept_ra_rtr_pref", "0");
				nm_device_ipv6_sysctl_set (device, "use_tempaddr", "0");
			}
		}

		if (old_state == NM_DEVICE_STATE_UNMANAGED || priv->firmware_missing) {
			if (!nm_device_bring_up (device, TRUE, &no_firmware) && no_firmware)
				nm_log_warn (LOGD_HW, "(%s): firmware may be missing.", nm_device_get_iface (device));
			nm_device_set_firmware_missing (device, no_firmware ? TRUE : FALSE);
		}
		/* Ensure the device gets deactivated in response to stuff like
		 * carrier changes or rfkill.  But don't deactivate devices that are
		 * about to assume a connection since that defeats the purpose of
		 * assuming the device's existing connection.
		 *
		 * Note that we "deactivate" the device even when coming from
		 * UNMANAGED, to ensure that it's in a clean state.
		 */
		if (reason != NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED)
			nm_device_cleanup (device, reason);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state > NM_DEVICE_STATE_UNAVAILABLE)
			nm_device_cleanup (device, reason);
		break;
	default:
		break;
	}

	/* Reset autoconnect flag when the device is activating or connected. */
	if (   state >= NM_DEVICE_STATE_PREPARE
	    && state <= NM_DEVICE_STATE_ACTIVATED)
		priv->autoconnect = TRUE;

	g_object_notify (G_OBJECT (device), NM_DEVICE_STATE);
	g_object_notify (G_OBJECT (device), NM_DEVICE_STATE_REASON);
	g_signal_emit_by_name (device, "state-changed", state, old_state, reason);

	/* Post-process the event after internal notification */

	switch (state) {
	case NM_DEVICE_STATE_UNAVAILABLE:
		/* If the device can activate now (ie, it's got a carrier, the supplicant
		 * is active, or whatever) schedule a delayed transition to DISCONNECTED
		 * to get things rolling.  The device can't transition immediately because
		 * we can't change states again from the state handler for a variety of
		 * reasons.
		 */
		if (nm_device_is_available (device)) {
			nm_log_dbg (LOGD_DEVICE, "(%s): device is available, will transition to DISCONNECTED",
			            nm_device_get_iface (device));
			nm_device_queue_state (device, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
		} else {
			if (old_state == NM_DEVICE_STATE_UNMANAGED) {
				nm_log_dbg (LOGD_DEVICE, "(%s): device not yet available for transition to DISCONNECTED",
				            nm_device_get_iface (device));
			} else if (   old_state > NM_DEVICE_STATE_UNAVAILABLE
			           && nm_device_get_default_unmanaged (device))
				nm_device_queue_state (device, NM_DEVICE_STATE_UNMANAGED, NM_DEVICE_STATE_REASON_NONE);
		}
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		if (quitting) {
			nm_dispatcher_call_sync (DISPATCHER_ACTION_PRE_DOWN,
			                         nm_act_request_get_connection (req),
			                         device);
		} else {
			priv->dispatcher.post_state = NM_DEVICE_STATE_DISCONNECTED;
			priv->dispatcher.post_state_reason = reason;
			if (!nm_dispatcher_call (DISPATCHER_ACTION_PRE_DOWN,
			                         nm_act_request_get_connection (req),
			                         device,
			                         dispatcher_complete_proceed_state,
			                         device,
			                         &priv->dispatcher.call_id)) {
				/* Just proceed on errors */
				dispatcher_complete_proceed_state (0, device);
			}
		}
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (priv->queued_act_request) {
			NMActRequest *queued_req;

			queued_req = priv->queued_act_request;
			priv->queued_act_request = NULL;
			_device_activate (device, queued_req);
			g_object_unref (queued_req);
		} else if (   old_state > NM_DEVICE_STATE_DISCONNECTED
		           && nm_device_get_default_unmanaged (device))
			nm_device_queue_state (device, NM_DEVICE_STATE_UNMANAGED, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		nm_log_info (LOGD_DEVICE, "Activation (%s) successful, device activated.",
		             nm_device_get_iface (device));
		nm_dispatcher_call (DISPATCHER_ACTION_UP, nm_act_request_get_connection (req), device, NULL, NULL, NULL);
		break;
	case NM_DEVICE_STATE_FAILED:
		connection = nm_device_get_connection (device);
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s) failed for connection '%s'",
		             nm_device_get_iface (device),
		             connection ? nm_connection_get_id (connection) : "<unknown>");

		/* Notify any slaves of the unexpected failure */
		nm_device_master_release_slaves (device);

		/* If the connection doesn't yet have a timestamp, set it to zero so that
		 * we can distinguish between connections we've tried to activate and have
		 * failed (zero timestamp), connections that succeeded (non-zero timestamp),
		 * and those we haven't tried yet (no timestamp).
		 */
		if (connection && !nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (connection), NULL)) {
			nm_settings_connection_update_timestamp (NM_SETTINGS_CONNECTION (connection),
			                                         (guint64) 0,
			                                         TRUE);
		}

		/* Schedule the transition to DISCONNECTED.  The device can't transition
		 * immediately because we can't change states again from the state
		 * handler for a variety of reasons.
		 */
		nm_device_queue_state (device, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_IP_CHECK:
		nm_device_start_ip_check (device);

		/* IP-related properties are only valid when the device has IP configuration;
		 * now that it does, ensure their change notifications are emitted.
		 */
		notify_ip_properties (device);
		break;
	case NM_DEVICE_STATE_SECONDARIES:
		ip_check_gw_ping_cleanup (device);
		nm_log_dbg (LOGD_DEVICE, "(%s): device entered SECONDARIES state",
		            nm_device_get_iface (device));
		break;
	default:
		break;
	}

	if (state > NM_DEVICE_STATE_DISCONNECTED)
		delete_on_deactivate_unschedule (device);

	if (   (old_state == NM_DEVICE_STATE_ACTIVATED || old_state == NM_DEVICE_STATE_DEACTIVATING)
	    && (state != NM_DEVICE_STATE_DEACTIVATING)) {
		if (quitting)
			nm_dispatcher_call_sync (DISPATCHER_ACTION_DOWN, nm_act_request_get_connection (req), device);
		else
			nm_dispatcher_call (DISPATCHER_ACTION_DOWN, nm_act_request_get_connection (req), device, NULL, NULL, NULL);
	}

	/* IP-related properties are only valid when the device has IP configuration.
	 * If it no longer does, ensure their change notifications are emitted.
	 */
	if (ip_config_valid (old_state) && !ip_config_valid (state))
	    notify_ip_properties (device);

	/* Dispose of the cached activation request */
	if (req)
		g_object_unref (req);

	priv->in_state_changed = FALSE;
}

void
nm_device_state_changed (NMDevice *device,
                         NMDeviceState state,
                         NMDeviceStateReason reason)
{
	_set_state_full (device, state, reason, FALSE);
}

static gboolean
queued_set_state (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState new_state;
	NMDeviceStateReason new_reason;

	if (priv->queued_state.id) {
		nm_log_dbg (LOGD_DEVICE, "(%s): running queued state change to %s (id %d)",
			        nm_device_get_iface (self),
			        state_to_string (priv->queued_state.state),
			        priv->queued_state.id);

		/* Clear queued state struct before triggering state change, since
		 * the state change may queue another state.
		 */
		priv->queued_state.id = 0;
		new_state = priv->queued_state.state;
		new_reason = priv->queued_state.reason;
		nm_device_queued_state_clear (self);

		nm_device_state_changed (self, new_state, new_reason);
		nm_device_remove_pending_action (self, queued_state_to_string (new_state), TRUE);
	} else {
		g_warn_if_fail (priv->queued_state.state == NM_DEVICE_STATE_UNKNOWN);
		g_warn_if_fail (priv->queued_state.reason == NM_DEVICE_STATE_REASON_NONE);
	}
	return FALSE;
}

void
nm_device_queue_state (NMDevice *self,
                       NMDeviceState state,
                       NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->queued_state.id && priv->queued_state.state == state)
		return;

	/* Add pending action for the new state before clearing the queued states, so
	 * that we don't accidently pop all pending states and reach 'startup complete'  */
	nm_device_add_pending_action (self, queued_state_to_string (state), TRUE);

	/* We should only ever have one delayed state transition at a time */
	if (priv->queued_state.id) {
		nm_log_warn (LOGD_DEVICE, "(%s): overwriting previously queued state change to %s (%s)",
		             nm_device_get_iface (self),
		             state_to_string (priv->queued_state.state),
		             reason_to_string (priv->queued_state.reason));
		nm_device_queued_state_clear (self);
	}

	priv->queued_state.state = state;
	priv->queued_state.reason = reason;
	priv->queued_state.id = g_idle_add (queued_set_state, self);

	nm_log_dbg (LOGD_DEVICE, "(%s): queued state change to %s due to %s (id %d)",
	            nm_device_get_iface (self), state_to_string (state), reason_to_string (reason),
	            priv->queued_state.id);
}

NMDeviceState
nm_device_queued_state_peek (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_STATE_UNKNOWN);

	priv = NM_DEVICE_GET_PRIVATE (self);

	return priv->queued_state.id ? priv->queued_state.state : NM_DEVICE_STATE_UNKNOWN;
}

void
nm_device_queued_state_clear (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->queued_state.id) {
		nm_log_dbg (LOGD_DEVICE, "(%s): clearing queued state transition (id %d)",
		            nm_device_get_iface (self), priv->queued_state.id);
		g_source_remove (priv->queued_state.id);
		nm_device_remove_pending_action (self, queued_state_to_string (priv->queued_state.state), TRUE);
	}
	memset (&priv->queued_state, 0, sizeof (priv->queued_state));
}

NMDeviceState
nm_device_get_state (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (device)->state;
}

/***********************************************************/
/* NMConfigDevice interface related stuff */

static guint
nm_device_get_hw_address_length (NMDevice *dev, gboolean *out_permanent)
{
	return NM_DEVICE_GET_CLASS (dev)->get_hw_address_length (dev, out_permanent);
}

const guint8 *
nm_device_get_hw_address (NMDevice *dev, guint *out_len)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (dev), NULL);
	priv = NM_DEVICE_GET_PRIVATE (dev);

	if (out_len)
		*out_len = priv->hw_addr_len;

	if (priv->hw_addr_len == 0)
		return NULL;
	else
		return priv->hw_addr;
}

gboolean
nm_device_update_hw_address (NMDevice *dev)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	gboolean changed = FALSE, permanent = FALSE;

	priv->hw_addr_len = nm_device_get_hw_address_length (dev, &permanent);

	/* If the address can't be changed, don't bother trying */
	if (permanent)
		return FALSE;

	if (priv->hw_addr_len) {
		int ifindex = nm_device_get_ip_ifindex (dev);
		gsize addrlen;
		const guint8 *binaddr;

		g_return_val_if_fail (ifindex > 0, FALSE);

		binaddr = nm_platform_link_get_address (ifindex, &addrlen);

		if (addrlen != priv->hw_addr_len) {
			nm_log_err (LOGD_HW | LOGD_DEVICE,
			            "(%s): hardware address is wrong length (got %zd, expected %d)",
			            nm_device_get_iface (dev), addrlen, priv->hw_addr_len);
		} else {
			changed = !!memcmp (priv->hw_addr, binaddr, addrlen);
			if (changed) {
				char *addrstr = nm_utils_hwaddr_ntoa_len (binaddr, priv->hw_addr_len);

				memcpy (priv->hw_addr, binaddr, addrlen);
				nm_log_dbg (LOGD_HW | LOGD_DEVICE,
				            "(%s): hardware address is %s",
				            nm_device_get_iface (dev), addrstr);
				g_free (addrstr);
				g_object_notify (G_OBJECT (dev), NM_DEVICE_HW_ADDRESS);
			}
		}
	} else {
		int i;

		/* hw_addr_len is now 0; see if hw_addr was already empty */
		for (i = 0; i < sizeof (priv->hw_addr) && !changed; i++) {
			if (priv->hw_addr[i])
				changed = TRUE;
		}
		if (changed) {
			memset (priv->hw_addr, 0, sizeof (priv->hw_addr));
			nm_log_dbg (LOGD_HW | LOGD_DEVICE,
			            "(%s): previous hardware address is no longer valid",
			            nm_device_get_iface (dev));
			g_object_notify (G_OBJECT (dev), NM_DEVICE_HW_ADDRESS);
		}
	}

	return changed;
}

gboolean
nm_device_set_hw_addr (NMDevice *device, const guint8 *addr,
                       const char *detail, guint64 hw_log_domain)
{
	const char *iface;
	char *mac_str = NULL;
	gboolean success = FALSE;
	guint len;
	const guint8 *cur_addr = nm_device_get_hw_address (device, &len);

	g_return_val_if_fail (addr != NULL, FALSE);

	iface = nm_device_get_iface (device);

	/* Do nothing if current MAC is same */
	if (cur_addr && !memcmp (cur_addr, addr, len)) {
		nm_log_dbg (LOGD_DEVICE | hw_log_domain, "(%s): no MAC address change needed", iface);
		return TRUE;
	}

	mac_str = nm_utils_hwaddr_ntoa_len (addr, len);

	/* Can't change MAC address while device is up */
	nm_device_take_down (device, FALSE);

	success = nm_platform_link_set_address (nm_device_get_ip_ifindex (device), addr, len);
	if (success) {
		/* MAC address succesfully changed; update the current MAC to match */
		nm_device_update_hw_address (device);
		cur_addr = nm_device_get_hw_address (device, NULL);
		if (memcmp (cur_addr, addr, len) == 0) {
			nm_log_info (LOGD_DEVICE | hw_log_domain, "(%s): %s MAC address to %s",
			             iface, detail, mac_str);
		} else {
			nm_log_warn (LOGD_DEVICE | hw_log_domain, "(%s): new MAC address %s "
			             "not successfully set",
			             iface, mac_str);
			success = FALSE;
		}
	} else {
		nm_log_warn (LOGD_DEVICE | hw_log_domain, "(%s): failed to %s MAC address to %s",
		             iface, detail, mac_str);
	}
	nm_device_bring_up (device, TRUE, NULL);
	g_free (mac_str);

	return success;
}

/**
 * nm_device_spec_match_list:
 * @device: an #NMDevice
 * @specs: (element-type utf8): a list of device specs
 *
 * Checks if @device matches any of the specifications in @specs. The
 * currently-supported spec types are:
 *
 *     "mac:00:11:22:33:44:55" - matches a device with the given
 *     hardware address
 *
 *     "interface-name:foo0" - matches a device with the given
 *     interface name
 *
 *     "s390-subchannels:00.11.22" - matches a device with the given
 *     z/VM / s390 subchannels.
 *
 *     "*" - matches any device
 *
 * Returns: #TRUE if @device matches one of the specs in @specs
 */
gboolean
nm_device_spec_match_list (NMDevice *device, const GSList *specs)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	if (!specs)
		return FALSE;

	return NM_DEVICE_GET_CLASS (device)->spec_match_list (device, specs);
}

static gboolean
spec_match_list (NMDevice *device, const GSList *specs)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	char *hwaddr_str;
	gboolean matched = FALSE;

	if (nm_match_spec_string (specs, "*"))
		return TRUE;

	if (priv->hw_addr_len) {
		hwaddr_str = nm_utils_hwaddr_ntoa_len (priv->hw_addr, priv->hw_addr_len);
		matched = nm_match_spec_hwaddr (specs, hwaddr_str);
		g_free (hwaddr_str);
	}

	if (!matched)
		matched = nm_match_spec_interface_name (specs, nm_device_get_iface (device));

	return matched;
}

static guint
get_hw_address_length (NMDevice *dev, gboolean *out_permanent)
{
	size_t len;

	if (nm_platform_link_get_address (nm_device_get_ip_ifindex (dev), &len))
		return len;
	else
		return 0;
}

/***********************************************************/

#define DEFAULT_AUTOCONNECT TRUE

static void
nm_device_init (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->type = NM_DEVICE_TYPE_UNKNOWN;
	priv->capabilities = NM_DEVICE_CAP_NM_SUPPORTED;
	priv->state = NM_DEVICE_STATE_UNMANAGED;
	priv->state_reason = NM_DEVICE_STATE_REASON_NONE;
	priv->dhcp_timeout = 0;
	priv->rfkill_type = RFKILL_TYPE_UNKNOWN;
	priv->autoconnect = DEFAULT_AUTOCONNECT;
	priv->unmanaged_flags = NM_UNMANAGED_INTERNAL;
	priv->available_connections = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);
	priv->ip6_saved_properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
}

static void
nm_device_config_device_interface_init (NMConfigDeviceInterface *iface)
{
	iface->spec_match_list = (gboolean (*) (NMConfigDevice *, const GSList *)) nm_device_spec_match_list;
	iface->get_hw_address = (const guint8 * (*) (NMConfigDevice *, guint *)) nm_device_get_hw_address;
}

/*
 * Get driver info from SIOCETHTOOL ioctl() for 'iface'
 * Returns driver and firmware versions to 'driver_version and' 'firmware_version'
 */
static gboolean
device_get_driver_info (const char *iface, char **driver_version, char **firmware_version)
{
	struct ethtool_drvinfo drvinfo;
	struct ifreq req;
	int fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_HW, "couldn't open control socket.");
		return FALSE;
	}

	/* Get driver and firmware version info */
	memset (&drvinfo, 0, sizeof (drvinfo));
	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, iface, IFNAMSIZ);
	drvinfo.cmd = ETHTOOL_GDRVINFO;
	req.ifr_data = &drvinfo;

	errno = 0;
	if (ioctl (fd, SIOCETHTOOL, &req) < 0) {
		nm_log_dbg (LOGD_HW, "SIOCETHTOOL ioctl() failed: cmd=ETHTOOL_GDRVINFO, iface=%s, errno=%d",
		            iface, errno);
		close (fd);
		return FALSE;
	}
	if (driver_version)
		*driver_version = g_strdup (drvinfo.version);
	if (firmware_version)
		*firmware_version = g_strdup (drvinfo.fw_version);

	close (fd);
	return TRUE;
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDevice *dev;
	NMDevicePrivate *priv;
	NMPlatform *platform;
	static guint32 id = 0;

	object = G_OBJECT_CLASS (nm_device_parent_class)->constructor (type,
	                         n_construct_params,
	                         construct_params);
	if (!object)
		return NULL;

	dev = NM_DEVICE (object);
	priv = NM_DEVICE_GET_PRIVATE (dev);

	if (!priv->iface) {
		nm_log_err (LOGD_DEVICE, "No device interface provided, ignoring");
		goto error;
	}

	if (!priv->udi) {
		/* Use a placeholder UDI until we get a real one */
		priv->udi = g_strdup_printf ("/virtual/device/placeholder/%d", id++);
	}

	if (NM_DEVICE_GET_CLASS (dev)->get_generic_capabilities)
		priv->capabilities |= NM_DEVICE_GET_CLASS (dev)->get_generic_capabilities (dev);

	priv->fw_manager = nm_firewall_manager_get ();

	device_get_driver_info (priv->iface, &priv->driver_version, &priv->firmware_version);

	/* Watch for external IP config changes */
	platform = nm_platform_get ();
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, G_CALLBACK (device_ip_changed), dev);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, G_CALLBACK (device_ip_changed), dev);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, G_CALLBACK (device_ip_changed), dev);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, G_CALLBACK (device_ip_changed), dev);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK (link_changed_cb), dev);

	return object;

error:
	g_object_unref (dev);
	return NULL;
}

static void
constructed (GObject *object)
{
	NMDevice *dev = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);

	nm_device_update_hw_address (dev);

	if (NM_DEVICE_GET_CLASS (dev)->update_permanent_hw_address)
		NM_DEVICE_GET_CLASS (dev)->update_permanent_hw_address (dev);

	if (NM_DEVICE_GET_CLASS (dev)->update_initial_hw_address)
		NM_DEVICE_GET_CLASS (dev)->update_initial_hw_address (dev);

	/* Have to call update_initial_hw_address() before calling get_ignore_carrier() */
	if (device_has_capability (dev, NM_DEVICE_CAP_CARRIER_DETECT)) {
		priv->ignore_carrier = nm_config_get_ignore_carrier (nm_config_get (), NM_CONFIG_DEVICE (dev));

		check_carrier (dev);
		nm_log_info (LOGD_HW,
		             "(%s): carrier is %s%s",
		             nm_device_get_iface (NM_DEVICE (dev)),
		             priv->carrier ? "ON" : "OFF",
		             priv->ignore_carrier ? " (but ignored)" : "");
	} else {
		/* Fake online link when carrier detection is not available. */
		priv->carrier = TRUE;
	}

	if (priv->ifindex > 0) {
		priv->is_software = nm_platform_link_is_software (priv->ifindex);
		priv->physical_port_id = nm_platform_link_get_physical_port_id (priv->ifindex);
	}

	if (priv->ifindex > 0)
		priv->mtu = nm_platform_link_get_mtu (priv->ifindex);

	priv->con_provider = nm_connection_provider_get ();
	g_assert (priv->con_provider);
	g_signal_connect (priv->con_provider,
	                  NM_CP_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (cp_connection_added),
	                  dev);

	g_signal_connect (priv->con_provider,
	                  NM_CP_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (cp_connection_removed),
	                  dev);

	g_signal_connect (priv->con_provider,
	                  NM_CP_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (cp_connection_updated),
	                  dev);

	G_OBJECT_CLASS (nm_device_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatform *platform;

	dispatcher_cleanup (self);

	_cleanup_generic_pre (self, FALSE);

	g_warn_if_fail (priv->slaves == NULL);
	g_assert (priv->master_ready_id == 0);

	_cleanup_generic_post (self, FALSE);

	g_clear_pointer (&priv->ip6_saved_properties, g_hash_table_unref);

	if (priv->recheck_assume_id) {
		g_source_remove (priv->recheck_assume_id);
		priv->recheck_assume_id = 0;
	}

	link_disconnect_action_cancel (self);

	if (priv->con_provider) {
		g_signal_handlers_disconnect_by_func (priv->con_provider, cp_connection_added, self);
		g_signal_handlers_disconnect_by_func (priv->con_provider, cp_connection_removed, self);
		g_signal_handlers_disconnect_by_func (priv->con_provider, cp_connection_updated, self);
		priv->con_provider = NULL;
	}

	g_hash_table_unref (priv->available_connections);
	priv->available_connections = NULL;

	if (priv->carrier_wait_id) {
		g_source_remove (priv->carrier_wait_id);
		priv->carrier_wait_id = 0;
	}

	g_clear_object (&priv->queued_act_request);

	platform = nm_platform_get ();
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (device_ip_changed), self);
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (link_changed_cb), self);

	g_clear_object (&priv->fw_manager);

	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_slist_free_full (priv->pending_actions, g_free);
	g_clear_pointer (&priv->physical_port_id, g_free);
	g_free (priv->udi);
	g_free (priv->path);
	g_free (priv->iface);
	g_free (priv->ip_iface);
	g_free (priv->driver);
	g_free (priv->driver_version);
	g_free (priv->firmware_version);
	g_free (priv->type_desc);
	if (priv->dhcp_anycast_address)
		g_byte_array_free (priv->dhcp_anycast_address, TRUE);

	G_OBJECT_CLASS (nm_device_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
	NMPlatformLink *platform_device;
	const char *hw_addr;
 
	switch (prop_id) {
	case PROP_PLATFORM_DEVICE:
		platform_device = g_value_get_pointer (value);
		if (platform_device) {
			g_free (priv->udi);
			priv->udi = g_strdup (platform_device->udi);
			g_free (priv->iface);
			priv->iface = g_strdup (platform_device->name);
			priv->ifindex = platform_device->ifindex;
			g_free (priv->driver);
			priv->driver = g_strdup (platform_device->driver);
		}
		break;
	case PROP_UDI:
		if (g_value_get_string (value)) {
			g_free (priv->udi);
			priv->udi = g_value_dup_string (value);
		}
		break;
	case PROP_IFACE:
		if (g_value_get_string (value)) {
			g_free (priv->iface);
			priv->ifindex = 0;
			priv->iface = g_value_dup_string (value);

			/* Only look up the ifindex if it appears to be an actual kernel
			 * interface name.  eg Bluetooth devices won't have one until we know
			 * the IP interface.
			 */
			if (priv->iface && !strchr (priv->iface, ':')) {
				priv->ifindex = nm_platform_link_get_ifindex (priv->iface);
				if (priv->ifindex <= 0)
					nm_log_warn (LOGD_HW, "(%s): failed to look up interface index", priv->iface);
			}
		}
		break;
	case PROP_DRIVER:
		if (g_value_get_string (value)) {
			g_free (priv->driver);
			priv->driver = g_value_dup_string (value);
		}
		break;
	case PROP_DRIVER_VERSION:
		g_free (priv->driver_version);
		priv->driver_version = g_strdup (g_value_get_string (value));
		break;
	case PROP_FIRMWARE_VERSION:
		g_free (priv->firmware_version);
		priv->firmware_version = g_strdup (g_value_get_string (value));
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_IP4_ADDRESS:
		priv->ip4_address = g_value_get_uint (value);
		break;
	case PROP_AUTOCONNECT:
		priv->autoconnect = g_value_get_boolean (value);
		break;
	case PROP_FIRMWARE_MISSING:
		priv->firmware_missing = g_value_get_boolean (value);
		break;
	case PROP_DEVICE_TYPE:
		g_return_if_fail (priv->type == NM_DEVICE_TYPE_UNKNOWN);
		priv->type = g_value_get_uint (value);
		break;
	case PROP_TYPE_DESC:
		g_free (priv->type_desc);
		priv->type_desc = g_value_dup_string (value);
		break;
	case PROP_RFKILL_TYPE:
		priv->rfkill_type = g_value_get_uint (value);
		break;
	case PROP_IS_MASTER:
		priv->is_master = g_value_get_boolean (value);
		break;
	case PROP_HW_ADDRESS:
		priv->hw_addr_len = nm_device_get_hw_address_length (NM_DEVICE (object), NULL);

		hw_addr = g_value_get_string (value);
		if (!hw_addr)
			break;
		if (priv->hw_addr_len == 0) {
			g_warn_if_fail (*hw_addr == '\0');
			break;
		}

		if (!nm_utils_hwaddr_aton_len (hw_addr, priv->hw_addr, priv->hw_addr_len)) {
			g_warning ("Could not parse hw-address '%s'", hw_addr);
			memset (priv->hw_addr, 0, sizeof (priv->hw_addr));
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

#define DBUS_TYPE_STATE_REASON_STRUCT (dbus_g_type_get_struct ("GValueArray", G_TYPE_UINT, G_TYPE_UINT, G_TYPE_INVALID))

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *ac_path = NULL;
	GPtrArray *array;
	GHashTableIter iter;
	NMConnection *connection;

	switch (prop_id) {
	case PROP_UDI:
		g_value_set_string (value, priv->udi);
		break;
	case PROP_IFACE:
		g_value_set_string (value, priv->iface);
		break;
	case PROP_IP_IFACE:
		if (ip_config_valid (priv->state))
			g_value_set_string (value, nm_device_get_ip_iface (self));
		else
			g_value_set_string (value, NULL);
		break;
	case PROP_IFINDEX:
		g_value_set_int (value, priv->ifindex);
		break;
	case PROP_DRIVER:
		g_value_set_string (value, priv->driver);
		break;
	case PROP_DRIVER_VERSION:
		g_value_set_string (value, priv->driver_version);
		break;
	case PROP_FIRMWARE_VERSION:
		g_value_set_string (value, priv->firmware_version);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, (priv->capabilities & ~NM_DEVICE_CAP_INTERNAL_MASK));
		break;
	case PROP_IP4_ADDRESS:
		g_value_set_uint (value, priv->ip4_address);
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, priv->carrier);
		break;
	case PROP_MTU:
		g_value_set_uint (value, priv->mtu);
		break;
	case PROP_IP4_CONFIG:
		if (ip_config_valid (priv->state) && priv->ip4_config)
			g_value_set_boxed (value, nm_ip4_config_get_dbus_path (priv->ip4_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_DHCP4_CONFIG:
		if (ip_config_valid (priv->state) && priv->dhcp4_config)
			g_value_set_boxed (value, nm_dhcp4_config_get_dbus_path (priv->dhcp4_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_IP6_CONFIG:
		if (ip_config_valid (priv->state) && priv->ip6_config)
			g_value_set_boxed (value, nm_ip6_config_get_dbus_path (priv->ip6_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_DHCP6_CONFIG:
		if (ip_config_valid (priv->state) && priv->dhcp6_config)
			g_value_set_boxed (value, nm_dhcp6_config_get_dbus_path (priv->dhcp6_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case PROP_STATE_REASON:
		g_value_take_boxed (value, dbus_g_type_specialized_construct (DBUS_TYPE_STATE_REASON_STRUCT));
		dbus_g_type_struct_set (value, 0, priv->state, 1, priv->state_reason, G_MAXUINT);
		break;
	case PROP_ACTIVE_CONNECTION:
		if (priv->act_request)
			ac_path = nm_active_connection_get_path (NM_ACTIVE_CONNECTION (priv->act_request));
		g_value_set_boxed (value, ac_path ? ac_path : "/");
		break;
	case PROP_DEVICE_TYPE:
		g_value_set_uint (value, priv->type);
		break;
	case PROP_MANAGED:
		g_value_set_boolean (value, nm_device_get_managed (self));
		break;
	case PROP_AUTOCONNECT:
		g_value_set_boolean (value, priv->autoconnect);
		break;
	case PROP_FIRMWARE_MISSING:
		g_value_set_boolean (value, priv->firmware_missing);
		break;
	case PROP_TYPE_DESC:
		g_value_set_string (value, priv->type_desc);
		break;
	case PROP_RFKILL_TYPE:
		g_value_set_uint (value, priv->rfkill_type);
		break;
	case PROP_AVAILABLE_CONNECTIONS:
		array = g_ptr_array_sized_new (g_hash_table_size (priv->available_connections));
		g_hash_table_iter_init (&iter, priv->available_connections);
		while (g_hash_table_iter_next (&iter, (gpointer) &connection, NULL))
			g_ptr_array_add (array, g_strdup (nm_connection_get_path (connection)));
		g_value_take_boxed (value, array);
		break;
	case PROP_PHYSICAL_PORT_ID:
		g_value_set_string (value, priv->physical_port_id);
		break;
	case PROP_IS_MASTER:
		g_value_set_boolean (value, priv->is_master);
		break;
	case PROP_MASTER:
		g_value_set_object (value, priv->master);
		break;
	case PROP_HW_ADDRESS:
		if (priv->hw_addr_len)
			g_value_take_string (value, nm_utils_hwaddr_ntoa_len (priv->hw_addr, priv->hw_addr_len));
		else
			g_value_set_string (value, NULL);
		break;
	case PROP_HAS_PENDING_ACTION:
		g_value_set_boolean (value, nm_device_has_pending_action (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_class_init (NMDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDevicePrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->constructor = constructor;
	object_class->constructed = constructed;

	klass->link_changed = link_changed;

	klass->is_available = is_available;
	klass->act_stage1_prepare = act_stage1_prepare;
	klass->act_stage2_config = act_stage2_config;
	klass->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	klass->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	klass->act_stage4_ip4_config_timeout = act_stage4_ip4_config_timeout;
	klass->act_stage4_ip6_config_timeout = act_stage4_ip6_config_timeout;
	klass->have_any_ready_slaves = have_any_ready_slaves;

	klass->spec_match_list = spec_match_list;
	klass->can_auto_connect = can_auto_connect;
	klass->check_connection_compatible = check_connection_compatible;
	klass->check_connection_available = check_connection_available;
	klass->is_up = is_up;
	klass->bring_up = bring_up;
	klass->take_down = take_down;
	klass->carrier_changed = carrier_changed;
	klass->get_hw_address_length = get_hw_address_length;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PLATFORM_DEVICE,
		 g_param_spec_pointer (NM_DEVICE_PLATFORM_DEVICE,
		                       "Platform Device",
		                       "NMPlatform device object",
		                       G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_UDI,
		 g_param_spec_string (NM_DEVICE_UDI,
		                      "UDI",
		                      "Unique Device Identifier",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_IFACE,
		 g_param_spec_string (NM_DEVICE_IFACE,
		                      "Interface",
		                      "Interface",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_IP_IFACE,
		 g_param_spec_string (NM_DEVICE_IP_IFACE,
		                      "IP Interface",
		                      "IP Interface",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_DRIVER,
		 g_param_spec_string (NM_DEVICE_DRIVER,
		                      "Driver",
		                      "Driver",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_DRIVER_VERSION,
		 g_param_spec_string (NM_DEVICE_DRIVER_VERSION,
		                      "Driver Version",
		                      "Driver Version",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_FIRMWARE_VERSION,
		 g_param_spec_string (NM_DEVICE_FIRMWARE_VERSION,
		                      "Firmware Version",
		                      "Firmware Version",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_CAPABILITIES,
		                    "Capabilities",
		                    "Capabilities",
		                    0, G_MAXUINT32, NM_DEVICE_CAP_NONE,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_CARRIER,
		                       "Carrier",
		                       "Carrier",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_DEVICE_MTU,
		                    "MTU",
		                    "MTU",
		                    0, G_MAXUINT32, 1500,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_IP4_ADDRESS,
		 g_param_spec_uint (NM_DEVICE_IP4_ADDRESS,
		                    "IP4 address",
		                    "IP4 address",
		                    0, G_MAXUINT32, 0, /* FIXME */
		                    G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_IP4_CONFIG,
		 g_param_spec_boxed (NM_DEVICE_IP4_CONFIG,
		                     "IP4 Config",
		                     "IP4 Config",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_DHCP4_CONFIG,
		 g_param_spec_boxed (NM_DEVICE_DHCP4_CONFIG,
		                     "DHCP4 Config",
		                     "DHCP4 Config",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_IP6_CONFIG,
		 g_param_spec_boxed (NM_DEVICE_IP6_CONFIG,
		                     "IP6 Config",
		                     "IP6 Config",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_DHCP6_CONFIG,
		 g_param_spec_boxed (NM_DEVICE_DHCP6_CONFIG,
		                     "DHCP6 Config",
		                     "DHCP6 Config",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_DEVICE_STATE,
		                    "State",
		                    "State",
		                    0, G_MAXUINT32, NM_DEVICE_STATE_UNKNOWN,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_STATE_REASON,
		 g_param_spec_boxed (NM_DEVICE_STATE_REASON,
		                     "StateReason",
		                     "StateReason",
		                     DBUS_TYPE_STATE_REASON_STRUCT,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTION,
		 g_param_spec_boxed (NM_DEVICE_ACTIVE_CONNECTION,
		                     "ActiveConnection",
		                     "ActiveConnection",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_DEVICE_TYPE,
		 g_param_spec_uint (NM_DEVICE_DEVICE_TYPE,
		                    "DeviceType",
		                    "DeviceType",
		                    0, G_MAXUINT32, NM_DEVICE_TYPE_UNKNOWN,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_MANAGED,
		 g_param_spec_boolean (NM_DEVICE_MANAGED,
		                       "Managed",
		                       "Managed",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_AUTOCONNECT,
		 g_param_spec_boolean (NM_DEVICE_AUTOCONNECT,
		                       "Autoconnect",
		                       "Autoconnect",
		                       DEFAULT_AUTOCONNECT,
		                       G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_FIRMWARE_MISSING,
		 g_param_spec_boolean (NM_DEVICE_FIRMWARE_MISSING,
		                       "FirmwareMissing",
		                       "Firmware missing",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_TYPE_DESC,
		 g_param_spec_string (NM_DEVICE_TYPE_DESC,
		                      "Type Description",
		                      "Device type description",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_RFKILL_TYPE,
		 g_param_spec_uint (NM_DEVICE_RFKILL_TYPE,
		                    "Rfkill Type",
		                    "Type of rfkill switch (if any) supported by this device",
		                    RFKILL_TYPE_WLAN,
		                    RFKILL_TYPE_MAX,
		                    RFKILL_TYPE_UNKNOWN,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_IFINDEX,
		 g_param_spec_int (NM_DEVICE_IFINDEX,
		                   "Ifindex",
		                   "Ifindex",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_AVAILABLE_CONNECTIONS,
		 g_param_spec_boxed (NM_DEVICE_AVAILABLE_CONNECTIONS,
		                     "AvailableConnections",
		                     "AvailableConnections",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PHYSICAL_PORT_ID,
		 g_param_spec_string (NM_DEVICE_PHYSICAL_PORT_ID,
		                      "PhysicalPortId",
		                      "PhysicalPortId",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_IS_MASTER,
		 g_param_spec_boolean (NM_DEVICE_IS_MASTER,
		                       "IsMaster",
		                       "IsMaster",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_MASTER,
		 g_param_spec_object (NM_DEVICE_MASTER,
		                      "Master",
		                      "Master",
		                      NM_TYPE_DEVICE,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_HW_ADDRESS,
		                      "Hardware Address",
		                      "Hardware address",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_HAS_PENDING_ACTION,
		 g_param_spec_boolean (NM_DEVICE_HAS_PENDING_ACTION,
		                       "Has pending action",
		                       "Has pending action",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* Signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDeviceClass, state_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 3,
		              G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);

	signals[AUTOCONNECT_ALLOWED] =
		g_signal_new ("autoconnect-allowed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              0,
		              autoconnect_allowed_accumulator, NULL, NULL,
		              G_TYPE_BOOLEAN, 0);

	signals[AUTH_REQUEST] =
		g_signal_new (NM_DEVICE_AUTH_REQUEST,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              /* dbus-glib context, connection, permission, allow_interaction, callback, user_data */
		              G_TYPE_NONE, 6, G_TYPE_POINTER, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_POINTER, G_TYPE_POINTER);

	signals[IP4_CONFIG_CHANGED] =
		g_signal_new (NM_DEVICE_IP4_CONFIG_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_OBJECT);

	signals[IP6_CONFIG_CHANGED] =
		g_signal_new (NM_DEVICE_IP6_CONFIG_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_OBJECT);

	signals[REMOVED] =
		g_signal_new (NM_DEVICE_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[RECHECK_AUTO_ACTIVATE] =
		g_signal_new (NM_DEVICE_RECHECK_AUTO_ACTIVATE,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[RECHECK_ASSUME] =
		g_signal_new (NM_DEVICE_RECHECK_ASSUME,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_object_info);

	dbus_g_error_domain_register (NM_DEVICE_ERROR, NULL, NM_TYPE_DEVICE_ERROR);
}

