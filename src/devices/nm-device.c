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

#include "config.h"

#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netlink/route/addr.h>

#include "nm-default.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "nm-platform.h"
#include "nm-rdisc.h"
#include "nm-lndp-rdisc.h"
#include "nm-dhcp-manager.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dnsmasq-manager.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-rfkill-manager.h"
#include "nm-firewall-manager.h"
#include "nm-enum-types.h"
#include "nm-settings-connection.h"
#include "nm-connection-provider.h"
#include "nm-auth-utils.h"
#include "nm-dispatcher.h"
#include "nm-config.h"
#include "nm-dns-manager.h"
#include "nm-core-internal.h"
#include "nm-default-route-manager.h"
#include "nm-route-manager.h"
#include "sd-ipv4ll.h"
#include "nm-audit-manager.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF (NMDevice);

#include "nmdbus-device.h"

static void nm_device_update_metered (NMDevice *self);
static void ip_check_ping_watch_cb (GPid pid, gint status, gpointer user_data);
static gboolean ip_config_valid (NMDeviceState state);
static NMActStageReturn dhcp4_start (NMDevice *self, NMConnection *connection, NMDeviceStateReason *reason);
static gboolean dhcp6_start (NMDevice *self, gboolean wait_for_ll, NMDeviceStateReason *reason);

G_DEFINE_ABSTRACT_TYPE (NMDevice, nm_device, NM_TYPE_EXPORTED_OBJECT)

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
	LINK_INITIALIZED,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
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
	PROP_NM_PLUGIN_MISSING,
	PROP_TYPE_DESC,
	PROP_RFKILL_TYPE,
	PROP_IFINDEX,
	PROP_AVAILABLE_CONNECTIONS,
	PROP_PHYSICAL_PORT_ID,
	PROP_IS_MASTER,
	PROP_MASTER,
	PROP_HW_ADDRESS,
	PROP_HAS_PENDING_ACTION,
	PROP_METERED,
	LAST_PROP
};

/***********************************************************/

#define PENDING_ACTION_DHCP4 "dhcp4"
#define PENDING_ACTION_DHCP6 "dhcp6"
#define PENDING_ACTION_AUTOCONF6 "autoconf6"

typedef enum {
	CLEANUP_TYPE_DECONFIGURE,
	CLEANUP_TYPE_KEEP,
	CLEANUP_TYPE_REMOVED,
} CleanupType;

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
	NMLogDomain log_domain;
	guint timeout;
	guint watch;
	GPid pid;
	const char *binary;
	const char *address;
	guint deadline;
} PingInfo;

typedef struct {
	NMDevice *device;
	guint idle_add_id;
	int ifindex;
} DeleteOnDeactivateData;

typedef struct {
	gboolean in_state_changed;
	gboolean initialized;
	gboolean platform_link_initialized;

	guint device_link_changed_id;
	guint device_ip_link_changed_id;

	NMDeviceState state;
	NMDeviceStateReason state_reason;
	QueuedState   queued_state;
	guint queued_ip4_config_id;
	guint queued_ip6_config_id;
	GSList *pending_actions;

	char *        udi;
	char *        iface;   /* may change, could be renamed by user */
	int           ifindex;
	char *        ip_iface;
	int           ip_ifindex;
	NMDeviceType  type;
	char *        type_desc;
	char *        type_description;
	NMDeviceCapabilities capabilities;
	char *        driver;
	char *        driver_version;
	char *        firmware_version;
	RfKillType    rfkill_type;
	gboolean      firmware_missing;
	gboolean      nm_plugin_missing;
	GHashTable *  available_connections;
	char *        hw_addr;
	guint         hw_addr_len;
	char *        perm_hw_addr;
	char *        initial_hw_addr;
	char *        physical_port_id;
	guint         dev_id;

	NMUnmanagedFlags        unmanaged_flags;
	gboolean                is_nm_owned; /* whether the device is a device owned and created by NM */
	DeleteOnDeactivateData *delete_on_deactivate_data; /* data for scheduled cleanup when deleting link (g_idle_add) */

	GCancellable *deactivating_cancellable;

	guint32         ip4_address;

	NMActRequest *  queued_act_request;
	gboolean        queued_act_request_is_waiting_for_carrier;
	NMActRequest *  act_request;
	guint           act_source_id;
	gpointer        act_source_func;
	guint           act_source6_id;
	gpointer        act_source6_func;
	guint           recheck_assume_id;
	struct {
		guint       		call_id;
		NMDeviceStateReason available_reason;
		NMDeviceStateReason unavailable_reason;
	}               recheck_available;
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
	gboolean        up;   /* IFF_UP */

	/* Generic DHCP stuff */
	guint32         dhcp_timeout;
	char *          dhcp_anycast_address;

	/* IP4 configuration info */
	NMIP4Config *   ip4_config;     /* Combined config from VPN, settings, and device */
	IpState         ip4_state;
	NMIP4Config *   con_ip4_config; /* config from the setting */
	NMIP4Config *   dev_ip4_config; /* Config from DHCP, PPP, LLv4, etc */
	NMIP4Config *   ext_ip4_config; /* Stuff added outside NM */
	NMIP4Config *   wwan_ip4_config; /* WWAN configuration */
	struct {
		gboolean v4_has;
		gboolean v4_is_assumed;
		NMPlatformIP4Route v4;
		gboolean v6_has;
		gboolean v6_is_assumed;
		NMPlatformIP6Route v6;
	} default_route;

	gboolean v4_commit_first_time;
	gboolean v6_commit_first_time;

	/* DHCPv4 tracking */
	NMDhcpClient *  dhcp4_client;
	gulong          dhcp4_state_sigid;
	NMDhcp4Config * dhcp4_config;
	guint           dhcp4_restart_id;
	NMIP4Config *   vpn4_config;  /* routes added by a VPN which uses this device */

	guint           arp_round2_id;
	PingInfo        gw_ping;

	/* dnsmasq stuff for shared connections */
	NMDnsMasqManager *dnsmasq_manager;
	gulong            dnsmasq_state_id;

	/* Firewall */
	NMFirewallPendingCall fw_call;

	/* IPv4LL stuff */
	sd_ipv4ll *    ipv4ll;
	guint          ipv4ll_timeout;

	/* IP6 configuration info */
	NMIP6Config *  ip6_config;
	IpState        ip6_state;
	NMIP6Config *  con_ip6_config; /* config from the setting */
	NMIP6Config *  vpn6_config;  /* routes added by a VPN which uses this device */
	NMIP6Config *  wwan_ip6_config;
	NMIP6Config *  ext_ip6_config; /* Stuff added outside NM */
	gboolean       nm_ipv6ll; /* TRUE if NM handles the device's IPv6LL address */
	guint32        ip6_mtu;

	NMRDisc *      rdisc;
	gulong         rdisc_changed_id;
	gulong         rdisc_timeout_id;
	NMSettingIP6ConfigPrivacy rdisc_use_tempaddr;
	/* IP6 config from autoconf */
	NMIP6Config *  ac_ip6_config;

	guint          linklocal6_timeout_id;

	GHashTable *   ip6_saved_properties;

	NMDhcpClient *  dhcp6_client;
	NMRDiscDHCPLevel dhcp6_mode;
	gulong          dhcp6_state_sigid;
	NMDhcp6Config * dhcp6_config;
	/* IP6 config from DHCP */
	NMIP6Config *   dhcp6_ip6_config;
	/* Event ID of the current IP6 config from DHCP */
	char *          dhcp6_event_id;
	guint           dhcp6_restart_id;

	/* allow autoconnect feature */
	gboolean        autoconnect;

	/* master interface for bridge/bond/team slave */
	NMDevice *      master;
	gboolean        enslaved;
	guint           master_ready_id;

	/* slave management */
	gboolean        is_master;
	GSList *        slaves;    /* list of SlaveInfo */

	NMMetered       metered;

	NMConnectionProvider *con_provider;
} NMDevicePrivate;

static gboolean nm_device_set_ip4_config (NMDevice *self,
                                          NMIP4Config *config,
                                          guint32 default_route_metric,
                                          gboolean commit,
                                          gboolean routes_full_sync,
                                          NMDeviceStateReason *reason);
static gboolean ip4_config_merge_and_apply (NMDevice *self,
                                            NMIP4Config *config,
                                            gboolean commit,
                                            NMDeviceStateReason *out_reason);

static gboolean nm_device_set_ip6_config (NMDevice *self,
                                          NMIP6Config *config,
                                          gboolean commit,
                                          gboolean routes_full_sync,
                                          NMDeviceStateReason *reason);

static gboolean nm_device_master_add_slave (NMDevice *self, NMDevice *slave, gboolean configure);
static void nm_device_slave_notify_enslave (NMDevice *self, gboolean success);
static void nm_device_slave_notify_release (NMDevice *self, NMDeviceStateReason reason);

static gboolean addrconf6_start_with_link_ready (NMDevice *self);
static gboolean dhcp6_start_with_link_ready (NMDevice *self, NMConnection *connection);
static NMActStageReturn linklocal6_start (NMDevice *self);

static void _carrier_wait_check_queued_act_request (NMDevice *self);

static gboolean nm_device_get_default_unmanaged (NMDevice *self);

static void _set_state_full (NMDevice *self,
                             NMDeviceState state,
                             NMDeviceStateReason reason,
                             gboolean quitting);

static void nm_device_update_hw_address (NMDevice *self);

static gboolean queued_ip4_config_change (gpointer user_data);
static gboolean queued_ip6_config_change (gpointer user_data);

static void _set_unmanaged_flags (NMDevice *self,
                                  NMUnmanagedFlags flags,
                                  gboolean unmanaged);

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
	if ((gsize) state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return state_table[NM_DEVICE_STATE_UNKNOWN];
}

static const char *
state_to_string (NMDeviceState state)
{
	return queued_state_to_string (state) + strlen (QUEUED_PREFIX);
}

static const char *reason_table[] = {
	[NM_DEVICE_STATE_REASON_UNKNOWN]                  = "unknown",
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
	[NM_DEVICE_STATE_REASON_NEW_ACTIVATION]           = "new-activation",
	[NM_DEVICE_STATE_REASON_PARENT_CHANGED]           = "parent-changed",
	[NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED]   = "parent-managed-changed",
};

static const char *
reason_to_string (NMDeviceStateReason reason)
{
	if ((gsize) reason < G_N_ELEMENTS (reason_table))
		return reason_table[reason];
	return reason_table[NM_DEVICE_STATE_REASON_UNKNOWN];
}

/***********************************************************/

gboolean
nm_device_ipv6_sysctl_set (NMDevice *self, const char *property, const char *value)
{
	return nm_platform_sysctl_set (NM_PLATFORM_GET, nm_utils_ip6_property_path (nm_device_get_ip_iface (self), property), value);
}

static guint32
nm_device_ipv6_sysctl_get_int32 (NMDevice *self, const char *property, gint32 fallback)
{
	return nm_platform_sysctl_get_int32 (NM_PLATFORM_GET, nm_utils_ip6_property_path (nm_device_get_ip_iface (self), property), fallback);
}

gboolean
nm_device_has_capability (NMDevice *self, NMDeviceCapabilities caps)
{
	return NM_FLAGS_ANY (NM_DEVICE_GET_PRIVATE (self)->capabilities, caps);
}

/***********************************************************/

const char *
nm_device_get_udi (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->udi;
}

const char *
nm_device_get_iface (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->iface;
}

int
nm_device_get_ifindex (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, 0);

	return NM_DEVICE_GET_PRIVATE (self)->ifindex;
}

gboolean
nm_device_is_software (NMDevice *self)
{
	return NM_FLAGS_HAS (NM_DEVICE_GET_PRIVATE (self)->capabilities, NM_DEVICE_CAP_IS_SOFTWARE);
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
	/* If it's not set, default to ifindex */
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
		priv->ip_ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, priv->ip_iface);
		if (priv->ip_ifindex > 0) {
			if (nm_platform_check_support_user_ipv6ll (NM_PLATFORM_GET))
				nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, priv->ip_ifindex, TRUE);

			if (!nm_platform_link_is_up (NM_PLATFORM_GET, priv->ip_ifindex))
				nm_platform_link_set_up (NM_PLATFORM_GET, priv->ip_ifindex, NULL);
		} else {
			/* Device IP interface must always be a kernel network interface */
			_LOGW (LOGD_HW, "failed to look up interface index");
		}
	}

	/* We don't care about any saved values from the old iface */
	g_hash_table_remove_all (priv->ip6_saved_properties);

	/* Emit change notification */
	if (g_strcmp0 (old_ip_iface, priv->ip_iface))
		g_object_notify (G_OBJECT (self), NM_DEVICE_IP_IFACE);
	g_free (old_ip_iface);
}

static gboolean
get_ip_iface_identifier (NMDevice *self, NMUtilsIPv6IfaceId *out_iid)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMLinkType link_type;
	const guint8 *hwaddr = NULL;
	size_t hwaddr_len = 0;
	int ifindex;
	gboolean success;

	/* If we get here, we *must* have a kernel netdev, which implies an ifindex */
	ifindex = nm_device_get_ip_ifindex (self);
	g_assert (ifindex);

	link_type = nm_platform_link_get_type (NM_PLATFORM_GET, ifindex);
	g_return_val_if_fail (link_type > NM_LINK_TYPE_UNKNOWN, 0);

	hwaddr = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, &hwaddr_len);
	if (!hwaddr_len)
		return FALSE;

	success = nm_utils_get_ipv6_interface_identifier (link_type,
	                                                  hwaddr,
	                                                  hwaddr_len,
	                                                  priv->dev_id,
	                                                  out_iid);
	if (!success) {
		_LOGW (LOGD_HW, "failed to generate interface identifier "
		       "for link type %u hwaddr_len %zu", link_type, hwaddr_len);
	}
	return success;
}

static gboolean
nm_device_get_ip_iface_identifier (NMDevice *self, NMUtilsIPv6IfaceId *iid)
{
	return NM_DEVICE_GET_CLASS (self)->get_ip_iface_identifier (self, iid);
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
 * nm_device_get_metered:
 * @setting: the #NMDevice
 *
 * Returns: the #NMDevice:metered property of the device.
 *
 * Since: 1.2
 **/
NMMetered
nm_device_get_metered (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_METERED_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->metered;
}

/**
 * nm_device_get_priority():
 * @self: the #NMDevice
 *
 * Returns: the device's routing priority.  Lower numbers means a "better"
 *  device, eg higher priority.
 */
int
nm_device_get_priority (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), 1000);

	/* Device 'priority' is used for the default route-metric and is based on
	 * the device type. The settings ipv4.route-metric and ipv6.route-metric
	 * can overwrite this default.
	 *
	 * Currently for both IPv4 and IPv6 we use the same default values.
	 *
	 * The route-metric is used for the metric of the routes of device.
	 * This also applies to the default route. Therefore it affects also
	 * which device is the "best".
	 *
	 * For comparison, note that iproute2 by default adds IPv4 routes with
	 * metric 0, and IPv6 routes with metric 1024. The latter is the IPv6
	 * "user default" in the kernel (NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6).
	 * In kernel, the full uint32_t range is available for route
	 * metrics (except for IPv6, where 0 means 1024).
	 */

	switch (nm_device_get_device_type (self)) {
	/* 50 is reserved for VPN (NM_VPN_ROUTE_METRIC_DEFAULT) */
	case NM_DEVICE_TYPE_ETHERNET:
		return 100;
	case NM_DEVICE_TYPE_INFINIBAND:
		return 150;
	case NM_DEVICE_TYPE_ADSL:
		return 200;
	case NM_DEVICE_TYPE_WIMAX:
		return 250;
	case NM_DEVICE_TYPE_BOND:
		return 300;
	case NM_DEVICE_TYPE_TEAM:
		return 350;
	case NM_DEVICE_TYPE_VLAN:
		return 400;
	case NM_DEVICE_TYPE_BRIDGE:
		return 425;
	case NM_DEVICE_TYPE_WIFI:
		return 600;
	case NM_DEVICE_TYPE_OLPC_MESH:
		return 650;
	case NM_DEVICE_TYPE_MODEM:
		return 700;
	case NM_DEVICE_TYPE_BT:
		return 750;
	case NM_DEVICE_TYPE_GENERIC:
		return 950;
	case NM_DEVICE_TYPE_UNKNOWN:
		return 10000;
	case NM_DEVICE_TYPE_UNUSED1:
	case NM_DEVICE_TYPE_UNUSED2:
		/* omit default: to get compiler warning about missing switch cases */
		break;
	}
	return 11000;
}

static guint32
_get_ipx_route_metric (NMDevice *self,
                       gboolean is_v4)
{
	char *value;
	gint64 route_metric;
	NMSettingIPConfig *s_ip;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE (self), G_MAXUINT32);

	connection = nm_device_get_connection (self);
	if (connection) {
		s_ip = is_v4
		       ? nm_connection_get_setting_ip4_config (connection)
		       : nm_connection_get_setting_ip6_config (connection);

		/* Slave interfaces don't have IP settings, but we may get here when
		 * external changes are made or when noticing IP changes when starting
		 * the slave connection.
		 */
		if (s_ip) {
			route_metric = nm_setting_ip_config_get_route_metric (s_ip);
			if (route_metric >= 0)
				goto out;
		}
	}

	/* use the current NMConfigData, which makes this configuration reloadable.
	 * Note that that means that the route-metric might change between SIGHUP.
	 * You must cache the returned value if that is a problem. */
	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               is_v4 ? "ipv4.route-metric" : "ipv6.route-metric", self);
	if (value) {
		route_metric = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT32, -1);
		g_free (value);

		if (route_metric >= 0)
			goto out;
	}
	route_metric = nm_device_get_priority (self);
out:
	if (!is_v4)
		route_metric = nm_utils_ip6_route_metric_normalize (route_metric);
	return route_metric;
}

guint32
nm_device_get_ip4_route_metric (NMDevice *self)
{
	return _get_ipx_route_metric (self, TRUE);
}

guint32
nm_device_get_ip6_route_metric (NMDevice *self)
{
	return _get_ipx_route_metric (self, FALSE);
}

const NMPlatformIP4Route *
nm_device_get_ip4_default_route (NMDevice *self, gboolean *out_is_assumed)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (out_is_assumed)
		*out_is_assumed = priv->default_route.v4_is_assumed;

	return priv->default_route.v4_has ? &priv->default_route.v4 : NULL;
}

const NMPlatformIP6Route *
nm_device_get_ip6_default_route (NMDevice *self, gboolean *out_is_assumed)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (out_is_assumed)
		*out_is_assumed = priv->default_route.v6_is_assumed;

	return priv->default_route.v6_has ? &priv->default_route.v6 : NULL;
}

const char *
nm_device_get_type_desc (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->type_desc;
}

const char *
nm_device_get_type_description (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	/* Beware: this function should return the same
	 * value as nm_device_get_type_description() in libnm. */

	return NM_DEVICE_GET_CLASS (self)->get_type_description (self);
}

static const char *
get_type_description (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->type_description) {
		const char *typename;

		typename = G_OBJECT_TYPE_NAME (self);
		if (g_str_has_prefix (typename, "NMDevice"))
			typename += 8;
		priv->type_description = g_ascii_strdown (typename, -1);
	}

	return priv->type_description;
}

gboolean
nm_device_has_carrier (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->carrier;
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
nm_device_get_physical_port_id (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->physical_port_id;
}

/***********************************************************/

static gboolean
nm_device_uses_generated_assumed_connection (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;

	if (   priv->act_request
	    && nm_active_connection_get_assumed (NM_ACTIVE_CONNECTION (priv->act_request))) {
		connection = nm_act_request_get_connection (priv->act_request);
		if (   connection
		    && nm_settings_connection_get_nm_generated_assumed (NM_SETTINGS_CONNECTION (connection)))
			return TRUE;
	}
	return FALSE;
}

gboolean
nm_device_uses_assumed_connection (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   priv->act_request
	    && nm_active_connection_get_assumed (NM_ACTIVE_CONNECTION (priv->act_request)))
		return TRUE;
	return FALSE;
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
 * @self: the master device
 * @slave: the slave device to enslave
 * @connection: (allow-none): the slave device's connection
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function enslaves @slave.
 *
 * Returns: %TRUE on success, %FALSE on failure or if this device cannot enslave
 *  other devices.
 */
static gboolean
nm_device_enslave_slave (NMDevice *self, NMDevice *slave, NMConnection *connection)
{
	SlaveInfo *info;
	gboolean success = FALSE;
	gboolean configure;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (self)->enslave_slave != NULL, FALSE);

	info = find_slave_info (self, slave);
	if (!info)
		return FALSE;

	if (info->enslaved)
		success = TRUE;
	else {
		configure = (info->configure && connection != NULL);
		if (configure)
			g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

		success = NM_DEVICE_GET_CLASS (self)->enslave_slave (self, slave, connection, configure);
		info->enslaved = success;
	}

	nm_device_slave_notify_enslave (info->slave, success);

	/* Ensure the device's hardware address is up-to-date; it often changes
	 * when slaves change.
	 */
	nm_device_update_hw_address (self);

	/* Restart IP configuration if we're waiting for slaves.  Do this
	 * after updating the hardware address as IP config may need the
	 * new address.
	 */
	if (success) {
		if (NM_DEVICE_GET_PRIVATE (self)->ip4_state == IP_WAIT)
			nm_device_activate_stage3_ip4_start (self);

		if (NM_DEVICE_GET_PRIVATE (self)->ip6_state == IP_WAIT)
			nm_device_activate_stage3_ip6_start (self);
	}

	return success;
}

/**
 * nm_device_release_one_slave:
 * @self: the master device
 * @slave: the slave device to release
 * @configure: whether @self needs to actually release @slave
 * @reason: the state change reason for the @slave
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function releases the previously enslaved @slave and/or
 * updates the state of @self and @slave to reflect its release.
 *
 * Returns: %TRUE on success, %FALSE on failure, if this device cannot enslave
 *  other devices, or if @slave was never enslaved.
 */
static gboolean
nm_device_release_one_slave (NMDevice *self, NMDevice *slave, gboolean configure, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	SlaveInfo *info;
	gboolean success = FALSE;

	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (self)->release_slave != NULL, FALSE);

	info = find_slave_info (self, slave);
	if (!info)
		return FALSE;
	priv->slaves = g_slist_remove (priv->slaves, info);

	if (info->enslaved) {
		success = NM_DEVICE_GET_CLASS (self)->release_slave (self, slave, configure);
		/* The release_slave() implementation logs success/failure (in the
		 * correct device-specific log domain), so we don't have to do anything.
		 */
	}

	if (!configure) {
		g_warn_if_fail (reason == NM_DEVICE_STATE_REASON_NONE || reason == NM_DEVICE_STATE_REASON_REMOVED);
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
	nm_device_update_hw_address (self);

	return success;
}

/**
 * can_unmanaged_external_down:
 * @self: the device
 *
 * Check whether the device should stay NM_UNMANAGED_EXTERNAL_DOWN unless
 * IFF_UP-ed externally.
 */
static gboolean
can_unmanaged_external_down (NMDevice *self)
{
	return   nm_device_is_software (self)
	      && !nm_device_get_is_nm_owned (self);
}

/**
 * nm_device_finish_init:
 * @self: the master device
 *
 * Whatever needs to be done post-initialization, when the device has a DBus
 * object name.
 */
void
nm_device_finish_init (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_assert (priv->initialized == FALSE);

	/* Do not manage externally created software devices until they are IFF_UP */
	if (   NM_DEVICE_GET_CLASS (self)->can_unmanaged_external_down (self)
	    && !nm_platform_link_is_up (NM_PLATFORM_GET, priv->ifindex)
	    && priv->ifindex > 0)
		nm_device_set_initial_unmanaged_flag (self, NM_UNMANAGED_EXTERNAL_DOWN, TRUE);

	if (priv->master)
		nm_device_enslave_slave (priv->master, self, NULL);

	if (priv->ifindex > 0) {
		if (priv->ifindex == 1) {
			/* Unmanaged the loopback device with an explicit NM_UNMANAGED_LOOPBACK flag.
			 * Later we might want to manage 'lo' too. Currently that doesn't work because
			 * NetworkManager might down the interface or remove the 127.0.0.1 address. */
			nm_device_set_initial_unmanaged_flag (self, NM_UNMANAGED_LOOPBACK, TRUE);
		} else if (priv->platform_link_initialized || (priv->is_nm_owned && nm_device_is_software (self))) {
			gboolean platform_unmanaged = FALSE;

			if (nm_platform_link_get_unmanaged (NM_PLATFORM_GET, priv->ifindex, &platform_unmanaged))
				nm_device_set_initial_unmanaged_flag (self, NM_UNMANAGED_DEFAULT, platform_unmanaged);
		} else {
			/* Hardware and externally-created software links stay unmanaged
			 * until they are fully initialized by the platform. NM created
			 * links must be available for activation immediately and thus
			 * do not get the PLATFORM_INIT unmanaged flag set.
			 */
			nm_device_set_initial_unmanaged_flag (self, NM_UNMANAGED_PLATFORM_INIT, TRUE);
		}
	}

	priv->initialized = TRUE;
}

static void
update_dynamic_ip_setup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_hash_table_remove_all (priv->ip6_saved_properties);

	if (priv->dhcp4_client) {
		if (!nm_device_dhcp4_renew (self, FALSE)) {
			nm_device_state_changed (self,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_DHCP_FAILED);
			return;
		}
	}
	if (priv->dhcp6_client) {
		if (!nm_device_dhcp6_renew (self, FALSE)) {
			nm_device_state_changed (self,
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
carrier_changed (NMDevice *self, gboolean carrier)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!nm_device_get_managed (self))
		return;

	nm_device_recheck_available_connections (self);

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

		if (nm_device_activate_ip4_state_in_wait (self))
			nm_device_activate_stage3_ip4_start (self);
		if (nm_device_activate_ip6_state_in_wait (self))
			nm_device_activate_stage3_ip6_start (self);

		return;
	} else if (nm_device_get_enslaved (self) && !carrier) {
		/* Slaves don't deactivate when they lose carrier; for
		 * bonds/teams in particular that would be actively
		 * counterproductive.
		 */
		return;
	}

	if (carrier) {
		g_warn_if_fail (priv->state >= NM_DEVICE_STATE_UNAVAILABLE);

		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		} else if (priv->state == NM_DEVICE_STATE_DISCONNECTED) {
			/* If the device is already in DISCONNECTED state without a carrier
			 * (probably because it is tagged for carrier ignore) ensure that
			 * when the carrier appears, auto connections are rechecked for
			 * the device.
			 */
			nm_device_emit_recheck_auto_activate (self);
		} else if (priv->state == NM_DEVICE_STATE_ACTIVATED) {
			/* If the device is active without a carrier (probably because it is
			 * tagged for carrier ignore) ensure that when the carrier appears we
			 * renew DHCP leases and such.
			 */
			update_dynamic_ip_setup (self);
		}
	} else {
		g_return_if_fail (priv->state >= NM_DEVICE_STATE_UNAVAILABLE);

		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			if (nm_device_queued_state_peek (self) >= NM_DEVICE_STATE_DISCONNECTED)
				nm_device_queued_state_clear (self);
		} else {
			nm_device_queue_state (self, NM_DEVICE_STATE_UNAVAILABLE,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		}
	}
}

#define LINK_DISCONNECT_DELAY 4

static gboolean
link_disconnect_action_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_LOGD (LOGD_DEVICE, "link disconnected (calling deferred action) (id=%u)", priv->carrier_defer_id);

	priv->carrier_defer_id = 0;

	_LOGI (LOGD_DEVICE, "link disconnected (calling deferred action)");

	NM_DEVICE_GET_CLASS (self)->carrier_changed (self, FALSE);

	return FALSE;
}

static void
link_disconnect_action_cancel (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->carrier_defer_id) {
		g_source_remove (priv->carrier_defer_id);
		_LOGD (LOGD_DEVICE, "link disconnected (canceling deferred action) (id=%u)", priv->carrier_defer_id);
		priv->carrier_defer_id = 0;
	}
}

void
nm_device_set_carrier (NMDevice *self, gboolean carrier)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (self);
	NMDeviceState state = nm_device_get_state (self);

	if (priv->carrier == carrier)
		return;

	priv->carrier = carrier;
	g_object_notify (G_OBJECT (self), NM_DEVICE_CARRIER);

	if (priv->carrier) {
		_LOGI (LOGD_DEVICE, "link connected");
		link_disconnect_action_cancel (self);
		klass->carrier_changed (self, TRUE);

		if (priv->carrier_wait_id) {
			g_source_remove (priv->carrier_wait_id);
			priv->carrier_wait_id = 0;
			nm_device_remove_pending_action (self, "carrier wait", TRUE);
			_carrier_wait_check_queued_act_request (self);
		}
	} else if (state <= NM_DEVICE_STATE_DISCONNECTED) {
		_LOGI (LOGD_DEVICE, "link disconnected");
		klass->carrier_changed (self, FALSE);
	} else {
		_LOGI (LOGD_DEVICE, "link disconnected (deferring action for %d seconds)", LINK_DISCONNECT_DELAY);
		priv->carrier_defer_id = g_timeout_add_seconds (LINK_DISCONNECT_DELAY,
		                                                link_disconnect_action_cb, self);
		_LOGD (LOGD_DEVICE, "link disconnected (deferring action for %d seconds) (id=%u)",
		       LINK_DISCONNECT_DELAY, priv->carrier_defer_id);
	}
}

static void
device_set_master (NMDevice *self, int ifindex)
{
	NMDevice *master;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	master = nm_manager_get_device_by_ifindex (nm_manager_get (), ifindex);
	if (master && NM_DEVICE_GET_CLASS (master)->enslave_slave) {
		g_clear_object (&priv->master);
		priv->master = g_object_ref (master);
		nm_device_master_add_slave (master, self, FALSE);
	} else if (master) {
		_LOGI (LOGD_DEVICE, "enslaved to non-master-type device %s; ignoring",
		       nm_device_get_iface (master));
	} else {
		_LOGW (LOGD_DEVICE, "enslaved to unknown device %d %s",
		       ifindex,
		       nm_platform_link_get_name (NM_PLATFORM_GET, ifindex));
	}
}

static gboolean
device_link_changed (NMDevice *self)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (self);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMUtilsIPv6IfaceId token_iid;
	gboolean ip_ifname_changed = FALSE;
	const char *udi;
	NMPlatformLink info;
	const NMPlatformLink *pllink;
	int ifindex;

	priv->device_link_changed_id = 0;

	ifindex = nm_device_get_ifindex (self);
	pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex);
	if (!pllink)
		return G_SOURCE_REMOVE;

	info = *pllink;

	udi = nm_platform_link_get_udi (NM_PLATFORM_GET, info.ifindex);
	if (udi && g_strcmp0 (udi, priv->udi)) {
		/* Update UDI to what udev gives us */
		g_free (priv->udi);
		priv->udi = g_strdup (udi);
		g_object_notify (G_OBJECT (self), NM_DEVICE_UDI);
	}

	if (g_strcmp0 (info.driver, priv->driver)) {
		/* Update driver to what udev gives us */
		g_free (priv->driver);
		priv->driver = g_strdup (info.driver);
		g_object_notify (G_OBJECT (self), NM_DEVICE_DRIVER);
	}

	/* Update MTU if it has changed. */
	if (priv->mtu != info.mtu) {
		priv->mtu = info.mtu;
		g_object_notify (G_OBJECT (self), NM_DEVICE_MTU);
	}

	if (info.name[0] && strcmp (priv->iface, info.name) != 0) {
		_LOGI (LOGD_DEVICE, "interface index %d renamed iface from '%s' to '%s'",
		       priv->ifindex, priv->iface, info.name);
		g_free (priv->iface);
		priv->iface = g_strdup (info.name);

		/* If the device has no explicit ip_iface, then changing iface changes ip_iface too. */
		ip_ifname_changed = !priv->ip_iface;

		g_object_notify (G_OBJECT (self), NM_DEVICE_IFACE);
		if (ip_ifname_changed)
			g_object_notify (G_OBJECT (self), NM_DEVICE_IP_IFACE);

		/* Re-match available connections against the new interface name */
		nm_device_recheck_available_connections (self);

		/* Let any connections that use the new interface name have a chance
		 * to auto-activate on the device.
		 */
		nm_device_emit_recheck_auto_activate (self);
	}

	/* Update slave status for external changes */
	if (priv->enslaved && info.master != nm_device_get_ifindex (priv->master))
		nm_device_release_one_slave (priv->master, self, FALSE, NM_DEVICE_STATE_REASON_NONE);
	if (info.master && !priv->enslaved) {
		device_set_master (self, info.master);
		if (priv->master)
			nm_device_enslave_slave (priv->master, self, NULL);
	}

	if (priv->rdisc && nm_platform_link_get_ipv6_token (NM_PLATFORM_GET, priv->ifindex, &token_iid)) {
		_LOGD (LOGD_DEVICE, "IPv6 tokenized identifier present on device %s", priv->iface);
		if (nm_rdisc_set_iid (priv->rdisc, token_iid))
			nm_rdisc_start (priv->rdisc);
	}

	if (klass->link_changed)
		klass->link_changed (self, &info);

	/* Update DHCP, etc, if needed */
	if (ip_ifname_changed)
		update_dynamic_ip_setup (self);

	if (priv->up != NM_FLAGS_HAS (info.flags, IFF_UP)) {
		priv->up = NM_FLAGS_HAS (info.flags, IFF_UP);

		/* Manage externally-created software interfaces only when they are IFF_UP */
		g_assert (priv->ifindex > 0);
		if (NM_DEVICE_GET_CLASS (self)->can_unmanaged_external_down (self)) {
			gboolean external_down = nm_device_get_unmanaged_flag (self, NM_UNMANAGED_EXTERNAL_DOWN);

			if (external_down && NM_FLAGS_HAS (info.flags, IFF_UP)) {
				if (nm_device_get_state (self) < NM_DEVICE_STATE_DISCONNECTED) {
					/* Ensure the assume check is queued before any queued state changes
					 * from the transition to UNAVAILABLE.
					 */
					nm_device_queue_recheck_assume (self);

					/* Resetting the EXTERNAL_DOWN flag may change the device's state
					 * to UNAVAILABLE.  To ensure that the state change doesn't touch
					 * the device before assumption occurs, pass
					 * NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED as the reason.
					 */
					nm_device_set_unmanaged (self,
					                         NM_UNMANAGED_EXTERNAL_DOWN,
					                         FALSE,
					                         NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
				} else {
					/* Don't trigger a state change; if the device is in a
					 * state higher than UNAVAILABLE, it is already IFF_UP
					 * or an explicit activation request was received.
					 */
					_set_unmanaged_flags (self, NM_UNMANAGED_EXTERNAL_DOWN, FALSE);
				}
			} else if (!external_down && !NM_FLAGS_HAS (info.flags, IFF_UP) && nm_device_get_state (self) <= NM_DEVICE_STATE_DISCONNECTED) {
				/* If the device is already disconnected and is set !IFF_UP,
				 * unmanage it.
				 */
				nm_device_set_unmanaged (self,
				                         NM_UNMANAGED_EXTERNAL_DOWN,
				                         TRUE,
				                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			}
		}
	}

	if (priv->ifindex > 0 && !priv->platform_link_initialized && info.initialized) {
		gboolean platform_unmanaged = FALSE;

		priv->platform_link_initialized = TRUE;

		if (nm_platform_link_get_unmanaged (NM_PLATFORM_GET, priv->ifindex, &platform_unmanaged)) {
			nm_device_set_unmanaged (self,
			                         NM_UNMANAGED_DEFAULT,
			                         platform_unmanaged,
			                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
		}

		nm_device_set_unmanaged (self,
		                         NM_UNMANAGED_PLATFORM_INIT,
		                         FALSE,
		                         NM_DEVICE_STATE_REASON_NOW_MANAGED);

		g_signal_emit (self, signals[LINK_INITIALIZED], 0);
	}

	return G_SOURCE_REMOVE;
}

static gboolean
device_ip_link_changed (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const NMPlatformLink *pllink;
	int ip_ifindex;

	priv->device_ip_link_changed_id = 0;

	ip_ifindex = nm_device_get_ip_ifindex (self);
	pllink = nm_platform_link_get (NM_PLATFORM_GET, ip_ifindex);
	if (!pllink)
		return G_SOURCE_REMOVE;

	if (pllink->name[0] && g_strcmp0 (priv->ip_iface, pllink->name)) {
		_LOGI (LOGD_DEVICE, "interface index %d renamed ip_iface (%d) from '%s' to '%s'",
		       priv->ifindex, nm_device_get_ip_ifindex (self),
		       priv->ip_iface, pllink->name);
		g_free (priv->ip_iface);
		priv->ip_iface = g_strdup (pllink->name);

		g_object_notify (G_OBJECT (self), NM_DEVICE_IP_IFACE);
		update_dynamic_ip_setup (self);
	}
	return G_SOURCE_REMOVE;
}

static void
link_changed_cb (NMPlatform *platform,
                 NMPObjectType obj_type,
                 int ifindex,
                 NMPlatformLink *info,
                 NMPlatformSignalChangeType change_type,
                 NMPlatformReason reason,
                 NMDevice *self)
{
	NMDevicePrivate *priv;

	if (change_type != NM_PLATFORM_SIGNAL_CHANGED)
		return;

	priv = NM_DEVICE_GET_PRIVATE (self);

	/* We don't filter by 'reason' because we are interested in *all* link
	 * changes. For example a call to nm_platform_link_set_up() may result
	 * in an internal carrier change (i.e. we ask the kernel to set IFF_UP
	 * and it results in also setting IFF_LOWER_UP.
	 */

	if (ifindex == nm_device_get_ifindex (self)) {
		if (!priv->device_link_changed_id) {
			priv->device_link_changed_id = g_idle_add ((GSourceFunc) device_link_changed, self);
			_LOGD (LOGD_DEVICE, "queued link change for ifindex %d", ifindex);
		}
	} else if (ifindex == nm_device_get_ip_ifindex (self)) {
		if (!priv->device_ip_link_changed_id) {
			priv->device_ip_link_changed_id = g_idle_add ((GSourceFunc) device_ip_link_changed, self);
			_LOGD (LOGD_DEVICE, "queued link change for ip-ifindex %d", ifindex);
		}
	}
}

static void
link_changed (NMDevice *self, NMPlatformLink *info)
{
	/* Update carrier from link event if applicable. */
	if (   nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)
	    && !nm_device_has_capability (self, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
		nm_device_set_carrier (self, info->connected);
}

/**
 * nm_device_realize():
 * @self: the #NMDevice
 * @plink: an existing platform link or %NULL
 * @error: location to store error, or %NULL
 *
 * Initializes and sets up the device using existing backing resources.
 *
 * Returns: %TRUE on success, %FALSE on error
 */
gboolean
nm_device_realize (NMDevice *self, NMPlatformLink *plink, GError **error)
{
	/* Try to realize the device from existing resources */
	if (NM_DEVICE_GET_CLASS (self)->realize) {
		if (!NM_DEVICE_GET_CLASS (self)->realize (self, plink, error))
			return FALSE;
	}

	NM_DEVICE_GET_CLASS (self)->setup (self, plink);

	return TRUE;
}

/**
 * nm_device_create_and_realize():
 * @self: the #NMDevice
 * @connection: the #NMConnection being activated
 * @parent: the parent #NMDevice if any
 * @error: location to store error, or %NULL
 *
 * Creates any backing resources needed to realize the device to proceed
 * with activating @connection.
 *
 * Returns: %TRUE on success, %FALSE on error
 */
gboolean
nm_device_create_and_realize (NMDevice *self,
                              NMConnection *connection,
                              NMDevice *parent,
                              GError **error)
{
	NMPlatformLink plink = { .type = NM_LINK_TYPE_UNKNOWN };

	/* Create any resources the device needs */
	if (NM_DEVICE_GET_CLASS (self)->create_and_realize) {
		if (!NM_DEVICE_GET_CLASS (self)->create_and_realize (self, connection, parent, &plink, error))
			return FALSE;
	}

	NM_DEVICE_GET_CLASS (self)->setup (self, (plink.type != NM_LINK_TYPE_UNKNOWN) ? &plink : NULL);

	g_return_val_if_fail (nm_device_check_connection_compatible (self, connection), TRUE);
	return TRUE;
}

static void
update_device_from_platform_link (NMDevice *self, NMPlatformLink *plink)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *udi;

	g_return_if_fail (plink != NULL);

	udi = nm_platform_link_get_udi (NM_PLATFORM_GET, plink->ifindex);
	if (udi && !g_strcmp0 (udi, priv->udi)) {
		g_free (priv->udi);
		priv->udi = g_strdup (udi);
		g_object_notify (G_OBJECT (self), NM_DEVICE_UDI);
	}

	if (!g_strcmp0 (plink->name, priv->iface)) {
		g_free (priv->iface);
		priv->iface = g_strdup (plink->name);
		g_object_notify (G_OBJECT (self), NM_DEVICE_IFACE);
	}

	priv->ifindex = plink->ifindex;
	g_object_notify (G_OBJECT (self), NM_DEVICE_IFINDEX);

	priv->up = NM_FLAGS_HAS (plink->flags, IFF_UP);
	if (plink->driver && g_strcmp0 (plink->driver, priv->driver) != 0) {
		g_free (priv->driver);
		priv->driver = g_strdup (plink->driver);
		g_object_notify (G_OBJECT (self), NM_DEVICE_DRIVER);
	}
	priv->platform_link_initialized = plink->initialized;
}

static void
config_changed_update_ignore_carrier (NMConfig *config,
                                      NMConfigData *config_data,
                                      NMConfigChangeFlags changes,
                                      NMConfigData *old_data,
                                      NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   priv->state <= NM_DEVICE_STATE_DISCONNECTED
	    || priv->state > NM_DEVICE_STATE_ACTIVATED)
		priv->ignore_carrier = nm_config_data_get_ignore_carrier (config_data, self);
}

static void
check_carrier (NMDevice *self)
{
	int ifindex = nm_device_get_ip_ifindex (self);

	if (!nm_device_has_capability (self, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
		nm_device_set_carrier (self, nm_platform_link_is_connected (NM_PLATFORM_GET, ifindex));
}

static void
setup (NMDevice *self, NMPlatformLink *plink)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	static guint32 id = 0;

	/* The device should not be realized */
	g_return_if_fail (priv->ip_ifindex <= 0);
	g_return_if_fail (priv->ip_iface == NULL);

	g_object_freeze_notify (G_OBJECT (self));

	if (plink) {
		g_return_if_fail (priv->iface == NULL || strcmp (plink->name, priv->iface) == 0);
		update_device_from_platform_link (self, plink);
	}

	if (priv->ifindex > 0) {
		_LOGD (LOGD_DEVICE, "setup(): %s, kernel ifindex %d", G_OBJECT_TYPE_NAME (self), priv->ifindex);

		priv->physical_port_id = nm_platform_link_get_physical_port_id (NM_PLATFORM_GET, priv->ifindex);
		g_object_notify (G_OBJECT (self), NM_DEVICE_PHYSICAL_PORT_ID);

		priv->dev_id = nm_platform_link_get_dev_id (NM_PLATFORM_GET, priv->ifindex);

		if (nm_platform_link_is_software (NM_PLATFORM_GET, priv->ifindex))
			priv->capabilities |= NM_DEVICE_CAP_IS_SOFTWARE;

		priv->mtu = nm_platform_link_get_mtu (NM_PLATFORM_GET, priv->ifindex);
		g_object_notify (G_OBJECT (self), NM_DEVICE_MTU);

		nm_platform_link_get_driver_info (NM_PLATFORM_GET,
		                                  priv->ifindex,
		                                  NULL,
		                                  &priv->driver_version,
		                                  &priv->firmware_version);
		if (priv->driver_version)
			g_object_notify (G_OBJECT (self), NM_DEVICE_DRIVER_VERSION);
		if (priv->firmware_version)
			g_object_notify (G_OBJECT (self), NM_DEVICE_FIRMWARE_VERSION);

		if (nm_platform_check_support_user_ipv6ll (NM_PLATFORM_GET))
			priv->nm_ipv6ll = nm_platform_link_get_user_ipv6ll_enabled (NM_PLATFORM_GET, priv->ifindex);
	}

	if (NM_DEVICE_GET_CLASS (self)->get_generic_capabilities)
		priv->capabilities |= NM_DEVICE_GET_CLASS (self)->get_generic_capabilities (self);

	if (!priv->udi) {
		/* Use a placeholder UDI until we get a real one */
		priv->udi = g_strdup_printf ("/virtual/device/placeholder/%d", id++);
		g_object_notify (G_OBJECT (self), NM_DEVICE_UDI);
	}

	/* trigger initial ip config change to initialize ip-config */
	priv->queued_ip4_config_id = g_idle_add (queued_ip4_config_change, self);
	priv->queued_ip6_config_id = g_idle_add (queued_ip6_config_change, self);

	nm_device_update_hw_address (self);

	if (priv->hw_addr_len) {
		priv->initial_hw_addr = g_strdup (priv->hw_addr);
		_LOGD (LOGD_DEVICE | LOGD_HW, "read initial MAC address %s", priv->initial_hw_addr);

		if (priv->ifindex > 0) {
			guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
			size_t len = 0;

			if (nm_platform_link_get_permanent_address (NM_PLATFORM_GET, priv->ifindex, buf, &len)) {
				g_warn_if_fail (len == priv->hw_addr_len);
				priv->perm_hw_addr = nm_utils_hwaddr_ntoa (buf, priv->hw_addr_len);
				_LOGD (LOGD_DEVICE | LOGD_HW, "read permanent MAC address %s",
				       priv->perm_hw_addr);
			} else {
				/* Fall back to current address */
				_LOGD (LOGD_HW | LOGD_ETHER, "unable to read permanent MAC address");
				priv->perm_hw_addr = g_strdup (priv->hw_addr);
			}
		}
	}

	/* Note: initial hardware address must be read before calling get_ignore_carrier() */
	if (nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)) {
		NMConfig *config = nm_config_get ();

		priv->ignore_carrier = nm_config_data_get_ignore_carrier (nm_config_get_data (config), self);
		g_signal_connect (G_OBJECT (config),
		                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
		                  G_CALLBACK (config_changed_update_ignore_carrier),
		                  self);

		check_carrier (self);
		_LOGD (LOGD_HW,
		       "carrier is %s%s",
		       priv->carrier ? "ON" : "OFF",
		       priv->ignore_carrier ? " (but ignored)" : "");
	} else {
		/* Fake online link when carrier detection is not available. */
		priv->carrier = TRUE;
	}

	g_object_notify (G_OBJECT (self), NM_DEVICE_CAPABILITIES);

	/* Enslave ourselves */
	if (priv->ifindex > 0) {
		int master = nm_platform_link_get_master (NM_PLATFORM_GET, priv->ifindex);

		if (master > 0)
			device_set_master (self, master);
	}

	g_object_thaw_notify (G_OBJECT (self));
}

/**
 * nm_device_notify_component_added():
 * @self: the #NMDevice
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
nm_device_notify_component_added (NMDevice *self, GObject *component)
{
	if (NM_DEVICE_GET_CLASS (self)->component_added)
		return NM_DEVICE_GET_CLASS (self)->component_added (self, component);
	return FALSE;
}

/**
 * nm_device_owns_iface():
 * @self: the #NMDevice
 * @iface: an interface name
 *
 * Called by the manager to ask if the device or any of its components owns
 * @iface.  For example, a WWAN implementation would return %TRUE for an
 * ethernet interface name that was owned by the WWAN device's modem component,
 * because that ethernet interface is controlled by the WWAN device and cannot
 * be used independently of the WWAN device.
 *
 * Returns: %TRUE if @self or it's components owns the interface name,
 * %FALSE if not
 */
gboolean
nm_device_owns_iface (NMDevice *self, const char *iface)
{
	if (NM_DEVICE_GET_CLASS (self)->owns_iface)
		return NM_DEVICE_GET_CLASS (self)->owns_iface (self, iface);
	return FALSE;
}

NMConnection *
nm_device_new_default_connection (NMDevice *self)
{
	if (NM_DEVICE_GET_CLASS (self)->new_default_connection)
		return NM_DEVICE_GET_CLASS (self)->new_default_connection (self);
	return NULL;
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

	_LOGD (LOGD_DEVICE, "slave %s state change %d (%s) -> %d (%s)",
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
		if (priv->slaves == NULL && priv->state == NM_DEVICE_STATE_ACTIVATED)
			_LOGD (LOGD_DEVICE, "last slave removed; remaining activated");
	}
}

/**
 * nm_device_master_add_slave:
 * @self: the master device
 * @slave: the slave device to enslave
 * @configure: pass %TRUE if the slave should be configured by the master, or
 * %FALSE if it is already configured outside NetworkManager
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function adds @slave to the slave list for later enslavement.
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
static gboolean
nm_device_master_add_slave (NMDevice *self, NMDevice *slave, gboolean configure)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	SlaveInfo *info;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (self)->enslave_slave != NULL, FALSE);

	if (configure)
		g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

	if (!find_slave_info (self, slave)) {
		info = g_malloc0 (sizeof (SlaveInfo));
		info->slave = g_object_ref (slave);
		info->configure = configure;
		info->watch_id = g_signal_connect (slave, "state-changed",
		                                   G_CALLBACK (slave_state_changed), self);
		priv->slaves = g_slist_append (priv->slaves, info);
	}
	nm_device_queue_recheck_assume (self);

	return TRUE;
}


/**
 * nm_device_master_get_slaves:
 * @self: the master device
 *
 * Returns: any slaves of which @self is the master.  Caller owns returned list.
 */
GSList *
nm_device_master_get_slaves (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GSList *slaves = NULL, *iter;

	for (iter = priv->slaves; iter; iter = g_slist_next (iter))
		slaves = g_slist_prepend (slaves, ((SlaveInfo *) iter->data)->slave);

	return slaves;
}

/**
 * nm_device_master_get_slave_by_ifindex:
 * @self: the master device
 * @ifindex: the slave's interface index
 *
 * Returns: the slave with the given @ifindex of which @self is the master,
 *   or %NULL if no device with @ifindex is a slave of @self.
 */
NMDevice *
nm_device_master_get_slave_by_ifindex (NMDevice *self, int ifindex)
{
	GSList *iter;

	for (iter = NM_DEVICE_GET_PRIVATE (self)->slaves; iter; iter = g_slist_next (iter)) {
		SlaveInfo *info = iter->data;

		if (nm_device_get_ip_ifindex (info->slave) == ifindex)
			return info->slave;
	}
	return NULL;
}

/**
 * nm_device_master_check_slave_physical_port:
 * @self: the master device
 * @slave: a slave device
 * @log_domain: domain to log a warning in
 *
 * Checks if @self already has a slave with the same #NMDevice:physical-port-id
 * as @slave, and logs a warning if so.
 */
void
nm_device_master_check_slave_physical_port (NMDevice *self, NMDevice *slave,
                                            NMLogDomain log_domain)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
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
			_LOGW (log_domain, "slave %s shares a physical port with existing slave %s",
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
	if (nm_device_uses_generated_assumed_connection (self))
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
 * @self: the device
 *
 * If @self has been enslaved by another device, this returns that
 * device. Otherwise it returns %NULL. (In particular, note that if
 * @self is in the process of activating as a slave, but has not yet
 * been enslaved by its master, this will return %NULL.)
 *
 * Returns: (transfer none): @self's master, or %NULL
 */
NMDevice *
nm_device_get_master (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->enslaved)
		return priv->master;
	else
		return NULL;
}

/**
 * nm_device_slave_notify_enslave:
 * @self: the slave device
 * @success: whether the enslaving operation succeeded
 *
 * Notifies a slave that either it has been enslaved, or else its master tried
 * to enslave it and failed.
 */
static void
nm_device_slave_notify_enslave (NMDevice *self, gboolean success)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection = nm_device_get_connection (self);
	gboolean activating = (priv->state == NM_DEVICE_STATE_IP_CONFIG);

	g_assert (priv->master);

	if (!priv->enslaved) {
		if (success) {
			if (activating) {
				_LOGI (LOGD_DEVICE, "Activation: connection '%s' enslaved, continuing activation",
				       nm_connection_get_id (connection));
			} else
				_LOGI (LOGD_DEVICE, "enslaved to %s", nm_device_get_iface (priv->master));

			priv->enslaved = TRUE;
			g_object_notify (G_OBJECT (self), NM_DEVICE_MASTER);
		} else if (activating) {
			_LOGW (LOGD_DEVICE, "Activation: connection '%s' could not be enslaved",
			       nm_connection_get_id (connection));
		}
	}

	if (activating) {
		priv->ip4_state = IP_DONE;
		priv->ip6_state = IP_DONE;
		nm_device_queue_state (self,
		                       success ? NM_DEVICE_STATE_SECONDARIES : NM_DEVICE_STATE_FAILED,
		                       NM_DEVICE_STATE_REASON_NONE);
	} else
		nm_device_queue_recheck_assume (self);
}

/**
 * nm_device_slave_notify_release:
 * @self: the slave device
 * @reason: the reason associated with the state change
 *
 * Notifies a slave that it has been released, and why.
 */
static void
nm_device_slave_notify_release (NMDevice *self, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection = nm_device_get_connection (self);
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

		_LOGD (LOGD_DEVICE, "Activation: connection '%s' master %s",
		       nm_connection_get_id (connection),
		       master_status);

		nm_device_queue_state (self, new_state, reason);
	} else if (priv->master)
		_LOGI (LOGD_DEVICE, "released from master %s", nm_device_get_iface (priv->master));
	else
		_LOGD (LOGD_DEVICE, "released from master%s", priv->enslaved ? "" : " (was not enslaved)");

	if (priv->enslaved) {
		priv->enslaved = FALSE;
		g_object_notify (G_OBJECT (self), NM_DEVICE_MASTER);
	}
}

/**
 * nm_device_get_enslaved:
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device is enslaved to a master device (eg bridge or
 * bond or team), %FALSE if not
 */
gboolean
nm_device_get_enslaved (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->enslaved;
}

/**
 * nm_device_removed:
 * @self: the #NMDevice
 *
 * Called by the manager when the device was removed. Releases the device from
 * the master in case it's enslaved.
 */
void
nm_device_removed (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->enslaved)
		nm_device_release_one_slave (priv->master, self, FALSE, NM_DEVICE_STATE_REASON_REMOVED);
}


static gboolean
is_available (NMDevice *self, NMDeviceCheckDevAvailableFlags flags)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->carrier || priv->ignore_carrier)
		return TRUE;

	if (NM_FLAGS_HAS (flags, NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER))
		return TRUE;

	return FALSE;
}

/**
 * nm_device_is_available:
 * @self: the #NMDevice
 * @flags: additional flags to influence the check. Flags have the
 *   meaning to increase the availability of a device.
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
nm_device_is_available (NMDevice *self, NMDeviceCheckDevAvailableFlags flags)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->firmware_missing)
		return FALSE;

	return NM_DEVICE_GET_CLASS (self)->is_available (self, flags);
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

/**
 * nm_device_get_autoconnect:
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device allows autoconnect connections, or %FALSE if the
 * device is explicitly blocking all autoconnect connections.  Does not take
 * into account transient conditions like companion devices that may wish to
 * block the device.
 */
gboolean
nm_device_get_autoconnect (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_PRIVATE (self)->autoconnect;
}

static void
nm_device_set_autoconnect (NMDevice *self, gboolean autoconnect)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->autoconnect == autoconnect)
		return;

	if (autoconnect) {
		/* Default-unmanaged devices never autoconnect */
		if (!nm_device_get_default_unmanaged (self)) {
			priv->autoconnect = TRUE;
			g_object_notify (G_OBJECT (self), NM_DEVICE_AUTOCONNECT);
		}
	} else {
		priv->autoconnect = FALSE;
		g_object_notify (G_OBJECT (self), NM_DEVICE_AUTOCONNECT);
	}
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

/**
 * nm_device_autoconnect_allowed:
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device can be auto-connected immediately, taking
 * transient conditions into account (like companion devices that may wish to
 * block autoconnect for a time).
 */
gboolean
nm_device_autoconnect_allowed (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GValue instance = G_VALUE_INIT;
	GValue retval = G_VALUE_INIT;

	if (priv->state < NM_DEVICE_STATE_DISCONNECTED || !priv->autoconnect)
		return FALSE;

	/* The 'autoconnect-allowed' signal is emitted on a device to allow
	 * other listeners to block autoconnect on the device if they wish.
	 * This is mainly used by the OLPC Mesh devices to block autoconnect
	 * on their companion WiFi device as they share radio resources and
	 * cannot be connected at the same time.
	 */

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
can_auto_connect (NMDevice *self,
                  NMConnection *connection,
                  char **specific_object)
{
	NMSettingConnection *s_con;

	s_con = nm_connection_get_setting_connection (connection);
	if (!nm_setting_connection_get_autoconnect (s_con))
		return FALSE;

	return nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_NONE, NULL);
}

/**
 * nm_device_can_auto_connect:
 * @self: an #NMDevice
 * @connection: a #NMConnection
 * @specific_object: (out) (transfer full): on output, the path of an
 *   object associated with the returned connection, to be passed to
 *   nm_manager_activate_connection(), or %NULL.
 *
 * Checks if @connection can be auto-activated on @self right now.
 * This requires, at a minimum, that the connection be compatible with
 * @self, and that it have the #NMSettingConnection:autoconnect property
 * set, and that the device allow auto connections. Some devices impose
 * additional requirements. (Eg, a Wi-Fi connection can only be activated
 * if its SSID was seen in the last scan.)
 *
 * Returns: %TRUE, if the @connection can be auto-activated.
 **/
gboolean
nm_device_can_auto_connect (NMDevice *self,
                            NMConnection *connection,
                            char **specific_object)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (specific_object && !*specific_object, FALSE);

	if (nm_device_autoconnect_allowed (self))
		return NM_DEVICE_GET_CLASS (self)->can_auto_connect (self, connection, specific_object);
	return FALSE;
}

static gboolean
device_has_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* Check for IP configuration. */
	if (priv->ip4_config && nm_ip4_config_get_num_addresses (priv->ip4_config))
		return TRUE;
	if (priv->ip6_config && nm_ip6_config_get_num_addresses (priv->ip6_config))
		return TRUE;

	/* The existence of a software device is good enough. */
	if (nm_device_is_software (self))
		return TRUE;

	/* Slaves are also configured by definition */
	if (nm_platform_link_get_master (NM_PLATFORM_GET, priv->ifindex) > 0)
		return TRUE;

	return FALSE;
}

/**
 * nm_device_master_update_slave_connection:
 * @self: the master #NMDevice
 * @slave: the slave #NMDevice
 * @connection: the #NMConnection to update with the slave settings
 * @GError: (out): error description
 *
 * Reads the slave configuration for @slave and updates @connection with those
 * properties. This invokes a virtual function on the master device @self.
 *
 * Returns: %TRUE if the configuration was read and @connection updated,
 * %FALSE on failure.
 */
gboolean
nm_device_master_update_slave_connection (NMDevice *self,
                                          NMDevice *slave,
                                          NMConnection *connection,
                                          GError **error)
{
	NMDeviceClass *klass;
	gboolean success;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (slave, FALSE);
	g_return_val_if_fail (connection, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (nm_connection_get_setting_connection (connection), FALSE);

	g_return_val_if_fail (nm_device_get_iface (self), FALSE);

	klass = NM_DEVICE_GET_CLASS (self);
	if (klass->master_update_slave_connection) {
		success = klass->master_update_slave_connection (self, slave, connection, error);

		g_return_val_if_fail (!error || (success && !*error) || *error, success);
		return success;
	}

	g_set_error (error,
	             NM_DEVICE_ERROR,
	             NM_DEVICE_ERROR_FAILED,
	             "master device '%s' cannot update a slave connection for slave device '%s' (master type not supported?)",
	             nm_device_get_iface (self), nm_device_get_iface (slave));
	return FALSE;
}

NMConnection *
nm_device_generate_connection (NMDevice *self, NMDevice *master)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (self);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *ifname = nm_device_get_iface (self);
	NMConnection *connection;
	NMSetting *s_con;
	NMSetting *s_ip4;
	NMSetting *s_ip6;
	gs_free char *uuid = NULL;
	const char *ip4_method, *ip6_method;
	GError *error = NULL;

	/* If update_connection() is not implemented, just fail. */
	if (!klass->update_connection)
		return NULL;

	/* Return NULL if device is unconfigured. */
	if (!device_has_config (self)) {
		_LOGD (LOGD_DEVICE, "device has no existing configuration");
		return NULL;
	}

	connection = nm_simple_connection_new ();
	s_con = nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, ifname,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, ifname,
	              NM_SETTING_CONNECTION_TIMESTAMP, (guint64) time (NULL),
	              NULL);
	if (klass->connection_type)
		g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, klass->connection_type, NULL);
	nm_connection_add_setting (connection, s_con);

	/* If the device is a slave, update various slave settings */
	if (master) {
		if (!nm_device_master_update_slave_connection (master,
		                                               self,
		                                               connection,
		                                               &error))
		{
			_LOGE (LOGD_DEVICE, "master device '%s' failed to update slave connection: %s",
			       nm_device_get_iface (master), error ? error->message : "(unknown error)");
			g_error_free (error);
			g_object_unref (connection);
			return NULL;
		}
	} else {
		/* Only regular and master devices get IP configuration; slaves do not */
		s_ip4 = nm_ip4_config_create_setting (priv->ip4_config);
		nm_connection_add_setting (connection, s_ip4);

		s_ip6 = nm_ip6_config_create_setting (priv->ip6_config);
		nm_connection_add_setting (connection, s_ip6);
	}

	klass->update_connection (self, connection);

	/* Check the connection in case of update_connection() bug. */
	if (!nm_connection_verify (connection, &error)) {
		_LOGE (LOGD_DEVICE, "Generated connection does not verify: %s", error->message);
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
	    && !nm_setting_connection_get_master (NM_SETTING_CONNECTION (s_con))
	    && !priv->slaves) {
		_LOGD (LOGD_DEVICE, "ignoring generated connection (no IP and not in master-slave relationship)");
		g_object_unref (connection);
		connection = NULL;
	}

	/* Ignore any IPv6LL-only, not master connections without slaves,
	 * unless they are in the assume-ipv6ll-only list.
	 */
	if (   connection
	    && g_strcmp0 (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0
	    && g_strcmp0 (ip6_method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0
	    && !nm_setting_connection_get_master (NM_SETTING_CONNECTION (s_con))
	    && !priv->slaves
	    && !nm_config_data_get_assume_ipv6ll_only (NM_CONFIG_GET_DATA, self)) {
		_LOGD (LOGD_DEVICE, "ignoring generated connection (IPv6LL-only and not in master-slave relationship)");
		g_object_unref (connection);
		connection = NULL;
	}

	return connection;
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
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
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
check_connection_compatible (NMDevice *self, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *config_iface, *device_iface;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	config_iface = nm_setting_connection_get_interface_name (s_con);
	device_iface = nm_device_get_iface (self);
	if (config_iface && strcmp (config_iface, device_iface) != 0)
		return FALSE;

	return TRUE;
}

/**
 * nm_device_check_connection_compatible:
 * @self: an #NMDevice
 * @connection: an #NMConnection
 *
 * Checks if @connection could potentially be activated on @self.
 * This means only that @self has the proper capabilities, and that
 * @connection is not locked to some other device. It does not
 * necessarily mean that @connection could be activated on @self
 * right now. (Eg, it might refer to a Wi-Fi network that is not
 * currently available.)
 *
 * Returns: #TRUE if @connection could potentially be activated on
 *   @self.
 */
gboolean
nm_device_check_connection_compatible (NMDevice *self, NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	return NM_DEVICE_GET_CLASS (self)->check_connection_compatible (self, connection);
}

/**
 * nm_device_can_assume_connections:
 * @self: #NMDevice instance
 *
 * This is a convenience function to determine whether connection assumption
 * is available for this device.
 *
 * Returns: %TRUE if the device is capable of assuming connections, %FALSE if not
 */
static gboolean
nm_device_can_assume_connections (NMDevice *self)
{
	return !!NM_DEVICE_GET_CLASS (self)->update_connection;
}

/**
 * nm_device_can_assume_active_connection:
 * @self: #NMDevice instance
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
nm_device_can_assume_active_connection (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	const char *method;
	const char *assumable_ip6_methods[] = {
		NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		NM_SETTING_IP6_CONFIG_METHOD_DHCP,
		NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
		NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
		NULL
	};
	const char *assumable_ip4_methods[] = {
		NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
		NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
		NULL
	};

	if (!nm_device_can_assume_connections (self))
		return FALSE;

	connection = nm_device_get_connection (self);
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
	if (!_nm_utils_string_in_list (method, assumable_ip6_methods))
		return FALSE;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (!_nm_utils_string_in_list (method, assumable_ip4_methods))
		return FALSE;

	return TRUE;
}

static gboolean
nm_device_emit_recheck_assume (gpointer self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->recheck_assume_id = 0;
	if (!nm_device_get_act_request (self)) {
		_LOGD (LOGD_DEVICE, "emit RECHECK_ASSUME signal");
		g_signal_emit (self, signals[RECHECK_ASSUME], 0);
	}
	return G_SOURCE_REMOVE;
}

void
nm_device_queue_recheck_assume (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (nm_device_can_assume_connections (self) && !priv->recheck_assume_id)
		priv->recheck_assume_id = g_idle_add (nm_device_emit_recheck_assume, self);
}

static gboolean
recheck_available (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean now_available = nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE);
	NMDeviceState state = nm_device_get_state (self);
	NMDeviceState new_state = NM_DEVICE_STATE_UNKNOWN;

	priv->recheck_available.call_id = 0;

	if (state == NM_DEVICE_STATE_UNAVAILABLE && now_available) {
		new_state = NM_DEVICE_STATE_DISCONNECTED;
		nm_device_queue_state (self, new_state, priv->recheck_available.available_reason);
	} else if (state >= NM_DEVICE_STATE_DISCONNECTED && !now_available) {
		new_state = NM_DEVICE_STATE_UNAVAILABLE;
		nm_device_queue_state (self, new_state, priv->recheck_available.unavailable_reason);
	}
	_LOGD (LOGD_DEVICE, "device is %savailable, %s %s",
	       now_available ? "" : "not ",
	       new_state == NM_DEVICE_STATE_UNAVAILABLE ? "no change required for" : "will transition to",
	       state_to_string (new_state == NM_DEVICE_STATE_UNAVAILABLE ? state : new_state));

	priv->recheck_available.available_reason = NM_DEVICE_STATE_REASON_NONE;
	priv->recheck_available.unavailable_reason = NM_DEVICE_STATE_REASON_NONE;
	return G_SOURCE_REMOVE;
}

void
nm_device_queue_recheck_available (NMDevice *self,
                                   NMDeviceStateReason available_reason,
                                   NMDeviceStateReason unavailable_reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->recheck_available.available_reason = available_reason;
	priv->recheck_available.unavailable_reason = unavailable_reason;
	if (!priv->recheck_available.call_id)
		priv->recheck_available.call_id = g_idle_add (recheck_available, self);
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

	if (*act_source_id)
		_LOGE (LOGD_DEVICE, "activation stage already scheduled");

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

static gboolean
get_ip_config_may_fail (NMDevice *self, int family)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip = NULL;

	g_return_val_if_fail (self != NULL, TRUE);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* Fail the connection if the failed IP method is required to complete */
	switch (family) {
	case AF_INET:
		s_ip = nm_connection_get_setting_ip4_config (connection);
		break;
	case AF_INET6:
		s_ip = nm_connection_get_setting_ip6_config (connection);
		break;
	default:
		g_assert_not_reached ();
	}

	return nm_setting_ip_config_get_may_fail (s_ip);
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

	_LOGD (LOGD_DEVICE, "master connection ready; master device %s",
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
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMActiveConnection *active = NM_ACTIVE_CONNECTION (priv->act_request);

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	priv->ip4_state = priv->ip6_state = IP_NONE;

	/* Notify the new ActiveConnection along with the state change */
	g_object_notify (G_OBJECT (self), NM_DEVICE_ACTIVE_CONNECTION);

	_LOGD (LOGD_DEVICE, "Activation: Stage 1 of 5 (Device Prepare) started...");
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
			_LOGD (LOGD_DEVICE, "waiting for master connection to become ready");

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
	_LOGD (LOGD_DEVICE, "Activation: Stage 1 of 5 (Device Prepare) complete.");
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

	_LOGD (LOGD_DEVICE, "Activation: Stage 1 of 5 (Device Prepare) scheduled...");
}

static NMActStageReturn
act_stage2_config (NMDevice *self, NMDeviceStateReason *reason)
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
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	gboolean no_firmware = FALSE;
	NMActiveConnection *active = NM_ACTIVE_CONNECTION (priv->act_request);
	GSList *iter;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	_LOGD (LOGD_DEVICE, "Activation: Stage 2 of 5 (Device Configure) starting...");
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
		else if (   nm_device_uses_generated_assumed_connection (self)
		         && slave_state <= NM_DEVICE_STATE_DISCONNECTED)
			nm_device_queue_recheck_assume (info->slave);
	}

	_LOGD (LOGD_DEVICE, "Activation: Stage 2 of 5 (Device Configure) successful.");

	nm_device_activate_schedule_stage3_ip_config_start (self);

out:
	_LOGD (LOGD_DEVICE, "Activation: Stage 2 of 5 (Device Configure) complete.");
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

	_LOGD (LOGD_DEVICE, "Activation: Stage 2 of 5 (Device Configure) scheduled...");
}

/*
 * nm_device_check_ip_failed
 *
 * Progress the device to appropriate state if both IPv4 and IPv6 failed
 */
static void
nm_device_check_ip_failed (NMDevice *self, gboolean may_fail)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState state;

	if (   priv->ip4_state != IP_FAIL
	    || priv->ip6_state != IP_FAIL)
		return;

	if (nm_device_uses_assumed_connection (self)) {
		/* We have assumed configuration, but couldn't
		 * redo it. No problem, move to check state. */
		priv->ip4_state = priv->ip6_state = IP_DONE;
		state = NM_DEVICE_STATE_IP_CHECK;
	} else if (   may_fail
	           && get_ip_config_may_fail (self, AF_INET)
	           && get_ip_config_may_fail (self, AF_INET6)) {
		/* Couldn't start either IPv6 and IPv4 autoconfiguration,
		 * but both are allowed to fail. */
		state = NM_DEVICE_STATE_SECONDARIES;
	} else {
		/* Autoconfiguration attempted without success. */
		state = NM_DEVICE_STATE_FAILED;
	}

	nm_device_state_changed (self,
	                         state,
	                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
}

/*********************************************/
/* IPv4LL stuff */

static void
ipv4ll_timeout_remove (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ipv4ll_timeout) {
		g_source_remove (priv->ipv4ll_timeout);
		priv->ipv4ll_timeout = 0;
	}
}

static void
ipv4ll_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ipv4ll) {
		sd_ipv4ll_set_callback (priv->ipv4ll, NULL, NULL);
		sd_ipv4ll_stop (priv->ipv4ll);
		priv->ipv4ll = sd_ipv4ll_unref (priv->ipv4ll);
	}

	ipv4ll_timeout_remove (self);
}

static NMIP4Config *
ipv4ll_get_ip4_config (NMDevice *self, guint32 lla)
{
	NMIP4Config *config = NULL;
	NMPlatformIP4Address address;
	NMPlatformIP4Route route;

	config = nm_ip4_config_new (nm_device_get_ip_ifindex (self));
	g_assert (config);

	memset (&address, 0, sizeof (address));
	address.address = lla;
	address.plen = 16;
	address.source = NM_IP_CONFIG_SOURCE_IP4LL;
	nm_ip4_config_add_address (config, &address);

	/* Add a multicast route for link-local connections: destination= 224.0.0.0, netmask=240.0.0.0 */
	memset (&route, 0, sizeof (route));
	route.network = htonl (0xE0000000L);
	route.plen = 4;
	route.source = NM_IP_CONFIG_SOURCE_IP4LL;
	route.metric = nm_device_get_ip4_route_metric (self);
	nm_ip4_config_add_route (config, &route);

	return config;
}

#define IPV4LL_NETWORK (htonl (0xA9FE0000L))
#define IPV4LL_NETMASK (htonl (0xFFFF0000L))

static void
nm_device_handle_ipv4ll_event (sd_ipv4ll *ll, int event, void *data)
{
	NMDevice *self = data;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection = NULL;
	const char *method;
	struct in_addr address;
	NMIP4Config *config;
	int r;

	if (priv->act_request == NULL)
		return;

	connection = nm_act_request_get_connection (priv->act_request);
	g_assert (connection);

	/* Ignore if the connection isn't an AutoIP connection */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL) != 0)
		return;

	switch (event) {
	case IPV4LL_EVENT_BIND:
		r = sd_ipv4ll_get_address (ll, &address);
		if (r < 0) {
			_LOGE (LOGD_AUTOIP4, "invalid IPv4 link-local address received, error %d.", r);
			priv->ip4_state = IP_FAIL;
			nm_device_check_ip_failed (self, FALSE);
			return;
		}

		if ((address.s_addr & IPV4LL_NETMASK) != IPV4LL_NETWORK) {
			_LOGE (LOGD_AUTOIP4, "invalid address %08x received (not link-local).", address.s_addr);
			priv->ip4_state = IP_FAIL;
			nm_device_check_ip_failed (self, FALSE);
			return;
		}

		config = ipv4ll_get_ip4_config (self, address.s_addr);
		if (config == NULL) {
			_LOGE (LOGD_AUTOIP4, "failed to get IPv4LL config");
			priv->ip4_state = IP_FAIL;
			nm_device_check_ip_failed (self, FALSE);
			return;
		}

		if (priv->ip4_state == IP_CONF) {
			ipv4ll_timeout_remove (self);
			nm_device_activate_schedule_ip4_config_result (self, config);
		} else if (priv->ip4_state == IP_DONE) {
			if (!ip4_config_merge_and_apply (self, config, TRUE, NULL)) {
				_LOGE (LOGD_AUTOIP4, "failed to update IP4 config for autoip change.");
				priv->ip4_state = IP_FAIL;
				nm_device_check_ip_failed (self, FALSE);
			}
		} else
			g_assert_not_reached ();

		g_object_unref (config);
		break;
	default:
		_LOGW (LOGD_AUTOIP4, "IPv4LL address no longer valid after event %d.", event);
		priv->ip4_state = IP_FAIL;
		nm_device_check_ip_failed (self, FALSE);
	}
}

static gboolean
ipv4ll_timeout_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ipv4ll_timeout) {
		_LOGI (LOGD_AUTOIP4, "IPv4LL configuration timed out.");
		priv->ipv4ll_timeout = 0;
		ipv4ll_cleanup (self);

		if (priv->ip4_state == IP_CONF)
			nm_device_activate_schedule_ip4_config_timeout (self);
	}

	return FALSE;
}

static NMActStageReturn
ipv4ll_start (NMDevice *self, NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const struct ether_addr *addr;
	int ifindex, r;
	size_t addr_len;

	ipv4ll_cleanup (self);

	r = sd_ipv4ll_new (&priv->ipv4ll);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: new() failed with error %d", r);
		goto fail;
	}

	r = sd_ipv4ll_attach_event (priv->ipv4ll, NULL, 0);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: attach_event() failed with error %d", r);
		goto fail;
	}

	ifindex = nm_device_get_ip_ifindex (self);
	addr = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, &addr_len);
	if (!addr || addr_len != ETH_ALEN) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: can't retrieve hardware address");
		goto fail;
	}

	r = sd_ipv4ll_set_mac (priv->ipv4ll, addr);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: set_mac() failed with error %d", r);
		goto fail;
	}

	r = sd_ipv4ll_set_index (priv->ipv4ll, ifindex);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: set_index() failed with error %d", r);
		goto fail;
	}

	r = sd_ipv4ll_set_callback (priv->ipv4ll, nm_device_handle_ipv4ll_event, self);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: set_callback() failed with error %d", r);
		goto fail;
	}

	r = sd_ipv4ll_start (priv->ipv4ll);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: start() failed with error %d", r);
		goto fail;
	}

	_LOGI (LOGD_DEVICE | LOGD_AUTOIP4,
	       "Activation: Stage 3 of 5 (IP Configure Start) IPv4LL started");

	/* Start a timeout to bound the address attempt */
	priv->ipv4ll_timeout = g_timeout_add_seconds (20, ipv4ll_timeout_cb, self);

	return NM_ACT_STAGE_RETURN_POSTPONE;
fail:
	*reason = NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED;
	return NM_ACT_STAGE_RETURN_FAILURE;
}

/*********************************************/

static gboolean
_device_get_default_route_from_platform (NMDevice *self, int addr_family, NMPlatformIPRoute *out_route)
{
	gboolean success = FALSE;
	int ifindex = nm_device_get_ip_ifindex (self);
	GArray *routes;

	if (addr_family == AF_INET)
		routes = nm_platform_ip4_route_get_all (NM_PLATFORM_GET, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT);
	else
		routes = nm_platform_ip6_route_get_all (NM_PLATFORM_GET, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT);

	if (routes) {
		guint route_metric = G_MAXUINT32, m;
		const NMPlatformIPRoute *route = NULL, *r;
		guint i;

		/* if there are several default routes, find the one with the best metric */
		for (i = 0; i < routes->len; i++) {
			if (addr_family == AF_INET) {
				r = (const NMPlatformIPRoute *) &g_array_index (routes, NMPlatformIP4Route, i);
				m = r->metric;
			} else {
				r = (const NMPlatformIPRoute *) &g_array_index (routes, NMPlatformIP6Route, i);
				m = nm_utils_ip6_route_metric_normalize (r->metric);
			}
			if (!route || m < route_metric) {
				route = r;
				route_metric = m;
			}
		}

		if (route) {
			if (addr_family == AF_INET)
				*((NMPlatformIP4Route *) out_route) = *((NMPlatformIP4Route *) route);
			else
				*((NMPlatformIP6Route *) out_route) = *((NMPlatformIP6Route *) route);
			success = TRUE;
		}
		g_array_free (routes, TRUE);
	}
	return success;
}

/*********************************************/

static void
ensure_con_ip4_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ip_ifindex = nm_device_get_ip_ifindex (self);
	NMConnection *connection;

	if (priv->con_ip4_config)
		return;

	connection = nm_device_get_connection (self);
	if (!connection)
		return;

	priv->con_ip4_config = nm_ip4_config_new (ip_ifindex);
	nm_ip4_config_merge_setting (priv->con_ip4_config,
	                             nm_connection_get_setting_ip4_config (connection),
	                             nm_device_get_ip4_route_metric (self));

	if (nm_device_uses_assumed_connection (self)) {
		/* For assumed connections ignore all addresses and routes. */
		nm_ip4_config_reset_addresses (priv->con_ip4_config);
		nm_ip4_config_reset_routes (priv->con_ip4_config);
	}
}

static void
ensure_con_ip6_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ip_ifindex = nm_device_get_ip_ifindex (self);
	NMConnection *connection;

	if (priv->con_ip6_config)
		return;

	connection = nm_device_get_connection (self);
	if (!connection)
		return;

	priv->con_ip6_config = nm_ip6_config_new (ip_ifindex);
	nm_ip6_config_merge_setting (priv->con_ip6_config,
	                             nm_connection_get_setting_ip6_config (connection),
	                             nm_device_get_ip6_route_metric (self));

	if (nm_device_uses_assumed_connection (self)) {
		/* For assumed connections ignore all addresses and routes. */
		nm_ip6_config_reset_addresses (priv->con_ip6_config);
		nm_ip6_config_reset_routes (priv->con_ip6_config);
	}
}

/*********************************************/
/* DHCPv4 stuff */

static void
dhcp4_cleanup (NMDevice *self, CleanupType cleanup_type, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_clear_g_source (&priv->dhcp4_restart_id);

	if (priv->dhcp4_client) {
		/* Stop any ongoing DHCP transaction on this device */
		if (priv->dhcp4_state_sigid) {
			g_signal_handler_disconnect (priv->dhcp4_client, priv->dhcp4_state_sigid);
			priv->dhcp4_state_sigid = 0;
		}

		nm_device_remove_pending_action (self, PENDING_ACTION_DHCP4, FALSE);

		if (   cleanup_type == CLEANUP_TYPE_DECONFIGURE
		    || cleanup_type == CLEANUP_TYPE_REMOVED)
			nm_dhcp_client_stop (priv->dhcp4_client, release);

		g_clear_object (&priv->dhcp4_client);
	}

	if (priv->dhcp4_config) {
		g_clear_object (&priv->dhcp4_config);
		g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP4_CONFIG);
	}
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
	gboolean has_direct_route;
	const guint32 default_route_metric = nm_device_get_ip4_route_metric (self);
	guint32 gateway;
	gboolean connection_has_default_route, connection_is_never_default;
	gboolean routes_full_sync;
	gboolean ignore_auto_routes = FALSE;
	gboolean ignore_auto_dns = FALSE;

	/* Merge all the configs into the composite config */
	if (config) {
		g_clear_object (&priv->dev_ip4_config);
		priv->dev_ip4_config = g_object_ref (config);
	}

	/* Apply ignore-auto-routes and ignore-auto-dns settings */
	connection = nm_device_get_connection (self);
	if (connection) {
		NMSettingIPConfig *s_ip4 = nm_connection_get_setting_ip4_config (connection);

		if (s_ip4) {
			ignore_auto_routes = nm_setting_ip_config_get_ignore_auto_routes (s_ip4);
			ignore_auto_dns = nm_setting_ip_config_get_ignore_auto_dns (s_ip4);
		}
	}

	composite = nm_ip4_config_new (nm_device_get_ip_ifindex (self));

	if (commit)
		ensure_con_ip4_config (self);

	if (priv->dev_ip4_config) {
		nm_ip4_config_merge (composite, priv->dev_ip4_config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0));
	}
	if (priv->vpn4_config)
		nm_ip4_config_merge (composite, priv->vpn4_config, NM_IP_CONFIG_MERGE_DEFAULT);
	if (priv->ext_ip4_config)
		nm_ip4_config_merge (composite, priv->ext_ip4_config, NM_IP_CONFIG_MERGE_DEFAULT);

	/* Merge WWAN config *last* to ensure modem-given settings overwrite
	 * any external stuff set by pppd or other scripts.
	 */
	if (priv->wwan_ip4_config) {
		nm_ip4_config_merge (composite, priv->wwan_ip4_config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0));
	}

	/* Merge user overrides into the composite config. For assumed connections,
	 * con_ip4_config is empty. */
	if (priv->con_ip4_config)
		nm_ip4_config_merge (composite, priv->con_ip4_config, NM_IP_CONFIG_MERGE_DEFAULT);


	/* Add the default route.
	 *
	 * We keep track of the default route of a device in a private field.
	 * NMDevice needs to know the default route at this point, because the gateway
	 * might require a direct route (see below).
	 *
	 * But also, we don't want to add the default route to priv->ip4_config,
	 * because the default route from the setting might not be the same that
	 * NMDefaultRouteManager eventually configures (because the it might
	 * tweak the effective metric).
	 */

	/* unless we come to a different conclusion below, we have no default route and
	 * the route is assumed. */
	priv->default_route.v4_has = FALSE;
	priv->default_route.v4_is_assumed = TRUE;

	if (!commit) {
		/* during a non-commit event, we always pickup whatever is configured. */
		goto END_ADD_DEFAULT_ROUTE;
	}

	if (nm_device_uses_generated_assumed_connection (self)) {
		/* a generate-assumed-connection always detects the default route from platform */
		goto END_ADD_DEFAULT_ROUTE;
	}

	/* At this point, we treat assumed and non-assumed connections alike.
	 * For assumed connections we do that because we still manage RA and DHCP
	 * leases for them, so we must extend/update the default route on commits.
	 */

	connection_has_default_route
	    = nm_default_route_manager_ip4_connection_has_default_route (nm_default_route_manager_get (),
	                                                                 connection, &connection_is_never_default);

	if (   !priv->v4_commit_first_time
	    && connection_is_never_default) {
		/* If the connection is explicitly configured as never-default, we enforce the (absence of the)
		 * default-route only once. That allows the user to configure a connection as never-default,
		 * but he can add default routes externally (via a dispatcher script) and NM will not interfere. */
		goto END_ADD_DEFAULT_ROUTE;
	}

	/* we are about to commit (for a non-assumed connection). Enforce whatever we have
	 * configured. */
	priv->default_route.v4_is_assumed = FALSE;

	if (!connection_has_default_route)
		goto END_ADD_DEFAULT_ROUTE;

	if (!nm_ip4_config_get_num_addresses (composite)) {
		/* without addresses we can have no default route. */
		goto END_ADD_DEFAULT_ROUTE;
	}

	gateway = nm_ip4_config_get_gateway (composite);
	if (   !nm_ip4_config_has_gateway (composite)
	    && nm_device_get_device_type (self) != NM_DEVICE_TYPE_MODEM)
		goto END_ADD_DEFAULT_ROUTE;

	has_direct_route = (   gateway == 0
	                    || nm_ip4_config_get_subnet_for_host (composite, gateway)
	                    || nm_ip4_config_get_direct_route_for_host (composite, gateway));

	priv->default_route.v4_has = TRUE;
	memset (&priv->default_route.v4, 0, sizeof (priv->default_route.v4));
	priv->default_route.v4.source = NM_IP_CONFIG_SOURCE_USER;
	priv->default_route.v4.gateway = gateway;
	priv->default_route.v4.metric = default_route_metric;
	priv->default_route.v4.mss = nm_ip4_config_get_mss (composite);

	if (!has_direct_route) {
		NMPlatformIP4Route r = priv->default_route.v4;

		/* add a direct route to the gateway */
		r.network = gateway;
		r.plen = 32;
		r.gateway = 0;
		nm_ip4_config_add_route (composite, &r);
	}

END_ADD_DEFAULT_ROUTE:

	if (priv->default_route.v4_is_assumed) {
		/* If above does not explicitly assign a default route, we always pick up the
		 * default route based on what is currently configured.
		 * That means that even managed connections with never-default, can
		 * get a default route (if configured externally).
		 */
		priv->default_route.v4_has = _device_get_default_route_from_platform (self, AF_INET, (NMPlatformIPRoute *) &priv->default_route.v4);
	}

	/* Allow setting MTU etc */
	if (commit) {
		if (NM_DEVICE_GET_CLASS (self)->ip4_config_pre_commit)
			NM_DEVICE_GET_CLASS (self)->ip4_config_pre_commit (self, composite);
	}

	routes_full_sync =    commit
	                   && priv->v4_commit_first_time
	                   && !nm_device_uses_assumed_connection (self);

	success = nm_device_set_ip4_config (self, composite, default_route_metric, commit, routes_full_sync, out_reason);
	g_object_unref (composite);

	if (commit)
		priv->v4_commit_first_time = FALSE;
	return success;
}

static void
dhcp4_lease_change (NMDevice *self, NMIP4Config *config)
{
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	g_return_if_fail (config != NULL);

	if (!ip4_config_merge_and_apply (self, config, TRUE, &reason)) {
		_LOGW (LOGD_DHCP4, "failed to update IPv4 config for DHCP change.");
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

static gboolean
dhcp4_restart_cb (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;
	NMDeviceStateReason reason;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	priv->dhcp4_restart_id = 0;
	connection = nm_device_get_connection (self);

	if (dhcp4_start (self, connection, &reason) == NM_ACT_STAGE_RETURN_FAILURE)
		priv->dhcp4_restart_id = g_timeout_add_seconds (120, dhcp4_restart_cb, self);

	return FALSE;
}

static void
dhcp4_fail (NMDevice *self, gboolean timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	dhcp4_cleanup (self, CLEANUP_TYPE_DECONFIGURE, FALSE);

	/* Don't fail if there are static addresses configured on
	 * the device, instead retry after some time.
	 */
	if (   priv->ip4_state == IP_DONE
	    && priv->con_ip4_config
	    && nm_ip4_config_get_num_addresses (priv->con_ip4_config) > 0) {
		_LOGI (LOGD_DHCP4, "Scheduling DHCPv4 restart because device has IP addresses");
		priv->dhcp4_restart_id = g_timeout_add_seconds (120, dhcp4_restart_cb, self);
		return;
	}

	/* Instead of letting an assumed connection fail (which means that the
	 * device will transition to the ACTIVATED state without IP configuration),
	 * retry DHCP again.
	 */
	if (nm_device_uses_assumed_connection (self)) {
		_LOGI (LOGD_DHCP4, "Scheduling DHCPv4 restart because the connection is assumed");
		priv->dhcp4_restart_id = g_timeout_add_seconds (120, dhcp4_restart_cb, self);
		return;
	}

	if (timeout || (priv->ip4_state == IP_CONF))
		nm_device_activate_schedule_ip4_config_timeout (self);
	else if (priv->ip4_state == IP_DONE)
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
	else
		g_warn_if_reached ();
}

static void
dhcp4_state_changed (NMDhcpClient *client,
                     NMDhcpState state,
                     NMIP4Config *ip4_config,
                     GHashTable *options,
                     const char *event_id,
                     gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == FALSE);
	g_return_if_fail (!ip4_config || NM_IS_IP4_CONFIG (ip4_config));

	_LOGD (LOGD_DHCP4, "new DHCPv4 client state %d", state);

	switch (state) {
	case NM_DHCP_STATE_BOUND:
		if (!ip4_config) {
			_LOGW (LOGD_DHCP4, "failed to get IPv4 config in response to DHCP event.");
			nm_device_state_changed (self,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
			break;
		}

		nm_dhcp4_config_set_options (priv->dhcp4_config, options);
		g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP4_CONFIG);

		if (priv->ip4_state == IP_CONF)
			nm_device_activate_schedule_ip4_config_result (self, ip4_config);
		else if (priv->ip4_state == IP_DONE) {
			dhcp4_lease_change (self, ip4_config);
			nm_device_update_metered (self);
		}
		break;
	case NM_DHCP_STATE_TIMEOUT:
		dhcp4_fail (self, TRUE);
		break;
	case NM_DHCP_STATE_EXPIRE:
		/* Ignore expiry before we even have a lease (NAK, old lease, etc) */
		if (priv->ip4_state == IP_CONF)
			break;
		/* Fall through */
	case NM_DHCP_STATE_DONE:
	case NM_DHCP_STATE_FAIL:
		dhcp4_fail (self, FALSE);
		break;
	default:
		break;
	}
}

static NMActStageReturn
dhcp4_start (NMDevice *self,
             NMConnection *connection,
             NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingIPConfig *s_ip4;
	const guint8 *hw_addr;
	size_t hw_addr_len = 0;
	GByteArray *tmp = NULL;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);

	/* Clear old exported DHCP options */
	if (priv->dhcp4_config)
		g_object_unref (priv->dhcp4_config);
	priv->dhcp4_config = nm_dhcp4_config_new ();

	hw_addr = nm_platform_link_get_address (NM_PLATFORM_GET, nm_device_get_ip_ifindex (self), &hw_addr_len);
	if (hw_addr_len) {
		tmp = g_byte_array_sized_new (hw_addr_len);
		g_byte_array_append (tmp, hw_addr, hw_addr_len);
	}

	/* Begin DHCP on the interface */
	g_warn_if_fail (priv->dhcp4_client == NULL);
	priv->dhcp4_client = nm_dhcp_manager_start_ip4 (nm_dhcp_manager_get (),
	                                                nm_device_get_ip_iface (self),
	                                                nm_device_get_ip_ifindex (self),
	                                                tmp,
	                                                nm_connection_get_uuid (connection),
	                                                nm_device_get_ip4_route_metric (self),
	                                                nm_setting_ip_config_get_dhcp_send_hostname (s_ip4),
	                                                nm_setting_ip_config_get_dhcp_hostname (s_ip4),
	                                                nm_setting_ip4_config_get_dhcp_client_id (NM_SETTING_IP4_CONFIG (s_ip4)),
	                                                priv->dhcp_timeout,
	                                                priv->dhcp_anycast_address,
	                                                NULL);

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

	_LOGI (LOGD_DHCP4, "DHCPv4 lease renewal requested");

	/* Terminate old DHCP instance and release the old lease */
	dhcp4_cleanup (self, CLEANUP_TYPE_DECONFIGURE, release);

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
reserve_shared_ip (NMDevice *self, NMSettingIPConfig *s_ip4, NMPlatformIP4Address *address)
{
	if (G_UNLIKELY (shared_ips == NULL))
		shared_ips = g_hash_table_new (g_direct_hash, g_direct_equal);

	memset (address, 0, sizeof (*address));

	if (s_ip4 && nm_setting_ip_config_get_num_addresses (s_ip4)) {
		/* Use the first user-supplied address */
		NMIPAddress *user = nm_setting_ip_config_get_address (s_ip4, 0);

		g_assert (user);
		nm_ip_address_get_address_binary (user, &address->address);
		address->plen = nm_ip_address_get_prefix (user);
	} else {
		/* Find an unused address in the 10.42.x.x range */
		guint32 start = (guint32) ntohl (0x0a2a0001); /* 10.42.0.1 */
		guint32 count = 0;

		while (g_hash_table_lookup (shared_ips, GUINT_TO_POINTER (start + count))) {
			count += ntohl (0x100);
			if (count > ntohl (0xFE00)) {
				_LOGE (LOGD_SHARING, "ran out of shared IP addresses!");
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

	if (!reserve_shared_ip (self, nm_connection_get_setting_ip4_config (connection), &address)) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NULL;
	}

	config = nm_ip4_config_new (nm_device_get_ip_ifindex (self));
	address.source = NM_IP_CONFIG_SOURCE_SHARED;
	nm_ip4_config_add_address (config, &address);

	/* Remove the address lock when the object gets disposed */
	g_object_set_data_full (G_OBJECT (config), "shared-ip",
	                        GUINT_TO_POINTER (address.address),
	                        release_shared_ip);

	return config;
}

/*********************************************/

static gboolean
connection_ip4_method_requires_carrier (NMConnection *connection,
                                        gboolean *out_ip4_enabled)
{
	const char *method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	static const char *ip4_carrier_methods[] = {
		NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
		NULL
	};

	if (out_ip4_enabled)
		*out_ip4_enabled = !!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	return _nm_utils_string_in_list (method, ip4_carrier_methods);
}

static gboolean
connection_ip6_method_requires_carrier (NMConnection *connection,
                                        gboolean *out_ip6_enabled)
{
	const char *method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	static const char *ip6_carrier_methods[] = {
		NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		NM_SETTING_IP6_CONFIG_METHOD_DHCP,
		NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
		NULL
	};

	if (out_ip6_enabled)
		*out_ip6_enabled = !!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	return _nm_utils_string_in_list (method, ip6_carrier_methods);
}

static gboolean
connection_requires_carrier (NMConnection *connection)
{
	NMSettingIPConfig *s_ip4, *s_ip6;
	gboolean ip4_carrier_wanted, ip6_carrier_wanted;
	gboolean ip4_used = FALSE, ip6_used = FALSE;

	ip4_carrier_wanted = connection_ip4_method_requires_carrier (connection, &ip4_used);
	if (ip4_carrier_wanted) {
		/* If IPv4 wants a carrier and cannot fail, the whole connection
		 * requires a carrier regardless of the IPv6 method.
		 */
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (s_ip4 && !nm_setting_ip_config_get_may_fail (s_ip4))
			return TRUE;
	}

	ip6_carrier_wanted = connection_ip6_method_requires_carrier (connection, &ip6_used);
	if (ip6_carrier_wanted) {
		/* If IPv6 wants a carrier and cannot fail, the whole connection
		 * requires a carrier regardless of the IPv4 method.
		 */
		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (s_ip6 && !nm_setting_ip_config_get_may_fail (s_ip6))
			return TRUE;
	}

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
have_any_ready_slaves (NMDevice *self, const GSList *slaves)
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

	if (   connection_ip4_method_requires_carrier (connection, NULL)
	    && priv->is_master
	    && !priv->carrier) {
		_LOGI (LOGD_IP4 | LOGD_DEVICE,
		       "IPv4 config waiting until carrier is on");
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
			_LOGI (LOGD_DEVICE | LOGD_IP4,
			       "IPv4 config waiting until slaves are ready");
			return NM_ACT_STAGE_RETURN_WAIT;
		}
	}

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);

	/* Start IPv4 addressing based on the method requested */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0)
		ret = dhcp4_start (self, connection, reason);
	else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL) == 0)
		ret = ipv4ll_start (self, reason);
	else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0) {
		/* Use only IPv4 config from the connection data */
		*out_config = nm_ip4_config_new (nm_device_get_ip_ifindex (self));
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
	} else
		_LOGW (LOGD_IP4, "unhandled IPv4 config method '%s'; will fail", method);

	return ret;
}

/*********************************************/
/* DHCPv6 stuff */

static void
dhcp6_cleanup (NMDevice *self, CleanupType cleanup_type, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_NONE;
	g_clear_object (&priv->dhcp6_ip6_config);
	g_clear_pointer (&priv->dhcp6_event_id, g_free);
	nm_clear_g_source (&priv->dhcp6_restart_id);

	if (priv->dhcp6_client) {
		if (priv->dhcp6_state_sigid) {
			g_signal_handler_disconnect (priv->dhcp6_client, priv->dhcp6_state_sigid);
			priv->dhcp6_state_sigid = 0;
		}

		if (   cleanup_type == CLEANUP_TYPE_DECONFIGURE
		    || cleanup_type == CLEANUP_TYPE_REMOVED)
			nm_dhcp_client_stop (priv->dhcp6_client, release);

		g_clear_object (&priv->dhcp6_client);
	}

	nm_device_remove_pending_action (self, PENDING_ACTION_DHCP6, FALSE);

	if (priv->dhcp6_config) {
		g_clear_object (&priv->dhcp6_config);
		g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP6_CONFIG);
	}
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
	gboolean has_direct_route;
	const struct in6_addr *gateway;
	gboolean connection_has_default_route, connection_is_never_default;
	gboolean routes_full_sync;
	gboolean ignore_auto_routes = FALSE;
	gboolean ignore_auto_dns = FALSE;

	/* Apply ignore-auto-routes and ignore-auto-dns settings */
	connection = nm_device_get_connection (self);
	if (connection) {
		NMSettingIPConfig *s_ip6 = nm_connection_get_setting_ip6_config (connection);

		if (s_ip6) {
			ignore_auto_routes = nm_setting_ip_config_get_ignore_auto_routes (s_ip6);
			ignore_auto_dns = nm_setting_ip_config_get_ignore_auto_dns (s_ip6);
		}
	}

	/* If no config was passed in, create a new one */
	composite = nm_ip6_config_new (nm_device_get_ip_ifindex (self));

	if (commit)
		ensure_con_ip6_config (self);
	g_assert (composite);

	/* Merge all the IP configs into the composite config */
	if (priv->ac_ip6_config) {
		nm_ip6_config_merge (composite, priv->ac_ip6_config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0));
	}
	if (priv->dhcp6_ip6_config) {
		nm_ip6_config_merge (composite, priv->dhcp6_ip6_config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0));
	}
	if (priv->vpn6_config)
		nm_ip6_config_merge (composite, priv->vpn6_config, NM_IP_CONFIG_MERGE_DEFAULT);
	if (priv->ext_ip6_config)
		nm_ip6_config_merge (composite, priv->ext_ip6_config, NM_IP_CONFIG_MERGE_DEFAULT);

	/* Merge WWAN config *last* to ensure modem-given settings overwrite
	 * any external stuff set by pppd or other scripts.
	 */
	if (priv->wwan_ip6_config) {
		nm_ip6_config_merge (composite, priv->wwan_ip6_config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0));
	}

	/* Merge user overrides into the composite config. For assumed connections,
	 * con_ip6_config is empty. */
	if (priv->con_ip6_config)
		nm_ip6_config_merge (composite, priv->con_ip6_config, NM_IP_CONFIG_MERGE_DEFAULT);

	/* Add the default route.
	 *
	 * We keep track of the default route of a device in a private field.
	 * NMDevice needs to know the default route at this point, because the gateway
	 * might require a direct route (see below).
	 *
	 * But also, we don't want to add the default route to priv->ip6_config,
	 * because the default route from the setting might not be the same that
	 * NMDefaultRouteManager eventually configures (because the it might
	 * tweak the effective metric).
	 */

	/* unless we come to a different conclusion below, we have no default route and
	 * the route is assumed. */
	priv->default_route.v6_has = FALSE;
	priv->default_route.v6_is_assumed = TRUE;

	if (!commit) {
		/* during a non-commit event, we always pickup whatever is configured. */
		goto END_ADD_DEFAULT_ROUTE;
	}

	if (nm_device_uses_generated_assumed_connection (self)) {
		/* a generate-assumed-connection always detects the default route from platform */
		goto END_ADD_DEFAULT_ROUTE;
	}

	/* At this point, we treat assumed and non-assumed connections alike.
	 * For assumed connections we do that because we still manage RA and DHCP
	 * leases for them, so we must extend/update the default route on commits.
	 */

	connection_has_default_route
	    = nm_default_route_manager_ip6_connection_has_default_route (nm_default_route_manager_get (),
	                                                                 connection, &connection_is_never_default);

	if (   !priv->v6_commit_first_time
	    && connection_is_never_default) {
		/* If the connection is explicitly configured as never-default, we enforce the (absence of the)
		 * default-route only once. That allows the user to configure a connection as never-default,
		 * but he can add default routes externally (via a dispatcher script) and NM will not interfere. */
		goto END_ADD_DEFAULT_ROUTE;
	}

	/* we are about to commit (for a non-assumed connection). Enforce whatever we have
	 * configured. */
	priv->default_route.v6_is_assumed = FALSE;

	if (!connection_has_default_route)
		goto END_ADD_DEFAULT_ROUTE;

	if (!nm_ip6_config_get_num_addresses (composite)) {
		/* without addresses we can have no default route. */
		goto END_ADD_DEFAULT_ROUTE;
	}

	gateway = nm_ip6_config_get_gateway (composite);
	if (!gateway)
		goto END_ADD_DEFAULT_ROUTE;


	has_direct_route = nm_ip6_config_get_direct_route_for_host (composite, gateway) != NULL;



	priv->default_route.v6_has = TRUE;
	memset (&priv->default_route.v6, 0, sizeof (priv->default_route.v6));
	priv->default_route.v6.source = NM_IP_CONFIG_SOURCE_USER;
	priv->default_route.v6.gateway = *gateway;
	priv->default_route.v6.metric = nm_device_get_ip6_route_metric (self);
	priv->default_route.v6.mss = nm_ip6_config_get_mss (composite);

	if (!has_direct_route) {
		NMPlatformIP6Route r = priv->default_route.v6;

		/* add a direct route to the gateway */
		r.network = *gateway;
		r.plen = 128;
		r.gateway = in6addr_any;
		nm_ip6_config_add_route (composite, &r);
	}

END_ADD_DEFAULT_ROUTE:

	if (priv->default_route.v6_is_assumed) {
		/* If above does not explicitly assign a default route, we always pick up the
		 * default route based on what is currently configured.
		 * That means that even managed connections with never-default, can
		 * get a default route (if configured externally).
		 */
		priv->default_route.v6_has = _device_get_default_route_from_platform (self, AF_INET6, (NMPlatformIPRoute *) &priv->default_route.v6);
	}

	nm_ip6_config_addresses_sort (composite,
	    priv->rdisc ? priv->rdisc_use_tempaddr : NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

	/* Allow setting MTU etc */
	if (commit) {
		if (NM_DEVICE_GET_CLASS (self)->ip6_config_pre_commit)
			NM_DEVICE_GET_CLASS (self)->ip6_config_pre_commit (self, composite);
	}

	routes_full_sync =    commit
	                   && priv->v6_commit_first_time
	                   && !nm_device_uses_assumed_connection (self);

	success = nm_device_set_ip6_config (self, composite, commit, routes_full_sync, out_reason);
	g_object_unref (composite);
	if (commit)
		priv->v6_commit_first_time = FALSE;
	return success;
}

static void
dhcp6_lease_change (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	if (priv->dhcp6_ip6_config == NULL) {
		_LOGW (LOGD_DHCP6, "failed to get DHCPv6 config for rebind");
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
		return;
	}

	g_assert (priv->dhcp6_client);  /* sanity check */

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* Apply the updated config */
	if (ip6_config_merge_and_apply (self, TRUE, &reason) == FALSE) {
		_LOGW (LOGD_DHCP6, "failed to update IPv6 config in response to DHCP event.");
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
	} else {
		/* Notify dispatcher scripts of new DHCPv6 config */
		nm_dispatcher_call (DISPATCHER_ACTION_DHCP6_CHANGE, connection, self, NULL, NULL, NULL);
	}
}

static gboolean
dhcp6_restart_cb (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;
	NMDeviceStateReason reason;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	priv->dhcp6_restart_id = 0;

	if (!dhcp6_start (self, FALSE, &reason))
		priv->dhcp6_restart_id = g_timeout_add_seconds (120, dhcp6_restart_cb, self);

	return FALSE;
}

static void
dhcp6_fail (NMDevice *self, gboolean timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, FALSE);

	if (priv->dhcp6_mode == NM_RDISC_DHCP_LEVEL_MANAGED) {
		/* Don't fail if there are static addresses configured on
		 * the device, instead retry after some time.
		 */
		if (   priv->ip6_state == IP_DONE
		    && priv->con_ip6_config
		    && nm_ip6_config_get_num_addresses (priv->con_ip6_config)) {
			_LOGI (LOGD_DHCP6, "Scheduling DHCPv6 restart because device has IP addresses");
			priv->dhcp6_restart_id = g_timeout_add_seconds (120, dhcp6_restart_cb, self);
			return;
		}

		/* Instead of letting an assumed connection fail (which means that the
		 * device will transition to the ACTIVATED state without IP configuration),
		 * retry DHCP again.
		 */
		if (nm_device_uses_assumed_connection (self)) {
			_LOGI (LOGD_DHCP6, "Scheduling DHCPv6 restart because the connection is assumed");
			priv->dhcp6_restart_id = g_timeout_add_seconds (120, dhcp6_restart_cb, self);
			return;
		}

		if (timeout || (priv->ip6_state == IP_CONF))
			nm_device_activate_schedule_ip6_config_timeout (self);
		else if (priv->ip6_state == IP_DONE)
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
		else
			g_warn_if_reached ();
	} else {
		/* not a hard failure; just live with the RA info */
		if (priv->ip6_state == IP_CONF)
			nm_device_activate_schedule_ip6_config_result (self);
	}
}

static void
dhcp6_timeout (NMDevice *self, NMDhcpClient *client)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dhcp6_mode == NM_RDISC_DHCP_LEVEL_MANAGED)
		dhcp6_fail (self, TRUE);
	else {
		/* not a hard failure; just live with the RA info */
		dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, FALSE);
		if (priv->ip6_state == IP_CONF)
			nm_device_activate_schedule_ip6_config_result (self);
	}
}

static void
dhcp6_state_changed (NMDhcpClient *client,
                     NMDhcpState state,
                     NMIP6Config *ip6_config,
                     GHashTable *options,
                     const char *event_id,
                     gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint i;

	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == TRUE);
	g_return_if_fail (!ip6_config || NM_IS_IP6_CONFIG (ip6_config));

	_LOGD (LOGD_DHCP6, "new DHCPv6 client state %d", state);

	switch (state) {
	case NM_DHCP_STATE_BOUND:
		/* If the server sends multiple IPv6 addresses, we receive a state
		 * changed event for each of them. Use the event ID to merge IPv6
		 * addresses from the same transaction into a single configuration.
		 */
		if (   ip6_config
		    && event_id
		    && priv->dhcp6_event_id
		    && !strcmp (event_id, priv->dhcp6_event_id)) {
			for (i = 0; i < nm_ip6_config_get_num_addresses (ip6_config); i++) {
				nm_ip6_config_add_address (priv->dhcp6_ip6_config,
				                           nm_ip6_config_get_address (ip6_config, i));
			}
		} else {
			g_clear_object (&priv->dhcp6_ip6_config);
			g_clear_pointer (&priv->dhcp6_event_id, g_free);
			if (ip6_config) {
				priv->dhcp6_ip6_config = g_object_ref (ip6_config);
				priv->dhcp6_event_id = g_strdup (event_id);
				nm_dhcp6_config_set_options (priv->dhcp6_config, options);
				g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP6_CONFIG);
			}
		}

		if (priv->ip6_state == IP_CONF) {
			if (priv->dhcp6_ip6_config == NULL) {
				/* FIXME: Initial DHCP failed; should we fail IPv6 entirely then? */
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_DHCP_FAILED);
				break;
			}
			nm_device_activate_schedule_ip6_config_result (self);
		} else if (priv->ip6_state == IP_DONE)
			dhcp6_lease_change (self);
		break;
	case NM_DHCP_STATE_TIMEOUT:
		dhcp6_timeout (self, client);
		break;
	case NM_DHCP_STATE_EXPIRE:
		/* Ignore expiry before we even have a lease (NAK, old lease, etc) */
		if (priv->ip6_state != IP_CONF)
			dhcp6_fail (self, FALSE);
		break;
	case NM_DHCP_STATE_DONE:
		/* In IPv6 info-only mode, the client doesn't handle leases so it
		 * may exit right after getting a response from the server.  That's
		 * normal.  In that case we just ignore the exit.
		 */
		if (priv->dhcp6_mode == NM_RDISC_DHCP_LEVEL_OTHERCONF)
			break;
		/* Otherwise, fall through */
	case NM_DHCP_STATE_FAIL:
		dhcp6_fail (self, FALSE);
		break;
	default:
		break;
	}
}

static gboolean
dhcp6_start_with_link_ready (NMDevice *self, NMConnection *connection)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingIPConfig *s_ip6;
	GByteArray *tmp = NULL;
	const guint8 *hw_addr;
	size_t hw_addr_len = 0;

	g_assert (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);

	hw_addr = nm_platform_link_get_address (NM_PLATFORM_GET, nm_device_get_ip_ifindex (self), &hw_addr_len);
	if (hw_addr_len) {
		tmp = g_byte_array_sized_new (hw_addr_len);
		g_byte_array_append (tmp, hw_addr, hw_addr_len);
	}

	priv->dhcp6_client = nm_dhcp_manager_start_ip6 (nm_dhcp_manager_get (),
	                                                nm_device_get_ip_iface (self),
	                                                nm_device_get_ip_ifindex (self),
	                                                tmp,
	                                                nm_connection_get_uuid (connection),
	                                                nm_device_get_ip6_route_metric (self),
	                                                nm_setting_ip_config_get_dhcp_send_hostname (s_ip6),
	                                                nm_setting_ip_config_get_dhcp_hostname (s_ip6),
	                                                priv->dhcp_timeout,
	                                                priv->dhcp_anycast_address,
	                                                (priv->dhcp6_mode == NM_RDISC_DHCP_LEVEL_OTHERCONF) ? TRUE : FALSE,
	                                                nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6)));
	if (tmp)
		g_byte_array_free (tmp, TRUE);

	if (priv->dhcp6_client) {
		priv->dhcp6_state_sigid = g_signal_connect (priv->dhcp6_client,
		                                            NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
		                                            G_CALLBACK (dhcp6_state_changed),
		                                            self);
	}

	return !!priv->dhcp6_client;
}

static gboolean
dhcp6_start (NMDevice *self, gboolean wait_for_ll, NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;

	g_clear_object (&priv->dhcp6_config);
	priv->dhcp6_config = nm_dhcp6_config_new ();

	g_warn_if_fail (priv->dhcp6_ip6_config == NULL);
	g_clear_object (&priv->dhcp6_ip6_config);
	g_clear_pointer (&priv->dhcp6_event_id, g_free);

	connection = nm_device_get_connection (self);
	g_assert (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!nm_setting_ip_config_get_may_fail (s_ip6) ||
	    !strcmp (nm_setting_ip_config_get_method (s_ip6), NM_SETTING_IP6_CONFIG_METHOD_DHCP))
		nm_device_add_pending_action (self, PENDING_ACTION_DHCP6, TRUE);

	if (wait_for_ll) {
		NMActStageReturn ret;

		/* ensure link local is ready... */
		ret = linklocal6_start (self);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
			/* success; wait for the LL address to show up */
			return TRUE;
		}

		/* success; already have the LL address; kick off DHCP */
		g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS || ret == NM_ACT_STAGE_RETURN_FINISH);
	}

	if (!dhcp6_start_with_link_ready (self, connection)) {
		*reason = NM_DEVICE_STATE_REASON_DHCP_START_FAILED;
		return FALSE;
	}

	return TRUE;
}

gboolean
nm_device_dhcp6_renew (NMDevice *self, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (priv->dhcp6_client != NULL, FALSE);

	_LOGI (LOGD_DHCP6, "DHCPv6 lease renewal requested");

	/* Terminate old DHCP instance and release the old lease */
	dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, release);

	/* Start DHCP again on the interface */
	return dhcp6_start (self, FALSE, NULL);
}

/******************************************/

static gboolean
have_ip6_address (const NMIP6Config *ip6_config, gboolean linklocal)
{
	guint i;

	if (!ip6_config)
		return FALSE;

	linklocal = !!linklocal;

	for (i = 0; i < nm_ip6_config_get_num_addresses (ip6_config); i++) {
		const NMPlatformIP6Address *addr = nm_ip6_config_get_address (ip6_config, i);

		if ((IN6_IS_ADDR_LINKLOCAL (&addr->address) == linklocal) &&
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

	_LOGD (LOGD_DEVICE, "linklocal6: waiting for link-local addresses failed due to timeout");

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
	g_assert (have_ip6_address (priv->ip6_config, TRUE));

	linklocal6_cleanup (self);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	_LOGD (LOGD_DEVICE, "linklocal6: waiting for link-local addresses successful, continue with method %s", method);

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0) {
		if (!addrconf6_start_with_link_ready (self)) {
			/* Time out IPv6 instead of failing the entire activation */
			nm_device_activate_schedule_ip6_config_timeout (self);
		}
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0) {
		if (!dhcp6_start_with_link_ready (self, connection)) {
			/* Time out IPv6 instead of failing the entire activation */
			nm_device_activate_schedule_ip6_config_timeout (self);
		}
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0)
		nm_device_activate_schedule_ip6_config_result (self);
	else
		g_return_if_fail (FALSE);
}

static void
check_and_add_ipv6ll_addr (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ip_ifindex = nm_device_get_ip_ifindex (self);
	NMUtilsIPv6IfaceId iid;
	struct in6_addr lladdr;
	guint i, n;

	if (priv->nm_ipv6ll == FALSE)
		return;

	if (priv->ip6_config) {
		n = nm_ip6_config_get_num_addresses (priv->ip6_config);
		for (i = 0; i < n; i++) {
			const NMPlatformIP6Address *addr;

			addr = nm_ip6_config_get_address (priv->ip6_config, i);
			if (IN6_IS_ADDR_LINKLOCAL (&addr->address)) {
				/* Already have an LL address, nothing to do */
				return;
			}
		}
	}

	if (!nm_device_get_ip_iface_identifier (self, &iid)) {
		_LOGW (LOGD_IP6, "failed to get interface identifier; IPv6 may be broken");
		return;
	}

	memset (&lladdr, 0, sizeof (lladdr));
	lladdr.s6_addr16[0] = htons (0xfe80);
	nm_utils_ipv6_addr_set_interface_identfier (&lladdr, iid);
	_LOGD (LOGD_IP6, "adding IPv6LL address %s", nm_utils_inet6_ntop (&lladdr, NULL));
	if (!nm_platform_ip6_address_add (NM_PLATFORM_GET,
	                                  ip_ifindex,
	                                  lladdr,
	                                  in6addr_any,
	                                  64,
	                                  NM_PLATFORM_LIFETIME_PERMANENT,
	                                  NM_PLATFORM_LIFETIME_PERMANENT,
	                                  0)) {
		_LOGW (LOGD_IP6, "failed to add IPv6 link-local address %s",
		       nm_utils_inet6_ntop (&lladdr, NULL));
	}
}

static NMActStageReturn
linklocal6_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	const char *method;

	linklocal6_cleanup (self);

	if (have_ip6_address (priv->ip6_config, TRUE))
		return NM_ACT_STAGE_RETURN_FINISH;

	connection = nm_device_get_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	_LOGD (LOGD_DEVICE, "linklocal6: starting IPv6 with method '%s', but the device has no link-local addresses configured. Wait.", method);

	check_and_add_ipv6ll_addr (self);

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
		s_kernel = !!nm_platform_check_support_kernel_extended_ifa_flags (NM_PLATFORM_GET);

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

static void nm_device_ipv6_set_mtu (NMDevice *self, guint32 mtu);

static void
nm_device_set_mtu (NMDevice *self, guint32 mtu)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ifindex = nm_device_get_ip_ifindex (self);

	if (mtu)
		priv->mtu = mtu;

	/* Ensure the IPv6 MTU is still alright. */
	if (priv->ip6_mtu)
		nm_device_ipv6_set_mtu (self, priv->ip6_mtu);

	if (priv->mtu && priv->mtu != nm_platform_link_get_mtu (NM_PLATFORM_GET, ifindex))
		nm_platform_link_set_mtu (NM_PLATFORM_GET, ifindex, priv->mtu);
}

static void
nm_device_ipv6_set_mtu (NMDevice *self, guint32 mtu)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint32 plat_mtu = nm_device_ipv6_sysctl_get_int32 (self, "mtu", priv->mtu);
	char val[16];

	priv->ip6_mtu = mtu ?: plat_mtu;

	if (priv->ip6_mtu && priv->mtu && priv->mtu < priv->ip6_mtu) {
		_LOGI (LOGD_DEVICE | LOGD_IP6, "Lowering IPv6 MTU (%d) to match device MTU (%d)",
		       priv->ip6_mtu, priv->mtu);
		priv->ip6_mtu = priv->mtu;
	}

	if (priv->ip6_mtu && priv->ip6_mtu < 1280) {
		_LOGI (LOGD_DEVICE | LOGD_IP6, "IPv6 MTU (%d) smaller than 1280, adjusting",
		       priv->ip6_mtu);
		priv->ip6_mtu = 1280;
	}

	if (priv->ip6_mtu && priv->mtu && priv->mtu < priv->ip6_mtu) {
		_LOGI (LOGD_DEVICE | LOGD_IP6, "Raising device MTU (%d) to match IPv6 MTU (%d)",
		       priv->mtu, priv->ip6_mtu);
		nm_device_set_mtu (self, priv->ip6_mtu);
	}

	if (priv->ip6_mtu != plat_mtu) {
		g_snprintf (val, sizeof (val), "%d", mtu);
		nm_device_ipv6_sysctl_set (self, "mtu", val);
	}
}

static void
rdisc_config_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int i;
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
		                 nm_platform_check_support_kernel_extended_ifa_flags (NM_PLATFORM_GET);
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

	if (!priv->ac_ip6_config)
		priv->ac_ip6_config = nm_ip6_config_new (nm_device_get_ip_ifindex (self));

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
			address.source = NM_IP_CONFIG_SOURCE_RDISC;
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
				route.source = NM_IP_CONFIG_SOURCE_RDISC;
				route.metric = nm_device_get_ip6_route_metric (self);

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
		dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, TRUE);

		priv->dhcp6_mode = rdisc->dhcp_level;
		if (priv->dhcp6_mode != NM_RDISC_DHCP_LEVEL_NONE) {
			NMDeviceStateReason reason;

			_LOGD (LOGD_DEVICE | LOGD_DHCP6,
			       "Activation: Stage 3 of 5 (IP Configure Start) starting DHCPv6"
			       " as requested by IPv6 router...");
			if (!dhcp6_start (self, FALSE, &reason)) {
				if (priv->dhcp6_mode == NM_RDISC_DHCP_LEVEL_MANAGED)
					nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
			}
			return;
		}
	}

	if (changed & NM_RDISC_CONFIG_HOP_LIMIT)
		nm_platform_sysctl_set_ip6_hop_limit_safe (NM_PLATFORM_GET, nm_device_get_ip_iface (self), rdisc->hop_limit);

	if (changed & NM_RDISC_CONFIG_MTU)
		priv->ip6_mtu = rdisc->mtu;

	nm_device_activate_schedule_ip6_config_result (self);
}

static void
rdisc_ra_timeout (NMRDisc *rdisc, NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* We don't want to stop listening for router advertisements completely,
	 * but instead let device activation continue activating.  If an RA
	 * shows up later, we'll use it as long as the device is not disconnected.
	 */

	_LOGD (LOGD_IP6, "timed out waiting for IPv6 router advertisement");
	if (priv->ip6_state == IP_CONF) {
		/* If RA is our only source of addressing information and we don't
		 * ever receive one, then time out IPv6.  But if there is other
		 * IPv6 configuration, like manual IPv6 addresses or external IPv6
		 * config, consider that sufficient for IPv6 success.
		 */
		if (have_ip6_address (priv->ip6_config, FALSE))
			nm_device_activate_schedule_ip6_config_result (self);
		else
			nm_device_activate_schedule_ip6_config_timeout (self);
	}
}

static gboolean
addrconf6_start_with_link_ready (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMUtilsIPv6IfaceId iid;

	g_assert (priv->rdisc);

	if (nm_platform_link_get_ipv6_token (NM_PLATFORM_GET, priv->ifindex, &iid)) {
		_LOGD (LOGD_DEVICE, "IPv6 tokenized identifier present on device %s", priv->iface);
	} else if (!nm_device_get_ip_iface_identifier (self, &iid)) {
		_LOGW (LOGD_IP6, "failed to get interface identifier; IPv6 cannot continue");
		return FALSE;
	}

	/* Apply any manual configuration before starting RA */
	if (!ip6_config_merge_and_apply (self, TRUE, NULL))
		_LOGW (LOGD_IP6, "failed to apply manual IPv6 configuration");

	nm_device_ipv6_sysctl_set (self, "accept_ra", "1");
	nm_device_ipv6_sysctl_set (self, "accept_ra_defrtr", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_pinfo", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_rtr_pref", "0");

	priv->rdisc_changed_id = g_signal_connect (priv->rdisc,
	                                           NM_RDISC_CONFIG_CHANGED,
	                                           G_CALLBACK (rdisc_config_changed),
	                                           self);
	priv->rdisc_timeout_id = g_signal_connect (priv->rdisc,
	                                           NM_RDISC_RA_TIMEOUT,
	                                           G_CALLBACK (rdisc_ra_timeout),
	                                           self);

	nm_rdisc_set_iid (priv->rdisc, iid);
	nm_rdisc_start (priv->rdisc);
	return TRUE;
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
		_LOGE (LOGD_IP6, "failed to start router discovery (%s)", ip_iface);
		return FALSE;
	}

	priv->rdisc_use_tempaddr = use_tempaddr;
	print_support_extended_ifa_flags (use_tempaddr);

	if (!nm_setting_ip_config_get_may_fail (nm_connection_get_setting_ip6_config (connection)))
		nm_device_add_pending_action (self, PENDING_ACTION_AUTOCONF6, TRUE);

	/* ensure link local is ready... */
	ret = linklocal6_start (self);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
		/* success; wait for the LL address to show up */
		return TRUE;
	}

	/* success; already have the LL address; kick off router discovery */
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS || ret == NM_ACT_STAGE_RETURN_FINISH);
	return addrconf6_start_with_link_ready (self);
}

static void
addrconf6_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->rdisc_changed_id) {
		g_signal_handler_disconnect (priv->rdisc, priv->rdisc_changed_id);
		priv->rdisc_changed_id = 0;
	}

	if (priv->rdisc_timeout_id) {
		g_signal_handler_disconnect (priv->rdisc, priv->rdisc_timeout_id);
		priv->rdisc_timeout_id = 0;
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
		value = nm_platform_sysctl_get (NM_PLATFORM_GET, nm_utils_ip6_property_path (ifname, ip6_properties_to_save[i]));
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
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		/* Don't touch "disable_ipv6" if we're doing userland IPv6LL */
		if (priv->nm_ipv6ll && strcmp (key, "disable_ipv6") == 0)
			continue;
		nm_device_ipv6_sysctl_set (self, key, value);
	}
}

static inline void
set_disable_ipv6 (NMDevice *self, const char *value)
{
	/* We only touch disable_ipv6 when NM is not managing the IPv6LL address */
	if (NM_DEVICE_GET_PRIVATE (self)->nm_ipv6ll == FALSE)
		nm_device_ipv6_sysctl_set (self, "disable_ipv6", value);
}

static inline void
set_nm_ipv6ll (NMDevice *self, gboolean enable)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ifindex = nm_device_get_ip_ifindex (self);
	char *value;

	if (!nm_platform_check_support_user_ipv6ll (NM_PLATFORM_GET))
		return;

	priv->nm_ipv6ll = enable;
	if (ifindex > 0) {
		const char *detail = enable ? "enable" : "disable";

		_LOGD (LOGD_IP6, "will %s userland IPv6LL", detail);
		if (!nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, ifindex, enable))
			_LOGW (LOGD_IP6, "failed to %s userspace IPv6LL address handling", detail);

		if (enable) {
			/* Bounce IPv6 to ensure the kernel stops IPv6LL address generation */
			value = nm_platform_sysctl_get (NM_PLATFORM_GET, 
			                                nm_utils_ip6_property_path (nm_device_get_ip_iface (self), "disable_ipv6"));
			if (g_strcmp0 (value, "0") == 0)
				nm_device_ipv6_sysctl_set (self, "disable_ipv6", "1");
			g_free (value);

			/* Ensure IPv6 is enabled */
			nm_device_ipv6_sysctl_set (self, "disable_ipv6", "0");
		}

	}
}

/************************************************************************/

static NMSettingIP6ConfigPrivacy
_ip6_privacy_clamp (NMSettingIP6ConfigPrivacy use_tempaddr)
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

static NMSettingIP6ConfigPrivacy
_ip6_privacy_get (NMDevice *self)
{
	NMSettingIP6ConfigPrivacy ip6_privacy;
	gs_free char *value = NULL;
	NMConnection *connection;

	g_return_val_if_fail (self, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

	/* 1.) First look at the per-connection setting. If it is not -1 (unknown),
	 * use it. */
	connection = nm_device_get_connection (self);
	if (connection) {
		NMSettingIPConfig *s_ip6 = nm_connection_get_setting_ip6_config (connection);

		if (s_ip6) {
			ip6_privacy = nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6));
			ip6_privacy = _ip6_privacy_clamp (ip6_privacy);
			if (ip6_privacy != NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
				return ip6_privacy;
		}
	}

	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "ipv6.ip6-privacy", self);

	/* 2.) use the default value from the configuration. */
	ip6_privacy = _nm_utils_ascii_str_to_int64 (value, 10,
	                                            NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
	                                            NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
	                                            NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
	if (ip6_privacy != NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
		return ip6_privacy;

	/* 3.) No valid default-value configured. Fallback to reading sysctl.
	 *
	 * Instead of reading static config files in /etc, just read the current sysctl value.
	 * This works as NM only writes to "/proc/sys/net/ipv6/conf/IFNAME/use_tempaddr", but leaves
	 * the "default" entry untouched. */
	ip6_privacy = nm_platform_sysctl_get_int32 (NM_PLATFORM_GET, "/proc/sys/net/ipv6/conf/default/use_tempaddr", NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
	return _ip6_privacy_clamp (ip6_privacy);
}

/****************************************************************/

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

	if (   connection_ip6_method_requires_carrier (connection, NULL)
	    && priv->is_master
	    && !priv->carrier) {
		_LOGI (LOGD_IP6 | LOGD_DEVICE,
		       "IPv6 config waiting until carrier is on");
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
			_LOGI (LOGD_DEVICE | LOGD_IP6,
			       "IPv6 config waiting until slaves are ready");
			return NM_ACT_STAGE_RETURN_WAIT;
		}
	}

	priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_NONE;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0) {
		if (!priv->master) {
			gboolean old_nm_ipv6ll = priv->nm_ipv6ll;

			/* When activating an IPv6 'ignore' connection we need to revert back
			 * to kernel IPv6LL, but the kernel won't actually assign an address
			 * to the interface until disable_ipv6 is bounced.
			 */
			set_nm_ipv6ll (self, FALSE);
			if (old_nm_ipv6ll == TRUE)
				nm_device_ipv6_sysctl_set (self, "disable_ipv6", "1");
			restore_ip6_properties (self);
		}
		return NM_ACT_STAGE_RETURN_STOP;
	}

	/* Ensure the MTU makes sense. If it was below 1280 the kernel would not
	 * expose any ipv6 sysctls or allow presence of any addresses on the interface,
	 * including LL, which * would make it impossible to autoconfigure MTU to a
	 * correct value. */
	if (!nm_device_uses_assumed_connection (self))
		nm_device_ipv6_set_mtu (self, priv->ip6_mtu);

	/* Any method past this point requires an IPv6LL address. Use NM-controlled
	 * IPv6LL if this is not an assumed connection, since assumed connections
	 * will already have IPv6 set up.
	 */
	if (!nm_device_uses_assumed_connection (self))
		set_nm_ipv6ll (self, TRUE);

	/* Re-enable IPv6 on the interface */
	set_disable_ipv6 (self, "0");

	ip6_privacy = _ip6_privacy_get (self);

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0) {
		if (!addrconf6_start (self, ip6_privacy)) {
			/* IPv6 might be disabled; allow IPv4 to proceed */
			ret = NM_ACT_STAGE_RETURN_STOP;
		} else
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0) {
		ret = linklocal6_start (self);
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0) {
		priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_MANAGED;
		if (!dhcp6_start (self, TRUE, reason)) {
			/* IPv6 might be disabled; allow IPv4 to proceed */
			ret = NM_ACT_STAGE_RETURN_STOP;
		} else
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0) {
		/* New blank config */
		*out_config = nm_ip6_config_new (nm_device_get_ip_ifindex (self));
		g_assert (*out_config);

		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else
		_LOGW (LOGD_IP6, "unhandled IPv6 config method '%s'; will fail", method);

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
		/* Activation not wanted */
		priv->ip6_state = IP_FAIL;
	} else if (ret == NM_ACT_STAGE_RETURN_FINISH) {
		/* Early finish, nothing more to do */
		priv->ip6_state = IP_DONE;
		if (nm_device_get_state (self) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_state_changed (self, NM_DEVICE_STATE_IP_CHECK, NM_DEVICE_STATE_REASON_NONE);
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
	NMActiveConnection *master;
	NMDevice *master_device;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	priv->ip4_state = priv->ip6_state = IP_WAIT;

	_LOGD (LOGD_DEVICE, "Activation: Stage 3 of 5 (IP Configure Start) started...");
	nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	/* Device should be up before we can do anything with it */
	if (!nm_platform_link_is_up (NM_PLATFORM_GET, nm_device_get_ip_ifindex (self)))
		_LOGW (LOGD_DEVICE, "interface %s not up for IP configuration", nm_device_get_ip_iface (self));

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
			_LOGI (LOGD_DEVICE, "Activation: connection '%s' waiting on master '%s'",
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

	nm_device_check_ip_failed (self, TRUE);

out:
	_LOGD (LOGD_DEVICE, "Activation: Stage 3 of 5 (IP Configure Start) complete.");
	return FALSE;
}


static void
fw_change_zone_cb (GError *error, gpointer user_data)
{
	NMDevice *self;
	NMDevicePrivate *priv;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_DEVICE (user_data);
	priv = NM_DEVICE_GET_PRIVATE (self);

	priv->fw_call = NULL;

	if (error) {
		/* FIXME: fail the device activation? */
	}

	activation_source_schedule (self, nm_device_activate_stage3_ip_config_start, 0);
	_LOGD (LOGD_DEVICE, "Activation: Stage 3 of 5 (IP Configure Start) scheduled.");
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

	g_return_if_fail (!priv->fw_call);

	/* Add the interface to the specified firewall zone */
	connection = nm_device_get_connection (self);
	g_assert (connection);
	s_con = nm_connection_get_setting_connection (connection);

	zone = nm_setting_connection_get_zone (s_con);

	if (nm_device_uses_assumed_connection (self)) {
		_LOGD (LOGD_DEVICE, "Activation: skip setting firewall zone '%s' for assumed device", zone ? zone : "default");
		activation_source_schedule (self, nm_device_activate_stage3_ip_config_start, 0);
		_LOGD (LOGD_DEVICE, "Activation: Stage 3 of 5 (IP Configure Start) scheduled.");
		return;
	}

	_LOGD (LOGD_DEVICE, "Activation: setting firewall zone '%s'", zone ? zone : "default");
	priv->fw_call = nm_firewall_manager_add_or_change_zone (nm_firewall_manager_get (),
	                                                        nm_device_get_ip_iface (self),
	                                                        zone,
	                                                        FALSE,
	                                                        fw_change_zone_cb,
	                                                        self);
}

static NMActStageReturn
act_stage4_ip4_config_timeout (NMDevice *self, NMDeviceStateReason *reason)
{
	if (!get_ip_config_may_fail (self, AF_INET)) {
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
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET);

	_LOGD (LOGD_DEVICE | LOGD_IP4, "Activation: Stage 4 of 5 (IPv4 Configure Timeout) started...");

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip4_config_timeout (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	priv->ip4_state = IP_FAIL;

	nm_device_check_ip_failed (self, FALSE);

out:
	_LOGD (LOGD_DEVICE | LOGD_IP4, "Activation: Stage 4 of 5 (IPv4 Configure Timeout) complete.");
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

	_LOGD (LOGD_DEVICE | LOGD_IP4, "Activation: Stage 4 of 5 (IPv4 Configure Timeout) scheduled...");
}


static NMActStageReturn
act_stage4_ip6_config_timeout (NMDevice *self, NMDeviceStateReason *reason)
{
	if (!get_ip_config_may_fail (self, AF_INET6)) {
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
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET6);

	_LOGD (LOGD_DEVICE | LOGD_IP6, "Activation: Stage 4 of 5 (IPv6 Configure Timeout) started...");

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip6_config_timeout (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

	priv->ip6_state = IP_FAIL;

	nm_device_check_ip_failed (self, FALSE);

out:
	_LOGD (LOGD_DEVICE | LOGD_IP6, "Activation: Stage 4 of 5 (IPv6 Configure Timeout) complete.");
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

	_LOGD (LOGD_DEVICE | LOGD_IP6, "Activation: Stage 4 of 5 (IPv6 Configure Timeout) scheduled...");
}

static gboolean
share_init (void)
{
	char *modules[] = { "ip_tables", "iptable_nat", "nf_nat_ftp", "nf_nat_irc",
	                    "nf_nat_sip", "nf_nat_tftp", "nf_nat_pptp", "nf_nat_h323",
	                    NULL };
	char **iter;
	int errsv;

	if (!nm_platform_sysctl_set (NM_PLATFORM_GET, "/proc/sys/net/ipv4/ip_forward", "1")) {
		errsv = errno;
		nm_log_err (LOGD_SHARING, "share: error starting IP forwarding: (%d) %s",
		            errsv, strerror (errsv));
		return FALSE;
	}

	if (!nm_platform_sysctl_set (NM_PLATFORM_GET, "/proc/sys/net/ipv4/ip_dynaddr", "1")) {
		errsv = errno;
		nm_log_err (LOGD_SHARING, "share: error starting IP forwarding: (%d) %s",
		            errsv, strerror (errsv));
	}

	for (iter = modules; *iter; iter++)
		nm_utils_modprobe (NULL, FALSE, *iter, NULL);

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
		_LOGE (LOGD_SHARING, "share: (%s) failed to start dnsmasq: %s",
		       ip_iface, (error && error->message) ? error->message : "(unknown)");
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
	const char *argv[] = { NULL, mode_arg, "-q", "-I", nm_device_get_ip_iface (self), "-c", "1", NULL, NULL };
	int ip_arg = G_N_ELEMENTS (argv) - 2;
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	int i, num;
	NMIPAddress *addr;
	GError *error = NULL;

	connection = nm_device_get_connection (self);
	if (!connection)
		return;
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return;
	num = nm_setting_ip_config_get_num_addresses (s_ip4);
	if (num == 0)
		return;

	argv[0] = nm_utils_find_helper ("arping", NULL, NULL);
	if (!argv[0]) {
		_LOGW (LOGD_DEVICE | LOGD_IP4, "arping could not be found; no ARPs will be sent");
		return;
	}

	for (i = 0; i < num; i++) {
		gs_free char *tmp_str = NULL;
		gboolean success;

		addr = nm_setting_ip_config_get_address (s_ip4, i);
		argv[ip_arg] = nm_ip_address_get_address (addr);

		_LOGD (LOGD_DEVICE | LOGD_IP4,
		       "arping: run %s", (tmp_str = g_strjoinv (" ", (char **) argv)));
		success = g_spawn_async (NULL, (char **) argv, NULL,
		                         G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
		                         NULL, NULL, NULL, &error);
		if (!success) {
			_LOGW (LOGD_DEVICE | LOGD_IP4,
			       "arping: could not send ARP for local address %s: %s",
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
	NMSettingIPConfig *s_ip4;
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
	num = nm_setting_ip_config_get_num_addresses (s_ip4);
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
	const char *method;
	NMConnection *connection;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	int ip_ifindex;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET);

	_LOGD (LOGD_DEVICE, "Activation: Stage 5 of 5 (IPv4 Commit) started...");

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Interface must be IFF_UP before IP config can be applied */
	ip_ifindex = nm_device_get_ip_ifindex (self);
	if (!nm_platform_link_is_up (NM_PLATFORM_GET, ip_ifindex) && !nm_device_uses_assumed_connection (self)) {
		nm_platform_link_set_up (NM_PLATFORM_GET, ip_ifindex, NULL);
		if (!nm_platform_link_is_up (NM_PLATFORM_GET, ip_ifindex))
			_LOGW (LOGD_DEVICE, "interface %s not up for IP configuration", nm_device_get_ip_iface (self));
	}

	/* NULL to use the existing priv->dev_ip4_config */
	if (!ip4_config_merge_and_apply (self, NULL, TRUE, &reason)) {
		_LOGD (LOGD_DEVICE | LOGD_IP4, "Activation: Stage 5 of 5 (IPv4 Commit) failed");
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}

	/* Start IPv4 sharing if we need it */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);

	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0) {
		if (!start_sharing (self, priv->ip4_config)) {
			_LOGW (LOGD_SHARING, "Activation: Stage 5 of 5 (IPv4 Commit) start sharing failed.");
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
	_LOGD (LOGD_DEVICE, "Activation: Stage 5 of 5 (IPv4 Commit) complete.");

	return FALSE;
}

static void
nm_device_queued_ip_config_change_clear (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->queued_ip4_config_id) {
		_LOGD (LOGD_DEVICE, "clearing queued IP4 config change");
		g_source_remove (priv->queued_ip4_config_id);
		priv->queued_ip4_config_id = 0;
	}
	if (priv->queued_ip6_config_id) {
		_LOGD (LOGD_DEVICE, "clearing queued IP6 config change");
		g_source_remove (priv->queued_ip6_config_id);
		priv->queued_ip6_config_id = 0;
	}
}

void
nm_device_activate_schedule_ip4_config_result (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	priv = NM_DEVICE_GET_PRIVATE (self);

	g_clear_object (&priv->dev_ip4_config);
	if (config)
		priv->dev_ip4_config = g_object_ref (config);

	nm_device_queued_ip_config_change_clear (self);
	activation_source_schedule (self, nm_device_activate_ip4_config_commit, AF_INET);

	_LOGD (LOGD_DEVICE | LOGD_IP4, "Activation: Stage 5 of 5 (IPv4 Configure Commit) scheduled...");
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
	NMActRequest *req;
	NMConnection *connection;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	int ip_ifindex;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET6);

	_LOGD (LOGD_DEVICE, "Activation: Stage 5 of 5 (IPv6 Commit) started...");

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Interface must be IFF_UP before IP config can be applied */
	ip_ifindex = nm_device_get_ip_ifindex (self);
	if (!nm_platform_link_is_up (NM_PLATFORM_GET, ip_ifindex) && !nm_device_uses_assumed_connection (self)) {
		nm_platform_link_set_up (NM_PLATFORM_GET, ip_ifindex, NULL);
		if (!nm_platform_link_is_up (NM_PLATFORM_GET, ip_ifindex))
			_LOGW (LOGD_DEVICE, "interface %s not up for IP configuration", nm_device_get_ip_iface (self));
	}

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
		_LOGW (LOGD_DEVICE | LOGD_IP6, "Activation: Stage 5 of 5 (IPv6 Commit) failed");
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
	}

	_LOGD (LOGD_DEVICE, "Activation: Stage 5 of 5 (IPv6 Commit) complete.");

	return FALSE;
}

void
nm_device_activate_schedule_ip6_config_result (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_DEVICE (self));

	/* If IP had previously failed, move it back to IP_CONF since we
	 * clearly now have configuration.
	 */
	if (priv->ip6_state == IP_FAIL)
		priv->ip6_state = IP_CONF;

	activation_source_schedule (self, nm_device_activate_ip6_config_commit, AF_INET6);

	_LOGD (LOGD_DEVICE | LOGD_IP6, "Activation: Stage 5 of 5 (IPv6 Commit) scheduled...");
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
	guint32 addr;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (   priv->ip4_config
	    && ip_config_valid (priv->state)
	    && nm_ip4_config_get_num_addresses (priv->ip4_config)) {
		addr = nm_ip4_config_get_address (priv->ip4_config, 0)->address;
		if (addr != priv->ip4_address) {
			priv->ip4_address = addr;
			g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_ADDRESS);
		}
	}
}

gboolean
nm_device_get_is_nm_owned (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->is_nm_owned;
}

void
nm_device_set_nm_owned (NMDevice *self)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	NM_DEVICE_GET_PRIVATE (self)->is_nm_owned = TRUE;
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
	NMDevice *self = data->device;

	if (data->device) {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (data->device);

		g_object_remove_weak_pointer (G_OBJECT (data->device), (void **) &data->device);
		priv->delete_on_deactivate_data = NULL;
	}

	_LOGD (LOGD_DEVICE, "delete_on_deactivate: cleanup and delete virtual link #%d (id=%u)",
	       data->ifindex, data->idle_add_id);
	nm_platform_link_delete (NM_PLATFORM_GET, data->ifindex);
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
		_LOGD (LOGD_DEVICE, "delete_on_deactivate: cancel cleanup and delete virtual link #%d (id=%u)",
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
	if (priv->queued_act_request)
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

	_LOGD (LOGD_DEVICE, "delete_on_deactivate: schedule cleanup and delete virtual link #%d (id=%u)",
	       ifindex, data->idle_add_id);
}

static void
disconnect_cb (NMDevice *self,
               GDBusMethodInvocation *context,
               NMAuthSubject *subject,
               GError *error,
               gpointer user_data)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GError *local = NULL;

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DISCONNECT, self, FALSE, subject, error->message);
		return;
	}

	/* Authorized */
	if (priv->state <= NM_DEVICE_STATE_DISCONNECTED) {
		local = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "Device is not active");
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DISCONNECT, self, FALSE, subject, local->message);
		g_dbus_method_invocation_take_error (context, local);
	} else {
		nm_device_set_autoconnect (self, FALSE);

		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
		g_dbus_method_invocation_return_value (context, NULL);
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DISCONNECT, self, TRUE, subject, NULL);
	}
}

static void
_clear_queued_act_request (NMDevicePrivate *priv)
{
	if (priv->queued_act_request) {
		nm_active_connection_set_state ((NMActiveConnection *) priv->queued_act_request, NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);
		g_clear_object (&priv->queued_act_request);
	}
}

static void
impl_device_disconnect (NMDevice *self, GDBusMethodInvocation *context)
{
	NMConnection *connection;
	GError *error = NULL;

	if (NM_DEVICE_GET_PRIVATE (self)->act_request == NULL) {
		error = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "This device is not active");
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* Ask the manager to authenticate this request for us */
	g_signal_emit (self, signals[AUTH_REQUEST], 0,
	               context,
	               connection,
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               disconnect_cb,
	               NULL);
}

static void
delete_cb (NMDevice *self,
           GDBusMethodInvocation *context,
           NMAuthSubject *subject,
           GError *error,
           gpointer user_data)
{
	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DELETE, self, FALSE, subject, error->message);
		return;
	}

	/* Authorized */
	nm_platform_link_delete (NM_PLATFORM_GET, nm_device_get_ifindex (self));
	g_dbus_method_invocation_return_value (context, NULL);
	nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DELETE, self, TRUE, subject, NULL);
}

static void
impl_device_delete (NMDevice *self, GDBusMethodInvocation *context)
{
	GError *error = NULL;

	if (!nm_device_is_software (self)) {
		error = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_SOFTWARE,
		                             "This device is not a software device");
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	/* Ask the manager to authenticate this request for us */
	g_signal_emit (self, signals[AUTH_REQUEST], 0,
	               context,
	               NULL,
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               delete_cb,
	               NULL);
}

static gboolean
_device_activate (NMDevice *self, NMActRequest *req)
{
	NMDevicePrivate *priv;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	/* Ensure the activation request is still valid; the master may have
	 * already failed in which case activation of this device should not proceed.
	 */
	if (nm_active_connection_get_state (NM_ACTIVE_CONNECTION (req)) >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING)
		return FALSE;

	priv = NM_DEVICE_GET_PRIVATE (self);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	_LOGI (LOGD_DEVICE, "Activation: starting connection '%s' (%s)",
	       nm_connection_get_id (connection),
	       nm_connection_get_uuid (connection));

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
	return TRUE;
}

static void
_carrier_wait_check_queued_act_request (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *queued_req;

	if (   !priv->queued_act_request
	    || !priv->queued_act_request_is_waiting_for_carrier)
		return;

	priv->queued_act_request_is_waiting_for_carrier = FALSE;
	if (!priv->carrier) {
		_LOGD (LOGD_DEVICE, "Cancel queued activation request as we have no carrier after timeout");
		g_clear_object (&priv->queued_act_request);
	} else {
		_LOGD (LOGD_DEVICE, "Activate queued activation request as we now have carrier");
		queued_req = priv->queued_act_request;
		priv->queued_act_request = NULL;
		_device_activate (self, queued_req);
		g_object_unref (queued_req);
	}
}

static gboolean
_carrier_wait_check_act_request_must_queue (NMDevice *self, NMActRequest *req)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;

	/* If we have carrier or if we are not waiting for it, the activation
	 * request is not blocked waiting for carrier. */
	if (priv->carrier)
		return FALSE;
	if (priv->carrier_wait_id == 0)
		return FALSE;

	connection = nm_act_request_get_connection (req);

	if (!nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_ALL, NULL)) {
		/* We passed all @flags we have, and no @specific_object.
		 * This equals maximal availability, if a connection is not available
		 * in this case, it is not waiting for carrier.
		 *
		 * Actually, why are we even trying to activate it? Strange, but whatever
		 * the reason, don't wait for carrier.
		 */
		return FALSE;
	}

	if (nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_ALL & ~_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER, NULL)) {
		/* The connection was available with flags ALL, and it is still available
		 * if we pretend not to wait for carrier. That means that the
		 * connection is available now, and does not wait for carrier.
		 *
		 * Since the flags increase the availability of a connection, when checking
		 * ALL&~WAITING_CARRIER, it means that we certainly would wait for carrier. */
		return FALSE;
	}

	/* The activation request must wait for carrier. */
	return TRUE;
}

void
nm_device_steal_connection (NMDevice *self, NMConnection *connection)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_LOGW (LOGD_DEVICE, "disconnecting connection '%s' for new activation request.",
	       nm_connection_get_id (connection));

	if (   priv->queued_act_request
	    && connection == nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (priv->queued_act_request)))
		_clear_queued_act_request (priv);

	if (   priv->act_request
	    && connection == nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (priv->act_request))
	    && priv->state < NM_DEVICE_STATE_DEACTIVATING)
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_NEW_ACTIVATION);
}

void
nm_device_queue_activation (NMDevice *self, NMActRequest *req)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean must_queue;

	must_queue = _carrier_wait_check_act_request_must_queue (self, req);

	if (!priv->act_request && !must_queue) {
		/* Just activate immediately */
		if (!_device_activate (self, req))
			g_assert_not_reached ();
		return;
	}

	/* supercede any already-queued request */
	_clear_queued_act_request (priv);
	priv->queued_act_request = g_object_ref (req);
	priv->queued_act_request_is_waiting_for_carrier = must_queue;

	_LOGD (LOGD_DEVICE, "queue activation request waiting for %s", must_queue ? "carrier" : "currently active connection to disconnect");

	/* Deactivate existing activation request first */
	if (priv->act_request) {
		_LOGI (LOGD_DEVICE, "disconnecting for new activation request.");
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_NEW_ACTIVATION);
	}
}

/*
 * nm_device_is_activating
 *
 * Return whether or not the device is currently activating itself.
 *
 */
gboolean
nm_device_is_activating (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	state = nm_device_get_state (self);
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

NMDhcp4Config *
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
                          guint32 default_route_metric,
                          gboolean commit,
                          gboolean routes_full_sync,
                          NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	NMIP4Config *old_config = NULL;
	gboolean has_changes = FALSE;
	gboolean success = TRUE;
	NMDeviceStateReason reason_local = NM_DEVICE_STATE_REASON_NONE;
	int ip_ifindex, config_ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);
	ip_ifindex = nm_device_get_ip_ifindex (self);

	if (new_config) {
		config_ifindex = nm_ip4_config_get_ifindex (new_config);
		if (config_ifindex > 0)
			g_return_val_if_fail (ip_ifindex == config_ifindex, FALSE);
	}

	old_config = priv->ip4_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config) {
		gboolean assumed = nm_device_uses_assumed_connection (self);

		nm_device_set_mtu (self, nm_ip4_config_get_mtu (new_config));

		/* For assumed devices we must not touch the kernel-routes, such as the device-route.
		 * FIXME: this is wrong in case where "assumed" means "take-over-seamlessly". In this
		 * case, we should manage the device route, for example on new DHCP lease. */
		success = nm_ip4_config_commit (new_config, ip_ifindex,
		                                routes_full_sync,
		                                assumed ? (gint64) -1 : (gint64) default_route_metric);
		if (!success)
			reason_local = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	}

	if (new_config) {
		if (old_config) {
			/* has_changes is set only on relevant changes, because when the configuration changes,
			 * this causes a re-read and reset. This should only happen for relevant changes */
			nm_ip4_config_replace (old_config, new_config, &has_changes);
			if (has_changes) {
				_LOGD (LOGD_IP4, "update IP4Config instance (%s)",
				       nm_exported_object_get_path (NM_EXPORTED_OBJECT (old_config)));
			}
		} else {
			has_changes = TRUE;
			priv->ip4_config = g_object_ref (new_config);

			if (success && !nm_exported_object_is_exported (NM_EXPORTED_OBJECT (new_config)))
				nm_exported_object_export (NM_EXPORTED_OBJECT (new_config));

			_LOGD (LOGD_IP4, "set IP4Config instance (%s)",
			       nm_exported_object_get_path (NM_EXPORTED_OBJECT (new_config)));
		}
	} else if (old_config) {
		has_changes = TRUE;
		priv->ip4_config = NULL;
		_LOGD (LOGD_IP4, "clear IP4Config instance (%s)",
		       nm_exported_object_get_path (NM_EXPORTED_OBJECT (old_config)));
		/* Device config is invalid if combined config is invalid */
		g_clear_object (&priv->dev_ip4_config);
	}

	nm_default_route_manager_ip4_update_default_route (nm_default_route_manager_get (), self);

	if (has_changes) {
		_update_ip4_address (self);

		if (old_config != priv->ip4_config)
			g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_CONFIG);
		g_signal_emit (self, signals[IP4_CONFIG_CHANGED], 0, priv->ip4_config, old_config);

		if (old_config != priv->ip4_config && old_config)
			g_object_unref (old_config);

		if (nm_device_uses_generated_assumed_connection (self)) {
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
nm_device_set_vpn4_config (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->vpn4_config == config)
		return;

	g_clear_object (&priv->vpn4_config);
	if (config)
		priv->vpn4_config = g_object_ref (config);

	/* NULL to use existing configs */
	if (!ip4_config_merge_and_apply (self, NULL, TRUE, NULL))
		_LOGW (LOGD_IP4, "failed to set VPN routes for device");
}

void
nm_device_set_wwan_ip4_config (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->wwan_ip4_config == config)
		return;

	g_clear_object (&priv->wwan_ip4_config);
	if (config)
		priv->wwan_ip4_config = g_object_ref (config);

	/* NULL to use existing configs */
	if (!ip4_config_merge_and_apply (self, NULL, TRUE, NULL))
		_LOGW (LOGD_IP4, "failed to set WWAN IPv4 configuration");
}

static gboolean
nm_device_set_ip6_config (NMDevice *self,
                          NMIP6Config *new_config,
                          gboolean commit,
                          gboolean routes_full_sync,
                          NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	NMIP6Config *old_config = NULL;
	gboolean has_changes = FALSE;
	gboolean success = TRUE;
	NMDeviceStateReason reason_local = NM_DEVICE_STATE_REASON_NONE;
	int ip_ifindex, config_ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);
	ip_ifindex = nm_device_get_ip_ifindex (self);

	if (new_config) {
		config_ifindex = nm_ip6_config_get_ifindex (new_config);
		if (config_ifindex > 0)
			g_return_val_if_fail (ip_ifindex == config_ifindex, FALSE);
	}

	old_config = priv->ip6_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config) {
		nm_device_ipv6_set_mtu (self, priv->ip6_mtu);
		success = nm_ip6_config_commit (new_config,
		                                ip_ifindex,
		                                routes_full_sync);
		if (!success)
			reason_local = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	}

	if (new_config) {
		if (old_config) {
			/* has_changes is set only on relevant changes, because when the configuration changes,
			 * this causes a re-read and reset. This should only happen for relevant changes */
			nm_ip6_config_replace (old_config, new_config, &has_changes);
			if (has_changes) {
				_LOGD (LOGD_IP6, "update IP6Config instance (%s)",
				       nm_exported_object_get_path (NM_EXPORTED_OBJECT (old_config)));
			}
		} else {
			has_changes = TRUE;
			priv->ip6_config = g_object_ref (new_config);

			if (success && !nm_exported_object_is_exported (NM_EXPORTED_OBJECT (new_config)))
				nm_exported_object_export (NM_EXPORTED_OBJECT (new_config));

			_LOGD (LOGD_IP6, "set IP6Config instance (%s)",
			       nm_exported_object_get_path (NM_EXPORTED_OBJECT (new_config)));
		}
	} else if (old_config) {
		has_changes = TRUE;
		priv->ip6_config = NULL;
		_LOGD (LOGD_IP6, "clear IP6Config instance (%s)",
		       nm_exported_object_get_path (NM_EXPORTED_OBJECT (old_config)));
	}

	nm_default_route_manager_ip6_update_default_route (nm_default_route_manager_get (), self);

	if (has_changes) {
		if (old_config != priv->ip6_config)
			g_object_notify (G_OBJECT (self), NM_DEVICE_IP6_CONFIG);
		g_signal_emit (self, signals[IP6_CONFIG_CHANGED], 0, priv->ip6_config, old_config);

		if (old_config != priv->ip6_config && old_config)
			g_object_unref (old_config);

		if (nm_device_uses_generated_assumed_connection (self)) {
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
nm_device_set_vpn6_config (NMDevice *self, NMIP6Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->vpn6_config == config)
		return;

	g_clear_object (&priv->vpn6_config);
	if (config)
		priv->vpn6_config = g_object_ref (config);

	/* NULL to use existing configs */
	if (!ip6_config_merge_and_apply (self, TRUE, NULL))
		_LOGW (LOGD_IP6, "failed to set VPN routes for device");
}

void
nm_device_set_wwan_ip6_config (NMDevice *self, NMIP6Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->wwan_ip6_config == config)
		return;

	g_clear_object (&priv->wwan_ip6_config);
	if (config)
		priv->wwan_ip6_config = g_object_ref (config);

	/* NULL to use existing configs */
	if (!ip6_config_merge_and_apply (self, TRUE, NULL))
		_LOGW (LOGD_IP6, "failed to set WWAN IPv6 configuration");
}

NMDhcp6Config *
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

	nm_clear_g_source (&priv->gw_ping.watch);
	nm_clear_g_source (&priv->gw_ping.timeout);

	if (priv->gw_ping.pid) {
		nm_utils_kill_child_async (priv->gw_ping.pid, SIGTERM, priv->gw_ping.log_domain, "ping", 1000, NULL, NULL);
		priv->gw_ping.pid = 0;
	}

	g_clear_pointer (&priv->gw_ping.binary, g_free);
	g_clear_pointer (&priv->gw_ping.address, g_free);
}

static gboolean
spawn_ping (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gs_free char *str_timeout = NULL;
	gs_free char *tmp_str = NULL;
	const char *args[] = { priv->gw_ping.binary, "-I", nm_device_get_ip_iface (self),
	                       "-c", "1", "-w", NULL, priv->gw_ping.address, NULL };
	gs_free_error GError *error = NULL;
	gboolean ret;

	args[6] = str_timeout = g_strdup_printf ("%u", priv->gw_ping.deadline);
	tmp_str = g_strjoinv (" ", (gchar **) args);
	_LOGD (priv->gw_ping.log_domain, "ping: running '%s'", tmp_str);

	ret = g_spawn_async ("/",
	                     (gchar **) args,
	                      NULL,
	                      G_SPAWN_DO_NOT_REAP_CHILD,
	                      NULL,
	                      NULL,
	                      &priv->gw_ping.pid,
	                      &error);

	if (!ret) {
		_LOGW (priv->gw_ping.log_domain, "ping: could not spawn %s: %s",
		       priv->gw_ping.binary, error->message);
	}

	return ret;
}

static gboolean
respawn_ping_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->gw_ping.watch = 0;

	if (spawn_ping (self)) {
		priv->gw_ping.watch = g_child_watch_add (priv->gw_ping.pid,
		                                         ip_check_ping_watch_cb, self);
	} else {
		ip_check_gw_ping_cleanup (self);
		ip_check_pre_up (self);
	}

	return FALSE;
}

static void
ip_check_ping_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMLogDomain log_domain = priv->gw_ping.log_domain;
	gboolean success = FALSE;

	if (!priv->gw_ping.watch)
		return;
	priv->gw_ping.watch = 0;
	priv->gw_ping.pid = 0;

	if (WIFEXITED (status)) {
		if (WEXITSTATUS (status) == 0) {
			_LOGD (log_domain, "ping: gateway ping succeeded");
			success = TRUE;
		} else {
			_LOGW (log_domain, "ping: gateway ping failed with error code %d",
			       WEXITSTATUS (status));
		}
	} else
		_LOGW (log_domain, "ping: stopped unexpectedly with status %d", status);

	if (success) {
		/* We've got connectivity, proceed to pre_up */
		ip_check_gw_ping_cleanup (self);
		ip_check_pre_up (self);
	} else {
		/* If ping exited with an error it may have returned early,
		 * wait 1 second and restart it */
		priv->gw_ping.watch = g_timeout_add_seconds (1, respawn_ping_cb, self);
	}
}

static gboolean
ip_check_ping_timeout_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->gw_ping.timeout = 0;

	_LOGW (priv->gw_ping.log_domain, "ping: gateway ping timed out");

	ip_check_gw_ping_cleanup (self);
	ip_check_pre_up (self);
	return FALSE;
}

static gboolean
start_ping (NMDevice *self,
            NMLogDomain log_domain,
            const char *binary,
            const char *address,
            guint timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (priv->gw_ping.watch == 0, FALSE);
	g_return_val_if_fail (priv->gw_ping.timeout == 0, FALSE);

	priv->gw_ping.log_domain = log_domain;
	priv->gw_ping.address = g_strdup (address);
	priv->gw_ping.binary = g_strdup (binary);
	priv->gw_ping.deadline = timeout + 10;	/* the proper termination is enforced by a timer */

	if (spawn_ping (self)) {
		priv->gw_ping.watch = g_child_watch_add (priv->gw_ping.pid, ip_check_ping_watch_cb, self);
		priv->gw_ping.timeout = g_timeout_add_seconds (timeout, ip_check_ping_timeout_cb, self);
		return TRUE;
	}

	ip_check_gw_ping_cleanup (self);
	return FALSE;
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
	NMLogDomain log_domain = LOGD_IP4;

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
		if (priv->ip4_config && priv->ip4_state == IP_DONE) {
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
		start_ping (self, log_domain, ping_binary, buf, timeout);

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

	_carrier_wait_check_queued_act_request (self);

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
is_up (NMDevice *self)
{
	int ifindex = nm_device_get_ip_ifindex (self);

	return ifindex > 0 ? nm_platform_link_is_up (NM_PLATFORM_GET, ifindex) : TRUE;
}

gboolean
nm_device_bring_up (NMDevice *self, gboolean block, gboolean *no_firmware)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean device_is_up = FALSE;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	_LOGD (LOGD_HW, "bringing up device.");

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
			if (!nm_platform_link_refresh (NM_PLATFORM_GET, ifindex))
				return FALSE;
			device_is_up = nm_device_is_up (self);
		} while (!device_is_up && nm_utils_get_monotonic_timestamp_us () < wait_until);
	}

	if (!device_is_up) {
		if (block)
			_LOGW (LOGD_HW, "device not up after timeout!");
		else
			_LOGD (LOGD_HW, "device not up immediately");
		return FALSE;
	}

	/* Devices that support carrier detect must be IFF_UP to report carrier
	 * changes; so after setting the device IFF_UP we must suppress startup
	 * complete (via a pending action) until either the carrier turns on, or
	 * a timeout is reached.
	 */
	if (nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)) {
		if (priv->carrier_wait_id)
			g_source_remove (priv->carrier_wait_id);
		else
			nm_device_add_pending_action (self, "carrier wait", TRUE);
		priv->carrier_wait_id = g_timeout_add_seconds (5, carrier_wait_timeout, self);
	}

	/* Can only get HW address of some devices when they are up */
	nm_device_update_hw_address (self);

	_update_ip4_address (self);
	return TRUE;
}

static gboolean
bring_up (NMDevice *self, gboolean *no_firmware)
{
	int ifindex = nm_device_get_ip_ifindex (self);
	gboolean result;

	if (ifindex <= 0) {
		if (no_firmware)
			*no_firmware = FALSE;
		return TRUE;
	}

	result = nm_platform_link_set_up (NM_PLATFORM_GET, ifindex, no_firmware);

	/* Store carrier immediately. */
	if (result && nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT))
		check_carrier (self);

	return result;
}

void
nm_device_take_down (NMDevice *self, gboolean block)
{
	gboolean device_is_up;

	g_return_if_fail (NM_IS_DEVICE (self));

	_LOGD (LOGD_HW, "taking down device.");

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
			if (!nm_platform_link_refresh (NM_PLATFORM_GET, ifindex))
				return;
			device_is_up = nm_device_is_up (self);
		} while (device_is_up && nm_utils_get_monotonic_timestamp_us () < wait_until);
	}

	if (device_is_up) {
		if (block)
			_LOGW (LOGD_HW, "device not down after timeout!");
		else
			_LOGD (LOGD_HW, "device not down immediately");
	}
}

static gboolean
take_down (NMDevice *self)
{
	int ifindex = nm_device_get_ip_ifindex (self);

	if (ifindex > 0)
		return nm_platform_link_set_down (NM_PLATFORM_GET, ifindex);

	/* devices without ifindex are always up. */
	_LOGD (LOGD_HW, "cannot take down device without ifindex");
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

void
nm_device_set_nm_plugin_missing (NMDevice *self, gboolean new_missing)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->nm_plugin_missing != new_missing) {
		priv->nm_plugin_missing = new_missing;
		g_object_notify (G_OBJECT (self), NM_DEVICE_NM_PLUGIN_MISSING);
	}
}

gboolean
nm_device_get_nm_plugin_missing (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->nm_plugin_missing;
}

static NMIP4Config *
find_ip4_lease_config (NMDevice *self,
                       NMConnection *connection,
                       NMIP4Config *ext_ip4_config)
{
	const char *ip_iface = nm_device_get_ip_iface (self);
	int ip_ifindex = nm_device_get_ip_ifindex (self);
	GSList *leases, *liter;
	NMIP4Config *found = NULL;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (ext_ip4_config), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	leases = nm_dhcp_manager_get_lease_ip_configs (nm_dhcp_manager_get (),
	                                               ip_iface,
	                                               ip_ifindex,
	                                               nm_connection_get_uuid (connection),
	                                               FALSE,
	                                               nm_device_get_ip4_route_metric (self));
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
capture_lease_config (NMDevice *self,
                      NMIP4Config *ext_ip4_config,
                      NMIP4Config **out_ip4_config,
                      NMIP6Config *ext_ip6_config,
                      NMIP6Config **out_ip6_config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
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

		if (!nm_device_check_connection_compatible (self, candidate))
			continue;

		/* IPv4 leases */
		method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP4_CONFIG);
		if (out_ip4_config && strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0) {
			*out_ip4_config = find_ip4_lease_config (self, candidate, ext_ip4_config);
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
update_ip4_config (NMDevice *self, gboolean initial)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ifindex;
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

		/* FIXME: ext_ip4_config does not contain routes with source==RTPROT_KERNEL.
		 * Hence, we will wrongly remove device-routes with metric=0 if they were added by
		 * the user on purpose. This should be fixed by also tracking and exposing
		 * kernel routes. */

		/* This function was called upon external changes. Remove the configuration
		 * (addresses,routes) that is no longer present externally from the internal
		 * config. This way, we don't re-add addresses that were manually removed
		 * by the user. */
		if (priv->con_ip4_config)
			nm_ip4_config_intersect (priv->con_ip4_config, priv->ext_ip4_config);
		if (priv->dev_ip4_config)
			nm_ip4_config_intersect (priv->dev_ip4_config, priv->ext_ip4_config);
		if (priv->vpn4_config)
			nm_ip4_config_intersect (priv->vpn4_config, priv->ext_ip4_config);
		if (priv->wwan_ip4_config)
			nm_ip4_config_intersect (priv->wwan_ip4_config, priv->ext_ip4_config);

		/* Remove parts from ext_ip4_config to only contain the information that
		 * was configured externally -- we already have the same configuration from
		 * internal origins. */
		if (priv->con_ip4_config)
			nm_ip4_config_subtract (priv->ext_ip4_config, priv->con_ip4_config);
		if (priv->dev_ip4_config)
			nm_ip4_config_subtract (priv->ext_ip4_config, priv->dev_ip4_config);
		if (priv->vpn4_config)
			nm_ip4_config_subtract (priv->ext_ip4_config, priv->vpn4_config);
		if (priv->wwan_ip4_config)
			nm_ip4_config_subtract (priv->ext_ip4_config, priv->wwan_ip4_config);

		ip4_config_merge_and_apply (self, NULL, FALSE, NULL);
	}
}

static void
update_ip6_config (NMDevice *self, gboolean initial)
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

	/* IPv6 */
	g_clear_object (&priv->ext_ip6_config);
	priv->ext_ip6_config = nm_ip6_config_capture (ifindex, capture_resolv_conf, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
	if (priv->ext_ip6_config) {

		/* Check this before modifying ext_ip6_config */
		linklocal6_just_completed = priv->linklocal6_timeout_id &&
		                            have_ip6_address (priv->ext_ip6_config, TRUE);

		/* This function was called upon external changes. Remove the configuration
		 * (addresses,routes) that is no longer present externally from the internal
		 * config. This way, we don't re-add addresses that were manually removed
		 * by the user. */
		if (priv->con_ip6_config)
			nm_ip6_config_intersect (priv->con_ip6_config, priv->ext_ip6_config);
		if (priv->ac_ip6_config)
			nm_ip6_config_intersect (priv->ac_ip6_config, priv->ext_ip6_config);
		if (priv->dhcp6_ip6_config)
			nm_ip6_config_intersect (priv->dhcp6_ip6_config, priv->ext_ip6_config);
		if (priv->wwan_ip6_config)
			nm_ip6_config_intersect (priv->wwan_ip6_config, priv->ext_ip6_config);
		if (priv->vpn6_config)
			nm_ip6_config_intersect (priv->vpn6_config, priv->ext_ip6_config);

		/* Remove parts from ext_ip6_config to only contain the information that
		 * was configured externally -- we already have the same configuration from
		 * internal origins. */
		if (priv->con_ip6_config)
			nm_ip6_config_subtract (priv->ext_ip6_config, priv->con_ip6_config);
		if (priv->ac_ip6_config)
			nm_ip6_config_subtract (priv->ext_ip6_config, priv->ac_ip6_config);
		if (priv->dhcp6_ip6_config)
			nm_ip6_config_subtract (priv->ext_ip6_config, priv->dhcp6_ip6_config);
		if (priv->wwan_ip6_config)
			nm_ip6_config_subtract (priv->ext_ip6_config, priv->wwan_ip6_config);
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
nm_device_capture_initial_config (NMDevice *self)
{
	update_ip4_config (self, TRUE);
	update_ip6_config (self, TRUE);
}

static gboolean
queued_ip4_config_change (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* Wait for any queued state changes */
	if (priv->queued_state.id)
		return TRUE;

	priv->queued_ip4_config_id = 0;
	g_object_ref (self);
	update_ip4_config (self, FALSE);
	g_object_unref (self);

	return FALSE;
}

static gboolean
queued_ip6_config_change (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* Wait for any queued state changes */
	if (priv->queued_state.id)
		return TRUE;

	priv->queued_ip6_config_id = 0;
	g_object_ref (self);
	update_ip6_config (self, FALSE);

	/* If no IPv6 link-local address exists but other addresses do then we
	 * must add the LL address to remain conformant with RFC 3513 chapter 2.1
	 * ("Addressing Model"): "All interfaces are required to have at least
	 * one link-local unicast address".
	 */
	if (priv->ip6_config && nm_ip6_config_get_num_addresses (priv->ip6_config))
		check_and_add_ipv6ll_addr (self);

	g_object_unref (self);

	return FALSE;
}

static void
device_ipx_changed (NMPlatform *platform,
                    NMPObjectType obj_type,
                    int ifindex,
                    gpointer platform_object,
                    NMPlatformSignalChangeType change_type,
                    NMPlatformReason reason,
                    NMDevice *self)
{
	NMDevicePrivate *priv;

	if (nm_device_get_ip_ifindex (self) != ifindex)
		return;

	priv = NM_DEVICE_GET_PRIVATE (self);
	switch (obj_type) {
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		if (!priv->queued_ip4_config_id) {
			priv->queued_ip4_config_id = g_idle_add (queued_ip4_config_change, self);
			_LOGD (LOGD_DEVICE, "queued IP4 config change");
		}
		break;
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		if (!priv->queued_ip6_config_id) {
			priv->queued_ip6_config_id = g_idle_add (queued_ip6_config_change, self);
			_LOGD (LOGD_DEVICE, "queued IP6 config change");
		}
		break;
	default:
		g_return_if_reached ();
	}
}

/**
 * nm_device_get_managed():
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device is managed
 */
gboolean
nm_device_get_managed (NMDevice *self)
{
	NMDevicePrivate *priv;
	gboolean managed;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	/* Return the composite of all managed flags.  However, if the device
	 * is a default-unmanaged device, and would be managed except for the
	 * default-unmanaged flag (eg, only NM_UNMANAGED_DEFAULT is set) then
	 * the device is managed whenever it's not in the UNMANAGED state.
	 */
	managed = !NM_FLAGS_ANY (priv->unmanaged_flags, ~NM_UNMANAGED_DEFAULT);
	if (managed && NM_FLAGS_HAS (priv->unmanaged_flags, NM_UNMANAGED_DEFAULT))
		managed = (priv->state > NM_DEVICE_STATE_UNMANAGED);

	return managed;
}

/**
 * nm_device_get_unmanaged_flag():
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device is unmanaged for @flag.
 */
gboolean
nm_device_get_unmanaged_flag (NMDevice *self, NMUnmanagedFlags flag)
{
	return NM_FLAGS_ANY (NM_DEVICE_GET_PRIVATE (self)->unmanaged_flags, flag);
}

/**
 * nm_device_get_default_unmanaged():
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device is by default unmanaged
 */
static gboolean
nm_device_get_default_unmanaged (NMDevice *self)
{
	return nm_device_get_unmanaged_flag (self, NM_UNMANAGED_DEFAULT);
}

static void
_set_unmanaged_flags (NMDevice *self,
                      NMUnmanagedFlags flags,
                      gboolean unmanaged)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (unmanaged) {
		if (!NM_FLAGS_ALL (priv->unmanaged_flags, flags)) {
			_LOGD (LOGD_DEVICE, "unmanaged: flags set to 0x%0llx (was 0x%0llx, %s 0x%0llx)",
			       (long long unsigned) (priv->unmanaged_flags | flags),
			       (long long unsigned) priv->unmanaged_flags,
			       "set",
			       (long long unsigned) (~priv->unmanaged_flags & flags));
			priv->unmanaged_flags |= flags;
		}
	} else {
		if (NM_FLAGS_ANY (priv->unmanaged_flags, flags)) {
			_LOGD (LOGD_DEVICE, "unmanaged: flags set to 0x%0llx (was 0x%0llx, %s 0x%0llx)",
			       (long long unsigned) (priv->unmanaged_flags & (~flags)),
			       (long long unsigned) priv->unmanaged_flags,
			       "clear",
			       (long long unsigned) (priv->unmanaged_flags & flags));
			priv->unmanaged_flags &= ~flags;
		}
	}
}

void
nm_device_set_unmanaged (NMDevice *self,
                         NMUnmanagedFlags flag,
                         gboolean unmanaged,
                         NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	gboolean was_managed, now_managed;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (flag <= NM_UNMANAGED_LAST);

	priv = NM_DEVICE_GET_PRIVATE (self);

	was_managed = nm_device_get_managed (self);
	_set_unmanaged_flags (self, flag, unmanaged);
	now_managed = nm_device_get_managed (self);

	if (was_managed != now_managed) {
		_LOGD (LOGD_DEVICE, "now %s", unmanaged ? "unmanaged" : "managed");

		g_object_notify (G_OBJECT (self), NM_DEVICE_MANAGED);

		if (unmanaged)
			nm_device_state_changed (self, NM_DEVICE_STATE_UNMANAGED, reason);
		else if (nm_device_get_state (self) == NM_DEVICE_STATE_UNMANAGED)
			nm_device_state_changed (self, NM_DEVICE_STATE_UNAVAILABLE, reason);
	}
}

void
nm_device_set_unmanaged_quitting (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* It's OK to block here because we're quitting */
	if (nm_device_is_activating (self) || priv->state == NM_DEVICE_STATE_ACTIVATED)
		_set_state_full (self, NM_DEVICE_STATE_DEACTIVATING, NM_DEVICE_STATE_REASON_NOW_UNMANAGED, TRUE);

	nm_device_set_unmanaged (self,
	                         NM_UNMANAGED_INTERNAL,
	                         TRUE,
	                         NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
}

/**
 * nm_device_set_initial_unmanaged_flag():
 * @self: the #NMDevice
 * @flag: an #NMUnmanagedFlag
 * @unmanaged: %TRUE or %FALSE to set or clear @flag
 *
 * Like nm_device_set_unmanaged(), but must be set before the device is
 * initialized by nm_device_finish_init(), and does not trigger state changes.
 * Should only be used when initializing a device.
 */
void
nm_device_set_initial_unmanaged_flag (NMDevice *self,
                                      NMUnmanagedFlags flag,
                                      gboolean unmanaged)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (flag <= NM_UNMANAGED_LAST);

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->initialized == FALSE);

	_set_unmanaged_flags (self, flag, unmanaged);
}

void
nm_device_set_dhcp_timeout (NMDevice *self, guint32 timeout)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	NM_DEVICE_GET_PRIVATE (self)->dhcp_timeout = timeout;
}

void
nm_device_set_dhcp_anycast_address (NMDevice *self, const char *addr)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (!addr || nm_utils_hwaddr_valid (addr, ETH_ALEN));

	priv = NM_DEVICE_GET_PRIVATE (self);

	g_free (priv->dhcp_anycast_address);
	priv->dhcp_anycast_address = g_strdup (addr);
}

static void
nm_device_update_metered (NMDevice *self)
{
#define NM_METERED_INVALID ((NMMetered) -1)
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingConnection *setting;
	NMMetered conn_value, value = NM_METERED_INVALID;
	NMConnection *connection = NULL;
	NMDeviceState state;

	g_return_if_fail (NM_IS_DEVICE (self));

	state = nm_device_get_state (self);
	if (   state <= NM_DEVICE_STATE_DISCONNECTED
	    || state > NM_DEVICE_STATE_ACTIVATED)
		value = NM_METERED_UNKNOWN;

	if (value == NM_METERED_INVALID) {
		connection = nm_device_get_connection (self);
		if (connection) {
			setting = nm_connection_get_setting_connection (connection);
			if (setting) {
				conn_value = nm_setting_connection_get_metered (setting);
				if (conn_value != NM_METERED_UNKNOWN)
					value = conn_value;
			}
		}
	}

	/* Try to guess a value using the metered flag in IP configuration */
	if (value == NM_METERED_INVALID) {
		if (   priv->ip4_config
		    && priv->ip4_state == IP_DONE
		    && nm_ip4_config_get_metered (priv->ip4_config))
			value = NM_METERED_GUESS_YES;
	}

	/* Otherwise look at connection type */
	if (value == NM_METERED_INVALID) {
		if (   nm_connection_is_type (connection, NM_SETTING_GSM_SETTING_NAME)
		    || nm_connection_is_type (connection, NM_SETTING_CDMA_SETTING_NAME))
			value = NM_METERED_GUESS_YES;
		else
			value = NM_METERED_GUESS_NO;
	}

	if (value != priv->metered) {
		_LOGD (LOGD_DEVICE, "set metered value %d", value);
		priv->metered = value;
		g_object_notify (G_OBJECT (self), NM_DEVICE_METERED);
	}
}

/**
 * nm_device_check_connection_available():
 * @self: the #NMDevice
 * @connection: the #NMConnection to check for availability
 * @flags: flags to affect the decision making of whether a connection
 *   is available. Adding a flag can only make a connection more available,
 *   not less.
 * @specific_object: a device type dependent argument to further
 *   filter the result. Passing a non %NULL specific object can only reduce
 *   the availability of a connection.
 *
 * Check if @connection is available to be activated on @self.
 *
 * Returns: %TRUE if @connection can be activated on @self
 */
gboolean
nm_device_check_connection_available (NMDevice *self,
                                      NMConnection *connection,
                                      NMDeviceCheckConAvailableFlags flags,
                                      const char *specific_object)
{
	NMDeviceState state;

	state = nm_device_get_state (self);
	if (state < NM_DEVICE_STATE_UNMANAGED)
		return FALSE;
	if (   state < NM_DEVICE_STATE_UNAVAILABLE
	    && nm_device_get_unmanaged_flag (self, NM_UNMANAGED_ALL & ~NM_UNMANAGED_DEFAULT))
		return FALSE;
	if (   state < NM_DEVICE_STATE_DISCONNECTED
	    && (   (   !NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER)
	            && !nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE))
	        || (    NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER)
	            && !nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER))))
		return FALSE;

	if (!nm_device_check_connection_compatible (self, connection))
		return FALSE;

	return NM_DEVICE_GET_CLASS (self)->check_connection_available (self, connection, flags, specific_object);
}

static void
_signal_available_connections_changed (NMDevice *self)
{
	g_object_notify (G_OBJECT (self), NM_DEVICE_AVAILABLE_CONNECTIONS);
}

static void
_clear_available_connections (NMDevice *self, gboolean do_signal)
{
	g_hash_table_remove_all (NM_DEVICE_GET_PRIVATE (self)->available_connections);
	if (do_signal == TRUE)
		_signal_available_connections_changed (self);
}

static gboolean
_try_add_available_connection (NMDevice *self, NMConnection *connection)
{
	if (nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_NONE, NULL)) {
		g_hash_table_add (NM_DEVICE_GET_PRIVATE (self)->available_connections,
		                  g_object_ref (connection));
		return TRUE;
	}
	return FALSE;
}

static gboolean
_del_available_connection (NMDevice *self, NMConnection *connection)
{
	return g_hash_table_remove (NM_DEVICE_GET_PRIVATE (self)->available_connections, connection);
}

static gboolean
check_connection_available (NMDevice *self,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

	/* Connections which require a network connection are not available when
	 * the device has no carrier, even with ignore-carrer=TRUE.
	 */
	if (   priv->carrier
	    || !connection_requires_carrier (connection))
		return TRUE;

	if (   NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER)
	    && priv->carrier_wait_id != 0) {
		/* The device has no carrier though the connection requires it.
		 *
		 * If we are still waiting for carrier, the connection is available
		 * for an explicit user-request. */
		return TRUE;
	}

	return FALSE;
}

void
nm_device_recheck_available_connections (NMDevice *self)
{
	NMDevicePrivate *priv;
	const GSList *connections, *iter;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE(self);

	if (priv->con_provider) {
		_clear_available_connections (self, FALSE);

		connections = nm_connection_provider_get_connections (priv->con_provider);
		for (iter = connections; iter; iter = g_slist_next (iter))
			_try_add_available_connection (self, NM_CONNECTION (iter->data));

		_signal_available_connections_changed (self);
	}
}

/**
 * nm_device_get_available_connections:
 * @self: the #NMDevice
 * @specific_object: a specific object path if any
 *
 * Returns a list of connections available to activate on the device, taking
 * into account any device-specific details given by @specific_object (like
 * WiFi access point path).
 *
 * Returns: caller-owned #GPtrArray of #NMConnections
 */
GPtrArray *
nm_device_get_available_connections (NMDevice *self, const char *specific_object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
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
			if (   !specific_object /* << Optimization: we know that the connection is available without @specific_object.  */
			    || nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_NONE, specific_object))
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
nm_device_supports_vlans (NMDevice *self)
{
	return nm_platform_link_supports_vlans (NM_PLATFORM_GET, nm_device_get_ifindex (self));
}

/**
 * nm_device_add_pending_action():
 * @self: the #NMDevice to add the pending action to
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
nm_device_add_pending_action (NMDevice *self, const char *action, gboolean assert_not_yet_pending)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GSList *iter;
	guint count = 0;

	g_return_val_if_fail (action, FALSE);

	/* Check if the action is already pending. Cannot add duplicate actions */
	for (iter = priv->pending_actions; iter; iter = iter->next) {
		if (!strcmp (action, iter->data)) {
			if (assert_not_yet_pending) {
				_LOGW (LOGD_DEVICE, "add_pending_action (%d): '%s' already pending",
				       count + g_slist_length (iter), action);
				g_return_val_if_reached (FALSE);
			} else {
				_LOGD (LOGD_DEVICE, "add_pending_action (%d): '%s' already pending (expected)",
				       count + g_slist_length (iter), action);
			}
			return FALSE;
		}
		count++;
	}

	priv->pending_actions = g_slist_append (priv->pending_actions, g_strdup (action));
	count++;

	_LOGD (LOGD_DEVICE, "add_pending_action (%d): '%s'", count, action);

	if (count == 1)
		g_object_notify (G_OBJECT (self), NM_DEVICE_HAS_PENDING_ACTION);

	return TRUE;
}

/**
 * nm_device_remove_pending_action():
 * @self: the #NMDevice to remove the pending action from
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
nm_device_remove_pending_action (NMDevice *self, const char *action, gboolean assert_is_pending)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GSList *iter;
	guint count = 0;

	g_return_val_if_fail (action, FALSE);

	for (iter = priv->pending_actions; iter; iter = iter->next) {
		if (!strcmp (action, iter->data)) {
			_LOGD (LOGD_DEVICE, "remove_pending_action (%d): '%s'",
			       count + g_slist_length (iter->next), /* length excluding 'iter' */
			       action);
			g_free (iter->data);
			priv->pending_actions = g_slist_delete_link (priv->pending_actions, iter);
			if (priv->pending_actions == NULL)
				g_object_notify (G_OBJECT (self), NM_DEVICE_HAS_PENDING_ACTION);
			return TRUE;
		}
		count++;
	}

	if (assert_is_pending) {
		_LOGW (LOGD_DEVICE, "remove_pending_action (%d): '%s' not pending", count, action);
		g_return_val_if_reached (FALSE);
	} else
		_LOGD (LOGD_DEVICE, "remove_pending_action (%d): '%s' not pending (expected)", count, action);

	return FALSE;
}

gboolean
nm_device_has_pending_action (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	return !!priv->pending_actions;
}

/***********************************************************/

static void
_cleanup_ip_pre (NMDevice *self, CleanupType cleanup_type)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->ip4_state = priv->ip6_state = IP_NONE;
	nm_device_queued_ip_config_change_clear (self);

	dhcp4_cleanup (self, cleanup_type, FALSE);
	arp_cleanup (self);
	dhcp6_cleanup (self, cleanup_type, FALSE);
	linklocal6_cleanup (self);
	addrconf6_cleanup (self);
	dnsmasq_cleanup (self);
	ipv4ll_cleanup (self);
}

static void
_cancel_activation (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* Clean up when device was deactivated during call to firewall */
	if (priv->fw_call) {
		nm_firewall_manager_cancel_call (nm_firewall_manager_get (), priv->fw_call);
		priv->fw_call = NULL;
	}

	ip_check_gw_ping_cleanup (self);

	/* Break the activation chain */
	activation_source_clear (self, TRUE, AF_INET);
	activation_source_clear (self, TRUE, AF_INET6);
}

static void
_cleanup_generic_pre (NMDevice *self, CleanupType cleanup_type)
{
	NMConnection *connection;

	_cancel_activation (self);

	connection = nm_device_get_connection (self);
	if (   cleanup_type == CLEANUP_TYPE_DECONFIGURE
	    && connection
	    && !nm_device_uses_assumed_connection (self)) {
		nm_firewall_manager_remove_from_zone (nm_firewall_manager_get (),
		                                      nm_device_get_ip_iface (self),
		                                      NULL);
	}

	/* Clear any queued transitions */
	nm_device_queued_state_clear (self);

	_cleanup_ip_pre (self, cleanup_type);
}

static void
_cleanup_generic_post (NMDevice *self, CleanupType cleanup_type)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason ignored = NM_DEVICE_STATE_REASON_NONE;

	priv->default_route.v4_has = FALSE;
	priv->default_route.v4_is_assumed = TRUE;
	priv->default_route.v6_has = FALSE;
	priv->default_route.v6_is_assumed = TRUE;

	priv->v4_commit_first_time = TRUE;
	priv->v6_commit_first_time = TRUE;

	nm_default_route_manager_ip4_update_default_route (nm_default_route_manager_get (), self);
	nm_default_route_manager_ip6_update_default_route (nm_default_route_manager_get (), self);

	/* Clean up IP configs; this does not actually deconfigure the
	 * interface; the caller must flush routes and addresses explicitly.
	 */
	nm_device_set_ip4_config (self, NULL, 0, TRUE, TRUE, &ignored);
	nm_device_set_ip6_config (self, NULL, TRUE, TRUE, &ignored);
	g_clear_object (&priv->con_ip4_config);
	g_clear_object (&priv->dev_ip4_config);
	g_clear_object (&priv->ext_ip4_config);
	g_clear_object (&priv->wwan_ip4_config);
	g_clear_object (&priv->vpn4_config);
	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->con_ip6_config);
	g_clear_object (&priv->ac_ip6_config);
	g_clear_object (&priv->ext_ip6_config);
	g_clear_object (&priv->vpn6_config);
	g_clear_object (&priv->wwan_ip6_config);
	g_clear_object (&priv->ip6_config);

	clear_act_request (self);

	/* Clear legacy IPv4 address property */
	if (priv->ip4_address) {
		priv->ip4_address = 0;
		g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_ADDRESS);
	}

	if (cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
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
nm_device_cleanup (NMDevice *self, NMDeviceStateReason reason, CleanupType cleanup_type)
{
	NMDevicePrivate *priv;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (reason == NM_DEVICE_STATE_REASON_NOW_MANAGED)
		_LOGD (LOGD_DEVICE, "preparing device");
	else
		_LOGD (LOGD_DEVICE, "deactivating device (reason '%s') [%d]", reason_to_string (reason), reason);

	/* Save whether or not we tried IPv6 for later */
	priv = NM_DEVICE_GET_PRIVATE (self);

	_cleanup_generic_pre (self, cleanup_type);

	/* Turn off kernel IPv6 */
	if (cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
		set_disable_ipv6 (self, "1");
		nm_device_ipv6_sysctl_set (self, "accept_ra", "0");
		nm_device_ipv6_sysctl_set (self, "use_tempaddr", "0");
	}

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate)
		NM_DEVICE_GET_CLASS (self)->deactivate (self);

	/* master: release slaves */
	nm_device_master_release_slaves (self);

	/* slave: mark no longer enslaved */
	if (nm_platform_link_get_master (NM_PLATFORM_GET, priv->ifindex) <= 0) {
		g_clear_object (&priv->master);
		priv->enslaved = FALSE;
		g_object_notify (G_OBJECT (self), NM_DEVICE_MASTER);
	}

	/* Take out any entries in the routing table and any IP address the device had. */
	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex > 0) {
		nm_route_manager_route_flush (nm_route_manager_get (), ifindex);
		nm_platform_address_flush (NM_PLATFORM_GET, ifindex);
	}

	nm_device_update_metered (self);
	_cleanup_generic_post (self, cleanup_type);
}

static char *
bin2hexstr (const char *bytes, gsize len)
{
	GString *str;
	int i;

	g_return_val_if_fail (bytes != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);

	str = g_string_sized_new (len * 2 + 1);
	for (i = 0; i < len; i++) {
		if (str->len)
			g_string_append_c (str, ':');
		g_string_append_printf (str, "%02x", (guint8) bytes[i]);
	}
	return g_string_free (str, FALSE);
}

static char *
find_dhcp4_address (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint i, n;

	if (!priv->ip4_config)
		return NULL;

	n = nm_ip4_config_get_num_addresses (priv->ip4_config);
	for (i = 0; i < n; i++) {
		const NMPlatformIP4Address *a = nm_ip4_config_get_address (priv->ip4_config, i);

		if (a->source == NM_IP_CONFIG_SOURCE_DHCP)
			return g_strdup (nm_utils_inet4_ntop (a->address, NULL));
	}
	return NULL;
}

void
nm_device_spawn_iface_helper (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean configured = FALSE;
	NMConnection *connection;
	GError *error = NULL;
	const char *method;
	GPtrArray *argv;
	gs_free char *dhcp4_address = NULL;
	char *logging_backend;

	if (priv->state != NM_DEVICE_STATE_ACTIVATED)
		return;
	if (!nm_device_can_assume_connections (self))
		return;

	connection = nm_device_get_connection (self);
	g_assert (connection);

	argv = g_ptr_array_sized_new (10);
	g_ptr_array_set_free_func (argv, g_free);

	g_ptr_array_add (argv, g_strdup (LIBEXECDIR "/nm-iface-helper"));
	g_ptr_array_add (argv, g_strdup ("--ifname"));
	g_ptr_array_add (argv, g_strdup (nm_device_get_ip_iface (self)));
	g_ptr_array_add (argv, g_strdup ("--uuid"));
	g_ptr_array_add (argv, g_strdup (nm_connection_get_uuid (connection)));

	logging_backend = nm_config_get_is_debug (nm_config_get ())
	                  ? g_strdup ("debug")
	                  : nm_config_data_get_value (NM_CONFIG_GET_DATA_ORIG,
	                                              NM_CONFIG_KEYFILE_GROUP_LOGGING,
	                                              NM_CONFIG_KEYFILE_KEY_LOGGING_BACKEND,
	                                              NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
	if (logging_backend) {
		g_ptr_array_add (argv, g_strdup ("--logging-backend"));
		g_ptr_array_add (argv, logging_backend);
	}

	dhcp4_address = find_dhcp4_address (self);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0) {
		NMSettingIPConfig *s_ip4;
		char *hex_client_id;

		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		g_assert (s_ip4);

		g_ptr_array_add (argv, g_strdup ("--priority4"));
		g_ptr_array_add (argv, g_strdup_printf ("%u", nm_device_get_ip4_route_metric (self)));

		g_ptr_array_add (argv, g_strdup ("--dhcp4"));
		g_ptr_array_add (argv, g_strdup (dhcp4_address));
		if (nm_setting_ip_config_get_may_fail (s_ip4) == FALSE)
			g_ptr_array_add (argv, g_strdup ("--dhcp4-required"));

		if (priv->dhcp4_client) {
			const char *hostname;
			GBytes *client_id;

			client_id = nm_dhcp_client_get_client_id (priv->dhcp4_client);
			if (client_id) {
				g_ptr_array_add (argv, g_strdup ("--dhcp4-clientid"));
				hex_client_id = bin2hexstr (g_bytes_get_data (client_id, NULL),
				                            g_bytes_get_size (client_id));
				g_ptr_array_add (argv, hex_client_id);
			}

			hostname = nm_dhcp_client_get_hostname (priv->dhcp4_client);
			if (hostname) {
				g_ptr_array_add (argv, g_strdup ("--dhcp4-hostname"));
				g_ptr_array_add (argv, g_strdup (hostname));
			}
		}

		configured = TRUE;
	}

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0) {
		NMSettingIPConfig *s_ip6;
		char *hex_iid;
		NMUtilsIPv6IfaceId iid = NM_UTILS_IPV6_IFACE_ID_INIT;

		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		g_assert (s_ip6);

		g_ptr_array_add (argv, g_strdup ("--priority6"));
		g_ptr_array_add (argv, g_strdup_printf ("%u", nm_device_get_ip6_route_metric (self)));

		g_ptr_array_add (argv, g_strdup ("--slaac"));

		if (nm_setting_ip_config_get_may_fail (s_ip6) == FALSE)
			g_ptr_array_add (argv, g_strdup ("--slaac-required"));

		g_ptr_array_add (argv, g_strdup ("--slaac-tempaddr"));
		g_ptr_array_add (argv, g_strdup_printf ("%d", priv->rdisc_use_tempaddr));

		if (nm_device_get_ip_iface_identifier (self, &iid)) {
			g_ptr_array_add (argv, g_strdup ("--iid"));
			hex_iid = bin2hexstr ((const char *) iid.id_u8, sizeof (NMUtilsIPv6IfaceId));
			g_ptr_array_add (argv, hex_iid);
		}

		configured = TRUE;
	}

	if (configured) {
		GPid pid;

		g_ptr_array_add (argv, NULL);

		if (nm_logging_enabled (LOGL_DEBUG, LOGD_DEVICE)) {
			char *tmp;

			tmp = g_strjoinv (" ", (char **) argv->pdata);
			_LOGD (LOGD_DEVICE, "running '%s'", tmp);
			g_free (tmp);
		}

		if (g_spawn_async (NULL, (char **) argv->pdata, NULL,
		                   G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &error)) {
			_LOGI (LOGD_DEVICE, "spawned helper PID %u", (guint) pid);
		} else {
			_LOGW (LOGD_DEVICE, "failed to spawn helper: %s", error->message);
			g_error_free (error);
		}
	}

	g_ptr_array_unref (argv);
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
notify_ip_properties (NMDevice *self)
{
	g_object_notify (G_OBJECT (self), NM_DEVICE_IP_IFACE);
	g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_CONFIG);
	g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP4_CONFIG);
	g_object_notify (G_OBJECT (self), NM_DEVICE_IP6_CONFIG);
	g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP6_CONFIG);
}

static void
ip6_managed_setup (NMDevice *self)
{
	set_nm_ipv6ll (self, TRUE);
	set_disable_ipv6 (self, "1");
	nm_device_ipv6_sysctl_set (self, "accept_ra_defrtr", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_pinfo", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_rtr_pref", "0");
	nm_device_ipv6_sysctl_set (self, "use_tempaddr", "0");
}

static void
deactivate_async_ready (NMDevice *self,
                        GAsyncResult *res,
                        gpointer user_data)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason reason = GPOINTER_TO_UINT (user_data);
	GError *error = NULL;

	NM_DEVICE_GET_CLASS (self)->deactivate_async_finish (self, res, &error);

	/* If operation cancelled, just return */
	if (   g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)
	    || (priv->deactivating_cancellable && g_cancellable_is_cancelled (priv->deactivating_cancellable))) {
		nm_log_warn (LOGD_DEVICE, "Deactivation (%s) cancelled",
		             nm_device_get_iface (self));
	}
	/* In every other case, transition to the DISCONNECTED state */
	else {
		if (error)
			nm_log_warn (LOGD_DEVICE, "Deactivation (%s) failed: %s",
			             nm_device_get_iface (self),
			             error->message);
		nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED, reason);
	}

	g_clear_object (&priv->deactivating_cancellable);
	g_clear_error (&error);
}

static void
deactivate_dispatcher_complete (guint call_id, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason reason;

	g_return_if_fail (call_id == priv->dispatcher.call_id);
	g_return_if_fail (priv->dispatcher.post_state == NM_DEVICE_STATE_DISCONNECTED);

	reason = priv->dispatcher.post_state_reason;

	priv->dispatcher.call_id = 0;
	priv->dispatcher.post_state = NM_DEVICE_STATE_UNKNOWN;
	priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;

	if (priv->deactivating_cancellable) {
		g_warn_if_reached ();
		g_cancellable_cancel (priv->deactivating_cancellable);
		g_clear_object (&priv->deactivating_cancellable);
	}

	if (   NM_DEVICE_GET_CLASS (self)->deactivate_async
	    && NM_DEVICE_GET_CLASS (self)->deactivate_async_finish) {
		priv->deactivating_cancellable = g_cancellable_new ();
		NM_DEVICE_GET_CLASS (self)->deactivate_async (self,
		                                              priv->deactivating_cancellable,
		                                              (GAsyncReadyCallback) deactivate_async_ready,
		                                              GUINT_TO_POINTER (reason));
	} else
		nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED, reason);
}

static void
_set_state_full (NMDevice *self,
                 NMDeviceState state,
                 NMDeviceStateReason reason,
                 gboolean quitting)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState old_state;
	NMActRequest *req;
	gboolean no_firmware = FALSE;
	NMConnection *connection;

	/* Track re-entry */
	g_warn_if_fail (priv->in_state_changed == FALSE);
	priv->in_state_changed = TRUE;

	g_return_if_fail (NM_IS_DEVICE (self));

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

	_LOGI (LOGD_DEVICE, "device state change: %s -> %s (reason '%s') [%d %d %d]",
	       state_to_string (old_state),
	       state_to_string (state),
	       reason_to_string (reason),
	       old_state,
	       state,
	       reason);

	/* Clear any queued transitions */
	nm_device_queued_state_clear (self);

	dispatcher_cleanup (self);
	if (priv->deactivating_cancellable)
		g_cancellable_cancel (priv->deactivating_cancellable);

	/* Cache the activation request for the dispatcher */
	req = priv->act_request ? g_object_ref (priv->act_request) : NULL;

	if (state <= NM_DEVICE_STATE_UNAVAILABLE) {
		_clear_available_connections (self, TRUE);
		_clear_queued_act_request (priv);
	}

	/* Update the available connections list when a device first becomes available */
	if (   (state >= NM_DEVICE_STATE_DISCONNECTED && old_state < NM_DEVICE_STATE_DISCONNECTED)
	    || nm_device_get_default_unmanaged (self))
		nm_device_recheck_available_connections (self);

	/* Handle the new state here; but anything that could trigger
	 * another state change should be done below.
	 */
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		nm_device_set_firmware_missing (self, FALSE);
		if (old_state > NM_DEVICE_STATE_UNMANAGED) {
			if (reason == NM_DEVICE_STATE_REASON_REMOVED) {
				nm_device_cleanup (self, reason, CLEANUP_TYPE_REMOVED);
			} else {
				/* Clean up if the device is now unmanaged but was activated */
				if (nm_device_get_act_request (self))
					nm_device_cleanup (self, reason, CLEANUP_TYPE_DECONFIGURE);
				nm_device_take_down (self, TRUE);
				set_nm_ipv6ll (self, FALSE);
				restore_ip6_properties (self);
			}
		}
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state == NM_DEVICE_STATE_UNMANAGED) {
			save_ip6_properties (self);
			if (reason != NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED)
				ip6_managed_setup (self);
		}

		if (reason != NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED) {
			if (old_state == NM_DEVICE_STATE_UNMANAGED || priv->firmware_missing) {
				if (!nm_device_bring_up (self, TRUE, &no_firmware) && no_firmware)
					_LOGW (LOGD_HW, "firmware may be missing.");
				nm_device_set_firmware_missing (self, no_firmware ? TRUE : FALSE);
			}

			/* Ensure the device gets deactivated in response to stuff like
			 * carrier changes or rfkill.  But don't deactivate devices that are
			 * about to assume a connection since that defeats the purpose of
			 * assuming the device's existing connection.
			 *
			 * Note that we "deactivate" the device even when coming from
			 * UNMANAGED, to ensure that it's in a clean state.
			 */
			nm_device_cleanup (self, reason, CLEANUP_TYPE_DECONFIGURE);
		}
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state > NM_DEVICE_STATE_DISCONNECTED) {
			/* Ensure devices that previously assumed a connection now have
			 * userspace IPv6LL enabled.
			 */
			set_nm_ipv6ll (self, TRUE);

			nm_device_cleanup (self, reason, CLEANUP_TYPE_DECONFIGURE);
		} else if (old_state < NM_DEVICE_STATE_DISCONNECTED) {
			if (reason != NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED) {
				/* Ensure IPv6 is set up as it may not have been done when
				 * entering the UNAVAILABLE state depending on the reason.
				 */
				ip6_managed_setup (self);
			}
		}
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		if (old_state > NM_DEVICE_STATE_NEED_AUTH) {
			/* Clean up any half-done IP operations if the device's layer2
			 * finds out it needs authentication during IP config.
			 */
			_cleanup_ip_pre (self, CLEANUP_TYPE_DECONFIGURE);
		}
		break;
	default:
		break;
	}

	/* Reset autoconnect flag when the device is activating or connected. */
	if (   state >= NM_DEVICE_STATE_PREPARE
	    && state <= NM_DEVICE_STATE_ACTIVATED)
		nm_device_set_autoconnect (self, TRUE);

	g_object_notify (G_OBJECT (self), NM_DEVICE_STATE);
	g_object_notify (G_OBJECT (self), NM_DEVICE_STATE_REASON);
	g_signal_emit_by_name (self, "state-changed", state, old_state, reason);

	/* Post-process the event after internal notification */

	switch (state) {
	case NM_DEVICE_STATE_UNAVAILABLE:
		/* If the device can activate now (ie, it's got a carrier, the supplicant
		 * is active, or whatever) schedule a delayed transition to DISCONNECTED
		 * to get things rolling.  The device can't transition immediately because
		 * we can't change states again from the state handler for a variety of
		 * reasons.
		 */
		if (nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE)) {
			nm_device_queue_recheck_available (self,
			                                   NM_DEVICE_STATE_REASON_NONE,
			                                   NM_DEVICE_STATE_REASON_NONE);
		} else {
			if (old_state == NM_DEVICE_STATE_UNMANAGED)
				_LOGD (LOGD_DEVICE, "device not yet available for transition to DISCONNECTED");
			else if (   old_state > NM_DEVICE_STATE_UNAVAILABLE
			         && nm_device_get_default_unmanaged (self))
				nm_device_queue_state (self, NM_DEVICE_STATE_UNMANAGED, NM_DEVICE_STATE_REASON_NONE);
		}
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		_cancel_activation (self);

		if (nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)) {
			/* We cache the ignore_carrier state to not react on config-reloads while the connection
			 * is active. But on deactivating, reset the ignore-carrier flag to the current state. */
			priv->ignore_carrier = nm_config_data_get_ignore_carrier (NM_CONFIG_GET_DATA, self);
		}

		if (quitting) {
			nm_dispatcher_call_sync (DISPATCHER_ACTION_PRE_DOWN,
			                         nm_act_request_get_connection (req),
			                         self);
		} else {
			priv->dispatcher.post_state = NM_DEVICE_STATE_DISCONNECTED;
			priv->dispatcher.post_state_reason = reason;
			if (!nm_dispatcher_call (DISPATCHER_ACTION_PRE_DOWN,
			                         nm_act_request_get_connection (req),
			                         self,
			                         deactivate_dispatcher_complete,
			                         self,
			                         &priv->dispatcher.call_id)) {
				/* Just proceed on errors */
				deactivate_dispatcher_complete (0, self);
			}
		}
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (   priv->queued_act_request
		    && !priv->queued_act_request_is_waiting_for_carrier) {
			NMActRequest *queued_req;
			gboolean success;

			queued_req = priv->queued_act_request;
			priv->queued_act_request = NULL;
			success = _device_activate (self, queued_req);
			g_object_unref (queued_req);
			if (success)
				break;
			/* fall through */
		}
		if (   old_state > NM_DEVICE_STATE_DISCONNECTED
		    && nm_device_get_default_unmanaged (self))
			nm_device_queue_state (self, NM_DEVICE_STATE_UNMANAGED, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		_LOGI (LOGD_DEVICE, "Activation: successful, device activated.");
		nm_device_update_metered (self);
		nm_dispatcher_call (DISPATCHER_ACTION_UP, nm_act_request_get_connection (req), self, NULL, NULL, NULL);
		break;
	case NM_DEVICE_STATE_FAILED:
		if (nm_device_uses_assumed_connection (self)) {
			/* Avoid tearing down assumed connection, assume it's connected */
			nm_device_queue_state (self,
			                       NM_DEVICE_STATE_ACTIVATED,
			                       NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
			break;
		}

		connection = nm_device_get_connection (self);
		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: failed for connection '%s'",
		       connection ? nm_connection_get_id (connection) : "<unknown>");

		/* Notify any slaves of the unexpected failure */
		nm_device_master_release_slaves (self);

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
		nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_IP_CHECK:
		nm_device_start_ip_check (self);

		/* IP-related properties are only valid when the device has IP configuration;
		 * now that it does, ensure their change notifications are emitted.
		 */
		notify_ip_properties (self);
		break;
	case NM_DEVICE_STATE_SECONDARIES:
		ip_check_gw_ping_cleanup (self);
		_LOGD (LOGD_DEVICE, "device entered SECONDARIES state");
		break;
	default:
		break;
	}

	if (state > NM_DEVICE_STATE_DISCONNECTED)
		delete_on_deactivate_unschedule (self);

	if (   (old_state == NM_DEVICE_STATE_ACTIVATED || old_state == NM_DEVICE_STATE_DEACTIVATING)
	    && (state != NM_DEVICE_STATE_DEACTIVATING)) {
		if (quitting)
			nm_dispatcher_call_sync (DISPATCHER_ACTION_DOWN, nm_act_request_get_connection (req), self);
		else
			nm_dispatcher_call (DISPATCHER_ACTION_DOWN, nm_act_request_get_connection (req), self, NULL, NULL, NULL);
	}

	/* IP-related properties are only valid when the device has IP configuration.
	 * If it no longer does, ensure their change notifications are emitted.
	 */
	if (ip_config_valid (old_state) && !ip_config_valid (state))
	    notify_ip_properties (self);

	/* Dispose of the cached activation request */
	if (req)
		g_object_unref (req);

	priv->in_state_changed = FALSE;
}

void
nm_device_state_changed (NMDevice *self,
                         NMDeviceState state,
                         NMDeviceStateReason reason)
{
	_set_state_full (self, state, reason, FALSE);
}

static gboolean
queued_set_state (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState new_state;
	NMDeviceStateReason new_reason;

	if (priv->queued_state.id) {
		_LOGD (LOGD_DEVICE, "running queued state change to %s (id %d)",
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
		_LOGW (LOGD_DEVICE, "overwriting previously queued state change to %s (%s)",
		       state_to_string (priv->queued_state.state),
		       reason_to_string (priv->queued_state.reason));
		nm_device_queued_state_clear (self);
	}

	priv->queued_state.state = state;
	priv->queued_state.reason = reason;
	priv->queued_state.id = g_idle_add (queued_set_state, self);

	_LOGD (LOGD_DEVICE, "queued state change to %s due to %s (id %d)",
	       state_to_string (state), reason_to_string (reason),
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
		_LOGD (LOGD_DEVICE, "clearing queued state transition (id %d)",
		       priv->queued_state.id);
		g_source_remove (priv->queued_state.id);
		nm_device_remove_pending_action (self, queued_state_to_string (priv->queued_state.state), TRUE);
	}
	memset (&priv->queued_state, 0, sizeof (priv->queued_state));
}

NMDeviceState
nm_device_get_state (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_STATE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->state;
}

/***********************************************************/
/* NMConfigDevice interface related stuff */

const char *
nm_device_get_hw_address (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);
	priv = NM_DEVICE_GET_PRIVATE (self);

	return priv->hw_addr_len ? priv->hw_addr : NULL;
}

static void
nm_device_update_hw_address (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (self);
	const guint8 *hwaddr;
	gsize hwaddrlen = 0;

	if (ifindex <= 0)
		return;

	hwaddr = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, &hwaddrlen);

	if (hwaddrlen) {
		if (!priv->hw_addr || !nm_utils_hwaddr_matches (priv->hw_addr, -1, hwaddr, hwaddrlen)) {
			g_free (priv->hw_addr);
			priv->hw_addr = nm_utils_hwaddr_ntoa (hwaddr, hwaddrlen);

			_LOGD (LOGD_HW | LOGD_DEVICE, "hardware address now %s", priv->hw_addr);
			g_object_notify (G_OBJECT (self), NM_DEVICE_HW_ADDRESS);
		}
	} else {
		/* Invalid or no hardware address */
		if (priv->hw_addr_len != 0) {
			g_clear_pointer (&priv->hw_addr, g_free);
			_LOGD (LOGD_HW | LOGD_DEVICE,
			       "previous hardware address is no longer valid");
			g_object_notify (G_OBJECT (self), NM_DEVICE_HW_ADDRESS);
		}
	}
	priv->hw_addr_len = hwaddrlen;
}

gboolean
nm_device_set_hw_addr (NMDevice *self, const char *addr,
                       const char *detail, guint64 hw_log_domain)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean success = FALSE;
	const char *cur_addr = nm_device_get_hw_address (self);
	guint8 addr_bytes[NM_UTILS_HWADDR_LEN_MAX];

	g_return_val_if_fail (addr != NULL, FALSE);

	/* Do nothing if current MAC is same */
	if (cur_addr && nm_utils_hwaddr_matches (cur_addr, -1, addr, -1)) {
		_LOGD (LOGD_DEVICE | hw_log_domain, "no MAC address change needed");
		return TRUE;
	}
	if (!nm_utils_hwaddr_aton (addr, addr_bytes, priv->hw_addr_len)) {
		_LOGW (LOGD_DEVICE | hw_log_domain, "invalid MAC address %s", addr);
		return FALSE;
	}

	/* Can't change MAC address while device is up */
	nm_device_take_down (self, FALSE);

	success = nm_platform_link_set_address (NM_PLATFORM_GET, nm_device_get_ip_ifindex (self), addr_bytes, priv->hw_addr_len);
	if (success) {
		/* MAC address succesfully changed; update the current MAC to match */
		nm_device_update_hw_address (self);
		cur_addr = nm_device_get_hw_address (self);
		if (cur_addr && nm_utils_hwaddr_matches (cur_addr, -1, addr, -1)) {
			_LOGI (LOGD_DEVICE | hw_log_domain, "%s MAC address to %s",
			       detail, addr);
		} else {
			_LOGW (LOGD_DEVICE | hw_log_domain,
			       "new MAC address %s not successfully set", addr);
			success = FALSE;
		}
	} else {
		_LOGW (LOGD_DEVICE | hw_log_domain, "failed to %s MAC address to %s",
		       detail, addr);
	}
	nm_device_bring_up (self, TRUE, NULL);

	return success;
}

const char *
nm_device_get_permanent_hw_address (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->perm_hw_addr;
}

const char *
nm_device_get_initial_hw_address (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->initial_hw_addr;
}

/**
 * nm_device_spec_match_list:
 * @self: an #NMDevice
 * @specs: (element-type utf8): a list of device specs
 *
 * Checks if @self matches any of the specifications in @specs. The
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
 * Returns: #TRUE if @self matches one of the specs in @specs
 */
gboolean
nm_device_spec_match_list (NMDevice *self, const GSList *specs)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (!specs)
		return FALSE;

	return NM_DEVICE_GET_CLASS (self)->spec_match_list (self, specs) == NM_MATCH_SPEC_MATCH;
}

static NMMatchSpecMatchType
spec_match_list (NMDevice *self, const GSList *specs)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMMatchSpecMatchType matched = NM_MATCH_SPEC_NO_MATCH, m;
	const GSList *iter;

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((const char *) iter->data, "*")) {
			matched = NM_MATCH_SPEC_MATCH;
			break;
		}
	}
	if (priv->hw_addr_len) {
		m = nm_match_spec_hwaddr (specs, priv->hw_addr);
		matched = MAX (matched, m);
	}
	if (matched != NM_MATCH_SPEC_NEG_MATCH) {
		m = nm_match_spec_interface_name (specs, nm_device_get_iface (self));
		matched = MAX (matched, m);
	}
	if (matched != NM_MATCH_SPEC_NEG_MATCH) {
		m = nm_match_spec_device_type (specs, nm_device_get_type_description (self));
		matched = MAX (matched, m);
	}
	return matched;
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

	priv->default_route.v4_is_assumed = TRUE;
	priv->default_route.v6_is_assumed = TRUE;

	priv->v4_commit_first_time = TRUE;
	priv->v6_commit_first_time = TRUE;
}

static void
constructed (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatform *platform;

	if (NM_DEVICE_GET_CLASS (self)->get_generic_capabilities)
		priv->capabilities |= NM_DEVICE_GET_CLASS (self)->get_generic_capabilities (self);

	/* Watch for external IP config changes */
	platform = nm_platform_get ();
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK (link_changed_cb), self);

	priv->con_provider = nm_connection_provider_get ();
	g_assert (priv->con_provider);
	g_signal_connect (priv->con_provider,
	                  NM_CP_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (cp_connection_added),
	                  self);

	g_signal_connect (priv->con_provider,
	                  NM_CP_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (cp_connection_removed),
	                  self);

	g_signal_connect (priv->con_provider,
	                  NM_CP_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (cp_connection_updated),
	                  self);

	/* Update default-unmanaged device available connections immediately,
	 * since they don't transition from UNMANAGED (and thus the state handler
	 * doesn't run and update them) until something external happens.
	 */
	if (nm_device_get_default_unmanaged (self)) {
		nm_device_set_autoconnect (self, FALSE);
		nm_device_recheck_available_connections (self);
	}

	G_OBJECT_CLASS (nm_device_parent_class)->constructed (object);

	_LOGD (LOGD_DEVICE, "constructed (%s)", G_OBJECT_TYPE_NAME (self));
}

static void
dispose (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatform *platform;

	_LOGD (LOGD_DEVICE, "disposing");

	g_signal_handlers_disconnect_by_func (nm_config_get (), config_changed_update_ignore_carrier, self);

	dispatcher_cleanup (self);

	_cleanup_generic_pre (self, CLEANUP_TYPE_KEEP);

	g_warn_if_fail (priv->slaves == NULL);
	g_assert (priv->master_ready_id == 0);

	/* Let the kernel manage IPv6LL again */
	set_nm_ipv6ll (self, FALSE);

	_cleanup_generic_post (self, CLEANUP_TYPE_KEEP);

	g_hash_table_remove_all (priv->ip6_saved_properties);

	if (priv->recheck_assume_id) {
		g_source_remove (priv->recheck_assume_id);
		priv->recheck_assume_id = 0;
	}

	if (priv->recheck_available.call_id) {
		g_source_remove (priv->recheck_available.call_id);
		priv->recheck_available.call_id = 0;
	}

	link_disconnect_action_cancel (self);

	if (priv->con_provider) {
		g_signal_handlers_disconnect_by_func (priv->con_provider, cp_connection_added, self);
		g_signal_handlers_disconnect_by_func (priv->con_provider, cp_connection_removed, self);
		g_signal_handlers_disconnect_by_func (priv->con_provider, cp_connection_updated, self);
		priv->con_provider = NULL;
	}

	g_hash_table_remove_all (priv->available_connections);

	if (priv->carrier_wait_id) {
		g_source_remove (priv->carrier_wait_id);
		priv->carrier_wait_id = 0;
	}

	_clear_queued_act_request (priv);

	platform = nm_platform_get ();
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (device_ipx_changed), self);
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (link_changed_cb), self);

	nm_clear_g_source (&priv->device_link_changed_id);
	nm_clear_g_source (&priv->device_ip_link_changed_id);

	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_LOGD (LOGD_DEVICE, "finalize(): %s", G_OBJECT_TYPE_NAME (self));

	g_free (priv->hw_addr);
	g_free (priv->perm_hw_addr);
	g_free (priv->initial_hw_addr);
	g_slist_free_full (priv->pending_actions, g_free);
	g_clear_pointer (&priv->physical_port_id, g_free);
	g_free (priv->udi);
	g_free (priv->iface);
	g_free (priv->ip_iface);
	g_free (priv->driver);
	g_free (priv->driver_version);
	g_free (priv->firmware_version);
	g_free (priv->type_desc);
	g_free (priv->type_description);
	g_free (priv->dhcp_anycast_address);

	g_hash_table_unref (priv->ip6_saved_properties);
	g_hash_table_unref (priv->available_connections);

	G_OBJECT_CLASS (nm_device_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *hw_addr, *p;
	guint count;

	switch (prop_id) {
	case PROP_UDI:
		if (g_value_get_string (value)) {
			g_free (priv->udi);
			priv->udi = g_value_dup_string (value);
		}
		break;
	case PROP_IFACE:
		if (g_value_get_string (value)) {
			g_free (priv->iface);
			priv->iface = g_value_dup_string (value);
			priv->ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, priv->iface);
			if (priv->ifindex > 0)
				priv->up = nm_platform_link_is_up (NM_PLATFORM_GET, priv->ifindex);
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
		nm_device_set_autoconnect (self, g_value_get_boolean (value));
		break;
	case PROP_FIRMWARE_MISSING:
		priv->firmware_missing = g_value_get_boolean (value);
		break;
	case PROP_NM_PLUGIN_MISSING:
		priv->nm_plugin_missing = g_value_get_boolean (value);
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
		/* construct only */
		p = hw_addr = g_value_get_string (value);

		/* Hardware address length is the number of ':' plus 1 */
		count = 1;
		while (p && *p) {
			if (*p++ == ':')
				count++;
		}
		if (count < ETH_ALEN || count > NM_UTILS_HWADDR_LEN_MAX) {
			if (hw_addr && *hw_addr) {
				_LOGW (LOGD_DEVICE, "ignoring hardware address '%s' with unexpected length %d",
				       hw_addr, count);
			}
			break;
		}

		priv->hw_addr_len = count;
		g_free (priv->hw_addr);
		if (nm_utils_hwaddr_valid (hw_addr, priv->hw_addr_len))
			priv->hw_addr = g_strdup (hw_addr);
		else {
			_LOGW (LOGD_DEVICE, "could not parse hw-address '%s'", hw_addr);
			priv->hw_addr = NULL;
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
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
		nm_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->ip4_config : NULL);
		break;
	case PROP_DHCP4_CONFIG:
		nm_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->dhcp4_config : NULL);
		break;
	case PROP_IP6_CONFIG:
		nm_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->ip6_config : NULL);
		break;
	case PROP_DHCP6_CONFIG:
		nm_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->dhcp6_config : NULL);
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case PROP_STATE_REASON:
		g_value_take_variant (value,
		                      g_variant_new ("(uu)", priv->state, priv->state_reason));
		break;
	case PROP_ACTIVE_CONNECTION:
		nm_utils_g_value_set_object_path (value, priv->act_request);
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
	case PROP_NM_PLUGIN_MISSING:
		g_value_set_boolean (value, priv->nm_plugin_missing);
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
		g_ptr_array_add (array, NULL);
		g_value_take_boxed (value, (char **) g_ptr_array_free (array, FALSE));
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
		g_value_set_string (value, priv->hw_addr);
		break;
	case PROP_HAS_PENDING_ACTION:
		g_value_set_boolean (value, nm_device_has_pending_action (self));
		break;
	case PROP_METERED:
		g_value_set_uint (value, priv->metered);
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
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDevicePrivate));

	exported_object_class->export_path = NM_DBUS_PATH "/Devices/%u";

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
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

	klass->get_type_description = get_type_description;
	klass->spec_match_list = spec_match_list;
	klass->can_auto_connect = can_auto_connect;
	klass->check_connection_compatible = check_connection_compatible;
	klass->check_connection_available = check_connection_available;
	klass->can_unmanaged_external_down = can_unmanaged_external_down;
	klass->setup = setup;
	klass->is_up = is_up;
	klass->bring_up = bring_up;
	klass->take_down = take_down;
	klass->carrier_changed = carrier_changed;
	klass->get_ip_iface_identifier = get_ip_iface_identifier;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_UDI,
		 g_param_spec_string (NM_DEVICE_UDI, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IFACE,
		 g_param_spec_string (NM_DEVICE_IFACE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IP_IFACE,
		 g_param_spec_string (NM_DEVICE_IP_IFACE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DRIVER,
		 g_param_spec_string (NM_DEVICE_DRIVER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DRIVER_VERSION,
		 g_param_spec_string (NM_DEVICE_DRIVER_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_FIRMWARE_VERSION,
		 g_param_spec_string (NM_DEVICE_FIRMWARE_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_CAPABILITIES, "", "",
		                    0, G_MAXUINT32, NM_DEVICE_CAP_NONE,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_DEVICE_MTU, "", "",
		                    0, G_MAXUINT32, 1500,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IP4_ADDRESS,
		 g_param_spec_uint (NM_DEVICE_IP4_ADDRESS, "", "",
		                    0, G_MAXUINT32, 0, /* FIXME */
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IP4_CONFIG,
		 g_param_spec_string (NM_DEVICE_IP4_CONFIG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DHCP4_CONFIG,
		 g_param_spec_string (NM_DEVICE_DHCP4_CONFIG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IP6_CONFIG,
		 g_param_spec_string (NM_DEVICE_IP6_CONFIG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DHCP6_CONFIG,
		 g_param_spec_string (NM_DEVICE_DHCP6_CONFIG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_DEVICE_STATE, "", "",
		                    0, G_MAXUINT32, NM_DEVICE_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_STATE_REASON,
		 g_param_spec_variant (NM_DEVICE_STATE_REASON, "", "",
		                       G_VARIANT_TYPE ("(uu)"),
		                       NULL,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTION,
		 g_param_spec_string (NM_DEVICE_ACTIVE_CONNECTION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DEVICE_TYPE,
		 g_param_spec_uint (NM_DEVICE_DEVICE_TYPE, "", "",
		                    0, G_MAXUINT32, NM_DEVICE_TYPE_UNKNOWN,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MANAGED,
		 g_param_spec_boolean (NM_DEVICE_MANAGED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_AUTOCONNECT,
		 g_param_spec_boolean (NM_DEVICE_AUTOCONNECT, "", "",
		                       DEFAULT_AUTOCONNECT,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_FIRMWARE_MISSING,
		 g_param_spec_boolean (NM_DEVICE_FIRMWARE_MISSING, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_NM_PLUGIN_MISSING,
		 g_param_spec_boolean (NM_DEVICE_NM_PLUGIN_MISSING, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TYPE_DESC,
		 g_param_spec_string (NM_DEVICE_TYPE_DESC, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_RFKILL_TYPE,
		 g_param_spec_uint (NM_DEVICE_RFKILL_TYPE, "", "",
		                    RFKILL_TYPE_WLAN,
		                    RFKILL_TYPE_MAX,
		                    RFKILL_TYPE_UNKNOWN,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IFINDEX,
		 g_param_spec_int (NM_DEVICE_IFINDEX, "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READABLE |
		                   G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_AVAILABLE_CONNECTIONS,
		 g_param_spec_boxed (NM_DEVICE_AVAILABLE_CONNECTIONS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PHYSICAL_PORT_ID,
		 g_param_spec_string (NM_DEVICE_PHYSICAL_PORT_ID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IS_MASTER,
		 g_param_spec_boolean (NM_DEVICE_IS_MASTER, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MASTER,
		 g_param_spec_object (NM_DEVICE_MASTER, "", "",
		                      NM_TYPE_DEVICE,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_HAS_PENDING_ACTION,
		 g_param_spec_boolean (NM_DEVICE_HAS_PENDING_ACTION, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:metered:
	 *
	 * Whether the connection is metered.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_METERED,
		 g_param_spec_uint (NM_DEVICE_METERED, "", "",
		                    0, G_MAXUINT32, NM_METERED_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

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
		              /* context, connection, permission, allow_interaction, callback, user_data */
		              G_TYPE_NONE, 6, G_TYPE_DBUS_METHOD_INVOCATION, NM_TYPE_CONNECTION, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_POINTER, G_TYPE_POINTER);

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

	signals[LINK_INITIALIZED] =
		g_signal_new (NM_DEVICE_LINK_INITIALIZED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_SKELETON,
	                                        "Disconnect", impl_device_disconnect,
	                                        "Delete", impl_device_delete,
	                                        NULL);
}
