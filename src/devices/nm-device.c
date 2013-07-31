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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
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

#include "nm-glib-compat.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-device-ethernet.h"
#include "NetworkManagerUtils.h"
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
#include "nm-platform.h"

static void impl_device_disconnect (NMDevice *device, DBusGMethodInvocation *context);

#include "nm-device-glue.h"

#define DBUS_G_TYPE_UINT_STRUCT (dbus_g_type_get_struct ("GValueArray", G_TYPE_UINT, G_TYPE_UINT, G_TYPE_INVALID))

/* default to installed helper, but can be modified for testing */
const char *nm_device_autoipd_helper_path = LIBEXECDIR "/nm-avahi-autoipd.action";

/***********************************************************/
#define NM_DEVICE_ERROR (nm_device_error_quark ())

static GQuark
nm_device_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-device-error");
	return quark;
}

/***********************************************************/

enum {
	STATE_CHANGED,
	AUTOCONNECT_ALLOWED,
	AUTH_REQUEST,
	IP4_CONFIG_CHANGED,
	IP6_CONFIG_CHANGED,
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
	PROP_IS_MASTER,
	PROP_HW_ADDRESS,
	LAST_PROP
};

#define DEFAULT_AUTOCONNECT TRUE

/***********************************************************/

static void nm_device_config_device_interface_init (NMConfigDeviceInterface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMDevice, nm_device, G_TYPE_OBJECT,
                                  G_IMPLEMENT_INTERFACE (NM_TYPE_CONFIG_DEVICE, nm_device_config_device_interface_init))

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

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
	guint watch_id;
} SlaveInfo;

typedef struct {
	guint log_domain;
	guint timeout;
	guint watch;
	GPid pid;
} PingInfo;

typedef struct {
	gboolean disposed;
	gboolean initialized;
	gboolean in_state_changed;

	NMDeviceState state;
	NMDeviceStateReason state_reason;
	QueuedState   queued_state;
	guint queued_ip_config_id;

	char *        udi;
	char *        path;
	char *        iface;   /* may change, could be renamed by user */
	int           ifindex;
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

	gboolean      manager_managed; /* whether managed by NMManager or not */
	gboolean      default_unmanaged; /* whether unmanaged by default */

	guint32         ip4_address;

	NMActRequest *  act_request;
	guint           act_source_id;
	gpointer        act_source_func;
	guint           act_source6_id;
	gpointer        act_source6_func;
	gulong          secrets_updated_id;
	gulong          secrets_failed_id;

	/* Link stuff */
	guint           link_connected_id;
	guint           link_disconnected_id;
	guint           carrier_defer_id;
	gboolean        carrier;
	gboolean        ignore_carrier;

	/* Generic DHCP stuff */
	NMDHCPManager * dhcp_manager;
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

	NMRDisc *      rdisc;
	gulong         rdisc_config_changed_sigid;
	/* IP6 config from autoconf */
	NMIP6Config *  ac_ip6_config;

	char *         ip6_accept_ra_path;
	gint32         ip6_accept_ra_save;

	/* IPv6 privacy extensions (RFC4941) */
	char *         ip6_privacy_tempaddr_path;
	gint32         ip6_privacy_tempaddr_save;

	NMDHCPClient *  dhcp6_client;
	NMRDiscDHCPLevel dhcp6_mode;
	gulong          dhcp6_state_sigid;
	gulong          dhcp6_timeout_sigid;
	NMDHCP6Config * dhcp6_config;
	/* IP6 config from DHCP */
	NMIP6Config *   dhcp6_ip6_config;

	/* allow autoconnect feature */
	gboolean        autoconnect;

	/* master interface for bridge/bond slave */
	NMDevice *      master;
	gboolean        enslaved;

	/* slave management */
	gboolean        is_master;
	GSList *        slaves;    /* list of SlaveInfo */

	NMConnectionProvider *con_provider;

	/* connection provider signals for available connections property */
	guint cp_added_id;
	guint cp_loaded_id;
	guint cp_removed_id;
	guint cp_updated_id;

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

static gboolean nm_device_activate_ip6_config_commit (gpointer user_data);

static gboolean check_connection_available (NMDevice *device, NMConnection *connection);

static gboolean spec_match_list (NMDevice *device, const GSList *specs);

static void _clear_available_connections (NMDevice *device, gboolean do_signal);

static void dhcp4_cleanup (NMDevice *self, gboolean stop, gboolean release);

static const char *reason_to_string (NMDeviceStateReason reason);

static void ip_check_gw_ping_cleanup (NMDevice *self);

static void cp_connection_added (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data);
static void cp_connections_loaded (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data);
static void cp_connection_removed (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data);
static void cp_connection_updated (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data);

static const char *state_to_string (NMDeviceState state);

static void link_changed_cb (NMPlatform *platform, int ifindex, NMPlatformLink *info, NMPlatformReason reason, NMDevice *device);
static void check_carrier (NMDevice *device);

static void nm_device_queued_ip_config_change_clear (NMDevice *self);
static void update_ip_config (NMDevice *self);
static void device_ip_changed (NMPlatform *platform, int ifindex, gpointer platform_object, NMPlatformReason reason, gpointer user_data);

static const char const *platform_ip_signals[] = {
	NM_PLATFORM_IP4_ADDRESS_ADDED,
	NM_PLATFORM_IP4_ADDRESS_CHANGED,
	NM_PLATFORM_IP4_ADDRESS_REMOVED,
	NM_PLATFORM_IP4_ROUTE_ADDED,
	NM_PLATFORM_IP4_ROUTE_CHANGED,
	NM_PLATFORM_IP4_ROUTE_REMOVED,
	NM_PLATFORM_IP6_ADDRESS_ADDED,
	NM_PLATFORM_IP6_ADDRESS_CHANGED,
	NM_PLATFORM_IP6_ADDRESS_REMOVED,
	NM_PLATFORM_IP6_ROUTE_ADDED,
	NM_PLATFORM_IP6_ROUTE_CHANGED,
	NM_PLATFORM_IP6_ROUTE_REMOVED,
};
static const int n_platform_ip_signals = G_N_ELEMENTS (platform_ip_signals);

static void
nm_device_init (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatform *platform;
	int i;

	priv->type = NM_DEVICE_TYPE_UNKNOWN;
	priv->capabilities = NM_DEVICE_CAP_NM_SUPPORTED;
	priv->state = NM_DEVICE_STATE_UNMANAGED;
	priv->state_reason = NM_DEVICE_STATE_REASON_NONE;
	priv->dhcp_timeout = 0;
	priv->rfkill_type = RFKILL_TYPE_UNKNOWN;
	priv->autoconnect = DEFAULT_AUTOCONNECT;
	priv->available_connections = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);

	/* Watch for external IP config changes */
	platform = nm_platform_get ();
	for (i = 0; i < n_platform_ip_signals; i++) {
		g_signal_connect (platform, platform_ip_signals[i],
		                  G_CALLBACK (device_ip_changed), self);
	}

	g_signal_connect (platform, NM_PLATFORM_LINK_CHANGED,
	                  G_CALLBACK (link_changed_cb), self);
}

static void
update_accept_ra_save (NMDevice *self)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	char *new_path;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);

	new_path = g_strdup_printf ("/proc/sys/net/ipv6/conf/%s/accept_ra", ip_iface);
	g_assert (new_path);

	if (priv->ip6_accept_ra_path) {
		/* If the IP iface is different from before, use the new value */
		if (!strcmp (new_path, priv->ip6_accept_ra_path)) {
			g_free (new_path);
			return;
		}
		g_free (priv->ip6_accept_ra_path);
	}

	/* Grab the original value of "accept_ra" so we can restore it when NM exits */
	priv->ip6_accept_ra_path = new_path;
	if (!nm_utils_get_proc_sys_net_value_with_bounds (priv->ip6_accept_ra_path,
	                                                  ip_iface,
	                                                  &priv->ip6_accept_ra_save,
	                                                  0, 2)) {
		g_free (priv->ip6_accept_ra_path);
		priv->ip6_accept_ra_path = NULL;
	}
}

static void
update_ip6_privacy_save (NMDevice *self)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	char *new_path;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);

	new_path = g_strdup_printf ("/proc/sys/net/ipv6/conf/%s/use_tempaddr", ip_iface);
	g_assert (new_path);

	if (priv->ip6_privacy_tempaddr_path) {
		/* If the IP iface is different from before, use the new value */
		if (!strcmp (new_path, priv->ip6_privacy_tempaddr_path)) {
			g_free (new_path);
			return;
		}
		g_free (priv->ip6_privacy_tempaddr_path);
	}

	/* Grab the original value of "use_tempaddr" so we can restore it when NM exits */
	priv->ip6_privacy_tempaddr_path = new_path;
	if (!nm_utils_get_proc_sys_net_value (priv->ip6_privacy_tempaddr_path,
	                                      ip_iface,
	                                      &priv->ip6_privacy_tempaddr_save)) {
		g_free (priv->ip6_privacy_tempaddr_path);
		priv->ip6_privacy_tempaddr_path = NULL;
	}
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

static gboolean
device_has_capability (NMDevice *device, NMDeviceCapabilities caps)
{
	return !!(NM_DEVICE_GET_PRIVATE (device)->capabilities & caps);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDevice *dev;
	NMDevicePrivate *priv;

	object = G_OBJECT_CLASS (nm_device_parent_class)->constructor (type,
	                         n_construct_params,
	                         construct_params);
	if (!object)
		return NULL;

	dev = NM_DEVICE (object);
	priv = NM_DEVICE_GET_PRIVATE (dev);

	if (!priv->udi) {
		nm_log_err (LOGD_DEVICE, "No device udi provided, ignoring");
		goto error;
	}

	if (!priv->iface) {
		nm_log_err (LOGD_DEVICE, "No device interface provided, ignoring");
		goto error;
	}

	if (NM_DEVICE_GET_CLASS (dev)->get_generic_capabilities)
		priv->capabilities |= NM_DEVICE_GET_CLASS (dev)->get_generic_capabilities (dev);

	priv->dhcp_manager = nm_dhcp_manager_get ();

	priv->fw_manager = nm_firewall_manager_get ();

	device_get_driver_info (priv->iface, &priv->driver_version, &priv->firmware_version);

	update_accept_ra_save (dev);
	update_ip6_privacy_save (dev);
	update_ip_config (dev);

	priv->initialized = TRUE;
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

	if (G_OBJECT_CLASS (nm_device_parent_class)->constructed)
		G_OBJECT_CLASS (nm_device_parent_class)->constructed (object);
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

	return ifindex ? nm_platform_link_is_up (ifindex) : TRUE;
}

void
nm_device_set_path (NMDevice *self, const char *path)
{
	NMDevicePrivate *priv;

	g_return_if_fail (self != NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->path == NULL);

	priv->path = g_strdup (path);
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

/*
 * Get/set functions for iface
 */
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
	old_ip_iface = priv->ip_iface;
	priv->ip_ifindex = 0;

	priv->ip_iface = g_strdup (iface);
	if (priv->ip_iface) {
		priv->ip_ifindex = nm_platform_link_get_ifindex (priv->ip_iface);
		if (priv->ip_ifindex <= 0) {
			/* Device IP interface must always be a kernel network interface */
			nm_log_warn (LOGD_HW, "(%s): failed to look up interface index", iface);
		}
	}

	/* Emit change notification */
	if (g_strcmp0 (old_ip_iface, priv->ip_iface))
		g_object_notify (G_OBJECT (self), NM_DEVICE_IP_IFACE);
	g_free (old_ip_iface);
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

/*
 * Get/set functions for driver
 */
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

const char *
nm_device_get_firmware_version (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->firmware_version;
}


/*
 * Get/set functions for type
 */
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
	case NM_DEVICE_TYPE_VLAN:
		return 6;
	case NM_DEVICE_TYPE_MODEM:
		return 7;
	case NM_DEVICE_TYPE_BT:
		return 8;
	case NM_DEVICE_TYPE_WIFI:
		return 9;
	case NM_DEVICE_TYPE_OLPC_MESH:
		return 10;
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

void
nm_device_set_connection_provider (NMDevice *device,
                                   NMConnectionProvider *provider)
{
	NMDevicePrivate *priv;

	g_return_if_fail (device != NULL);
	g_return_if_fail (NM_IS_CONNECTION_PROVIDER (provider));

	priv = NM_DEVICE_GET_PRIVATE (device);
	g_return_if_fail (priv->con_provider == NULL);

	priv->con_provider = provider;
	priv->cp_added_id = g_signal_connect (priv->con_provider,
	                                      NM_CP_SIGNAL_CONNECTION_ADDED,
	                                      G_CALLBACK (cp_connection_added),
	                                      device);

	priv->cp_loaded_id = g_signal_connect (priv->con_provider,
	                                       NM_CP_SIGNAL_CONNECTIONS_LOADED,
	                                       G_CALLBACK (cp_connections_loaded),
	                                       device);

	priv->cp_removed_id = g_signal_connect (priv->con_provider,
	                                        NM_CP_SIGNAL_CONNECTION_REMOVED,
	                                        G_CALLBACK (cp_connection_removed),
	                                        device);

	priv->cp_updated_id = g_signal_connect (priv->con_provider,
	                                        NM_CP_SIGNAL_CONNECTION_UPDATED,
	                                        G_CALLBACK (cp_connection_updated),
	                                        device);
}

NMConnectionProvider *
nm_device_get_connection_provider (NMDevice *device)
{
	g_return_val_if_fail (device != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (device)->con_provider;
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
 * @connection: the slave device's connection
 *
 * If @dev is capable of enslaving other devices (ie it's a bridge, bond, etc)
 * then this function enslaves @slave.
 *
 * Returns: %TRUE on success, %FALSE on failure or if this device cannot enslave
 *  other devices.
 */
static gboolean
nm_device_enslave_slave (NMDevice *dev, NMDevice *slave, NMConnection *connection)
{
	SlaveInfo *info;
	gboolean success = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (dev)->enslave_slave != NULL, FALSE);

	info = find_slave_info (dev, slave);
	if (!info)
		return FALSE;

	g_warn_if_fail (info->enslaved == FALSE);
	success = NM_DEVICE_GET_CLASS (dev)->enslave_slave (dev, slave, connection);
	if (success) {
		info->enslaved = TRUE;
		nm_device_slave_notify_enslaved (info->slave, TRUE, FALSE);
	}

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
 * @failed: %TRUE if the release was unexpected, ie the master failed
 *
 * If @dev is capable of enslaving other devices (ie it's a bridge, bond, etc)
 * then this function releases the previously enslaved @slave.
 *
 * Returns: %TRUE on success, %FALSE on failure, if this device cannot enslave
 *  other devices, or if @slave was never enslaved.
 */
static gboolean
nm_device_release_one_slave (NMDevice *dev, NMDevice *slave, gboolean failed)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	SlaveInfo *info;
	gboolean success = FALSE;

	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (dev)->release_slave != NULL, FALSE);

	info = find_slave_info (dev, slave);
	if (!info)
		return FALSE;

	if (info->enslaved) {
		success = NM_DEVICE_GET_CLASS (dev)->release_slave (dev, slave);
		g_warn_if_fail (success);
	}
	nm_device_slave_notify_enslaved (info->slave, FALSE, failed);

	priv->slaves = g_slist_remove (priv->slaves, info);
	free_slave_info (info);

	/* Ensure the device's hardware address is up-to-date; it often changes
	 * when slaves change.
	 */
	nm_device_update_hw_address (dev);

	return success;
}

static gboolean
connection_is_static (NMConnection *connection)
{
	NMSettingIP4Config *ip4;
	NMSettingIP6Config *ip6;
	const char *method;

	ip4 = nm_connection_get_setting_ip4_config (connection);
	if (ip4) {
		method = nm_setting_ip4_config_get_method (ip4);
		if (   g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) != 0
		    && g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) != 0)
		return FALSE;
	}

	ip6 = nm_connection_get_setting_ip6_config (connection);
	if (ip6) {
		method = nm_setting_ip6_config_get_method (ip6);
		if (   g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) != 0
		    && g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) != 0)
			return FALSE;
	}

	return TRUE;
}

static gboolean
has_static_connection (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const GSList *connections, *iter;

	connections = nm_connection_provider_get_connections (priv->con_provider);
	for (iter = connections; iter; iter = iter->next) {
		NMConnection *connection = iter->data;

		if (   nm_device_check_connection_compatible (self, connection, NULL)
		    && connection_is_static (connection))
			return TRUE;
	}
	return FALSE;
}

static void
carrier_changed (NMDevice *device, gboolean carrier)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if (!nm_device_get_managed (device))
		return;

	if (priv->ignore_carrier) {
		/* Ignore all carrier-off, and ignore carrier-on on connected devices */
		if (!carrier || priv->state > NM_DEVICE_STATE_DISCONNECTED)
			return;
	}

	if (nm_device_is_master (device)) {
		/* Bridge/bond carrier does not affect its own activation, but
		 * when carrier comes on, if there are slaves waiting, it will
		 * restart them.
		 */
		if (!carrier)
			return;

		if (nm_device_activate_ip4_state_in_wait (device))
			nm_device_activate_stage3_ip4_start (device);
		if (nm_device_activate_ip6_state_in_wait (device))
			nm_device_activate_stage3_ip6_start (device);

		return;
	} else if (nm_device_get_enslaved (device) && !carrier) {
		/* Slaves don't deactivate when they lose carrier; for bonds
		 * in particular that would be actively counterproductive.
		 */
		return;
	}

	if (carrier) {
		g_warn_if_fail (priv->state >= NM_DEVICE_STATE_UNAVAILABLE);

		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_queue_state (device, NM_DEVICE_STATE_DISCONNECTED,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		}
	} else {
		g_return_if_fail (priv->state >= NM_DEVICE_STATE_UNAVAILABLE);

		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			if (nm_device_queued_state_peek (device) >= NM_DEVICE_STATE_DISCONNECTED)
				nm_device_queued_state_clear (device);
		} else {
			nm_device_queue_state (device, NM_DEVICE_STATE_UNAVAILABLE,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		}
	}
}

gboolean
nm_device_has_carrier (NMDevice *device)
{
	return NM_DEVICE_GET_PRIVATE (device)->carrier;
}

/* Returns %TRUE if @device is unavailable for connections because it
 * needs carrier but does not have it.
 */
static gboolean
nm_device_is_unavailable_because_of_carrier (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	return !priv->carrier && !priv->ignore_carrier;
}

#define LINK_DISCONNECT_DELAY 4

static gboolean
link_disconnect_action_cb (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	priv->carrier_defer_id = 0;

	nm_log_info (LOGD_DEVICE, "(%s): link disconnected (calling deferred action)",
	             nm_device_get_iface (device));

	NM_DEVICE_GET_CLASS (device)->carrier_changed (device, FALSE);

	return FALSE;
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
		if (priv->carrier_defer_id) {
			g_source_remove (priv->carrier_defer_id);
			priv->carrier_defer_id = 0;
		}
		klass->carrier_changed (device, TRUE);
	} else if (state <= NM_DEVICE_STATE_DISCONNECTED) {
		nm_log_info (LOGD_DEVICE, "(%s): link disconnected", iface);
		klass->carrier_changed (device, FALSE);
	} else {
		nm_log_info (LOGD_DEVICE, "(%s): link disconnected (deferring action for %d seconds)",
		             iface, LINK_DISCONNECT_DELAY);
		priv->carrier_defer_id = g_timeout_add_seconds (LINK_DISCONNECT_DELAY,
		                                                link_disconnect_action_cb, device);
	}
}

static void
link_changed_cb (NMPlatform *platform, int ifindex, NMPlatformLink *info, NMPlatformReason reason, NMDevice *device)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (device);

	if (ifindex != nm_device_get_ifindex (device))
		return;

	if (klass->link_changed)
		klass->link_changed (device, info);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	if (   device_has_capability (device, NM_DEVICE_CAP_CARRIER_DETECT)
	    && !device_has_capability (device, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
		nm_device_set_carrier (device, info->connected);
}

static void
check_carrier (NMDevice *device)
{
	int ifindex = nm_device_get_ip_ifindex (device);

	if (!device_has_capability (device, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
		nm_device_set_carrier (device, nm_platform_link_is_connected (ifindex));
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

	g_assert (priv->state > NM_DEVICE_STATE_DISCONNECTED);
	g_assert (priv->state <= NM_DEVICE_STATE_ACTIVATED);

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
		nm_device_release_one_slave (self, slave, FALSE);
		/* Bridge/bond interfaces are left up until manually deactivated */
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
 *
 * If @dev is capable of enslaving other devices (ie it's a bridge, bond, etc)
 * then this function adds @slave to the slave list for later enslavement.
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
gboolean
nm_device_master_add_slave (NMDevice *dev, NMDevice *slave)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	SlaveInfo *info;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (dev)->enslave_slave != NULL, FALSE);

	if (!find_slave_info (dev, slave)) {
		info = g_malloc0 (sizeof (SlaveInfo));
		info->slave = g_object_ref (slave);
		info->watch_id = g_signal_connect (slave, "state-changed",
		                                   G_CALLBACK (slave_state_changed), dev);
		priv->slaves = g_slist_prepend (priv->slaves, info);
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
 *   or %NULL if no device with @ifinidex is a slave of @device.
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
 * nm_device_is_master:
 * @dev: the device
 *
 * Returns: whether @dev can enslave other devices (eg, bridge or bond)
 */
gboolean
nm_device_is_master (NMDevice *dev)
{
	return NM_DEVICE_GET_PRIVATE (dev)->is_master;
}

/* release all slaves */
static void
nm_device_master_release_slaves (NMDevice *self, gboolean failed)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	while (priv->slaves) {
		SlaveInfo *info = priv->slaves->data;

		nm_device_release_one_slave (self, info->slave, failed);
	}
}


/**
 * nm_device_slave_notify_enslaved:
 * @dev: the slave device
 * @enslaved: %TRUE if the device is now enslaved, %FALSE if released
 * @master_failed: if released, indicates whether the release was unexpected,
 *   ie the master device failed.
 *
 * Notifies a slave that it has been enslaved or released.  If released, provides
 * information on whether the release was expected or not, and thus whether the
 * slave should fail it's activation or gracefully deactivate.
 */
void
nm_device_slave_notify_enslaved (NMDevice *dev,
                                 gboolean enslaved,
                                 gboolean master_failed)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	NMConnection *connection = nm_device_get_connection (dev);

	if (enslaved) {
		g_assert (priv->master);
		g_warn_if_fail (priv->enslaved == FALSE);
		g_warn_if_fail (priv->state == NM_DEVICE_STATE_IP_CONFIG);

		nm_log_info (LOGD_DEVICE,
				     "Activation (%s) connection '%s' enslaved, continuing activation",
				     nm_device_get_iface (dev),
				     nm_connection_get_id (connection));

		/* Now that we're enslaved, proceed with activation.  Remember, slaves
		 * don't have any IP configuration, so they skip directly to SECONDARIES.
		 */
		priv->enslaved = TRUE;
		priv->ip4_state = IP_DONE;
		priv->ip6_state = IP_DONE;
		nm_device_queue_state (dev, NM_DEVICE_STATE_SECONDARIES, NM_DEVICE_STATE_REASON_NONE);
	} else {
		NMDeviceState new_state = NM_DEVICE_STATE_DISCONNECTED;
		NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

		if (   priv->state > NM_DEVICE_STATE_DISCONNECTED
		    && priv->state <= NM_DEVICE_STATE_ACTIVATED) {
			if (master_failed) {
				new_state = NM_DEVICE_STATE_FAILED;
				reason = NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED;

				nm_log_warn (LOGD_DEVICE,
				             "Activation (%s) connection '%s' master failed",
				             nm_device_get_iface (dev),
				             nm_connection_get_id (connection));
			} else {
				nm_log_dbg (LOGD_DEVICE,
				            "Activation (%s) connection '%s' master deactivated",
				            nm_device_get_iface (dev),
				            nm_connection_get_id (connection));
			}

			nm_device_queue_state (dev, new_state, reason);
		}
	}
}

/**
 * nm_device_get_enslaved:
 * @device: the #NMDevice
 *
 * Returns: %TRUE if the device is enslaved to a master device (eg bridge or
 * bond), %FALSE if not
 */
gboolean
nm_device_get_enslaved (NMDevice *device)
{
	return NM_DEVICE_GET_PRIVATE (device)->enslaved;
}

/*
 * nm_device_get_act_request
 *
 * Return the devices activation request, if any.
 *
 */
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

static gboolean
is_available (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	if (!priv->carrier) {
		if (priv->ignore_carrier && has_static_connection (device))
			return TRUE;
		return FALSE;
	}

	return TRUE;
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

/**
 * nm_device_can_activate:
 * @self: the #NMDevice
 * @connection: (allow-none) an #NMConnection, or %NULL
 *
 * Checks if @self can currently activate @connection. In particular,
 * this requires that @self is available (per
 * nm_device_is_available()); that it is either managed or able to
 * become managed; and that it is able to activate @connection in its
 * current state (eg, if @connection requires carrier, then @self has
 * carrier).
 *
 * If @connection is %NULL, this just checks that @self could
 * theoretically activate *some* connection.
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
nm_device_can_activate (NMDevice *self, NMConnection *connection)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->manager_managed)
		return FALSE;

	if (   connection
	    && !nm_device_check_connection_compatible (self, connection, NULL))
		return FALSE;

	if (priv->default_unmanaged) {
		if (!nm_device_is_available (self))
			return FALSE;
	} else if (priv->state < NM_DEVICE_STATE_DISCONNECTED) {
		if (priv->state != NM_DEVICE_STATE_UNAVAILABLE || priv->carrier || !priv->ignore_carrier)
			return FALSE;

		/* @self is UNAVAILABLE because it doesn't have carrier, but
		 * ignore-carrier is set, so we might be able to ignore that.
		 */
		if (connection && connection_is_static (connection))
			return TRUE;
		else if (!connection && has_static_connection (self))
			return TRUE;
		else
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_device_ignore_carrier (NMDevice *dev)
{
	return NM_DEVICE_GET_PRIVATE (dev)->ignore_carrier;
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

RfKillType
nm_device_get_rfkill_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_PRIVATE (self)->rfkill_type;
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
	g_value_take_object (&instance, self);

	g_value_init (&retval, G_TYPE_BOOLEAN);
	if (priv->autoconnect)
		g_value_set_boolean (&retval, TRUE);
	else
		g_value_set_boolean (&retval, FALSE);

	/* Use g_signal_emitv() rather than g_signal_emit() to avoid the return
	 * value being changed if no handlers are connected */
	g_signal_emitv (&instance, signals[AUTOCONNECT_ALLOWED], 0, &retval);
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

	return nm_device_can_activate (device, connection);
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
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	NMSettingConnection *s_con;
	const char *config_iface, *device_iface;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	config_iface = nm_setting_connection_get_interface_name (s_con);
	device_iface = nm_device_get_iface (device);
	if (config_iface && strcmp (config_iface, device_iface) != 0) {
		g_set_error (error,
		             NM_DEVICE_ERROR, NM_DEVICE_ERROR_CONNECTION_INVALID,
		             "The connection is not valid for this interface.");
		return FALSE;
	}

	return TRUE;
}

/**
 * nm_device_check_connection_compatible:
 * @device: an #NMDevice
 * @connection: an #NMConnection
 * @error: return location for an error, or %NULL
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
nm_device_check_connection_compatible (NMDevice *device,
                                       NMConnection *connection,
                                       GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	return NM_DEVICE_GET_CLASS (device)->check_connection_compatible (device, connection, error);
}

gboolean
nm_device_can_assume_connections (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return !!NM_DEVICE_GET_CLASS (device)->match_l2_config;
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
		if (s_ip6 && !nm_setting_ip6_config_get_may_fail (s_ip6))
			return TRUE;
	} else {
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (s_ip4 && !nm_setting_ip4_config_get_may_fail (s_ip4))
			return TRUE;
	}

	return FALSE;
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
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	priv->ip4_state = priv->ip6_state = IP_NONE;

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 1 of 5 (Device Prepare) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE, NM_DEVICE_STATE_REASON_NONE);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage1_prepare (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
		goto out;
	} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

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
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (dev);
	GSList *iter;

	/* If we have slaves that aren't yet enslaved, do that now */
	for (iter = priv->slaves; iter; iter = g_slist_next (iter)) {
		SlaveInfo *info = iter->data;

		if (nm_device_get_state (info->slave) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_enslave_slave (dev, info->slave, nm_device_get_connection (info->slave));
	}

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
	const char *     iface;
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	gboolean no_firmware = FALSE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 2 of 5 (Device Configure) starting...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);

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
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

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
aipd_get_ip4_config (NMDevice *self, struct in_addr lla)
{
	NMIP4Config *config = NULL;
	NMPlatformIP4Address address;
	NMPlatformIP4Route route;

	config = nm_ip4_config_new ();
	g_assert (config);

	memset (&address, 0, sizeof (address));
	address.address = lla.s_addr;
	address.plen = 16;
	nm_ip4_config_add_address (config, &address);

	/* Add a multicast route for link-local connections: destination= 224.0.0.0, netmask=240.0.0.0 */
	memset (&route, 0, sizeof (route));
	route.network = htonl (0xE0000000L);
	route.plen = 4;
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
	NMSettingIP4Config *s_ip4 = NULL;
	const char *iface, *method = NULL;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	g_return_if_fail (event != NULL);

	if (priv->act_request == NULL)
		return;

	connection = nm_act_request_get_connection (priv->act_request);
	g_assert (connection);

	/* Ignore if the connection isn't an AutoIP connection */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL) != 0)
		return;

	iface = nm_device_get_iface (self);

	if (strcmp (event, "BIND") == 0) {
		struct in_addr lla;
		NMIP4Config *config;

		if (inet_pton (AF_INET, address, &lla) <= 0) {
			nm_log_err (LOGD_AUTOIP4, "(%s): invalid address %s received from avahi-autoipd.",
			            iface, address);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_AUTOIP_ERROR);
			return;
		}

		if ((lla.s_addr & IPV4LL_NETMASK) != IPV4LL_NETWORK) {
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

	if (nm_logging_level_enabled (LOGL_DEBUG))
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
	if (connection)
		nm_ip4_config_merge_setting (composite, nm_connection_get_setting_ip4_config (connection));

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
	NMDeviceState dev_state;
	NMIP4Config *config;

	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == FALSE);

	nm_log_dbg (LOGD_DHCP4, "(%s): new DHCPv4 client state %d",
	            nm_device_get_iface (device), state);

	dev_state = nm_device_get_state (device);

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

		if (priv->ip4_state == IP_CONF)
			nm_device_activate_schedule_ip4_config_result (device, config);
		else if (priv->ip4_state == IP_DONE)
			dhcp4_lease_change (device, config);
		g_object_unref (config);

		/* Update the DHCP4 config object with new DHCP options */
		nm_dhcp4_config_reset (priv->dhcp4_config);
		nm_dhcp_client_foreach_option (priv->dhcp4_client,
			                           dhcp4_add_option_cb,
			                           priv->dhcp4_config);
		g_object_notify (G_OBJECT (device), NM_DEVICE_DHCP4_CONFIG);
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
	guint8 *anycast = NULL;
	GByteArray *tmp = NULL;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);

	if (priv->dhcp_anycast_address)
		anycast = priv->dhcp_anycast_address->data;

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
	priv->dhcp4_client = nm_dhcp_manager_start_ip4 (priv->dhcp_manager,
	                                                nm_device_get_ip_iface (self),
	                                                tmp,
	                                                nm_connection_get_uuid (connection),
	                                                s_ip4,
	                                                priv->dhcp_timeout,
	                                                anycast);

	if (tmp)
		g_byte_array_free (tmp, TRUE);

	if (!priv->dhcp4_client) {
		*reason = NM_DEVICE_STATE_REASON_DHCP_START_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	priv->dhcp4_state_sigid = g_signal_connect (priv->dhcp4_client,
	                                            "state-changed",
	                                            G_CALLBACK (dhcp4_state_changed),
	                                            self);
	priv->dhcp4_timeout_sigid = g_signal_connect (priv->dhcp4_client,
	                                              "timeout",
	                                              G_CALLBACK (dhcp4_timeout),
	                                              self);

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

static guint32
reserve_shared_ip (void)
{
	guint32 start = (guint32) ntohl (0x0a2a0001); /* 10.42.0.1 */
	guint32 count = 0;

	while (g_hash_table_lookup (shared_ips, GUINT_TO_POINTER (start + count))) {
		count += ntohl (0x100);
		if (count > ntohl (0xFE00)) {
			nm_log_err (LOGD_SHARING, "ran out of shared IP addresses!");
			return 0;
		}
	}

	g_hash_table_insert (shared_ips, GUINT_TO_POINTER (start + count), GUINT_TO_POINTER (TRUE));
	return start + count;
}

static NMIP4Config *
shared4_new_config (NMDevice *self, NMDeviceStateReason *reason)
{
	NMIP4Config *config = NULL;
	NMPlatformIP4Address address;
	guint32 tmp_addr;

	g_return_val_if_fail (self != NULL, NULL);

	if (G_UNLIKELY (shared_ips == NULL))
		shared_ips = g_hash_table_new (g_direct_hash, g_direct_equal);

	tmp_addr = reserve_shared_ip ();
	if (!tmp_addr) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NULL;
	}

	config = nm_ip4_config_new ();
	memset (&address, 0, sizeof (address));
	address.address = tmp_addr;
	address.plen = 24;
	nm_ip4_config_add_address (config, &address);

	/* Remove the address lock when the object gets disposed */
	g_object_set_data_full (G_OBJECT (config), "shared-ip",
	                        GUINT_TO_POINTER (tmp_addr), release_shared_ip);

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
	NMSettingIP4Config *s_ip4;
	const char *method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	return g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0;
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *self,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
	GSList *slaves;
	gboolean ready_slaves;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* If we did not receive IP4 configuration information, default to DHCP.
	 * Slaves, on the other hand, never have any IP configuration themselves,
	 * since the master handles all of that.
	 */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (priv->master) /* eg, device is a slave */
		method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
	else if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);
	else
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	if (   g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) != 0
	    && nm_device_is_master (self)
	    && nm_device_is_unavailable_because_of_carrier (self)) {
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
		*out_config = shared4_new_config (self, reason);
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
dhcp6_add_option_cb (gpointer key, gpointer value, gpointer user_data)
{
	nm_dhcp6_config_add_option (NM_DHCP6_CONFIG (user_data),
	                            (const char *) key,
	                            (const char *) value);
}

static gboolean
ip6_config_merge_and_apply (NMDevice *self,
                            NMDeviceStateReason *out_reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	gboolean success;
	NMIP6Config *composite;

	connection = nm_device_get_connection (self);
	g_assert (connection);

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

	/* Merge user overrides into the composite config */
	nm_ip6_config_merge_setting (composite, nm_connection_get_setting_ip6_config (connection));

	success = nm_device_set_ip6_config (self, composite, TRUE, out_reason);
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
	if (ip6_config_merge_and_apply (device, &reason) == FALSE) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to update IPv6 config in response to DHCP event.",
		             nm_device_get_ip_iface (device));
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
	} else {
		/* Notify dispatcher scripts of new DHCPv6 config */
		nm_dispatcher_call (DISPATCHER_ACTION_DHCP6_CHANGE, connection, device, NULL, NULL);
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
	NMDeviceState dev_state;

	g_return_if_fail (nm_dhcp_client_get_ipv6 (client) == TRUE);

	nm_log_dbg (LOGD_DHCP6, "(%s): new DHCPv6 client state %d",
	            nm_device_get_iface (device), state);

	dev_state = nm_device_get_state (device);

	switch (state) {
	case DHC_BOUND6:
	case DHC_RENEW6:     /* lease renewed */
	case DHC_REBOOT:     /* have valid lease, but now obtained a different one */
	case DHC_REBIND6:    /* new, different lease */
		if (priv->dhcp6_ip6_config)
			g_object_unref (priv->dhcp6_ip6_config);
		priv->dhcp6_ip6_config = nm_dhcp_client_get_ip6_config (priv->dhcp6_client, FALSE);
		if (priv->ip6_state == IP_CONF) {
			if (priv->dhcp6_ip6_config == NULL) {
				/* FIXME: Initial DHCP failed; should we fail IPv6 entirely then? */
				nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_DHCP_FAILED);
				break;
			}
			nm_device_activate_schedule_ip6_config_result (device);
		} else if (priv->ip6_state == IP_DONE)
			dhcp6_lease_change (device);

		if (priv->dhcp6_ip6_config) {
			/* Update the DHCP6 config object with new DHCP options */
			nm_dhcp6_config_reset (priv->dhcp6_config);
			nm_dhcp_client_foreach_option (priv->dhcp6_client,
			                               dhcp6_add_option_cb,
			                               priv->dhcp6_config);
			g_object_notify (G_OBJECT (device), NM_DEVICE_DHCP6_CONFIG);
		}
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
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	guint8 *anycast = NULL;
	GByteArray *tmp = NULL;

	if (!connection) {
		connection = nm_device_get_connection (self);
		g_assert (connection);
	}

	/* Begin a DHCP transaction on the interface */

	if (priv->dhcp_anycast_address)
		anycast = priv->dhcp_anycast_address->data;

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

	priv->dhcp6_client = nm_dhcp_manager_start_ip6 (priv->dhcp_manager,
	                                                nm_device_get_ip_iface (self),
	                                                tmp,
	                                                nm_connection_get_uuid (connection),
	                                                nm_connection_get_setting_ip6_config (connection),
	                                                priv->dhcp_timeout,
	                                                anycast,
	                                                (dhcp_opt == NM_RDISC_DHCP_LEVEL_OTHERCONF) ? TRUE : FALSE);
	if (tmp)
		g_byte_array_free (tmp, TRUE);

	if (priv->dhcp6_client) {
		priv->dhcp6_state_sigid = g_signal_connect (priv->dhcp6_client,
		                                            "state-changed",
		                                            G_CALLBACK (dhcp6_state_changed),
		                                            self);
		priv->dhcp6_timeout_sigid = g_signal_connect (priv->dhcp6_client,
		                                              "timeout",
		                                              G_CALLBACK (dhcp6_timeout),
		                                              self);

		/* DHCP devices will be notified by the DHCP manager when stuff happens */
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		*reason = NM_DEVICE_STATE_REASON_DHCP_START_FAILED;
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

/******************************************/

static void dhcp6_cleanup (NMDevice *self, gboolean stop, gboolean release);

static void
rdisc_config_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMConnection *connection;
	int i;
	NMDeviceStateReason reason;

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

		for (i = 0; i < rdisc->addresses->len; i++) {
			NMRDiscAddress *discovered_address = &g_array_index (rdisc->addresses, NMRDiscAddress, i);
			NMPlatformIP6Address address;

			memset (&address, 0, sizeof (address));
			address.address = discovered_address->address;
			address.plen = 128;
			address.timestamp = discovered_address->timestamp;
			address.lifetime = discovered_address->lifetime;
			address.preferred = discovered_address->preferred;

			nm_ip6_config_add_address (priv->ac_ip6_config, &address);
		}
	}

	if (changed & NM_RDISC_CONFIG_ROUTES) {
		/* Rebuild route list from router discovery cache. */
		nm_ip6_config_reset_routes (priv->ac_ip6_config);

		for (i = 0; i < rdisc->routes->len; i++) {
			NMRDiscRoute *discovered_route = &g_array_index (rdisc->routes, NMRDiscRoute, i);
			NMPlatformIP6Route route;

			memset (&route, 0, sizeof (route));
			route.network = discovered_route->network;
			route.plen = discovered_route->plen;
			route.gateway = discovered_route->gateway;

			nm_ip6_config_add_route (priv->ac_ip6_config, &route);
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

	nm_device_activate_schedule_ip6_config_result (device);
}

static gboolean
addrconf6_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;

	connection = nm_device_get_connection (self);
	g_assert (connection);

	g_warn_if_fail (priv->ac_ip6_config == NULL);
	if (priv->ac_ip6_config) {
		g_object_unref (priv->ac_ip6_config);
		priv->ac_ip6_config = NULL;
	}

	priv->rdisc = nm_lndp_rdisc_new (nm_device_get_ip_ifindex (self), nm_device_get_ip_iface (self));
	nm_platform_sysctl_set (priv->ip6_accept_ra_path, "0");

	if (!priv->rdisc) {
		nm_log_err (LOGD_IP6, "Failed to start router discovery.");
		return FALSE;
	}

	priv->rdisc_config_changed_sigid = g_signal_connect (
			priv->rdisc, NM_RDISC_CONFIG_CHANGED, G_CALLBACK (rdisc_config_changed), self);

	/* FIXME: what if interface has no lladdr, like PPP? */
	if (priv->hw_addr_len)
		nm_rdisc_set_lladdr (priv->rdisc, (const char *) priv->hw_addr, priv->hw_addr_len);

	nm_rdisc_start (priv->rdisc);

	return TRUE;
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

	g_clear_object (&priv->ac_ip6_config);
	g_clear_object (&priv->rdisc);
}

/******************************************/

/* Get net.ipv6.conf.default.use_tempaddr value from /etc/sysctl.conf or
 * /lib/sysctl.d/sysctl.conf
 */
static int
ip6_use_tempaddr (void)
{
	char *contents = NULL;
	gsize len = 0;
	const char *group_name = "[forged_group]\n";
	char *sysctl_data = NULL;
	GKeyFile *keyfile;
	GError *error = NULL;
	int tmp, ret = -1;

	/* Read file contents to a string. */
	if (!g_file_get_contents ("/etc/sysctl.conf", &contents, &len, NULL))
		if (!g_file_get_contents ("/lib/sysctl.d/sysctl.conf", &contents, &len, NULL))
			return -1;

	/* Prepend a group so that we can use GKeyFile parser. */
	sysctl_data = g_strdup_printf ("%s%s", group_name, contents);

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_data (keyfile, sysctl_data, len + strlen (group_name), G_KEY_FILE_NONE, NULL))
		goto done;

	tmp = g_key_file_get_integer (keyfile, "forged_group", "net.ipv6.conf.default.use_tempaddr", &error);
	if (error == NULL)
		ret = tmp;

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
	NMSettingIP6Config *s_ip6;
	const char *method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (s_ip6)
		method = nm_setting_ip6_config_get_method (s_ip6);

	/* SLAAC, DHCP, and Link-Local depend on connectivity (and thus slaves)
	 * to complete addressing.  SLAAC and DHCP obviously need a peer to
	 * provide a prefix, while Link-Local must perform DAD on the local link.
	 */
	return    g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	       || g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0
	       || g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0;
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
	NMSettingIP6Config *s_ip6;
	const char *method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
	int conf_use_tempaddr;
	NMSettingIP6ConfigPrivacy ip6_privacy = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
	const char *ip6_privacy_str = "0\n";
	GSList *slaves;
	gboolean ready_slaves;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ip_iface = nm_device_get_ip_iface (self);

	connection = nm_device_get_connection (self);
	g_assert (connection);

	/* If we did not receive IP6 configuration information, default to AUTO.
	 * Slaves, on the other hand, never have any IP configuration themselves,
	 * since the master handles all of that.
	 */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (priv->master) /* eg, device is a slave */
		method = NM_SETTING_IP6_CONFIG_METHOD_IGNORE;
	else if (s_ip6)
		method = nm_setting_ip6_config_get_method (s_ip6);
	else
		method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;

	if (   g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) != 0
	    && nm_device_is_master (self)
	    && nm_device_is_unavailable_because_of_carrier (self)) {
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

	update_accept_ra_save (self);
	update_ip6_privacy_save (self);

	priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_NONE;

	if (   strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	    || strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0) {
		if (!addrconf6_start (self)) {
			*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
			ret = NM_ACT_STAGE_RETURN_FAILURE;
		} else
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0) {
		/* Router advertisements shouldn't be used in pure DHCP mode */
		if (priv->ip6_accept_ra_path)
			nm_utils_do_sysctl (priv->ip6_accept_ra_path, "0");

		priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_MANAGED;
		ret = dhcp6_start (self, connection, priv->dhcp6_mode, reason);
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0) {
		/* reset the saved RA value when ipv6 is ignored */
		if (priv->ip6_accept_ra_path) {
			nm_utils_do_sysctl (priv->ip6_accept_ra_path,
			                    priv->ip6_accept_ra_save ? "1" : "0");
		}
		ret = NM_ACT_STAGE_RETURN_STOP;
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0) {
		/* New blank config */
		*out_config = nm_ip6_config_new ();
		g_assert (*out_config);

		/* Router advertisements shouldn't be used in manual mode */
		if (priv->ip6_accept_ra_path)
			nm_utils_do_sysctl (priv->ip6_accept_ra_path, "0");
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else {
		nm_log_warn (LOGD_IP6, "(%s): unhandled IPv6 config method '%s'; will fail",
		             nm_device_get_ip_iface (self), method);
	}

	/* Other methods (shared) aren't implemented yet */

	/* Enable/disable IPv6 Privacy Extensions.
	 * If a global value is configured by sysadmin (e.g. /etc/sysctl.conf),
	 * use that value instead of per-connection value.
	 */
	conf_use_tempaddr = ip6_use_tempaddr ();
	if (conf_use_tempaddr >= 0)
		ip6_privacy = conf_use_tempaddr;
	else if (s_ip6)
		ip6_privacy = nm_setting_ip6_config_get_ip6_privacy (s_ip6);
	ip6_privacy = CLAMP (ip6_privacy, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);

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
	if (priv->ip6_privacy_tempaddr_path)
		nm_utils_do_sysctl (priv->ip6_privacy_tempaddr_path, ip6_privacy_str);

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
	int ifindex;
	NMDevice *master;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 3 of 5 (IP Configure Start) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	/* Make sure the interface is up before trying to do anything with it */
	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex && !nm_platform_link_is_up (ifindex))
		nm_platform_link_set_up (ifindex);

	priv->ip4_state = priv->ip6_state = IP_WAIT;

	/* If the device is a slave, then we don't do any IP configuration but we
	 * use the IP config stage to indicate to the master we're ready for
	 * enslavement.  Either the master has already enslaved us, in which case
	 * our state transition to SECONDARIES is already queued courtesy of
	 * nm_device_slave_notify_enslaved(), or the master is still activating,
	 * in which case we postpone activation here until the master enslaves us,
	 * which calls nm_device_slave_notify_enslaved().
	 */
	master = nm_active_connection_get_master (NM_ACTIVE_CONNECTION (priv->act_request));
	if (master) {
		if (priv->enslaved == FALSE) {
			nm_log_info (LOGD_DEVICE, "Activation (%s) connection '%s' waiting on master '%s'",
						 nm_device_get_iface (self),
						 nm_connection_get_id (nm_device_get_connection (self)),
						 nm_device_get_iface (master));
		}
		goto out;
	}

	/* IPv4 */
	if (!nm_device_activate_stage3_ip4_start (self))
		goto out;

	/* IPv6 */
	if (!nm_device_activate_stage3_ip6_start (self))
		goto out;

out:
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 3 of 5 (IP Configure Start) complete.", iface);
	return FALSE;
}


static void
fw_add_to_zone_cb (GError *error, gpointer user_data)
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
	NMDeviceState state;
	const char *zone;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	state = nm_device_get_state (self);
	if (nm_active_connection_get_assumed (NM_ACTIVE_CONNECTION (priv->act_request)) == FALSE)
		g_warn_if_fail (state >= NM_DEVICE_STATE_PREPARE && state <= NM_DEVICE_STATE_NEED_AUTH);

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
	                                                        TRUE,
	                                                        fw_add_to_zone_cb,
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

	if (!nm_utils_do_sysctl ("/proc/sys/net/ipv4/ip_forward", "1")) {
		nm_log_err (LOGD_SHARING, "Error starting IP forwarding: (%d) %s",
					errno, strerror (errno));
		return FALSE;
	}

	if (!nm_utils_do_sysctl ("/proc/sys/net/ipv4/ip_dynaddr", "1")) {
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

static gboolean
nm_device_activate_ip4_config_commit (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	const char *iface, *method = NULL;
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	int ifindex;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 5 of 5 (IPv4 Commit) started...",
	             iface);

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Make sure the interface is up again just because */
	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex && !nm_platform_link_is_up (ifindex))
		nm_platform_link_set_up (ifindex);

	/* NULL to use the existing priv->dev_ip4_config */
	if (!ip4_config_merge_and_apply (self, NULL, TRUE, &reason)) {
		nm_log_info (LOGD_DEVICE | LOGD_IP4,
			         "Activation (%s) Stage 5 of 5 (IPv4 Commit) failed",
					 iface);
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}

	/* Start IPv4 sharing if we need it */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0) {
		if (!start_sharing (self, priv->ip4_config)) {
			nm_log_warn (LOGD_SHARING, "Activation (%s) Stage 5 of 5 (IPv4 Commit) start sharing failed.", iface);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
			goto out;
		}
	}

	/* Enter the IP_CHECK state if this is the first method to complete */
	priv->ip4_state = IP_DONE;
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
	NMActRequest *req;
	const char *iface;
	NMConnection *connection;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	int ifindex;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET6);

	iface = nm_device_get_iface (self);
	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 5 of 5 (IPv6 Commit) started...",
	             iface);

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Make sure the interface is up again just because */
	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex && !nm_platform_link_is_up (ifindex))
		nm_platform_link_set_up (ifindex);

	/* Allow setting MTU etc */
	if (NM_DEVICE_GET_CLASS (self)->ip6_config_pre_commit)
		NM_DEVICE_GET_CLASS (self)->ip6_config_pre_commit (self);

	if (ip6_config_merge_and_apply (self, &reason)) {
		/* Enter the IP_CHECK state if this is the first method to complete */
		priv->ip6_state = IP_DONE;
		if (nm_device_get_state (self) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_state_changed (self, NM_DEVICE_STATE_IP_CHECK, NM_DEVICE_STATE_REASON_NONE);
	} else {
		nm_log_info (LOGD_DEVICE | LOGD_IP6,
			         "Activation (%s) Stage 5 of 5 (IPv6 Commit) failed",
					 iface);
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
	}

	nm_log_info (LOGD_DEVICE, "Activation (%s) Stage 5 of 5 (IPv6 Commit) complete.",
	             iface);

	return FALSE;
}

void
nm_device_activate_schedule_ip6_config_result (NMDevice *self)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	activation_source_schedule (self, nm_device_activate_ip6_config_commit, AF_INET6);

	nm_log_info (LOGD_DEVICE | LOGD_IP6,
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
	NMDevicePrivate * priv;

	g_return_if_fail (self != NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->act_request)
		return;

	if (priv->secrets_updated_id) {
		g_signal_handler_disconnect (priv->act_request,
		                             priv->secrets_updated_id);
		priv->secrets_updated_id = 0;
	}

	if (priv->secrets_failed_id) {
		g_signal_handler_disconnect (priv->act_request,
		                             priv->secrets_failed_id);
		priv->secrets_failed_id = 0;
	}

	nm_active_connection_set_default (NM_ACTIVE_CONNECTION (priv->act_request), FALSE);

	g_object_unref (priv->act_request);
	priv->act_request = NULL;
}

static void
dhcp4_cleanup (NMDevice *self, gboolean stop, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dhcp4_config) {
		g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP4_CONFIG);
		g_object_unref (priv->dhcp4_config);
		priv->dhcp4_config = NULL;
	}

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

		if (stop)
			nm_dhcp_client_stop (priv->dhcp4_client, release);

		g_object_unref (priv->dhcp4_client);
		priv->dhcp4_client = NULL;
	}
}

static void
dhcp6_cleanup (NMDevice *self, gboolean stop, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->dhcp6_mode = NM_RDISC_DHCP_LEVEL_NONE;

	if (priv->dhcp6_ip6_config) {
		g_object_unref (priv->dhcp6_ip6_config);
		priv->dhcp6_ip6_config = NULL;
	}

	if (priv->dhcp6_config) {
		g_object_notify (G_OBJECT (self), NM_DEVICE_DHCP6_CONFIG);
		g_object_unref (priv->dhcp6_config);
		priv->dhcp6_config = NULL;
	}

	if (priv->dhcp6_client) {
		if (priv->dhcp6_state_sigid) {
			g_signal_handler_disconnect (priv->dhcp6_client, priv->dhcp6_state_sigid);
			priv->dhcp6_state_sigid = 0;
		}

		if (priv->dhcp6_timeout_sigid) {
			g_signal_handler_disconnect (priv->dhcp6_client, priv->dhcp6_timeout_sigid);
			priv->dhcp6_timeout_sigid = 0;
		}

		if (stop)
			nm_dhcp_client_stop (priv->dhcp6_client, release);

		g_object_unref (priv->dhcp6_client);
		priv->dhcp6_client = NULL;
	}
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

/*
 * nm_device_deactivate
 *
 * Remove a device's routing table entries and IP address.
 *
 */
static void
nm_device_deactivate (NMDevice *self, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	NMDeviceStateReason ignored = NM_DEVICE_STATE_REASON_NONE;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con = NULL;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE (self));

	nm_log_info (LOGD_DEVICE, "(%s): deactivating device (reason '%s') [%d]",
	             nm_device_get_iface (self), reason_to_string (reason), reason);

	/* Save whether or not we tried IPv6 for later */
	priv = NM_DEVICE_GET_PRIVATE (self);

	/* Clean up when device was deactivated during call to firewall */
	if (priv->fw_call) {
		nm_firewall_manager_cancel_call (priv->fw_manager, priv->fw_call);
		priv->fw_call = NULL;
	}

	if (priv->act_request)
		connection = nm_act_request_get_connection (priv->act_request);
	if (connection) {
		s_con = nm_connection_get_setting_connection (connection);
		nm_firewall_manager_remove_from_zone (priv->fw_manager,
		                                      nm_device_get_ip_iface (self),
		                                      nm_setting_connection_get_zone (s_con));
	}

	ip_check_gw_ping_cleanup (self);

	/* Break the activation chain */
	activation_source_clear (self, TRUE, AF_INET);
	activation_source_clear (self, TRUE, AF_INET6);

	/* Clear any queued transitions */
	nm_device_queued_state_clear (self);
	nm_device_queued_ip_config_change_clear (self);

	priv->ip4_state = priv->ip6_state = IP_NONE;

	dhcp4_cleanup (self, TRUE, FALSE);
	dhcp6_cleanup (self, TRUE, FALSE);
	addrconf6_cleanup (self);
	dnsmasq_cleanup (self);
	aipd_cleanup (self);

	/* Turn off router advertisements until they are needed */
	if (priv->ip6_accept_ra_path)
		nm_utils_do_sysctl (priv->ip6_accept_ra_path, "0");

	/* Turn off IPv6 privacy extensions */
	if (priv->ip6_privacy_tempaddr_path)
		nm_utils_do_sysctl (priv->ip6_privacy_tempaddr_path, "0");

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate)
		NM_DEVICE_GET_CLASS (self)->deactivate (self);

	/* master: release slaves */
	nm_device_master_release_slaves (self, FALSE);

	/* slave: mark no longer enslaved */
	g_clear_object (&priv->master);
	priv->enslaved = FALSE;

	/* Tear down an existing activation request */
	clear_act_request (self);

	/* Take out any entries in the routing table and any IP address the device had. */
	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex > 0) {
		nm_platform_route_flush (ifindex);
		nm_platform_address_flush (ifindex);
	}

	/* Clean up nameservers and addresses */
	nm_device_set_ip4_config (self, NULL, TRUE, &ignored);
	nm_device_set_ip6_config (self, NULL, TRUE, &ignored);
	g_clear_object (&priv->ext_ip4_config);
	g_clear_object (&priv->vpn4_config);
	g_clear_object (&priv->vpn6_config);

	/* Clear legacy IPv4 address property */
	priv->ip4_address = 0;
	g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_ADDRESS);

	/* Only clear ip_iface after flushing all routes and addreses, since
	 * those are identified by ip_iface, not by iface (which might be a tty
	 * or ATM device).
	 */
	nm_device_set_ip_iface (self, NULL);
}

static void
disconnect_cb (NMDevice *device,
               DBusGMethodInvocation *context,
               GError *error,
               gpointer user_data)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	GError *local = NULL;

	if (error)
		dbus_g_method_return_error (context, error);
	else {
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
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			dbus_g_method_return (context);
		}
	}
}

static void
impl_device_disconnect (NMDevice *device, DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (NM_DEVICE_GET_PRIVATE (device)->act_request == NULL) {
		error = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "This device is not active");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Ask the manager to authenticate this request for us */
	g_signal_emit (device, signals[AUTH_REQUEST], 0,
	               context,
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               disconnect_cb,
	               NULL);
}

void
nm_device_activate (NMDevice *self, NMActRequest *req)
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

	if (priv->state < NM_DEVICE_STATE_DISCONNECTED) {
		g_return_if_fail (nm_device_can_activate (self, connection));

		if (priv->state == NM_DEVICE_STATE_UNMANAGED) {
			nm_device_state_changed (self,
			                         NM_DEVICE_STATE_UNAVAILABLE,
			                         NM_DEVICE_STATE_REASON_NONE);
		}
		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_state_changed (self,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_NONE);
		}
	}

	g_warn_if_fail (priv->state == NM_DEVICE_STATE_DISCONNECTED);

	priv->act_request = g_object_ref (req);
	g_object_notify (G_OBJECT (self), NM_DEVICE_ACTIVE_CONNECTION);

	if (nm_active_connection_get_assumed (NM_ACTIVE_CONNECTION (req))) {
		/* If it's an assumed connection, let the device subclass short-circuit
		 * the normal connection process and just copy its IP configs from the
		 * interface.
		 */
		nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);
		nm_device_activate_schedule_stage3_ip_config_start (self);
	} else {
		NMDevice *master;

		/* HACK: update the state a bit early to avoid a race between the 
		 * scheduled stage1 handler and nm_policy_device_change_check() thinking
		 * that the activation request isn't deferred because the deferred bit
		 * gets cleared a bit too early, when the connection becomes valid.
		 */
		nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE, NM_DEVICE_STATE_REASON_NONE);

		/* Handle any dependencies this connection might have */
		master = nm_active_connection_get_master (NM_ACTIVE_CONNECTION (req));
		if (master) {
			/* Master should at least already be activating */
			g_assert (nm_device_get_state (master) > NM_DEVICE_STATE_DISCONNECTED);

			g_assert (priv->master == NULL);
			priv->master = g_object_ref (master);
			nm_device_master_add_slave (master, self);
		}

		nm_device_activate_schedule_stage1_device_prepare (self);
	}
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


static gboolean
can_interrupt_activation (NMDevice *device)
{
	/* Devices that support carrier detect can interrupt activation
	 * if the link becomes inactive.
	 */
	return nm_device_is_unavailable_because_of_carrier (device);
}

gboolean
nm_device_can_interrupt_activation (NMDevice *self)
{
	gboolean	interrupt = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);

	if (NM_DEVICE_GET_CLASS (self)->can_interrupt_activation)
		interrupt = NM_DEVICE_GET_CLASS (self)->can_interrupt_activation (self);
	return interrupt;
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
	gboolean success = TRUE;
	int ip_ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);
	ip_ifindex = nm_device_get_ip_ifindex (self);

	old_config = priv->ip4_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config)
		success = nm_ip4_config_commit (new_config, ip_ifindex, nm_device_get_priority (self));

	if (nm_ip4_config_equal (new_config, old_config))
		return success;

	priv->ip4_config = NULL;

	if (new_config) {
		priv->ip4_config = g_object_ref (new_config);

		if (success || !commit) {
			/* Export over D-Bus */
			if (!nm_ip4_config_get_dbus_path (new_config))
				nm_ip4_config_export (new_config);
			_update_ip4_address (self);
		}

		if (!success && reason)
			*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	} else {
		/* Device config is invalid if combined config is invalid */
		g_clear_object (&priv->dev_ip4_config);
	}

	g_object_notify (G_OBJECT (self), NM_DEVICE_IP4_CONFIG);
	g_signal_emit (self, signals[IP4_CONFIG_CHANGED], 0, priv->ip4_config, old_config);

	if (old_config)
		g_object_unref (old_config);

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
	gboolean success = TRUE;
	int ip_ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);
	ip_ifindex = nm_device_get_ip_ifindex (self);

	old_config = priv->ip6_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config)
		success = nm_ip6_config_commit (new_config, ip_ifindex, nm_device_get_priority (self));

	if (nm_ip6_config_equal (new_config, old_config))
		return success;

	priv->ip6_config = NULL;

	if (new_config) {
		priv->ip6_config = g_object_ref (new_config);

		if (success || !commit) {
			/* Export over D-Bus */
			if (!nm_ip6_config_get_dbus_path (new_config))
				nm_ip6_config_export (new_config);
		}

		if (!success && reason)
			*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	}

	g_object_notify (G_OBJECT (self), NM_DEVICE_IP6_CONFIG);
	g_signal_emit (self, signals[IP6_CONFIG_CHANGED], 0, priv->ip6_config, old_config);

	if (old_config)
		g_object_unref (old_config);

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
	if (!ip6_config_merge_and_apply (device, NULL)) {
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

	/* We've got connectivity, proceed to secondaries */
	ip_check_gw_ping_cleanup (self);
	nm_device_state_changed (self, NM_DEVICE_STATE_SECONDARIES, NM_DEVICE_STATE_REASON_NONE);
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
	nm_device_state_changed (self, NM_DEVICE_STATE_SECONDARIES, NM_DEVICE_STATE_REASON_NONE);
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

	if (nm_logging_level_enabled (LOGL_DEBUG)) {
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

	/* If no ping was started, just advance to SECONDARIES */
	if (!priv->gw_ping.pid)
		nm_device_queue_state (self, NM_DEVICE_STATE_SECONDARIES, NM_DEVICE_STATE_REASON_NONE);
}

/****************************************************************/

gboolean
nm_device_bring_up (NMDevice *self, gboolean block, gboolean *no_firmware)
{
	gboolean success;
	guint32 tries = 0;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (nm_device_is_up (self))
		goto out;

	nm_log_info (LOGD_HW, "(%s): bringing up device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->bring_up) {
		success = NM_DEVICE_GET_CLASS (self)->bring_up (self, no_firmware);
		if (!success)
			return FALSE;
	}

	/* Wait for the device to come up if requested */
	while (block && !nm_device_is_up (self) && (tries++ < 50))
		g_usleep (200);

	if (!nm_device_is_up (self)) {
		nm_log_warn (LOGD_HW, "(%s): device not up after timeout!", nm_device_get_iface (self));
		return FALSE;
	}

out:
	/* Can only get HW address of some devices when they are up */
	nm_device_update_hw_address (self);

	_update_ip4_address (self);
	return TRUE;
}

static gboolean
bring_up (NMDevice *device, gboolean *no_firmware)
{
	int ifindex = nm_device_get_ip_ifindex (device);
	gboolean result;

	if (!ifindex)
		return TRUE;

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
	guint32 tries = 0;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (!nm_device_is_up (self))
		return;

	nm_log_info (LOGD_HW, "(%s): taking down device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->take_down)
		NM_DEVICE_GET_CLASS (self)->take_down (self);

	/* Wait for the device to come up if requested */
	while (block && nm_device_is_up (self) && (tries++ < 50))
		g_usleep (200);
}

static void
take_down (NMDevice *device)
{
	int ifindex = nm_device_get_ip_ifindex (device);

	if (ifindex)
		nm_platform_link_set_down (ifindex);
}

static void
dispose (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean deconfigure = TRUE;
	NMPlatform *platform;

	if (priv->disposed || !priv->initialized)
		goto out;

	priv->disposed = TRUE;

	/* Don't down can-assume-connection capable devices that are activated with
	 * a connection that can be assumed.
	 */
	if (nm_device_can_assume_connections (self) && (priv->state == NM_DEVICE_STATE_ACTIVATED)) {
		NMConnection *connection;
	    NMSettingIP4Config *s_ip4 = NULL;
		const char *method = NULL;

		connection = nm_device_get_connection (self);
		if (connection) {
			/* Only static or DHCP IPv4 connections can be left up.
			 * All IPv6 connections can be left up, so we don't have
			 * to check that.
			 */
			s_ip4 = nm_connection_get_setting_ip4_config (connection);
			if (s_ip4)
				method = nm_setting_ip4_config_get_method (s_ip4);
			if (   !method
			    || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)
			    || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)
			    || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
				deconfigure = FALSE;
		}
	}

	ip_check_gw_ping_cleanup (self);

	/* Clear any queued transitions */
	nm_device_queued_state_clear (self);
	nm_device_queued_ip_config_change_clear (self);

	/* Clean up and stop DHCP */
	dhcp4_cleanup (self, deconfigure, FALSE);
	dhcp6_cleanup (self, deconfigure, FALSE);
	addrconf6_cleanup (self);
	dnsmasq_cleanup (self);

	g_warn_if_fail (priv->slaves == NULL);

	/* Take the device itself down and clear its IPv4 configuration */
	if (nm_device_get_managed (self) && deconfigure) {
		NMDeviceStateReason ignored = NM_DEVICE_STATE_REASON_NONE;

		if (nm_device_get_act_request (self))
			nm_device_deactivate (self, NM_DEVICE_STATE_REASON_REMOVED);
		nm_device_set_ip4_config (self, NULL, TRUE, &ignored);

		nm_device_take_down (self, FALSE);
	}
	g_clear_object (&priv->dev_ip4_config);
	g_clear_object (&priv->ext_ip4_config);
	g_clear_object (&priv->vpn4_config);
	g_clear_object (&priv->ip4_config);

	g_clear_object (&priv->ip6_config);
	g_clear_object (&priv->ac_ip6_config);
	g_clear_object (&priv->dhcp6_ip6_config);
	g_clear_object (&priv->vpn6_config);

	/* reset the saved RA value */
	if (priv->ip6_accept_ra_path) {
		nm_utils_do_sysctl (priv->ip6_accept_ra_path,
		                    priv->ip6_accept_ra_save ? "1" : "0");
	}
	g_free (priv->ip6_accept_ra_path);

	/* reset the saved use_tempaddr value */
	if (priv->ip6_privacy_tempaddr_path) {
		char tmp[16];

		snprintf (tmp, sizeof (tmp), "%d", priv->ip6_privacy_tempaddr_save);
		nm_utils_do_sysctl (priv->ip6_privacy_tempaddr_path, tmp);
	}
	g_free (priv->ip6_privacy_tempaddr_path);

	if (priv->carrier_defer_id) {
		g_source_remove (priv->carrier_defer_id);
		priv->carrier_defer_id = 0;
	}

	if (priv->cp_added_id) {
	    g_signal_handler_disconnect (priv->con_provider, priv->cp_added_id);
	    priv->cp_added_id = 0;
	}

	if (priv->cp_loaded_id) {
	    g_signal_handler_disconnect (priv->con_provider, priv->cp_loaded_id);
	    priv->cp_loaded_id = 0;
	}

	if (priv->cp_removed_id) {
	    g_signal_handler_disconnect (priv->con_provider, priv->cp_removed_id);
	    priv->cp_removed_id = 0;
	}

	if (priv->cp_updated_id) {
	    g_signal_handler_disconnect (priv->con_provider, priv->cp_updated_id);
	    priv->cp_updated_id = 0;
	}

	g_hash_table_unref (priv->available_connections);

	activation_source_clear (self, TRUE, AF_INET);
	activation_source_clear (self, TRUE, AF_INET6);

	clear_act_request (self);

	platform = nm_platform_get ();
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (device_ip_changed), self);
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (link_changed_cb), self);

out:
	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dhcp_manager)
		g_object_unref (priv->dhcp_manager);

	if (priv->fw_manager)
		g_object_unref (priv->fw_manager);

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

static gboolean
has_ip_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ip4_state != IP_DONE && priv->ip6_state != IP_DONE)
		return FALSE;

	if (priv->state == NM_DEVICE_STATE_UNMANAGED)
		return TRUE;

	return (priv->state >= NM_DEVICE_STATE_IP_CONFIG
	        && priv->state <= NM_DEVICE_STATE_DEACTIVATING);
}

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
		if (has_ip_config (self))
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
	case PROP_IP4_CONFIG:
		if (has_ip_config (self) && priv->ip4_config)
			g_value_set_boxed (value, nm_ip4_config_get_dbus_path (priv->ip4_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_DHCP4_CONFIG:
		if (has_ip_config (self) && priv->dhcp4_client)
			g_value_set_boxed (value, nm_dhcp4_config_get_dbus_path (priv->dhcp4_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_IP6_CONFIG:
		if (has_ip_config (self) && priv->ip6_config)
			g_value_set_boxed (value, nm_ip6_config_get_dbus_path (priv->ip6_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_DHCP6_CONFIG:
		if (has_ip_config (self) && priv->dhcp6_client)
			g_value_set_boxed (value, nm_dhcp6_config_get_dbus_path (priv->dhcp6_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case PROP_STATE_REASON:
		g_value_take_boxed (value, dbus_g_type_specialized_construct (DBUS_G_TYPE_UINT_STRUCT));
		dbus_g_type_struct_set (value,
		                        0, priv->state,
		                        1, priv->state_reason,
		                        G_MAXUINT);
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
	case PROP_IS_MASTER:
		g_value_set_boolean (value, priv->is_master);
		break;
	case PROP_HW_ADDRESS:
		if (priv->hw_addr_len)
			g_value_take_string (value, nm_utils_hwaddr_ntoa_len (priv->hw_addr, priv->hw_addr_len));
		else
			g_value_set_string (value, NULL);
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
	klass->can_interrupt_activation = can_interrupt_activation;
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
		                     DBUS_G_TYPE_UINT_STRUCT,
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
		(object_class, PROP_IS_MASTER,
		 g_param_spec_boolean (NM_DEVICE_IS_MASTER,
		                       "IsMaster",
		                       "IsMaster",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_HW_ADDRESS,
		                      "Hardware Address",
		                      "Hardware address",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

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
		              /* dbus-glib context, permission, allow_interaction, callback, user_data */
		              G_TYPE_NONE, 5, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_POINTER, G_TYPE_POINTER);

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

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_object_info);

	dbus_g_error_domain_register (NM_DEVICE_ERROR, NULL, NM_TYPE_DEVICE_ERROR);
}

static void
nm_device_config_device_interface_init (NMConfigDeviceInterface *iface)
{
	iface->spec_match_list = (gboolean (*) (NMConfigDevice *, const GSList *)) nm_device_spec_match_list;
	iface->get_hw_address = (const guint8 * (*) (NMConfigDevice *, guint *)) nm_device_get_hw_address;
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

static const char *
state_to_string (NMDeviceState state)
{
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		return "unmanaged";
	case NM_DEVICE_STATE_UNAVAILABLE:
		return "unavailable";
	case NM_DEVICE_STATE_DISCONNECTED:
		return "disconnected";
	case NM_DEVICE_STATE_PREPARE:
		return "prepare";
	case NM_DEVICE_STATE_CONFIG:
		return "config";
	case NM_DEVICE_STATE_NEED_AUTH:
		return "need-auth";
	case NM_DEVICE_STATE_IP_CONFIG:
		return "ip-config";
	case NM_DEVICE_STATE_IP_CHECK:
		return "ip-check";
	case NM_DEVICE_STATE_SECONDARIES:
		return "secondaries";
	case NM_DEVICE_STATE_ACTIVATED:
		return "activated";
	case NM_DEVICE_STATE_DEACTIVATING:
		return "deactivating";
	case NM_DEVICE_STATE_FAILED:
		return "failed";
	default:
		break;
	}
	return "unknown";
}

static const char *
reason_to_string (NMDeviceStateReason reason)
{
	switch (reason) {
	case NM_DEVICE_STATE_REASON_NONE:
		return "none";
	case NM_DEVICE_STATE_REASON_NOW_MANAGED:
		return "managed";
	case NM_DEVICE_STATE_REASON_NOW_UNMANAGED:
		return "unmanaged";
	case NM_DEVICE_STATE_REASON_CONFIG_FAILED:
		return "config-failed";
	case NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE:
		return "ip-config-unavailable";
	case NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED:
		return "ip-config-expired";
	case NM_DEVICE_STATE_REASON_NO_SECRETS:
		return "no-secrets";
	case NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT:
		return "supplicant-disconnect";
	case NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED:
		return "supplicant-config-failed";
	case NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED:
		return "supplicant-failed";
	case NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT:
		return "supplicant-timeout";
	case NM_DEVICE_STATE_REASON_PPP_START_FAILED:
		return "ppp-start-failed";
	case NM_DEVICE_STATE_REASON_PPP_DISCONNECT:
		return "ppp-disconnect";
	case NM_DEVICE_STATE_REASON_PPP_FAILED:
		return "ppp-failed";
	case NM_DEVICE_STATE_REASON_DHCP_START_FAILED:
		return "dhcp-start-failed";
	case NM_DEVICE_STATE_REASON_DHCP_ERROR:
		return "dhcp-error";
	case NM_DEVICE_STATE_REASON_DHCP_FAILED:
		return "dhcp-failed";
	case NM_DEVICE_STATE_REASON_SHARED_START_FAILED:
		return "sharing-start-failed";
	case NM_DEVICE_STATE_REASON_SHARED_FAILED:
		return "sharing-failed";
	case NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED:
		return "autoip-start-failed";
	case NM_DEVICE_STATE_REASON_AUTOIP_ERROR:
		return "autoip-error";
	case NM_DEVICE_STATE_REASON_AUTOIP_FAILED:
		return "autoip-failed";
	case NM_DEVICE_STATE_REASON_MODEM_BUSY:
		return "modem-busy";
	case NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE:
		return "modem-no-dialtone";
	case NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER:
		return "modem-no-carrier";
	case NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT:
		return "modem-dial-timeout";
	case NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED:
		return "modem-dial-failed";
	case NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED:
		return "modem-init-failed";
	case NM_DEVICE_STATE_REASON_GSM_APN_FAILED:
		return "gsm-apn-failed";
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING:
		return "gsm-registration-idle";
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED:
		return "gsm-registration-denied";
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT:
		return "gsm-registration-timeout";
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED:
		return "gsm-registration-failed";
	case NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED:
		return "gsm-pin-check-failed";
	case NM_DEVICE_STATE_REASON_FIRMWARE_MISSING:
		return "firmware-missing";
	case NM_DEVICE_STATE_REASON_REMOVED:
		return "removed";
	case NM_DEVICE_STATE_REASON_SLEEPING:
		return "sleeping";
	case NM_DEVICE_STATE_REASON_CONNECTION_REMOVED:
		return "connection-removed";
	case NM_DEVICE_STATE_REASON_USER_REQUESTED:
		return "user-requested";
	case NM_DEVICE_STATE_REASON_CARRIER:
		return "carrier-changed";
	case NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED:
		return "connection-assumed";
	case NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE:
		return "supplicant-available";
	case NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND:
		return "modem-not-found";
	case NM_DEVICE_STATE_REASON_BT_FAILED:
		return "bluetooth-failed";
	case NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED:
		return "gsm-sim-not-inserted";
	case NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED:
		return "gsm-sim-pin-required";
	case NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED:
		return "gsm-sim-puk-required";
	case NM_DEVICE_STATE_REASON_GSM_SIM_WRONG:
		return "gsm-sim-wrong";
	case NM_DEVICE_STATE_REASON_INFINIBAND_MODE:
		return "infiniband-mode";
	case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
		return "dependency-failed";
	case NM_DEVICE_STATE_REASON_BR2684_FAILED:
		return "br2684-bridge-failed";
	case NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE:
		return "modem-manager-unavailable";
	case NM_DEVICE_STATE_REASON_SSID_NOT_FOUND:
		return "SSID not found";
	case NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED:
		return "secondary-connection-failed";
	default:
		break;
	}
	return "unknown";
}

void
nm_device_state_changed (NMDevice *device,
                         NMDeviceState state,
                         NMDeviceStateReason reason)
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

	/* Cache the activation request for the dispatcher */
	req = priv->act_request ? g_object_ref (priv->act_request) : NULL;

	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		_clear_available_connections (device, TRUE);

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
				nm_device_deactivate (device, reason);
			nm_device_take_down (device, TRUE);
		}
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state == NM_DEVICE_STATE_UNMANAGED || priv->firmware_missing) {
			if (!nm_device_bring_up (device, TRUE, &no_firmware) && no_firmware)
				nm_log_warn (LOGD_HW, "(%s): firmware may be missing.", nm_device_get_iface (device));
			nm_device_set_firmware_missing (device, no_firmware ? TRUE : FALSE);
		}
		/* Ensure the device gets deactivated in response to stuff like
		 * carrier changes or rfkill.  But don't deactivate devices that are
		 * about to assume a connection since that defeats the purpose of
		 * assuming the device's existing connection.
		 */
		if (reason != NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED &&
		    old_state != NM_DEVICE_STATE_UNMANAGED)
			nm_device_deactivate (device, reason);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state != NM_DEVICE_STATE_UNAVAILABLE)
			nm_device_deactivate (device, reason);
		break;
	default:
		priv->autoconnect = TRUE;
		break;
	}

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
			} else if (old_state > NM_DEVICE_STATE_UNAVAILABLE && priv->default_unmanaged)
				nm_device_queue_state (device, NM_DEVICE_STATE_UNMANAGED, NM_DEVICE_STATE_REASON_NONE);
		}
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state > NM_DEVICE_STATE_DISCONNECTED && priv->default_unmanaged)
			nm_device_queue_state (device, NM_DEVICE_STATE_UNMANAGED, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		nm_log_info (LOGD_DEVICE, "Activation (%s) successful, device activated.",
		             nm_device_get_iface (device));
		nm_dispatcher_call (DISPATCHER_ACTION_UP, nm_act_request_get_connection (req), device, NULL, NULL);
		break;
	case NM_DEVICE_STATE_FAILED:
		connection = nm_act_request_get_connection (req);
		nm_log_warn (LOGD_DEVICE | LOGD_WIFI,
		             "Activation (%s) failed for connection '%s'",
		             nm_device_get_iface (device),
		             nm_connection_get_id (connection));

		/* Notify any slaves of the unexpected failure */
		nm_device_master_release_slaves (device, TRUE);

		/* If the connection doesn't yet have a timestamp, set it to zero so that
		 * we can distinguish between connections we've tried to activate and have
		 * failed (zero timestamp), connections that succeeded (non-zero timestamp),
		 * and those we haven't tried yet (no timestamp).
		 */
		if (!nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (connection), NULL)) {
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
		break;
	case NM_DEVICE_STATE_SECONDARIES:
		ip_check_gw_ping_cleanup (device);
		nm_log_dbg (LOGD_DEVICE, "(%s): device entered SECONDARIES state",
		            nm_device_get_iface (device));
		break;
	default:
		break;
	}

	if (old_state == NM_DEVICE_STATE_ACTIVATED)
		nm_dispatcher_call (DISPATCHER_ACTION_DOWN, nm_act_request_get_connection (req), device, NULL, NULL);

	/* Dispose of the cached activation request */
	if (req)
		g_object_unref (req);

	priv->in_state_changed = FALSE;
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

	/* We should only ever have one delayed state transition at a time */
	if (priv->queued_state.id) {
		if (priv->queued_state.state == state)
			return;
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
	}
	memset (&priv->queued_state, 0, sizeof (priv->queued_state));
}

NMDeviceState
nm_device_get_state (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (device)->state;
}

static void
update_ip_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason ignored = NM_DEVICE_STATE_REASON_NONE;
	NMIP6Config *ip6_config = NULL;
	int ifindex;

	ifindex = nm_device_get_ip_ifindex (self);
	if (!ifindex)
		return;

	g_clear_object (&priv->ext_ip4_config);
	priv->ext_ip4_config = nm_ip4_config_capture (ifindex);
	if (priv->dev_ip4_config)
		nm_ip4_config_subtract (priv->ext_ip4_config, priv->dev_ip4_config);
	if (priv->vpn4_config)
		nm_ip4_config_subtract (priv->ext_ip4_config, priv->vpn4_config);

	ip4_config_merge_and_apply (self, NULL, FALSE, NULL);

	ip6_config = nm_ip6_config_capture (ifindex);
	nm_device_set_ip6_config (self, ip6_config, FALSE, &ignored);
	g_clear_object (&ip6_config);
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
	update_ip_config (self);
	return FALSE;
}

static void
device_ip_changed (NMPlatform *platform, int ifindex, gpointer platform_object, NMPlatformReason reason, gpointer user_data)
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

void
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

gboolean
nm_device_get_managed (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (!priv->manager_managed)
		return FALSE;
	else if (priv->default_unmanaged)
		return (priv->state != NM_DEVICE_STATE_UNMANAGED);
	else
		return TRUE;
}

static void
nm_device_set_managed_internal (NMDevice *device,
                                gboolean managed,
                                NMDeviceStateReason reason)
{
	nm_log_dbg (LOGD_DEVICE, "(%s): now %s",
	            nm_device_get_iface (device),
	            managed ? "managed" : "unmanaged");

	g_object_notify (G_OBJECT (device), NM_DEVICE_MANAGED);

	if (managed)
		nm_device_state_changed (device, NM_DEVICE_STATE_UNAVAILABLE, reason);
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_UNMANAGED, reason);
}

void
nm_device_set_manager_managed (NMDevice *device,
                               gboolean managed,
                               NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	gboolean was_managed, now_managed;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE (device);

	was_managed = nm_device_get_managed (device);
	priv->manager_managed = managed;
	now_managed = nm_device_get_managed (device);

	if (was_managed != now_managed)
		nm_device_set_managed_internal (device, now_managed, reason);
}

void
nm_device_set_default_unmanaged (NMDevice *device,
                                 gboolean default_unmanaged)
{
	NMDevicePrivate *priv;
	gboolean was_managed, now_managed;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE (device);

	was_managed = nm_device_get_managed (device);
	priv->default_unmanaged = default_unmanaged;
	now_managed = nm_device_get_managed (device);

	if (was_managed != now_managed)
		nm_device_set_managed_internal (device, now_managed,
		                                default_unmanaged ? NM_DEVICE_STATE_REASON_NOW_UNMANAGED :
		                                                    NM_DEVICE_STATE_REASON_NOW_MANAGED);
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

static gboolean
ip4_match_config (NMDevice *self, NMConnection *connection)
{
	NMSettingIP4Config *s_ip4;
	int i, num;
	GSList *leases, *iter;
	NMDHCPManager *dhcp_mgr;
	const char *method;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);

	/* Get any saved leases that apply to this connection */
	dhcp_mgr = nm_dhcp_manager_get ();
	leases = nm_dhcp_manager_get_lease_config (dhcp_mgr,
	                                           nm_device_get_iface (self),
	                                           nm_connection_get_uuid (connection),
						   FALSE);
	g_object_unref (dhcp_mgr);

	method = s_ip4 ? nm_setting_ip4_config_get_method (s_ip4) : NM_SETTING_IP4_CONFIG_METHOD_AUTO;
	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		gboolean found = FALSE;

		/* Find at least one lease's address on the device */
		for (iter = leases; iter; iter = g_slist_next (iter)) {
			NMIP4Config *ip4_config = iter->data;
			const NMPlatformIP4Address *address = nm_ip4_config_get_address (ip4_config, 0);

			if (address && nm_platform_ip4_address_exists (nm_device_get_ip_ifindex (self),
			                                               address->address,
			                                               address->plen)) {
				found = TRUE; /* Yay, device has same address as a lease */
				break;
			}
		}
		g_slist_foreach (leases, (GFunc) g_object_unref, NULL);
		g_slist_free (leases);
		return found;
	} else {
		/* Maybe the connection used to be DHCP and there are stale leases; ignore them */
		g_slist_foreach (leases, (GFunc) g_object_unref, NULL);
		g_slist_free (leases);
	}

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		// FIXME: Enforce no ipv4 addresses?
		return TRUE;
	}

	/* 'shared' and 'link-local' aren't supported methods because 'shared'
	 * requires too much iptables and dnsmasq state to be reclaimed, and
	 * avahi-autoipd isn't smart enough to allow the link-local address to be
	 * determined at any point other than when it was first assigned.
	 */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
		return FALSE;

	/* Everything below for static addressing */

	/* Find all IP4 addresses of this connection on the device */
	if (s_ip4) {
		num = nm_setting_ip4_config_get_num_addresses (s_ip4);
		for (i = 0; i < num; i++) {
			NMIP4Address *addr = nm_setting_ip4_config_get_address (s_ip4, i);

			if (!nm_platform_ip4_address_exists (nm_device_get_ip_ifindex (self),
					nm_ip4_address_get_address (addr),
					nm_ip4_address_get_prefix (addr)))
				return FALSE;
		}
	}

	/* Success; all the connection's static IP addresses are assigned to the device */
	return TRUE;
}

/**
 * nm_device_find_assumable_connection:
 * @device: an #NMDevice
 * @connections: (element-type NMConnection): a list of connections
 *
 * Searches @connections for one that matches the currently-configured
 * state of @device (in both L2 and L3 configuration). That is, it
 * looks for the connection such that if you activated that connection
 * on @device, it would result in @device having the configuration
 * that it has now. This is used at startup to attempt to match
 * already-active devices with corresponding #NMConnections.
 *
 * Some device types (eg, Wi-Fi) and subtypes (eg, PPPoE) can't be
 * matched reliably, so this will always fail for those devices.
 *
 * Returns: (transfer none): an #NMConnection that matches @device's
 *   current state, or %NULL if none match.
 */
NMConnection *
nm_device_find_assumable_connection (NMDevice *device, const GSList *connections)
{
	const GSList *iter;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	if (!NM_DEVICE_GET_CLASS (device)->match_l2_config)
		return NULL;

	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (!nm_device_check_connection_compatible (device, candidate, NULL))
			continue;

		if (!ip4_match_config (device, candidate))
			continue;

		/* FIXME: match IPv6 config */

		if (NM_DEVICE_GET_CLASS (device)->match_l2_config (device, candidate))
			return candidate;
	}

	return NULL;
}

/**
 * nm_device_hwaddr_matches:
 * @device: the device to use when matching the hardware address
 * @connection: the connection which supplies the hardware address
 * @other_hwaddr: if given, use this address instead of the device's actual
 *   hardware address
 * @other_hwaddr_len: length in bytes of @other_hwaddr
 * @fail_if_no_hwaddr: whether to fail the match if @connection does not contain
 *   a hardware address
 *
 * Matches a the devices hardware address (or @other_hwaddr if given) against
 * the hardware-specific setting in @connection.  Allows for device-agnostic
 * hardware address matching without having to know the internal details of
 * the connection and which settings are used by each device subclass.
 *
 * Returns: %TRUE if the @device 's hardware address or @other_hwaddr matches
 *  a hardware address in a hardware-specific setting in @connection
 */
gboolean
nm_device_hwaddr_matches (NMDevice *device,
                          NMConnection *connection,
                          const guint8 *other_hwaddr,
                          guint other_hwaddr_len,
                          gboolean fail_if_no_hwaddr)
{
	NMDevicePrivate *priv;
	const GByteArray *setting_hwaddr;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	priv = NM_DEVICE_GET_PRIVATE (device);

	if (other_hwaddr)
		g_return_val_if_fail (other_hwaddr_len != priv->hw_addr_len, FALSE);

	if (!NM_DEVICE_GET_CLASS (device)->get_connection_hw_address)
		return FALSE;

	setting_hwaddr = NM_DEVICE_GET_CLASS (device)->get_connection_hw_address (device, connection);
	if (setting_hwaddr) {
		g_return_val_if_fail (setting_hwaddr->len == priv->hw_addr_len, FALSE);

		if (other_hwaddr) {
			if (memcmp (setting_hwaddr->data, other_hwaddr, priv->hw_addr_len) == 0)
				return TRUE;
		} else if (memcmp (setting_hwaddr->data, priv->hw_addr, priv->hw_addr_len) == 0)
			return TRUE;
	} else if (fail_if_no_hwaddr == FALSE)
		return TRUE;

	return FALSE;
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

gboolean
nm_device_get_autoconnect (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return NM_DEVICE_GET_PRIVATE (device)->autoconnect;
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

	if (nm_device_check_connection_compatible (self, connection, NULL)) {
		/* Let subclasses implement additional checks on the connection */
		if (   NM_DEVICE_GET_CLASS (self)->check_connection_available
		    && NM_DEVICE_GET_CLASS (self)->check_connection_available (self, connection)) {

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
check_connection_available (NMDevice *device, NMConnection *connection)
{
	/* Default is to assume the connection is available unless a subclass
	 * overrides this with more specific checks.
	 */
	return TRUE;
}

void
nm_device_recheck_available_connections (NMDevice *device)
{
	NMDevicePrivate *priv;
	const GSList *connections, *iter;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE(device);

	_clear_available_connections (device, FALSE);

	connections = nm_connection_provider_get_connections (priv->con_provider);
	for (iter = connections; iter; iter = g_slist_next (iter))
		_try_add_available_connection (device, NM_CONNECTION (iter->data));

	_signal_available_connections_changed (device);
}

static void
cp_connection_added (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data)
{
	if (_try_add_available_connection (NM_DEVICE (user_data), connection))
		_signal_available_connections_changed (NM_DEVICE (user_data));
}

static void
cp_connections_loaded (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data)
{
	const GSList *connections, *iter;
	gboolean added = FALSE;

	connections = nm_connection_provider_get_connections (cp);
	for (iter = connections; iter; iter = g_slist_next (iter))
		added |= _try_add_available_connection (NM_DEVICE (user_data), NM_CONNECTION (iter->data));

	if (added)
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
	/* At the moment, NM's VLAN code assumes all VLANs are over ethernet. */
	return NM_IS_DEVICE_ETHERNET (device);
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
