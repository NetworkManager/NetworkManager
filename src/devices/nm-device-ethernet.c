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
 * Copyright (C) 2005 - 2014 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-device-ethernet.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <libudev.h>

#include "nm-device-private.h"
#include "nm-act-request.h"
#include "nm-ip4-config.h"
#include "NetworkManagerUtils.h"
#include "supplicant/nm-supplicant-manager.h"
#include "supplicant/nm-supplicant-interface.h"
#include "supplicant/nm-supplicant-config.h"
#include "ppp/nm-ppp-manager.h"
#include "ppp/nm-ppp-manager-call.h"
#include "ppp/nm-ppp-status.h"
#include "platform/nm-platform.h"
#include "platform/nm-platform-utils.h"
#include "nm-dcb.h"
#include "settings/nm-settings-connection.h"
#include "nm-config.h"
#include "nm-device-ethernet-utils.h"
#include "settings/nm-settings.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-udev-aux/nm-udev-utils.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceEthernet);

/*****************************************************************************/

#define PPPOE_RECONNECT_DELAY 7
#define PPPOE_ENCAP_OVERHEAD  8 /* 2 bytes for PPP, 6 for PPPoE */

/*****************************************************************************/

typedef struct Supplicant {
	NMSupplicantManager *mgr;
	NMSupplicantInterface *iface;

	/* signal handler ids */
	gulong iface_state_id;

	/* Timeouts and idles */
	guint con_timeout_id;
} Supplicant;

typedef enum {
	DCB_WAIT_UNKNOWN = 0,
	/* Ensure carrier is up before enabling DCB */
	DCB_WAIT_CARRIER_PREENABLE_UP,
	/* Wait for carrier down when device starts enabling */
	DCB_WAIT_CARRIER_PRECONFIG_DOWN,
	/* Wait for carrier up when device has finished enabling */
	DCB_WAIT_CARRIER_PRECONFIG_UP,
	/* Wait carrier down when device starts configuring */
	DCB_WAIT_CARRIER_POSTCONFIG_DOWN,
	/* Wait carrier up when device has finished configuring */
	DCB_WAIT_CARRIER_POSTCONFIG_UP,
} DcbWait;

typedef struct _NMDeviceEthernetPrivate {
	guint32             speed;

	Supplicant          supplicant;
	guint               supplicant_timeout_id;

	/* s390 */
	char *              subchan1;
	char *              subchan2;
	char *              subchan3;
	char *              subchannels; /* Composite used for checking unmanaged specs */
	char **             subchannels_dbus; /* Array exported on D-Bus */
	char *              s390_nettype;
	GHashTable *        s390_options;

	NMActRequestGetSecretsCallId *wired_secrets_id;

	/* PPPoE */
	NMPPPManager *ppp_manager;
	gint32        last_pppoe_time;
	guint         pppoe_wait_id;

	/* DCB */
	DcbWait       dcb_wait;
	guint         dcb_timeout_id;

	bool          dcb_handle_carrier_changes:1;
} NMDeviceEthernetPrivate;

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceEthernet,
	PROP_SPEED,
	PROP_S390_SUBCHANNELS,
);

/*****************************************************************************/

G_DEFINE_TYPE (NMDeviceEthernet, nm_device_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_ETHERNET_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDeviceEthernet, NM_IS_DEVICE_ETHERNET)

/*****************************************************************************/

static void wired_secrets_cancel (NMDeviceEthernet *self);

/*****************************************************************************/

static char *
get_link_basename (const char *parent_path, const char *name, GError **error)
{
	char *link_dest, *path;
	char *result = NULL;

	path = g_strdup_printf ("%s/%s", parent_path, name);
	link_dest = g_file_read_link (path, error);
	if (link_dest) {
		result = g_path_get_basename (link_dest);
		g_free (link_dest);
	}
	g_free (path);
	return result;
}

static void
_update_s390_subchannels (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	struct udev_device *dev = NULL;
	struct udev_device *parent = NULL;
	const char *parent_path, *item;
	int ifindex;
	GDir *dir;
	GError *error = NULL;

	if (priv->subchannels) {
		/* only read the subchannels once. For one, we don't expect them to change
		 * on multiple invocations. Second, we didn't implement proper reloading.
		 * Proper reloading might also be complicated, because the subchannels are
		 * used to match on devices based on a device-spec. Thus, it's not clear
		 * what it means to change afterwards. */
		return;
	}

	ifindex = nm_device_get_ifindex ((NMDevice *) self);
	dev = nm_platform_link_get_udev_device (nm_device_get_platform (NM_DEVICE (self)), ifindex);
	if (!dev)
		return;

	/* Try for the "ccwgroup" parent */
	parent = udev_device_get_parent_with_subsystem_devtype (dev, "ccwgroup", NULL);
	if (!parent) {
		/* FIXME: whatever 'lcs' devices' subsystem is here... */

		/* Not an s390 device */
		return;
	}

	parent_path = udev_device_get_syspath (parent);
	dir = g_dir_open (parent_path, 0, &error);
	if (!dir) {
		_LOGW (LOGD_DEVICE | LOGD_PLATFORM, "update-s390: failed to open directory '%s': %s",
		       parent_path, error->message);
		g_clear_error (&error);
		return;
	}

	while ((item = g_dir_read_name (dir))) {
		if (!strcmp (item, "cdev0")) {
			priv->subchan1 = get_link_basename (parent_path, "cdev0", &error);
		} else if (!strcmp (item, "cdev1")) {
			priv->subchan2 = get_link_basename (parent_path, "cdev1", &error);
		} else if (!strcmp (item, "cdev2")) {
			priv->subchan3 = get_link_basename (parent_path, "cdev2", &error);
		} else if (!strcmp (item, "driver")) {
			priv->s390_nettype = get_link_basename (parent_path, "driver", &error);
		} else if (   !strcmp (item, "layer2")
		           || !strcmp (item, "portname")
		           || !strcmp (item, "portno")) {
			gs_free char *path = NULL, *value = NULL;

			path = g_strdup_printf ("%s/%s", parent_path, item);
			value = nm_platform_sysctl_get (nm_device_get_platform (NM_DEVICE (self)), NMP_SYSCTL_PATHID_ABSOLUTE (path));

			if (   !strcmp (item, "portname")
			    && !g_strcmp0 (value, "no portname required")) {
				/* Do nothing */
			} else if (value && *value) {
				g_hash_table_insert (priv->s390_options, g_strdup (item), value);
				value = NULL;
			} else
				_LOGW (LOGD_DEVICE | LOGD_PLATFORM, "update-s390: error reading %s", path);
		}

		if (error) {
			_LOGW (LOGD_DEVICE | LOGD_PLATFORM, "update-s390: failed reading sysfs for %s (%s)", item, error->message);
			g_clear_error (&error);
		}
	}

	g_dir_close (dir);

	if (priv->subchan3) {
		priv->subchannels = g_strdup_printf ("%s,%s,%s",
		                                     priv->subchan1,
		                                     priv->subchan2,
		                                     priv->subchan3);
	} else if (priv->subchan2) {
		priv->subchannels = g_strdup_printf ("%s,%s",
		                                     priv->subchan1,
		                                     priv->subchan2);
	} else
		priv->subchannels = g_strdup (priv->subchan1);

	priv->subchannels_dbus = g_new (char *, 3 + 1);
	priv->subchannels_dbus[0] = g_strdup (priv->subchan1);
	priv->subchannels_dbus[1] = g_strdup (priv->subchan2);
	priv->subchannels_dbus[2] = g_strdup (priv->subchan3);
	priv->subchannels_dbus[3] = NULL;

	_LOGI (LOGD_DEVICE | LOGD_PLATFORM, "update-s390: found s390 '%s' subchannels [%s]",
	       nm_device_get_driver ((NMDevice *) self) ?: "(unknown driver)",
	       priv->subchannels);

	_notify (self, PROP_S390_SUBCHANNELS);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	if (new_state > NM_DEVICE_STATE_ACTIVATED)
		wired_secrets_cancel (NM_DEVICE_ETHERNET (device));
}

static void
nm_device_ethernet_init (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetPrivate);
	self->_priv = priv;

	priv->s390_options = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	int ifindex = nm_device_get_ifindex (device);

	if (ifindex > 0) {
		if (nm_platform_link_supports_carrier_detect (nm_device_get_platform (device), ifindex))
			return NM_DEVICE_CAP_CARRIER_DETECT;
		else {
			_LOGI (LOGD_PLATFORM, "driver '%s' does not support carrier detection.",
			       nm_device_get_driver (device));
		}
	}

	return NM_DEVICE_CAP_NONE;
}

static guint32
_subchannels_count_num (const char * const *array)
{
	int i;

	if (!array)
		return 0;
	for (i = 0; array[i]; i++)
		/* NOP */;
	return i;
}

static gboolean
match_subchans (NMDeviceEthernet *self, NMSettingWired *s_wired, gboolean *try_mac)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	const char * const *subchans;
	guint32 num1, num2;
	int i;

	*try_mac = TRUE;

	subchans = nm_setting_wired_get_s390_subchannels (s_wired);
	num1 = _subchannels_count_num (subchans);
	num2 = _subchannels_count_num ((const char * const *) priv->subchannels_dbus);
	/* connection has no subchannels */
	if (num1 == 0)
		return TRUE;
	/* connection requires subchannels but the device has none */
	if (num2 == 0)
		return FALSE;
	/* number of subchannels differ */
	if (num1 != num2)
		return FALSE;

	/* Make sure each subchannel in the connection is a subchannel of this device */
	for (i = 0; subchans[i]; i++) {
		const char *candidate = subchans[i];

		if (   (priv->subchan1 && !strcmp (priv->subchan1, candidate))
		    || (priv->subchan2 && !strcmp (priv->subchan2, candidate))
		    || (priv->subchan3 && !strcmp (priv->subchan3, candidate)))
			continue;

		return FALSE;  /* a subchannel was not found */
	}

	*try_mac = FALSE;
	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMSettingWired *s_wired;

	if (!NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	if (nm_connection_is_type (connection, NM_SETTING_PPPOE_SETTING_NAME)) {
		s_wired = nm_connection_get_setting_wired (connection);
	} else {
		s_wired = _nm_connection_check_main_setting (connection, NM_SETTING_WIRED_SETTING_NAME, error);
		if (!s_wired)
			return FALSE;
	}

	if (s_wired) {
		const char *mac, *perm_hw_addr;
		gboolean try_mac = TRUE;
		const char * const *mac_blacklist;
		int i;

		if (!match_subchans (self, s_wired, &try_mac)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "s390 subchannels don't match");
			return FALSE;
		}

		perm_hw_addr = nm_device_get_permanent_hw_address (device);
		mac = nm_setting_wired_get_mac_address (s_wired);
		if (perm_hw_addr) {
			if (   try_mac
			    && mac
			    && !nm_utils_hwaddr_matches (mac, -1, perm_hw_addr, -1)) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "permanent MAC address doesn't match");
				return FALSE;
			}

			/* Check for MAC address blacklist */
			mac_blacklist = nm_setting_wired_get_mac_address_blacklist (s_wired);
			for (i = 0; mac_blacklist[i]; i++) {
				if (!nm_utils_hwaddr_valid (mac_blacklist[i], ETH_ALEN)) {
					nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
					                            "invalid MAC in blacklist");
					return FALSE;
				}

				if (nm_utils_hwaddr_matches (mac_blacklist[i], -1, perm_hw_addr, -1)) {
					nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
					                            "permanent MAC address of device blacklisted");
					return FALSE;
				}
			}
		} else if (mac) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "device has no permanent MAC address to match");
			return FALSE;
		}
	}

	return TRUE;
}

/*****************************************************************************/
/* 802.1X */

static void
supplicant_interface_release (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	nm_clear_g_source (&priv->supplicant_timeout_id);
	nm_clear_g_source (&priv->supplicant.con_timeout_id);
	nm_clear_g_signal_handler (priv->supplicant.iface, &priv->supplicant.iface_state_id);

	if (priv->supplicant.iface) {
		nm_supplicant_interface_disconnect (priv->supplicant.iface);
		g_clear_object (&priv->supplicant.iface);
	}
}

static void
wired_secrets_cb (NMActRequest *req,
                  NMActRequestGetSecretsCallId *call_id,
                  NMSettingsConnection *connection,
                  GError *error,
                  gpointer user_data)
{
	NMDeviceEthernet *self = user_data;
	NMDevice *device = user_data;
	NMDeviceEthernetPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_ETHERNET (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	g_return_if_fail (priv->wired_secrets_id == call_id);

	priv->wired_secrets_id = NULL;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_settings_connection (req) == connection);

	if (error) {
		_LOGW (LOGD_ETHER, "%s", error->message);
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else
		nm_device_activate_schedule_stage1_device_prepare (device);
}

static void
wired_secrets_cancel (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->wired_secrets_id)
		nm_act_request_cancel_secrets (NULL, priv->wired_secrets_id);
	nm_assert (!priv->wired_secrets_id);
}

static void
wired_secrets_get_secrets (NMDeviceEthernet *self,
                           const char *setting_name,
                           NMSecretAgentGetSecretsFlags flags)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMActRequest *req;

	wired_secrets_cancel (self);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv->wired_secrets_id = nm_act_request_get_secrets (req,
	                                                     TRUE,
	                                                     setting_name,
	                                                     flags,
	                                                     NULL,
	                                                     wired_secrets_cb,
	                                                     self);
	g_return_if_fail (priv->wired_secrets_id);
}

static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *dev = NM_DEVICE (self);
	NMActRequest *req;
	NMConnection *applied_connection;
	const char *setting_name;

	priv->supplicant_timeout_id = 0;

	req = nm_device_get_act_request (dev);

	if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
		nm_device_state_changed (dev,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
		return FALSE;
	}

	/* Disconnect event during initial authentication and credentials
	 * ARE checked - we are likely to have wrong key.  Ask the user for
	 * another one.
	 */
	if (nm_device_get_state (dev) != NM_DEVICE_STATE_CONFIG)
		goto time_out;

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (req));

	applied_connection = nm_act_request_get_applied_connection (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name)
		goto time_out;

	_LOGI (LOGD_DEVICE | LOGD_ETHER,
	       "Activation: (ethernet) disconnected during authentication, asking for new key.");
	supplicant_interface_release (self);

	nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
	wired_secrets_get_secrets (self, setting_name, NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW);

	return FALSE;

time_out:
	_LOGW (LOGD_DEVICE | LOGD_ETHER, "link timed out.");
	nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);

	return FALSE;
}

static NMSupplicantConfig *
build_supplicant_config (NMDeviceEthernet *self,
                         GError **error)
{
	const char *con_uuid;
	NMSupplicantConfig *config = NULL;
	NMSetting8021x *security;
	NMConnection *connection;
	guint32 mtu;

	connection = nm_device_get_applied_connection (NM_DEVICE (self));

	g_return_val_if_fail (connection, NULL);

	con_uuid = nm_connection_get_uuid (connection);
	mtu = nm_platform_link_get_mtu (nm_device_get_platform (NM_DEVICE (self)),
	                                nm_device_get_ifindex (NM_DEVICE (self)));

	config = nm_supplicant_config_new (FALSE, FALSE, FALSE, FALSE);

	security = nm_connection_get_setting_802_1x (connection);
	if (!nm_supplicant_config_add_setting_8021x (config, security, con_uuid, mtu, TRUE, error)) {
		g_prefix_error (error, "802-1x-setting: ");
		g_clear_object (&config);
	}

	return config;
}

static void
supplicant_iface_assoc_cb (NMSupplicantInterface *iface,
                           GError *error,
                           gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);

	if (error && !nm_utils_error_is_cancelled (error, TRUE)) {
		supplicant_interface_release (self);
		nm_device_queue_state (NM_DEVICE (self),
		                       NM_DEVICE_STATE_FAILED,
		                       NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
	}
}

static void
supplicant_iface_state_cb (NMSupplicantInterface *iface,
                           int new_state_i,
                           int old_state_i,
                           int disconnect_reason,
                           gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMSupplicantConfig *config;
	NMDeviceState devstate;
	GError *error = NULL;
	NMSupplicantInterfaceState new_state = new_state_i;
	NMSupplicantInterfaceState old_state = old_state_i;

	if (new_state == old_state)
		return;

	_LOGI (LOGD_DEVICE | LOGD_ETHER, "supplicant interface state: %s -> %s",
	       nm_supplicant_interface_state_to_string (old_state),
	       nm_supplicant_interface_state_to_string (new_state));

	devstate = nm_device_get_state (device);

	switch (new_state) {
	case NM_SUPPLICANT_INTERFACE_STATE_READY:
		config = build_supplicant_config (self, &error);
		if (config) {
			nm_supplicant_interface_assoc (priv->supplicant.iface, config,
			                               supplicant_iface_assoc_cb, self);
			g_object_unref (config);
		} else {
			_LOGE (LOGD_DEVICE | LOGD_ETHER,
			       "Activation: (ethernet) couldn't build security configuration: %s",
			       error->message);
			g_clear_error (&error);

			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		nm_clear_g_source (&priv->supplicant_timeout_id);
		nm_clear_g_source (&priv->supplicant.con_timeout_id);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (devstate == NM_DEVICE_STATE_CONFIG) {
			_LOGI (LOGD_DEVICE | LOGD_ETHER,
			       "Activation: (ethernet) Stage 2 of 5 (Device Configure) successful.");
			nm_device_activate_schedule_stage3_ip_config_start (device);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			/* Start the link timeout so we allow some time for reauthentication */
			if (!priv->supplicant_timeout_id)
				priv->supplicant_timeout_id = g_timeout_add_seconds (15, link_timeout_cb, device);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
		supplicant_interface_release (self);

		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
		break;
	default:
		break;
	}
}

static NMActStageReturn
handle_auth_or_fail (NMDeviceEthernet *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	const char *setting_name;
	NMConnection *applied_connection;

	if (!nm_device_auth_retries_try_next (NM_DEVICE (self)))
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (req));

	applied_connection = nm_act_request_get_applied_connection (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name) {
		_LOGI (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	wired_secrets_get_secrets (self, setting_name,
	                             NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION
	                           | (new_secrets ? NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW : 0));
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static gboolean
supplicant_connection_timeout_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	NMSettingsConnection *connection;
	guint64 timestamp = 0;
	gboolean new_secrets = TRUE;

	priv->supplicant.con_timeout_id = 0;

	/* Authentication failed; either driver problems, the encryption key is
	 * wrong, the passwords or certificates were wrong or the Ethernet switch's
	 * port is not configured for 802.1x. */
	_LOGW (LOGD_DEVICE | LOGD_ETHER,
	       "Activation: (ethernet) association took too long.");

	supplicant_interface_release (self);
	req = nm_device_get_act_request (device);
	g_assert (req);

	connection = nm_act_request_get_settings_connection (req);
	g_assert (connection);

	/* Ask for new secrets only if we've never activated this connection
	 * before.  If we've connected before, don't bother the user with dialogs,
	 * just retry or fail, and if we never connect the user can fix the
	 * password somewhere else. */
	if (nm_settings_connection_get_timestamp (connection, &timestamp))
		new_secrets = !timestamp;

	if (handle_auth_or_fail (self, req, new_secrets) == NM_ACT_STAGE_RETURN_POSTPONE)
		_LOGW (LOGD_DEVICE | LOGD_ETHER, "Activation: (ethernet) asking for new secrets");
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);

	return FALSE;
}

static gboolean
supplicant_interface_init (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	guint timeout;

	supplicant_interface_release (self);

	priv->supplicant.iface = nm_supplicant_manager_create_interface (priv->supplicant.mgr,
	                                                                 nm_device_get_iface (NM_DEVICE (self)),
	                                                                 NM_SUPPLICANT_DRIVER_WIRED);

	if (!priv->supplicant.iface) {
		_LOGE (LOGD_DEVICE | LOGD_ETHER,
		       "Couldn't initialize supplicant interface");
		return FALSE;
	}

	/* Listen for its state signals */
	priv->supplicant.iface_state_id = g_signal_connect (priv->supplicant.iface,
	                                                    NM_SUPPLICANT_INTERFACE_STATE,
	                                                    G_CALLBACK (supplicant_iface_state_cb),
	                                                    self);

	/* Set up a timeout on the connection attempt */
	timeout = nm_device_get_supplicant_timeout (NM_DEVICE (self));
	priv->supplicant.con_timeout_id = g_timeout_add_seconds (timeout,
	                                                         supplicant_connection_timeout_cb,
	                                                         self);

	return TRUE;
}

static NMPlatformLinkDuplexType
link_duplex_to_platform (const char *duplex)
{
	if (!duplex)
		return NM_PLATFORM_LINK_DUPLEX_UNKNOWN;
	if (nm_streq (duplex, "full"))
		return NM_PLATFORM_LINK_DUPLEX_FULL;
	if (nm_streq (duplex, "half"))
		return NM_PLATFORM_LINK_DUPLEX_HALF;
	g_return_val_if_reached (NM_PLATFORM_LINK_DUPLEX_UNKNOWN);
}

static void
link_negotiation_set (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMSettingWired *s_wired;
	gboolean autoneg = TRUE;
	gboolean link_autoneg;
	NMPlatformLinkDuplexType duplex = NM_PLATFORM_LINK_DUPLEX_UNKNOWN;
	NMPlatformLinkDuplexType link_duplex;
	guint32 speed = 0;
	guint32 link_speed;

	s_wired = nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRED);
	if (s_wired) {
		autoneg = nm_setting_wired_get_auto_negotiate (s_wired);
		speed = nm_setting_wired_get_speed (s_wired);
		duplex = link_duplex_to_platform (nm_setting_wired_get_duplex (s_wired));
		if (!autoneg && !speed && !duplex) {
			_LOGD (LOGD_DEVICE, "set-link: ignore link negotiation");
			return;
		}
	}

	if (!nm_platform_ethtool_get_link_settings (nm_device_get_platform (device), nm_device_get_ifindex (device),
	                                            &link_autoneg, &link_speed, &link_duplex)) {
		_LOGW (LOGD_DEVICE, "set-link: unable to retrieve link negotiation");
		return;
	}

	/* If link negotiation setting are already in place do nothing and return with success */
	if (   !!autoneg == !!link_autoneg
	    && speed == link_speed
	    && duplex == link_duplex) {
		_LOGD (LOGD_DEVICE, "set-link: link negotiation is already configured");
		return;
	}

	if (autoneg && !speed && !duplex)
		_LOGD (LOGD_DEVICE, "set-link: configure auto-negotiation");
	else {
		_LOGD (LOGD_DEVICE, "set-link: configure %snegotiation (%u Mbit%s - %s duplex%s)",
		       autoneg ? "auto-" : "static ",
		       speed ?: link_speed,
		       speed ? "" : "*",
		       duplex
		         ? nm_platform_link_duplex_type_to_string (duplex)
		         : nm_platform_link_duplex_type_to_string (link_duplex),
		       duplex ? "" : "*");
	}

	if (!nm_platform_ethtool_set_link_settings (nm_device_get_platform (device),
	                                            nm_device_get_ifindex (device),
	                                            autoneg,
	                                            speed,
	                                            duplex)) {
		_LOGW (LOGD_DEVICE, "set-link: failure to set link negotiation");
		return;
	}
}

static gboolean
pppoe_reconnect_delay (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	priv->pppoe_wait_id = 0;
	_LOGI (LOGD_DEVICE, "PPPoE reconnect delay complete, resuming connection...");
	nm_device_activate_schedule_stage2_device_config (NM_DEVICE (self));
	return FALSE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMActStageReturn ret;

	ret = NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->act_stage1_prepare (dev, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	link_negotiation_set (dev);

	if (!nm_device_hw_addr_set_cloned (dev, nm_device_get_applied_connection (dev), FALSE))
		return NM_ACT_STAGE_RETURN_FAILURE;

	/* If we're re-activating a PPPoE connection a short while after
	 * a previous PPPoE connection was torn down, wait a bit to allow the
	 * remote side to handle the disconnection.  Otherwise the peer may
	 * get confused and fail to negotiate the new connection. (rh #1023503)
	 */
	if (priv->last_pppoe_time) {
		gint32 delay = nm_utils_get_monotonic_timestamp_s () - priv->last_pppoe_time;

		if (   delay < PPPOE_RECONNECT_DELAY
		    && nm_device_get_applied_setting (dev, NM_TYPE_SETTING_PPPOE)) {
			_LOGI (LOGD_DEVICE, "delaying PPPoE reconnect for %d seconds to ensure peer is ready...",
			       delay);
			g_assert (!priv->pppoe_wait_id);
			priv->pppoe_wait_id = g_timeout_add_seconds (delay,
			                                             pppoe_reconnect_delay,
			                                             self);
			return NM_ACT_STAGE_RETURN_POSTPONE;
		}
		priv->last_pppoe_time = 0;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
nm_8021x_stage2_config (NMDeviceEthernet *self, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMConnection *connection;
	NMSetting8021x *security;
	const char *setting_name;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	connection = nm_device_get_applied_connection (NM_DEVICE (self));

	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	security = nm_connection_get_setting_802_1x (connection);
	if (!security) {
		_LOGE (LOGD_DEVICE, "Invalid or missing 802.1X security");
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
		return ret;
	}

	if (!priv->supplicant.mgr)
		priv->supplicant.mgr = g_object_ref (nm_supplicant_manager_get ());

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		_LOGI (LOGD_DEVICE | LOGD_ETHER,
		       "Activation: (ethernet) connection '%s' has security, but secrets are required.",
		       nm_connection_get_id (connection));

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret != NM_ACT_STAGE_RETURN_POSTPONE)
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else {
		_LOGI (LOGD_DEVICE | LOGD_ETHER,
		       "Activation: (ethernet) connection '%s' requires no security. No secrets needed.",
		       nm_connection_get_id (connection));

		if (supplicant_interface_init (self))
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		else
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
	}

	return ret;
}

/*****************************************************************************/
/* PPPoE */

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	default:
		break;
	}
}

static void
ppp_ifindex_set (NMPPPManager *ppp_manager,
                 int ifindex,
                 const char *iface,
                 gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	if (!nm_device_set_ip_ifindex (device, ifindex)) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	}
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
                NMIP4Config *config,
                gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	/* Ignore PPP IP4 events that come in after initial configuration */
	if (nm_device_activate_ip4_state_in_conf (device))
		nm_device_activate_schedule_ip_config_result (device, AF_INET, NM_IP_CONFIG_CAST (config));
}

static NMActStageReturn
pppoe_stage3_ip4_config_start (NMDeviceEthernet *self, NMDeviceStateReason *out_failure_reason)
{
	NMDevice *device = NM_DEVICE (self);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingPppoe *s_pppoe;
	NMActRequest *req;
	GError *err = NULL;

	req = nm_device_get_act_request (device);

	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	s_pppoe = nm_device_get_applied_setting (device, NM_TYPE_SETTING_PPPOE);

	g_return_val_if_fail (s_pppoe, NM_ACT_STAGE_RETURN_FAILURE);

	priv->ppp_manager = nm_ppp_manager_create (nm_device_get_iface (device),
	                                           &err);

	if (priv->ppp_manager) {
		nm_ppp_manager_set_route_parameters (priv->ppp_manager,
		                                     nm_device_get_route_table (device, AF_INET),
		                                     nm_device_get_route_metric (device, AF_INET),
		                                     nm_device_get_route_table (device, AF_INET6),
		                                     nm_device_get_route_metric (device, AF_INET6));
	}

	if (   !priv->ppp_manager
	    || !nm_ppp_manager_start (priv->ppp_manager, req,
	                              nm_setting_pppoe_get_username (s_pppoe),
	                              30, 0, &err)) {
		_LOGW (LOGD_DEVICE, "PPPoE failed to start: %s", err->message);
		g_error_free (err);

		g_clear_object (&priv->ppp_manager);

		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_PPP_START_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_STATE_CHANGED,
	                  G_CALLBACK (ppp_state_changed),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_IFINDEX_SET,
	                  G_CALLBACK (ppp_ifindex_set),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_IP4_CONFIG,
	                  G_CALLBACK (ppp_ip4_config),
	                  self);
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static void dcb_state (NMDevice *device, gboolean timeout);

static gboolean
dcb_carrier_timeout (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (user_data);

	g_return_val_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG, G_SOURCE_REMOVE);

	priv->dcb_timeout_id = 0;
	if (priv->dcb_wait != DCB_WAIT_CARRIER_POSTCONFIG_DOWN) {
		_LOGW (LOGD_DCB, "DCB: timed out waiting for carrier (step %d)",
		       priv->dcb_wait);
	}
	dcb_state (device, TRUE);
	return G_SOURCE_REMOVE;
}

static gboolean
dcb_configure (NMDevice *device)
{
	NMDeviceEthernet *self = (NMDeviceEthernet *) device;
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingDcb *s_dcb;
	GError *error = NULL;

	nm_clear_g_source (&priv->dcb_timeout_id);

	s_dcb = nm_device_get_applied_setting (device, NM_TYPE_SETTING_DCB);

	g_return_val_if_fail (s_dcb, FALSE);

	if (!nm_dcb_setup (nm_device_get_iface (device), s_dcb, &error)) {
		_LOGW (LOGD_DCB, "Activation: (ethernet) failed to enable DCB/FCoE: %s",
		       error->message);
		g_clear_error (&error);
		return FALSE;
	}

	/* Pause again just in case the device takes the carrier down when
	 * setting specific DCB attributes.
	 */
	_LOGD (LOGD_DCB, "waiting for carrier (postconfig down)");
	priv->dcb_wait = DCB_WAIT_CARRIER_POSTCONFIG_DOWN;
	priv->dcb_timeout_id = g_timeout_add_seconds (3, dcb_carrier_timeout, device);
	return TRUE;
}

static gboolean
dcb_enable (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	GError *error = NULL;

	nm_clear_g_source (&priv->dcb_timeout_id);
	if (!nm_dcb_enable (nm_device_get_iface (device), TRUE, &error)) {
		_LOGW (LOGD_DCB, "Activation: (ethernet) failed to enable DCB/FCoE: %s",
		       error->message);
		g_clear_error (&error);
		return FALSE;
	}

	/* Pause for 3 seconds after enabling DCB to let the card reconfigure
	 * itself.  Drivers will often re-initialize internal settings which
	 * takes the carrier down for 2 or more seconds.  During this time,
	 * lldpad will refuse to do anything else with the card since the carrier
	 * is down.  But NM might get the carrier-down signal long after calling
	 * "dcbtool dcb on", so we have to first wait for the carrier to go down.
	 */
	_LOGD (LOGD_DCB, "waiting for carrier (preconfig down)");
	priv->dcb_wait = DCB_WAIT_CARRIER_PRECONFIG_DOWN;
	priv->dcb_timeout_id = g_timeout_add_seconds (3, dcb_carrier_timeout, device);
	return TRUE;
}

static void
dcb_state (NMDevice *device, gboolean timeout)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	gboolean carrier;

	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG);

	carrier = nm_platform_link_is_connected (nm_device_get_platform (device), nm_device_get_ifindex (device));
	_LOGD (LOGD_DCB, "dcb_state() wait %d carrier %d timeout %d", priv->dcb_wait, carrier, timeout);

	switch (priv->dcb_wait) {
	case DCB_WAIT_CARRIER_PREENABLE_UP:
		if (timeout || carrier) {
			_LOGD (LOGD_DCB, "dcb_state() enabling DCB");
			nm_clear_g_source (&priv->dcb_timeout_id);
			if (!dcb_enable (device)) {
				priv->dcb_handle_carrier_changes = FALSE;
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_FAILED,
				                         NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED);
			}
		}
		break;
	case DCB_WAIT_CARRIER_PRECONFIG_DOWN:
		nm_clear_g_source (&priv->dcb_timeout_id);
		priv->dcb_wait = DCB_WAIT_CARRIER_PRECONFIG_UP;

		if (!carrier) {
			/* Wait for the carrier to come back up */
			_LOGD (LOGD_DCB, "waiting for carrier (preconfig up)");
			priv->dcb_timeout_id = g_timeout_add_seconds (5, dcb_carrier_timeout, device);
			break;
		}
		_LOGD (LOGD_DCB, "dcb_state() preconfig down falling through");
		/* fall through */
	case DCB_WAIT_CARRIER_PRECONFIG_UP:
		if (timeout || carrier) {
			_LOGD (LOGD_DCB, "dcb_state() preconfig up configuring DCB");
			nm_clear_g_source (&priv->dcb_timeout_id);
			if (!dcb_configure (device)) {
				priv->dcb_handle_carrier_changes = FALSE;
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_FAILED,
				                         NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED);
			}
		}
		break;
	case DCB_WAIT_CARRIER_POSTCONFIG_DOWN:
		nm_clear_g_source (&priv->dcb_timeout_id);
		priv->dcb_wait = DCB_WAIT_CARRIER_POSTCONFIG_UP;

		if (!carrier) {
			/* Wait for the carrier to come back up */
			_LOGD (LOGD_DCB, "waiting for carrier (postconfig up)");
			priv->dcb_timeout_id = g_timeout_add_seconds (5, dcb_carrier_timeout, device);
			break;
		}
		_LOGD (LOGD_DCB, "dcb_state() postconfig down falling through");
		/* fall through */
	case DCB_WAIT_CARRIER_POSTCONFIG_UP:
		if (timeout || carrier) {
			_LOGD (LOGD_DCB, "dcb_state() postconfig up starting IP");
			nm_clear_g_source (&priv->dcb_timeout_id);
			priv->dcb_handle_carrier_changes = FALSE;
			priv->dcb_wait = DCB_WAIT_UNKNOWN;
			nm_device_activate_schedule_stage3_ip_config_start (device);
		}
		break;
	default:
		g_assert_not_reached ();
	}
}

/*****************************************************************************/

static gboolean
wake_on_lan_enable (NMDevice *device)
{
	NMSettingWiredWakeOnLan wol;
	NMSettingWired *s_wired;
	const char *password = NULL;

	s_wired = nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRED);

	if (s_wired) {
		wol = nm_setting_wired_get_wake_on_lan (s_wired);
		password = nm_setting_wired_get_wake_on_lan_password (s_wired);
		if (wol != NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT)
			goto found;
	}

	wol = nm_config_data_get_connection_default_int64 (NM_CONFIG_GET_DATA,
	                                                   NM_CON_DEFAULT ("ethernet.wake-on-lan"),
	                                                   device,
	                                                   NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
	                                                   G_MAXINT32,
	                                                   NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT);

	if (   NM_FLAGS_ANY (wol, NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS)
	    && !nm_utils_is_power_of_two (wol)) {
		nm_log_dbg (LOGD_ETHER, "invalid default value %u for wake-on-lan", (guint) wol);
		wol = NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT;
	}
	if (wol != NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT)
		goto found;
	wol = NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE;
found:
	return nm_platform_ethtool_set_wake_on_lan (nm_device_get_platform (device),
	                                            nm_device_get_ifindex (device),
	                                            wol, password);
}

/*****************************************************************************/

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceEthernet *self = (NMDeviceEthernet *) device;
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *connection_type;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	NMSettingDcb *s_dcb;

	s_con = nm_device_get_applied_setting (device, NM_TYPE_SETTING_CONNECTION);

	g_return_val_if_fail (s_con, NM_ACT_STAGE_RETURN_FAILURE);

	nm_clear_g_source (&priv->dcb_timeout_id);
	priv->dcb_handle_carrier_changes = FALSE;

	/* 802.1x has to run before any IP configuration since the 802.1x auth
	 * process opens the port up for normal traffic.
	 */
	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (!strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME)) {
		NMSetting8021x *security;

		security = nm_device_get_applied_setting (device, NM_TYPE_SETTING_802_1X);

		if (security) {
			/* FIXME: for now 802.1x is mutually exclusive with DCB */
			return nm_8021x_stage2_config (self, out_failure_reason);
		}
	}

	wake_on_lan_enable (device);

	/* DCB and FCoE setup */
	s_dcb = nm_device_get_applied_setting (device, NM_TYPE_SETTING_DCB);
	if (s_dcb) {
		/* lldpad really really wants the carrier to be up */
		if (nm_platform_link_is_connected (nm_device_get_platform (device), nm_device_get_ifindex (device))) {
			if (!dcb_enable (device)) {
				NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED);
				return NM_ACT_STAGE_RETURN_FAILURE;
			}
		} else {
			_LOGD (LOGD_DCB, "waiting for carrier (preenable up)");
			priv->dcb_wait = DCB_WAIT_CARRIER_PREENABLE_UP;
			priv->dcb_timeout_id = g_timeout_add_seconds (4, dcb_carrier_timeout, device);
		}

		priv->dcb_handle_carrier_changes = TRUE;
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}

	/* PPPoE setup */
	if (nm_connection_is_type (nm_device_get_applied_connection (device),
	                           NM_SETTING_PPPOE_SETTING_NAME)) {
		NMSettingPpp *s_ppp;

		s_ppp = nm_device_get_applied_setting (device, NM_TYPE_SETTING_PPP);
		if (s_ppp) {
			guint32 mtu = 0, mru = 0, mxu;

			mtu = nm_setting_ppp_get_mtu (s_ppp);
			mru = nm_setting_ppp_get_mru (s_ppp);
			mxu = mru > mtu ? mru : mtu;
			if (mxu) {
				_LOGD (LOGD_PPP, "set MTU to %u (PPP interface MRU %u, MTU %u)",
				       mxu + PPPOE_ENCAP_OVERHEAD, mru, mtu);
				nm_platform_link_set_mtu (nm_device_get_platform (device),
				                          nm_device_get_ifindex (device),
				                          mxu + PPPOE_ENCAP_OVERHEAD);
			}
		}
	}

	return ret;
}

static NMActStageReturn
act_stage3_ip_config_start (NMDevice *device,
                            int addr_family,
                            gpointer *out_config,
                            NMDeviceStateReason *out_failure_reason)
{
	NMSettingConnection *s_con;
	const char *connection_type;

	if (addr_family == AF_INET) {
		s_con = nm_device_get_applied_setting (device, NM_TYPE_SETTING_CONNECTION);

		g_return_val_if_fail (s_con, NM_ACT_STAGE_RETURN_FAILURE);

		connection_type = nm_setting_connection_get_connection_type (s_con);
		if (!strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
			return pppoe_stage3_ip4_config_start (NM_DEVICE_ETHERNET (device), out_failure_reason);
	}

	return NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->act_stage3_ip_config_start (device, addr_family, out_config, out_failure_reason);
}

static guint32
get_configured_mtu (NMDevice *device, NMDeviceMtuSource *out_source)
{
	/* MTU only set for plain ethernet */
	if (NM_DEVICE_ETHERNET_GET_PRIVATE ((NMDeviceEthernet *) device)->ppp_manager)
		return 0;

	return nm_device_get_configured_mtu_for_wired (device, out_source);
}

static void
deactivate (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingDcb *s_dcb;
	GError *error = NULL;

	nm_clear_g_source (&priv->pppoe_wait_id);

	if (priv->ppp_manager) {
		nm_ppp_manager_stop (priv->ppp_manager, NULL, NULL, NULL);
		g_clear_object (&priv->ppp_manager);
	}

	supplicant_interface_release (self);

	priv->dcb_wait = DCB_WAIT_UNKNOWN;
	nm_clear_g_source (&priv->dcb_timeout_id);
	priv->dcb_handle_carrier_changes = FALSE;

	/* Tear down DCB/FCoE if it was enabled */
	s_dcb = nm_device_get_applied_setting (device, NM_TYPE_SETTING_DCB);
	if (s_dcb) {
		if (!nm_dcb_cleanup (nm_device_get_iface (device), &error)) {
			_LOGW (LOGD_DEVICE | LOGD_PLATFORM, "failed to disable DCB/FCoE: %s",
			       error->message);
			g_clear_error (&error);
		}
	}

	/* Set last PPPoE connection time */
	if (nm_device_get_applied_setting (device, NM_TYPE_SETTING_PPPOE))
		priv->last_pppoe_time = nm_utils_get_monotonic_timestamp_s ();
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingWired *s_wired;
	NMSettingPppoe *s_pppoe;

	s_pppoe = nm_connection_get_setting_pppoe (connection);

	/* We can't telepathically figure out the service name or username, so if
	 * those weren't given, we can't complete the connection.
	 */
	if (s_pppoe && !nm_setting_verify (NM_SETTING (s_pppoe), NULL, error))
		return FALSE;

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired) {
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));
	}

	/* Default to an ethernet-only connection, but if a PPPoE setting was given
	 * then PPPoE should be our connection type.
	 */
	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           s_pppoe ? NM_SETTING_PPPOE_SETTING_NAME : NM_SETTING_WIRED_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           s_pppoe ? _("PPPoE connection") : _("Wired connection"),
	                           NULL,
	                           nm_setting_wired_get_mac_address (s_wired) ? NULL : nm_device_get_iface (device),
	                           s_pppoe ? FALSE : TRUE); /* No IPv6 by default yet for PPPoE */

	return TRUE;
}

static NMConnection *
new_default_connection (NMDevice *self)
{
	NMConnection *connection;
	NMSettingsConnection *const*connections;
	NMSetting *setting;
	gs_unref_hashtable GHashTable *existing_ids = NULL;
	struct udev_device *dev;
	const char *perm_hw_addr;
	const char *iface;
	const char *uprop = "0";
	gs_free char *defname = NULL;
	gs_free char *uuid = NULL;
	guint i, n_connections;

	perm_hw_addr = nm_device_get_permanent_hw_address (self);
	iface = nm_device_get_iface (self);

	connection = nm_simple_connection_new ();
	setting = nm_setting_connection_new ();
	nm_connection_add_setting (connection, setting);

	connections = nm_settings_get_connections (nm_device_get_settings (self), &n_connections);
	if (n_connections > 0) {
		existing_ids = g_hash_table_new (nm_str_hash, g_str_equal);
		for (i = 0; i < n_connections; i++)
			g_hash_table_add (existing_ids, (char *) nm_settings_connection_get_id (connections[i]));
	}
	defname = nm_device_ethernet_utils_get_default_wired_name (existing_ids);
	if (!defname)
		return NULL;

	/* Create a stable UUID. The UUID is also the Network_ID for stable-privacy addr-gen-mode,
	 * thus when it changes we will also generate different IPv6 addresses. */
	uuid = _nm_utils_uuid_generate_from_strings ("default-wired",
	                                             nm_utils_machine_id_str (),
	                                             defname,
	                                             perm_hw_addr ?: iface,
	                                             NULL);

	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, defname,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY, NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TIMESTAMP, (guint64) time (NULL),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, iface,
	              NULL);

	/* Check if we should create a Link-Local only connection */
	dev = nm_platform_link_get_udev_device (nm_device_get_platform (NM_DEVICE (self)), nm_device_get_ip_ifindex (self));
	if (dev)
		uprop = udev_device_get_property_value (dev, "NM_AUTO_DEFAULT_LINK_LOCAL_ONLY");

	if (nm_udev_utils_property_as_boolean (uprop)) {
		setting = nm_setting_ip4_config_new ();
		g_object_set (setting,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
		              NULL);
		nm_connection_add_setting (connection, setting);

		setting = nm_setting_ip6_config_new ();
		g_object_set (setting,
		              NM_SETTING_IP_CONFIG_METHOD,  NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
		              NULL);
		nm_connection_add_setting (connection, setting);
	}

	return connection;
}

static const char *
get_s390_subchannels (NMDevice *device)
{
	nm_assert (NM_IS_DEVICE_ETHERNET (device));

	return NM_DEVICE_ETHERNET_GET_PRIVATE ((NMDeviceEthernet *) device)->subchannels;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE ((NMDeviceEthernet *) device);
	NMSettingWired *s_wired = nm_connection_get_setting_wired (connection);
	gboolean perm_hw_addr_is_fake;
	const char *perm_hw_addr;
	const char *mac = nm_device_get_hw_address (device);
	const char *mac_prop = NM_SETTING_WIRED_MAC_ADDRESS;
	GHashTableIter iter;
	gpointer key, value;

	if (!s_wired) {
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_wired);
	}

	g_object_set (nm_connection_get_setting_connection (connection),
	              NM_SETTING_CONNECTION_TYPE, nm_connection_get_setting_pppoe (connection)
	                                          ? NM_SETTING_PPPOE_SETTING_NAME
	                                          : NM_SETTING_WIRED_SETTING_NAME, NULL);

	/* If the device reports a permanent address, use that for the MAC address
	 * and the current MAC, if different, is the cloned MAC.
	 */
	perm_hw_addr = nm_device_get_permanent_hw_address_full (device, TRUE, &perm_hw_addr_is_fake);
	if (perm_hw_addr && !perm_hw_addr_is_fake) {
		g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, perm_hw_addr, NULL);

		mac_prop = NULL;
		if (mac && !nm_utils_hwaddr_matches (perm_hw_addr, -1, mac, -1))
			mac_prop = NM_SETTING_WIRED_CLONED_MAC_ADDRESS;
	}

	if (mac_prop && mac && nm_utils_hwaddr_valid (mac, ETH_ALEN))
		g_object_set (s_wired, mac_prop, mac, NULL);

	/* We don't set the MTU as we don't know whether it was set explicitly */

	/* s390 */
	if (priv->subchannels_dbus)
		g_object_set (s_wired, NM_SETTING_WIRED_S390_SUBCHANNELS, priv->subchannels_dbus, NULL);
	if (priv->s390_nettype)
		g_object_set (s_wired, NM_SETTING_WIRED_S390_NETTYPE, priv->s390_nettype, NULL);

	_nm_setting_wired_clear_s390_options (s_wired);
	g_hash_table_iter_init (&iter, priv->s390_options);
	while (g_hash_table_iter_next (&iter, &key, &value))
		nm_setting_wired_add_s390_option (s_wired, (const char *) key, (const char *) value);
}

static void
link_speed_update (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	guint32 speed;

	if (!nm_platform_ethtool_get_link_settings (nm_device_get_platform (device), nm_device_get_ifindex (device), NULL, &speed, NULL))
		return;
	if (priv->speed == speed)
		return;

	priv->speed = speed;
	_LOGD (LOGD_PLATFORM | LOGD_ETHER, "speed is now %d Mb/s", speed);
	_notify (self, PROP_SPEED);
}

static void
carrier_changed_notify (NMDevice *device, gboolean carrier)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	if (priv->dcb_handle_carrier_changes) {
		nm_assert (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG);

		if (priv->dcb_timeout_id) {
			_LOGD (LOGD_DCB, "carrier_changed() calling dcb_state()");
			dcb_state (device, FALSE);
		}
	}

	if (carrier)
		link_speed_update (device);

	NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->carrier_changed_notify (device, carrier);
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->link_changed (device, pllink);
	if (pllink->initialized)
		_update_s390_subchannels ((NMDeviceEthernet *) device);
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->is_available (device, flags))
		return FALSE;

	return !!nm_device_get_initial_hw_address (device);
}

static gboolean
can_reapply_change (NMDevice *device,
                    const char *setting_name,
                    NMSetting *s_old,
                    NMSetting *s_new,
                    GHashTable *diffs,
                    GError **error)
{
	NMDeviceClass *device_class;

	/* Only handle wired setting here, delegate other settings to parent class */
	if (nm_streq (setting_name, NM_SETTING_WIRED_SETTING_NAME)) {
		return nm_device_hash_check_invalid_keys (diffs,
		                                          NM_SETTING_WIRED_SETTING_NAME,
		                                          error,
		                                          NM_SETTING_WIRED_MTU, /* reapplied with IP config */
		                                          NM_SETTING_WIRED_SPEED,
		                                          NM_SETTING_WIRED_DUPLEX,
		                                          NM_SETTING_WIRED_AUTO_NEGOTIATE,
		                                          NM_SETTING_WIRED_WAKE_ON_LAN,
		                                          NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD);
	}

	device_class = NM_DEVICE_CLASS (nm_device_ethernet_parent_class);
	return device_class->can_reapply_change (device,
	                                         setting_name,
	                                         s_old,
	                                         s_new,
	                                         diffs,
	                                         error);
}

static void
reapply_connection (NMDevice *device, NMConnection *con_old, NMConnection *con_new)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);

	NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->reapply_connection (device,
	                                                                       con_old,
	                                                                       con_new);

	_LOGD (LOGD_DEVICE, "reapplying wired settings");

	link_negotiation_set (device);
	wake_on_lan_enable (device);
}

static void
dispose (GObject *object)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	wired_secrets_cancel (self);

	supplicant_interface_release (self);

	nm_clear_g_source (&priv->pppoe_wait_id);

	nm_clear_g_source (&priv->dcb_timeout_id);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	g_clear_object (&priv->supplicant.mgr);
	g_free (priv->subchan1);
	g_free (priv->subchan2);
	g_free (priv->subchan3);
	g_free (priv->subchannels);
	g_strfreev (priv->subchannels_dbus);
	g_free (priv->s390_nettype);
	g_hash_table_destroy (priv->s390_options);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_SPEED:
		g_value_set_uint (value, priv->speed);
		break;
	case PROP_S390_SUBCHANNELS:
		g_value_set_boxed (value, priv->subchannels_dbus);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static const NMDBusInterfaceInfoExtended interface_info_device_wired = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_WIRED,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress",       "s",  NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("PermHwAddress",   "s",  NM_DEVICE_PERM_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Speed",           "u",  NM_DEVICE_ETHERNET_SPEED),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("S390Subchannels", "as", NM_DEVICE_ETHERNET_S390_SUBCHANNELS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Carrier",         "b",  NM_DEVICE_CARRIER),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_ethernet_class_init (NMDeviceEthernetClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceEthernetPrivate));

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_wired);

	device_class->connection_type_supported = NM_SETTING_WIRED_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_ETHERNET);

	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->complete_connection = complete_connection;
	device_class->new_default_connection = new_default_connection;

	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage2_config = act_stage2_config;
	device_class->act_stage3_ip_config_start = act_stage3_ip_config_start;
	device_class->get_configured_mtu = get_configured_mtu;
	device_class->deactivate = deactivate;
	device_class->get_s390_subchannels = get_s390_subchannels;
	device_class->update_connection = update_connection;
	device_class->carrier_changed_notify = carrier_changed_notify;
	device_class->link_changed = link_changed;
	device_class->is_available = is_available;
	device_class->can_reapply_change = can_reapply_change;
	device_class->reapply_connection = reapply_connection;

	device_class->state_changed = device_state_changed;

	obj_properties[PROP_SPEED] =
	    g_param_spec_uint (NM_DEVICE_ETHERNET_SPEED, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_S390_SUBCHANNELS] =
	    g_param_spec_boxed (NM_DEVICE_ETHERNET_S390_SUBCHANNELS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_ETHERNET_DEVICE_FACTORY (nm_ethernet_device_factory_get_type ())
#define NM_ETHERNET_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ETHERNET_DEVICE_FACTORY, NMEthernetDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_ETHERNET,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Ethernet",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_ETHERNET,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_ETHERNET,
	                                  NULL);
}

static gboolean
match_connection (NMDeviceFactory *factory, NMConnection *connection)
{
	const char *type = nm_connection_get_connection_type (connection);
	NMSettingPppoe *s_pppoe;

	if (nm_streq (type, NM_SETTING_WIRED_SETTING_NAME))
		return TRUE;

	nm_assert (nm_streq (type, NM_SETTING_PPPOE_SETTING_NAME));
	s_pppoe = nm_connection_get_setting_pppoe (connection);

	return !nm_setting_pppoe_get_parent (s_pppoe);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (ETHERNET, Ethernet, ethernet,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_ETHERNET)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_PPPOE_SETTING_NAME),
	factory_class->create_device = create_device;
	factory_class->match_connection = match_connection;
);
