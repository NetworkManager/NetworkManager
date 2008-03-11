/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdlib.h>

#include "nm-device-802-3-ethernet.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-activation-request.h"
#include "NetworkManagerUtils.h"
#include "nm-supplicant-manager.h"
#include "nm-netlink.h"
#include "nm-netlink-monitor.h"
#include "NetworkManagerSystem.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-pppoe.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-utils.h"

#include "nm-device-802-3-ethernet-glue.h"


G_DEFINE_TYPE (NMDevice8023Ethernet, nm_device_802_3_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_802_3_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetPrivate))

typedef struct {
	gboolean	dispose_has_run;

	struct ether_addr	hw_addr;
	char *			carrier_file_path;
	gulong			link_connected_id;
	gulong			link_disconnected_id;

	NMSupplicantInterface *sup_iface;
	gulong			iface_state_id; 

	/* PPPoE */
	NMPPPManager *ppp_manager;
	NMIP4Config  *pending_ip4_config;
} NMDevice8023EthernetPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_SPEED,

	LAST_PROP
};

static guint32 nm_device_802_3_ethernet_get_speed (NMDevice8023Ethernet *self);

static gboolean supports_mii_carrier_detect (NMDevice8023Ethernet *dev);
static gboolean supports_ethtool_carrier_detect (NMDevice8023Ethernet *dev);

static void supplicant_iface_state_cb (NMSupplicantInterface * iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       NMDevice8023Ethernet *self);


static void
nm_device_802_3_ethernet_carrier_on (NMNetlinkMonitor *monitor,
                                     int idx,
                                     gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);
	guint32 caps;

	/* Make sure signal is for us */
	if (nm_netlink_iface_to_index (nm_device_get_iface (dev)) == idx) {
		/* Ignore spurious netlink messages */
		caps = nm_device_get_capabilities (dev);
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			return;

		nm_device_set_carrier (dev, TRUE);
	}
}

static void
nm_device_802_3_ethernet_carrier_off (NMNetlinkMonitor *monitor,
                                      int idx,
                                      gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);
	guint32 caps;

	/* Make sure signal is for us */
	if (nm_netlink_iface_to_index (nm_device_get_iface (dev)) == idx) {
		/* Ignore spurious netlink messages */
		caps = nm_device_get_capabilities (dev);
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			return;

		nm_device_set_carrier (dev, FALSE);
	}
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDevice8023EthernetPrivate * priv;
	NMDevice * dev;
	guint32 caps;

	object = G_OBJECT_CLASS (nm_device_802_3_ethernet_parent_class)->constructor (type,
																   n_construct_params,
																   construct_params);
	if (!object)
		return NULL;

	dev = NM_DEVICE (object);
	priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);

	priv->carrier_file_path = g_strdup_printf ("/sys/class/net/%s/carrier",
	                                           nm_device_get_iface (dev));

	caps = nm_device_get_capabilities (dev);
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT) {
		/* Only listen to netlink for cards that support carrier detect */
		NMNetlinkMonitor * monitor = nm_netlink_monitor_get ();

		priv->link_connected_id = g_signal_connect (monitor, "carrier-on",
										    G_CALLBACK (nm_device_802_3_ethernet_carrier_on),
										    dev);
		priv->link_disconnected_id = g_signal_connect (monitor, "carrier-off",
											  G_CALLBACK (nm_device_802_3_ethernet_carrier_off),
											  dev);

		g_object_unref (monitor);
	} else {
		priv->link_connected_id = 0;
		priv->link_disconnected_id = 0;
		nm_device_set_carrier (dev, TRUE);
	}

	return object;
}

static void
nm_device_802_3_ethernet_init (NMDevice8023Ethernet * self)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self);

	priv->dispose_has_run = FALSE;

	memset (&(priv->hw_addr), 0, sizeof (struct ether_addr));

	nm_device_set_device_type (NM_DEVICE (self), DEVICE_TYPE_802_3_ETHERNET);
}

static void
real_update_link (NMDevice *dev)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);
	gboolean carrier = FALSE;
	guint32 caps;
	gchar * contents;
	gsize length;

	/* Devices that don't support carrier detect are always "on" and
	 * must be manually chosen by the user.
	 */
	caps = nm_device_get_capabilities (dev);
	if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT)) {
		carrier = TRUE;
		goto out;
	}

	if (g_file_get_contents (priv->carrier_file_path, &contents, &length, NULL)) {
		carrier = atoi (contents) > 0 ? TRUE : FALSE;
		g_free (contents);
	}

out:
	nm_device_set_carrier (dev, carrier);
}


static gboolean
real_is_up (NMDevice *device)
{
	/* Try device-specific tests first */
	if (NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (device)->sup_iface)
		return TRUE;

	return NM_DEVICE_CLASS (nm_device_802_3_ethernet_parent_class)->is_up (device);
}

static gboolean
real_bring_up (NMDevice *dev)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);
	NMSupplicantManager *sup_mgr;
	const char *iface;
	gulong id;

	iface = nm_device_get_iface (dev);
	sup_mgr = nm_supplicant_manager_get ();
	priv->sup_iface = nm_supplicant_manager_get_iface (sup_mgr, iface, FALSE);
	if (!priv->sup_iface) {
		nm_warning ("Couldn't initialize supplicant interface for %s.", iface);
		g_object_unref (sup_mgr);
		return FALSE;
	}

	id = g_signal_connect (priv->sup_iface,
	                       "state",
	                       G_CALLBACK (supplicant_iface_state_cb),
	                       NM_DEVICE_802_3_ETHERNET (dev));
	priv->iface_state_id = id;

	g_object_unref (sup_mgr);

	return TRUE;
}


static void
real_bring_down (NMDevice *dev)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);
	NMSupplicantManager *sup_mgr;

	sup_mgr = nm_supplicant_manager_get ();
	if (priv->sup_iface) {
		if (priv->iface_state_id > 0) {
			g_signal_handler_disconnect (priv->sup_iface, priv->iface_state_id);
			priv->iface_state_id = 0;
		}

		nm_supplicant_manager_release_iface (sup_mgr, priv->sup_iface);
		priv->sup_iface = NULL;
	}
	g_object_unref (sup_mgr);
}


NMDevice8023Ethernet *
nm_device_802_3_ethernet_new (const char *udi,
						const char *iface,
						const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice8023Ethernet *) g_object_new (NM_TYPE_DEVICE_802_3_ETHERNET,
										 NM_DEVICE_INTERFACE_UDI, udi,
										 NM_DEVICE_INTERFACE_IFACE, iface,
										 NM_DEVICE_INTERFACE_DRIVER, driver,
										 NULL);
}


/*
 * nm_device_802_3_ethernet_get_address
 *
 * Get a device's hardware address
 *
 */
void
nm_device_802_3_ethernet_get_address (NMDevice8023Ethernet *self, struct ether_addr *addr)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	memcpy (addr, &(NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self)->hw_addr), sizeof (struct ether_addr));
}


static void
real_set_hw_address (NMDevice *dev)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (dev);
	struct ifreq req;
	NMSock *sk;
	int ret;

	sk = nm_dev_sock_open (nm_device_get_iface (dev), DEV_GENERAL, __FUNCTION__, NULL);
	if (!sk)
		return;

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), sizeof (req.ifr_name) - 1);

	ret = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFHWADDR, &req);
	if (ret == 0)
		memcpy (&(NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self)->hw_addr),
				&(req.ifr_hwaddr.sa_data), sizeof (struct ether_addr));

	nm_dev_sock_close (sk);
}
static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (dev);
	guint32		caps = NM_DEVICE_CAP_NONE;

	/* cipsec devices are also explicitly unsupported at this time */
	if (strstr (nm_device_get_iface (dev), "cipsec"))
		return NM_DEVICE_CAP_NONE;

	if (supports_ethtool_carrier_detect (self) || supports_mii_carrier_detect (self))
		caps |= NM_DEVICE_CAP_CARRIER_DETECT;

	caps |= NM_DEVICE_CAP_NM_SUPPORTED;

	return caps;
}

static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	gboolean interrupt = FALSE;

	/* Devices that support carrier detect can interrupt activation
	 * if the link becomes inactive.
	 */
	if (nm_device_get_capabilities (dev) & NM_DEVICE_CAP_CARRIER_DETECT) {
		if (nm_device_get_carrier (dev) == FALSE) {
			interrupt = TRUE;
		}
	}
	return interrupt;
}

static gboolean
real_can_activate (NMDevice *dev, gboolean wireless_enabled)
{
	/* Can't do anything if there isn't a carrier */
	if (!nm_device_get_carrier (dev))
		return FALSE;

	return TRUE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
                               GSList *connections,
                               char **specific_object)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (dev);
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self);
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		NMSettingWired *s_wired;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (strcmp (s_con->type, NM_SETTING_WIRED_SETTING_NAME))
			continue;
		if (!s_con->autoconnect)
			continue;

		s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
		if (!s_wired)
			continue;

		if (s_wired->mac_address) {
			if (memcmp (s_wired->mac_address->data, priv->hw_addr.ether_addr_octet, ETH_ALEN))
				continue;
		}

		return connection;
	}
	return NULL;
}

static void
real_connection_secrets_updated (NMDevice *dev,
						   NMConnection *connection,
						   const char *setting_name)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);

	if (priv->ppp_manager) {
		/* PPPoE */
		nm_ppp_manager_update_secrets (priv->ppp_manager, nm_device_get_iface (dev), connection);
	}
}


/*****************************************************************************/
/* PPPoE */

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_NETWORK:
		nm_device_state_changed (device, NM_DEVICE_STATE_IP_CONFIG);
		break;
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED);
		break;
	case NM_PPP_STATUS_DEAD:
		if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED)
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
		else
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED);
		break;
	default:
		break;
	}
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
			 const char *iface,
			 NMIP4Config *config,
			 gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	nm_device_set_ip_iface (device, iface);
	NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip_config_get (device);
}

static NMActStageReturn
pppoe_stage2_config (NMDevice8023Ethernet *self)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self);
	NMActRequest *req;
	GError *err = NULL;
	NMActStageReturn ret;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	priv->ppp_manager = nm_ppp_manager_new ();
	if (nm_ppp_manager_start (priv->ppp_manager,
						 nm_device_get_iface (NM_DEVICE (self)),
						 req,
						 &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
					   G_CALLBACK (ppp_state_changed),
					   self);
		g_signal_connect (priv->ppp_manager, "ip4-config",
					   G_CALLBACK (ppp_ip4_config),
					   self);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_warning ("%s", err->message);
		g_error_free (err);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

/* FIXME: Move it to nm-device.c and then get rid of all foo_device_get_setting() all around.
   It's here now to keep the patch short. */
static NMSetting *
device_get_setting (NMDevice *device, GType setting_type)
{
	NMActRequest *req;
	NMSetting *setting = NULL;

	req = nm_device_get_act_request (device);
	if (req) {
		NMConnection *connection;

		connection = nm_act_request_get_connection (req);
		if (connection)
			setting = nm_connection_get_setting (connection, setting_type);
	}

	return setting;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device)
{
	NMSettingConnection *s_connection;
	NMActStageReturn ret;

	s_connection = NM_SETTING_CONNECTION (device_get_setting (device, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_connection);

	if (!strcmp (s_connection->type, NM_SETTING_WIRED_SETTING_NAME))
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	else if (!strcmp (s_connection->type, NM_SETTING_PPPOE_SETTING_NAME))
		ret = pppoe_stage2_config (NM_DEVICE_802_3_ETHERNET (device));
	else {
		nm_warning ("Invalid connection type '%s' for ethernet device", s_connection->type);
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device, NMIP4Config **config)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (device);
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self);
	NMActStageReturn ret;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (!priv->ppp_manager) {
		/* Regular ethernet connection. */

		/* Chain up to parent */
		ret = NM_DEVICE_CLASS (nm_device_802_3_ethernet_parent_class)->act_stage4_get_ip4_config (device, config);

		if ((ret == NM_ACT_STAGE_RETURN_SUCCESS)) {
			NMConnection *connection;
			NMSettingWired *s_wired;

			connection = nm_act_request_get_connection (nm_device_get_act_request (device));
			g_assert (connection);
			s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
			g_assert (s_wired);

			/* MTU override */
			if (s_wired->mtu)
				nm_ip4_config_set_mtu (*config, s_wired->mtu);
		}
	} else {
		/* PPPoE */
		*config = priv->pending_ip4_config;
		priv->pending_ip4_config = NULL;
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	}

	return ret;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (device);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}
}

static void
nm_device_802_3_ethernet_dispose (GObject *object)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (object);
	NMNetlinkMonitor *monitor;

	if (priv->dispose_has_run) {
		G_OBJECT_CLASS (nm_device_802_3_ethernet_parent_class)->dispose (object);
		return;
	}

	priv->dispose_has_run = TRUE;

	monitor = nm_netlink_monitor_get ();
	if (priv->link_connected_id) {
		g_signal_handler_disconnect (monitor, priv->link_connected_id);
		priv->link_connected_id = 0;
	}
	if (priv->link_disconnected_id) {
		g_signal_handler_disconnect (monitor, priv->link_disconnected_id);
		priv->link_disconnected_id = 0;
	}
	g_object_unref (monitor);

	G_OBJECT_CLASS (nm_device_802_3_ethernet_parent_class)->dispose (object);
}

static void
nm_device_802_3_ethernet_finalize (GObject *object)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (object);

	g_free (priv->carrier_file_path);

	G_OBJECT_CLASS (nm_device_802_3_ethernet_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMDevice8023Ethernet *device = NM_DEVICE_802_3_ETHERNET (object);
	struct ether_addr hw_addr;
	char hw_addr_buf[20];

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		memset (hw_addr_buf, 0, 20);
		nm_device_802_3_ethernet_get_address (device, &hw_addr);
		iw_ether_ntop (&hw_addr, hw_addr_buf);
		g_value_set_string (value, &hw_addr_buf[0]);
		break;
	case PROP_SPEED:
		g_value_set_uint (value, nm_device_802_3_ethernet_get_speed (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}


static void
nm_device_802_3_ethernet_class_init (NMDevice8023EthernetClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDevice8023EthernetPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = nm_device_802_3_ethernet_dispose;
	object_class->get_property = get_property;
	object_class->finalize = nm_device_802_3_ethernet_finalize;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->bring_down = real_bring_down;
	parent_class->update_link = real_update_link;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->set_hw_address = real_set_hw_address;
	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->can_activate = real_can_activate;
	parent_class->connection_secrets_updated = real_connection_secrets_updated;

	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->deactivate_quickly = real_deactivate_quickly;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_802_3_ETHERNET_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_DEVICE_802_3_ETHERNET_SPEED,
						   "Speed",
						   "Speed",
						   0, G_MAXUINT32, 0,
						   G_PARAM_READABLE));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_802_3_ethernet_object_info);
}


/****************************************************************************
 * WPA Supplicant control stuff
 *
 */
static void
supplicant_iface_state_cb (NMSupplicantInterface * iface,
                           guint32 new_state,
                           guint32 old_state,
                           NMDevice8023Ethernet *self)
{
	g_return_if_fail (self != NULL);

	nm_info ("(%s) supplicant interface is now in state %d (from %d).",
             nm_device_get_iface (NM_DEVICE (self)),
             new_state,
             old_state);
}


/**************************************/
/*    Ethtool capability detection    */
/**************************************/
#include <linux/sockios.h>
#include <linux/ethtool.h>

static gboolean
supports_ethtool_carrier_detect (NMDevice8023Ethernet *self)
{
	NMSock *			sk;
	struct ifreq		ifr;
	gboolean			supports_ethtool = FALSE;
	struct ethtool_cmd	edata;
	const char *		iface;

	g_return_val_if_fail (self != NULL, FALSE);

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (iface, DEV_GENERAL, __func__, NULL)) == NULL)
	{
		nm_warning ("cannot open socket on interface %s for ethtool detect: %s",
				iface, strerror (errno));
		return FALSE;
	}

	strncpy (ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
	edata.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (char *) &edata;

	nm_ioctl_info ("%s: About to ETHTOOL\n", iface);
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCETHTOOL, &ifr) == -1)
		goto out;

	supports_ethtool = TRUE;

out:
	nm_ioctl_info ("%s: Done with ETHTOOL\n", iface);
	nm_dev_sock_close (sk);
	return supports_ethtool;
}


/* Returns speed in Mb/s */
static guint32
nm_device_802_3_ethernet_get_speed (NMDevice8023Ethernet *self)
{
	NMSock *			sk;
	struct ifreq		ifr;
	struct ethtool_cmd	edata;
	const char *		iface;
	guint32				speed = 0;

	g_return_val_if_fail (self != NULL, FALSE);

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (iface, DEV_GENERAL, __func__, NULL)) == NULL)
	{
		nm_warning ("cannot open socket on interface %s for ethtool: %s",
				iface, strerror (errno));
		return FALSE;
	}

	strncpy (ifr.ifr_name, iface, sizeof (ifr.ifr_name) - 1);
	edata.cmd = ETHTOOL_GSET;
	ifr.ifr_data = (char *) &edata;
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCETHTOOL, &ifr) == -1)
		goto out;

	speed = edata.speed != G_MAXUINT16 ? edata.speed : 0;

out:
	nm_dev_sock_close (sk);
	return speed;
}


/**************************************/
/*    MII capability detection        */
/**************************************/
#define _LINUX_IF_H
#include <linux/mii.h>
#undef _LINUX_IF_H

static int
mdio_read (NMDevice8023Ethernet *self, NMSock *sk, struct ifreq *ifr, int location)
{
	struct mii_ioctl_data *mii;
	int val = -1;
	const char *	iface;

	g_return_val_if_fail (sk != NULL, -1);
	g_return_val_if_fail (ifr != NULL, -1);

	iface = nm_device_get_iface (NM_DEVICE (self));

	mii = (struct mii_ioctl_data *) &ifr->ifr_ifru;
	mii->reg_num = location;

	nm_ioctl_info ("%s: About to GET MIIREG\n", iface);
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCGMIIREG, ifr) >= 0)
		val = mii->val_out;
	nm_ioctl_info ("%s: Done with GET MIIREG\n", iface);

	return val;
}

static gboolean
supports_mii_carrier_detect (NMDevice8023Ethernet *self)
{
	NMSock *		sk;
	struct ifreq	ifr;
	int			bmsr;
	gboolean		supports_mii = FALSE;
	int			err;
	const char *	iface;

	g_return_val_if_fail (self != NULL, FALSE);

	iface = nm_device_get_iface (NM_DEVICE (self));
	if ((sk = nm_dev_sock_open (iface, DEV_GENERAL, __FUNCTION__, NULL)) == NULL)
	{
		nm_warning ("cannot open socket on interface %s for MII detect; errno=%d",
				iface, errno);
		return FALSE;
	}

	strncpy (ifr.ifr_name, iface, sizeof (ifr.ifr_name) - 1);
	nm_ioctl_info ("%s: About to GET MIIPHY\n", iface);
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCGMIIPHY, &ifr);
	nm_ioctl_info ("%s: Done with GET MIIPHY\n", iface);

	if (err < 0)
		goto out;

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	bmsr = mdio_read (self, sk, &ifr, MII_BMSR);
	supports_mii = (bmsr != -1) ? TRUE : FALSE;

out:
	nm_dev_sock_close (sk);
	return supports_mii;	
}
