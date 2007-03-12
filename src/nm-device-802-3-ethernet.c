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
#include "nm-netlink-monitor.h"
#include "nm-utils.h"

static gboolean impl_device_802_3_ethernet_activate (NMDevice8023Ethernet *device,
													 gboolean user_requested,
													 GError **err);

#include "nm-device-802-3-ethernet-glue.h"


G_DEFINE_TYPE (NMDevice8023Ethernet, nm_device_802_3_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_802_3_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetPrivate))

typedef struct {
	gboolean	dispose_has_run;

	struct ether_addr	hw_addr;
	char *			carrier_file_path;
	gulong			link_connected_id;
	gulong			link_disconnected_id;

	NMSupplicantInterface *  sup_iface;
} NMDevice8023EthernetPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_SPEED,

	LAST_PROP
};

static gboolean supports_mii_carrier_detect (NMDevice8023Ethernet *dev);
static gboolean supports_ethtool_carrier_detect (NMDevice8023Ethernet *dev);

static void supplicant_iface_state_cb (NMSupplicantInterface * iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       NMDevice80211Wireless *self);


static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_device_802_3_ethernet_parent_class)->constructor (type,
																				  n_construct_params,
																				  construct_params);
	if (!object)
		return NULL;

	NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (object)->carrier_file_path =
		g_strdup_printf ("/sys/class/net/%s/carrier", nm_device_get_iface (NM_DEVICE (object)));

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
nm_device_802_3_ethernet_link_activated (NMNetlinkMonitor *monitor,
                                         const char *iface,
                                         gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);

	/* Make sure signal is for us */
	if (!strcmp (nm_device_get_iface (dev), iface))
		nm_device_set_active_link (dev, TRUE);
}


static void
nm_device_802_3_ethernet_link_deactivated (NMNetlinkMonitor *monitor,
                                           const char *iface,
                                           gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);

	/* Make sure signal is for us */
	if (!strcmp (nm_device_get_iface (dev), iface))
		nm_device_set_active_link (dev, FALSE);
}

static void
real_update_link (NMDevice *dev)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);
	gboolean have_link = FALSE;
	guint32 caps;
	gchar * contents;
	gsize length;

	/* Devices that don't support carrier detect are always "on" and
	 * must be manually chosen by the user.
	 */
	caps = nm_device_get_capabilities (dev);
	if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT)) {
		have_link = TRUE;
		goto out;
	}

	if (g_file_get_contents (priv->carrier_file_path, &contents, &length, NULL)) {
		have_link = atoi (contents) > 0 ? TRUE : FALSE;
		g_free (contents);
	}

out:
	nm_device_set_active_link (dev, have_link);
}


static gboolean
real_is_up (NMDevice *device)
{
	if (!NM_DEVICE_CLASS (nm_device_802_3_ethernet_parent_class)->is_up (device))
		return FALSE;

	return !!NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (device)->sup_iface;
}

static gboolean
real_bring_up (NMDevice *dev)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);
	NMSupplicantManager *sup_mgr;
	const char *iface;
	guint32 caps;

	iface = nm_device_get_iface (dev);
	sup_mgr = nm_supplicant_manager_get ();
	priv->sup_iface = nm_supplicant_manager_get_iface (sup_mgr, iface, FALSE);
	if (!priv->sup_iface) {
		nm_warning ("Couldn't initialize supplicant interface for %s.", iface);
		g_object_unref (sup_mgr);
		return FALSE;
	}

	g_signal_connect (priv->sup_iface,
	                  "state",
	                  G_CALLBACK (supplicant_iface_state_cb),
	                  dev);

	g_object_unref (sup_mgr);

	caps = nm_device_get_capabilities (dev);
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT) {
		/* Only listen to netlink for cards that support carrier detect */
		NMNetlinkMonitor * monitor = nm_netlink_monitor_get ();
		priv->link_connected_id = g_signal_connect (monitor, "interface-connected",
													G_CALLBACK (nm_device_802_3_ethernet_link_activated),
													dev);
		priv->link_disconnected_id = g_signal_connect (monitor, "interface-disconnected",
													   G_CALLBACK (nm_device_802_3_ethernet_link_deactivated),
													   dev);
		g_object_unref (monitor);
	} else {
		priv->link_connected_id = 0;
		priv->link_disconnected_id = 0;
		nm_device_set_active_link (dev, TRUE);
	}

	return TRUE;
}


static void
real_bring_down (NMDevice *dev)
{
	NMDevice8023EthernetPrivate *priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (dev);
	NMSupplicantManager *sup_mgr;
	NMNetlinkMonitor *monitor;

	sup_mgr = nm_supplicant_manager_get ();
	nm_supplicant_manager_release_iface (sup_mgr, priv->sup_iface);
	priv->sup_iface = NULL;
	g_object_unref (sup_mgr);

	monitor = nm_netlink_monitor_get ();
	g_signal_handler_disconnect (monitor, priv->link_connected_id);
	priv->link_connected_id = 0;
	g_signal_handler_disconnect (monitor, priv->link_disconnected_id);
	priv->link_disconnected_id = 0;
	g_object_unref (monitor);
}


NMDevice8023Ethernet *
nm_device_802_3_ethernet_new (const char *iface,
							  const char *udi,
							  const char *driver,
							  gboolean test_dev,
							  NMData *app_data)
{
	GObject *obj;

	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);
	g_return_val_if_fail (app_data != NULL, NULL);

	obj = g_object_new (NM_TYPE_DEVICE_802_3_ETHERNET,
						NM_DEVICE_INTERFACE_UDI, udi,
						NM_DEVICE_INTERFACE_IFACE, iface,
						NM_DEVICE_INTERFACE_DRIVER, driver,
						NM_DEVICE_INTERFACE_APP_DATA, app_data,
						NULL);

	return NM_DEVICE_802_3_ETHERNET (obj);
}


void
nm_device_802_3_ethernet_activate (NMDevice8023Ethernet *self,
								   gboolean user_requested)
{
	NMDevice *device;
	NMActRequest *req;

	g_return_if_fail (NM_IS_DEVICE_802_3_ETHERNET (self));

	device = NM_DEVICE (self);
	req = nm_act_request_new (nm_device_get_app_data (device),
							  device,
							  NULL,
							  user_requested);

	nm_device_activate (device, req);
	nm_act_request_unref (req);
}


static gboolean
impl_device_802_3_ethernet_activate (NMDevice8023Ethernet *device,
									 gboolean user_requested,
									 GError **err)
{
	nm_device_802_3_ethernet_activate (device, user_requested);

	return TRUE;
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
		if (nm_device_has_active_link (dev) == FALSE) {
			interrupt = TRUE;
		}
	}
	return interrupt;
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
		g_value_set_int (value, nm_device_802_3_ethernet_get_speed (device));
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
	object_class->get_property = get_property;
	object_class->finalize = nm_device_802_3_ethernet_finalize;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->bring_down = real_bring_down;
	parent_class->update_link = real_update_link;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->set_hw_address = real_set_hw_address;

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
		 g_param_spec_int (NM_DEVICE_802_3_ETHERNET_SPEED,
						   "Speed",
						   "Speed",
						   0, G_MAXINT32, 0,
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
                           NMDevice80211Wireless *self)
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


int
nm_device_802_3_ethernet_get_speed (NMDevice8023Ethernet *self)
{
	NMSock *			sk;
	struct ifreq		ifr;
	struct ethtool_cmd	edata;
	const char *		iface;
	int				speed = 0;

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
	speed = edata.speed;

out:
	nm_dev_sock_close (sk);
	return speed;
}


/**************************************/
/*    MII capability detection        */
/**************************************/
#include <linux/mii.h>

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
