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
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdlib.h>

#include "nm-device-802-3-ethernet.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "NetworkManagerMain.h"
#include "nm-activation-request.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerPolicy.h"
#include "nm-supplicant-manager.h"
#include "nm-utils.h"
#include "kernel-types.h"

#define NM_DEVICE_802_3_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetPrivate))

struct _NMDevice8023EthernetPrivate
{
	gboolean	dispose_has_run;

	struct ether_addr	hw_addr;
	char *			carrier_file_path;
	gulong			link_connected_id;
	gulong			link_disconnected_id;
	guint           link_source_id;

	NMSupplicantInterface *  sup_iface;
};

static gboolean supports_mii_carrier_detect (NMDevice8023Ethernet *dev);
static gboolean supports_ethtool_carrier_detect (NMDevice8023Ethernet *dev);

static void	nm_device_802_3_ethernet_link_activated (NmNetlinkMonitor *monitor,
                                                        GObject *obj,
                                                        NMDevice8023Ethernet *self);
static void	nm_device_802_3_ethernet_link_deactivated (NmNetlinkMonitor *monitor,
                                                          GObject *obj,
                                                          NMDevice8023Ethernet *self);

static void supplicant_iface_state_cb (NMSupplicantInterface * iface,
                                       guint32 new_state,
                                       guint32 old_state,
                                       NMDevice80211Wireless *self);


static void
nm_device_802_3_ethernet_init (NMDevice8023Ethernet * self)
{
	self->priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self);
	self->priv->dispose_has_run = FALSE;
	self->priv->link_source_id = 0;

	memset (&(self->priv->hw_addr), 0, sizeof (struct ether_addr));

	nm_device_set_device_type (NM_DEVICE (self), DEVICE_TYPE_802_3_ETHERNET);
}

static void
real_init (NMDevice *dev)
{
	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (dev);
	NMData *				app_data;
	NmNetlinkMonitor *		monitor;
	NMSupplicantManager *   sup_mgr;

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	monitor = app_data->netlink_monitor;

	self->priv->link_connected_id = 
			g_signal_connect (G_OBJECT (monitor), "interface-connected",
				G_CALLBACK (nm_device_802_3_ethernet_link_activated), self);

	self->priv->link_disconnected_id = 
			g_signal_connect (G_OBJECT (monitor), "interface-disconnected",
				G_CALLBACK (nm_device_802_3_ethernet_link_deactivated), self);

	sup_mgr = nm_supplicant_manager_get ();
	self->priv->sup_iface = nm_supplicant_manager_get_iface (sup_mgr,
															 nm_device_get_iface (NM_DEVICE (self)),
															 FALSE);
	if (self->priv->sup_iface == NULL) {
		nm_warning ("Couldn't initialize supplicant interface for %s.",
		            nm_device_get_iface (NM_DEVICE (self)));
	} else {
		g_signal_connect (G_OBJECT (self->priv->sup_iface),
		                  "state",
		                  G_CALLBACK (supplicant_iface_state_cb),
		                  self);
	}
	g_object_unref (sup_mgr);
}

static void
nm_device_802_3_ethernet_link_activated (NmNetlinkMonitor *monitor,
                                         GObject *obj,
                                         NMDevice8023Ethernet *self)
{
	NMDevice * dev = NM_DEVICE (self);

	/* Make sure signal is for us */
	if (dev != NM_DEVICE (obj))
		return;

	nm_device_set_active_link (dev, TRUE);
}


static void
nm_device_802_3_ethernet_link_deactivated (NmNetlinkMonitor *monitor,
                                           GObject *obj,
                                           NMDevice8023Ethernet *self)
{
	NMDevice * dev = NM_DEVICE (self);

	/* Make sure signal is for us */
	if (dev != NM_DEVICE (obj))
		return;

	nm_device_set_active_link (dev, FALSE);
}

static gboolean
probe_link (NMDevice8023Ethernet *self)
{
	gboolean				have_link = FALSE;
	gchar *				contents;
	gsize				length;

	if (nm_device_get_removed (NM_DEVICE (self)))
		return FALSE;

	if (g_file_get_contents (self->priv->carrier_file_path, &contents, &length, NULL))
	{
		have_link = (gboolean) atoi (contents);
		g_free (contents);
	}

	/* We say that non-carrier-detect devices always have a link, because
	 * they never get auto-selected by NM.  The user has to force them on us,
	 * so we just hope the user knows whether or not the cable's plugged in.
	 */
	if (!have_link && !(nm_device_get_capabilities (NM_DEVICE (self)) & NM_DEVICE_CAP_CARRIER_DETECT))
		have_link = TRUE;

	return have_link;
}


static void
real_update_link (NMDevice *dev)
{
	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (dev);

	nm_device_set_active_link (NM_DEVICE (self), probe_link (self));
}


/*
 * nm_device_802_3_periodic_update
 *
 * Periodically update device statistics and link state.
 *
 */
static gboolean
nm_device_802_3_periodic_update (gpointer data)
{
	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (data);

	g_return_val_if_fail (self != NULL, TRUE);

	nm_device_set_active_link (NM_DEVICE (self), probe_link (self));

	return TRUE;
}


static void
real_start (NMDevice *dev)
{
	NMDevice8023Ethernet * self = NM_DEVICE_802_3_ETHERNET (dev);
	guint                  id;

	self->priv->carrier_file_path = g_strdup_printf ("/sys/class/net/%s/carrier",
			nm_device_get_iface (NM_DEVICE (dev)));

	/* Peridoically update link status */
	id = g_timeout_add (2000, nm_device_802_3_periodic_update, self);
	self->priv->link_source_id = id;
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

	memcpy (addr, &(self->priv->hw_addr), sizeof (struct ether_addr));
}


static void
real_set_hw_address (NMDevice *dev)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (dev);
	struct ifreq req;
	NMSock *sk;
	int ret;

	sk = nm_dev_sock_open (dev, DEV_GENERAL, __FUNCTION__, NULL);
	if (!sk)
		return;

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), sizeof (req.ifr_name) - 1);

	ret = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFHWADDR, &req);
	if (ret == 0)
		memcpy (&(self->priv->hw_addr), &(req.ifr_hwaddr.sa_data), sizeof (struct ether_addr));

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
nm_device_802_3_ethernet_dispose (GObject *object)
{
	NMDevice8023Ethernet *		self = NM_DEVICE_802_3_ETHERNET (object);
	NMDevice8023EthernetClass *	klass = NM_DEVICE_802_3_ETHERNET_GET_CLASS (object);
	NMDeviceClass *			parent_class;  
	NMData *					data = nm_device_get_app_data (NM_DEVICE (self));
	NMSupplicantManager *       sup_mgr;

	if (self->priv->dispose_has_run)
		/* If dispose did already run, return. */
		return;

	/* Make sure dispose does not run twice. */
	self->priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */
	sup_mgr = nm_supplicant_manager_get ();
	nm_supplicant_manager_release_iface (sup_mgr, self->priv->sup_iface);
	self->priv->sup_iface = NULL;
	g_object_unref (sup_mgr);

	g_signal_handler_disconnect (G_OBJECT (data->netlink_monitor),
		self->priv->link_connected_id);
	g_signal_handler_disconnect (G_OBJECT (data->netlink_monitor),
		self->priv->link_disconnected_id);

	if (self->priv->link_source_id) {
		g_source_remove (self->priv->link_source_id);
		self->priv->link_source_id = 0;
	}

	/* Chain up to the parent class */
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	G_OBJECT_CLASS (parent_class)->dispose (object);
}

static void
nm_device_802_3_ethernet_finalize (GObject *object)
{
	NMDevice8023Ethernet *		self = NM_DEVICE_802_3_ETHERNET (object);
	NMDevice8023EthernetClass *	klass = NM_DEVICE_802_3_ETHERNET_GET_CLASS (object);
	NMDeviceClass *			parent_class;  

	g_free (self->priv->carrier_file_path);

	/* Chain up to the parent class */
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	G_OBJECT_CLASS (parent_class)->finalize (object);
}


static void
nm_device_802_3_ethernet_class_init (NMDevice8023EthernetClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDevice8023EthernetPrivate));

	/* virtual methods */
	object_class->dispose = nm_device_802_3_ethernet_dispose;
	object_class->finalize = nm_device_802_3_ethernet_finalize;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->init = real_init;
	parent_class->start = real_start;
	parent_class->update_link = real_update_link;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->set_hw_address = real_set_hw_address;
}

GType
nm_device_802_3_ethernet_get_type (void)
{
	static GType type = 0;
	if (type == 0)
	{
		static const GTypeInfo info =
		{
			sizeof (NMDevice8023EthernetClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_device_802_3_ethernet_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMDevice8023Ethernet),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_device_802_3_ethernet_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_DEVICE,
					       "NMDevice8023Ethernet",
					       &info, 0);
	}
	return type;
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
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_GENERAL, __func__, NULL)) == NULL)
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
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_GENERAL, __func__, NULL)) == NULL)
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
	if ((sk = nm_dev_sock_open (NM_DEVICE (self), DEV_GENERAL, __FUNCTION__, NULL)) == NULL)
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
