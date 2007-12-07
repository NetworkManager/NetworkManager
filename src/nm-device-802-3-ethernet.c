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
#include <stdlib.h>

#include "nm-device-802-3-ethernet.h"
#include "nm-device-private.h"
#include "NetworkManagerMain.h"
#include "nm-activation-request.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerPolicy.h"
#include "nm-utils.h"
#include "kernel-types.h"

#define NM_DEVICE_802_3_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetPrivate))

struct _NMDevice8023EthernetPrivate
{
	gboolean	dispose_has_run;

	char *			carrier_file_path;
	gulong			link_connected_id;
	gulong			link_disconnected_id;
};

static gboolean supports_mii_carrier_detect (NMDevice8023Ethernet *dev);
static gboolean supports_ethtool_carrier_detect (NMDevice8023Ethernet *dev);

static void	nm_device_802_3_ethernet_link_activated (NmNetlinkMonitor *monitor,
                                                        GObject *obj,
                                                        NMDevice8023Ethernet *self);
static void	nm_device_802_3_ethernet_link_deactivated (NmNetlinkMonitor *monitor,
                                                          GObject *obj,
                                                          NMDevice8023Ethernet *self);


static void
nm_device_802_3_ethernet_init (NMDevice8023Ethernet * self)
{
	self->priv = NM_DEVICE_802_3_ETHERNET_GET_PRIVATE (self);
	self->priv->dispose_has_run = FALSE;
}

static void
real_init (NMDevice *dev)
{
	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (dev);
	NMData *				app_data;
	NmNetlinkMonitor *		monitor;
	guint32				caps;

	app_data = nm_device_get_app_data (NM_DEVICE (self));
	monitor = app_data->netlink_monitor;

	caps = nm_device_get_capabilities (NM_DEVICE (self));
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT) {
		/* Only listen to netlink for cards that support carrier detect */
		self->priv->link_connected_id = 
			g_signal_connect (G_OBJECT (monitor), "interface-connected",
				G_CALLBACK (nm_device_802_3_ethernet_link_activated), self);

		self->priv->link_disconnected_id = 
			g_signal_connect (G_OBJECT (monitor), "interface-disconnected",
				G_CALLBACK (nm_device_802_3_ethernet_link_deactivated), self);

		self->priv->carrier_file_path = g_strdup_printf ("/sys/class/net/%s/carrier",
				nm_device_get_iface (NM_DEVICE (dev)));
	} else {
		self->priv->link_connected_id = 0;
		self->priv->link_disconnected_id = 0;
		self->priv->carrier_file_path = NULL;
		nm_device_set_active_link (NM_DEVICE (dev), TRUE);
	}
}

static gboolean
link_activated_helper (NMDevice8023Ethernet *self)
{
	nm_device_set_active_link (NM_DEVICE (self), TRUE);
	return FALSE;
}

static void
nm_device_802_3_ethernet_link_activated (NmNetlinkMonitor *monitor,
                                         GObject *obj,
                                         NMDevice8023Ethernet *self)
{
	GSource * source;

	/* Make sure signal is for us */
	if (NM_DEVICE (self) != NM_DEVICE (obj))
		return;

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) link_activated_helper, self, NULL);
	g_source_attach (source, nm_device_get_main_context (NM_DEVICE (self)));
	g_source_unref (source);
}


static gboolean
link_deactivated_helper (NMDevice8023Ethernet *self)
{
	nm_device_set_active_link (NM_DEVICE (self), FALSE);
	return FALSE;
}

static void
nm_device_802_3_ethernet_link_deactivated (NmNetlinkMonitor *monitor,
                                           GObject *obj,
                                           NMDevice8023Ethernet *self)
{
	GSource * source;

	/* Make sure signal is for us */
	if (NM_DEVICE (self) != NM_DEVICE (obj))
		return;

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) link_deactivated_helper, self, NULL);
	g_source_attach (source, nm_device_get_main_context (NM_DEVICE (self)));
	g_source_unref (source);
}

static void
real_update_link (NMDevice *dev)
{
	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (dev);
	gboolean	have_link = FALSE;
	guint32	caps;
	gchar *	contents;
	gsize	length;

	if (nm_device_get_removed (NM_DEVICE (self)))
		goto out;

	/* Devices that don't support carrier detect are always "on" and
	 * must be manually chosen by the user.
	 */
	caps = nm_device_get_capabilities (NM_DEVICE (self));
	if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT)) {
		have_link = TRUE;
		goto out;
	}

	if (g_file_get_contents (self->priv->carrier_file_path, &contents, &length, NULL)) {
		have_link = atoi (contents) > 0 ? TRUE : FALSE;
		g_free (contents);
	}

out:
	nm_device_set_active_link (NM_DEVICE (self), have_link);
}


static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (dev);
	guint32		caps = NM_DEVICE_CAP_NONE;
	const char *	udi = NULL;
	char *		usb_test = NULL;
	NMData *		app_data;

	/* cipsec devices are also explicitly unsupported at this time */
	if (strstr (nm_device_get_iface (dev), "cipsec"))
		return NM_DEVICE_CAP_NONE;

	/* Ignore Ethernet-over-USB devices too for the moment (Red Hat #135722) */
	app_data = nm_device_get_app_data (dev);
	udi = nm_device_get_udi (dev);
	if (    libhal_device_property_exists (app_data->hal_ctx, udi, "usb.interface.class", NULL)
		&& (usb_test = libhal_device_get_property_string (app_data->hal_ctx, udi, "usb.interface.class", NULL)))
	{
		libhal_free_string (usb_test);
		return NM_DEVICE_CAP_NONE;
	}

	if (supports_ethtool_carrier_detect (self) || supports_mii_carrier_detect (self))
		caps |= NM_DEVICE_CAP_CARRIER_DETECT;

	caps |= NM_DEVICE_CAP_NM_SUPPORTED;

	return caps;
}


static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev, NMActRequest *req)
{
	NMDevice8023Ethernet * self = NM_DEVICE_802_3_ETHERNET (dev);
	NMDevice8023EthernetClass *	klass;
	NMDeviceClass * parent_class;

	/* Ensure ethernet devices have a link before going further with activation,
	 * partially works around Fedora #194124.
	 */
	if (!nm_device_has_active_link (dev))
		return NM_ACT_STAGE_RETURN_FAILURE;

	/* Chain up to parent */
	klass = NM_DEVICE_802_3_ETHERNET_GET_CLASS (self);
	parent_class = NM_DEVICE_CLASS (g_type_class_peek_parent (klass));
	return parent_class->act_stage1_prepare (dev, req);
}

static void
nm_device_802_3_ethernet_dispose (GObject *object)
{
	NMDevice8023Ethernet *		self = NM_DEVICE_802_3_ETHERNET (object);
	NMDevice8023EthernetClass *	klass = NM_DEVICE_802_3_ETHERNET_GET_CLASS (object);
	NMDeviceClass *			parent_class;  
	NMData *					data = nm_device_get_app_data (NM_DEVICE (self));

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

	if (self->priv->link_connected_id > 0) {
		g_signal_handler_disconnect (G_OBJECT (data->netlink_monitor),
			self->priv->link_connected_id);
	}
	if (self->priv->link_disconnected_id > 0) {
		g_signal_handler_disconnect (G_OBJECT (data->netlink_monitor),
			self->priv->link_disconnected_id);
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

	if (self->priv->carrier_file_path)
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

	object_class->dispose = nm_device_802_3_ethernet_dispose;
	object_class->finalize = nm_device_802_3_ethernet_finalize;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->init = real_init;
	parent_class->update_link = real_update_link;
	parent_class->act_stage1_prepare = real_act_stage1_prepare;

	g_type_class_add_private (object_class, sizeof (NMDevice8023EthernetPrivate));
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
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to ETHTOOL\n", iface);
#endif
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCETHTOOL, &ifr) == -1)
		goto out;

	supports_ethtool = TRUE;

out:
#ifdef IOCTL_DEBUG
	nm_info ("%s: Done with ETHTOOL\n", iface);
#endif
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

#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET MIIREG\n", iface);
#endif
	if (ioctl (nm_dev_sock_get_fd (sk), SIOCGMIIREG, ifr) >= 0)
		val = mii->val_out;
#ifdef IOCTL_DEBUG
	nm_info ("%s: Done with GET MIIREG\n", iface);
#endif

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
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET MIIPHY\n", iface);
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCGMIIPHY, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: Done with GET MIIPHY\n", iface);
#endif
	if (err < 0)
		goto out;

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	bmsr = mdio_read (self, sk, &ifr, MII_BMSR);
	supports_mii = (bmsr != -1) ? TRUE : FALSE;

out:
	nm_dev_sock_close (sk);
	return supports_mii;	
}
