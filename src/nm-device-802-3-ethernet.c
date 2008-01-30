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
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include "nm-device-802-3-ethernet.h"
#include "nm-device-private.h"
#include "NetworkManagerMain.h"
#include "nm-activation-request.h"
#include "nm-supplicant.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerPolicy.h"
#include "nm-dbus-nmi.h"
#include "nm-utils.h"
#include "kernel-types.h"

#define NM_DEVICE_802_3_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetPrivate))

struct _NMDevice8023EthernetPrivate
{
	gboolean	dispose_has_run;

	char *			carrier_file_path;
	gulong			link_connected_id;
	gulong			link_disconnected_id;
	NMSupplicant *		supplicant;
	GSource *			link_timeout;
	gboolean			failed_8021x;
};

static gboolean supports_mii_carrier_detect (NMDevice8023Ethernet *dev);
static gboolean supports_ethtool_carrier_detect (NMDevice8023Ethernet *dev);

static void	nm_device_802_3_ethernet_link_activated (NmNetlinkMonitor *monitor,
                                                        GObject *obj,
                                                        NMDevice8023Ethernet *self);
static void	nm_device_802_3_ethernet_link_deactivated (NmNetlinkMonitor *monitor,
                                                          GObject *obj,
                                                          NMDevice8023Ethernet *self);

static void remove_link_timeout (NMDevice8023Ethernet *self);


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
	if (!self->priv->failed_8021x)
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

	if (nm_device_get_removed (NM_DEVICE (self)) || self->priv->failed_8021x)
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


static void
real_deactivate_quickly (NMDevice *dev)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (dev);

	if (self->priv->supplicant) {
		g_object_unref (self->priv->supplicant);
		self->priv->supplicant = NULL;
	}

	remove_link_timeout (self);

	self->priv->failed_8021x = FALSE;
	real_update_link (dev);
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

static gboolean
supplicant_send_network_config (NMDevice8023Ethernet *self,
                                NMAPSecurity *security)
{
	gboolean success = FALSE;
	char *response = NULL;
	int nwid;
	struct wpa_ctrl *ctrl;

	ctrl = nm_supplicant_get_ctrl (self->priv->supplicant);
	g_assert (ctrl);

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "AP_SCAN 0"))
		goto out;

	/* Standard network setup info */
	if (!(response = nm_utils_supplicant_request (ctrl, "ADD_NETWORK"))) {
		nm_warning ("Supplicant error for ADD_NETWORK.\n");
		goto out;
	}
	if (sscanf (response, "%i\n", &nwid) != 1)
	{
		nm_warning ("Supplicant error for ADD_NETWORK.  Response: '%s'\n", response);
		g_free (response);
		goto out;
	}
	g_free (response);

	if (!nm_ap_security_write_supplicant_config (security, ctrl, nwid, NM_AP_SECURITY_WRITE_FLAG_WIRED))
		goto out;

	if (nm_device_activation_should_cancel (NM_DEVICE (self)))
		goto out;

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
										"ENABLE_NETWORK %i", nwid))
		goto out;

	success = TRUE;
out:
	return success;
}

static void
remove_link_timeout (NMDevice8023Ethernet *self)
{
	if (self->priv->link_timeout) {
		g_source_destroy (self->priv->link_timeout);
		self->priv->link_timeout = NULL;
	}
}

static void
link_timeout_done (gpointer user_data)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (user_data);

	self->priv->link_timeout = NULL;
}

static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDevice *			dev = NM_DEVICE (user_data);
 	NMDevice8023Ethernet *	self = NM_DEVICE_802_3_ETHERNET (user_data);	
 	NMActRequest *			req = nm_device_get_act_request (dev);
 	NMData *				data = nm_device_get_app_data (dev);

 	/* Disconnect event during initial authentication and credentials
 	 * ARE checked - we are likely to have wrong key.  Ask the user for
 	 * another one.
 	 */
 	if (nm_act_request_get_stage (req) == NM_ACT_STAGE_DEVICE_CONFIG) {
 		/* Association/authentication failed, we must have bad encryption key */
 		nm_info ("Activation (%s/wired): disconnected during association,"
 		         " asking for new key.", nm_device_get_iface (dev));
 		nm_supplicant_remove_timeout (self->priv->supplicant);
 		nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);
 	} else {
 		nm_info ("%s: link timed out.", nm_device_get_iface (dev));
		self->priv->failed_8021x = TRUE;
 		nm_device_set_active_link (dev, FALSE);
 	}

	return FALSE;
}

static gboolean
supplicant_timed_out (gpointer user_data)
{
	NMDevice *dev = NM_DEVICE (user_data);
	NMData *data = nm_device_get_app_data (dev);
	NMActRequest *req = nm_device_get_act_request (dev);

	nm_info ("Activation (%s/): association took too long, asking for new key.", nm_device_get_iface (dev));
	nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);

	return FALSE;
}

static void
supplicant_state_changed (NMSupplicant *supplicant,
					 gboolean connected,
					 gpointer user_data)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (user_data);
	NMDevice *dev = NM_DEVICE (self);
	NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

	if (connected) {
		remove_link_timeout (self);
		nm_device_set_active_link (dev, TRUE);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (req && (nm_act_request_get_stage (req) == NM_ACT_STAGE_DEVICE_CONFIG)) {
			nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) successful.",
				    nm_device_get_iface (dev));
			nm_supplicant_remove_timeout (self->priv->supplicant);
			nm_device_activate_schedule_stage3_ip_config_start (req);
		}
	} else {
		if (nm_device_is_activated (dev) || nm_device_is_activating (dev)) {
			/* Start the link timeout so we allow some time for reauthentication */
			if (!self->priv->link_timeout) {
				self->priv->link_timeout = g_timeout_source_new (8000);
				g_source_set_callback (self->priv->link_timeout,
								   link_timeout_cb,
								   self,
								   link_timeout_done);
				g_source_attach (self->priv->link_timeout, nm_device_get_main_context (dev));
				g_source_unref (self->priv->link_timeout);
			}
		} else
			nm_device_set_active_link (dev, FALSE);
	}
}

static void
supplicant_down (NMSupplicant *supplicant,
			  gpointer user_data)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (user_data);

	remove_link_timeout (self);
}

static NMActStageReturn
real_act_stage2_config (NMDevice *dev, NMActRequest *req)
{
	NMDevice8023Ethernet *self = NM_DEVICE_802_3_ETHERNET (dev);
	NMWiredNetwork *wired_net;
	NMAPSecurity *security;
	const char *iface;
	GMainContext *ctx;

	if (self->priv->supplicant)
		g_object_unref (self->priv->supplicant);

	wired_net = nm_act_request_get_wired_network (req);
	if (!wired_net)
		return NM_ACT_STAGE_RETURN_SUCCESS;

	iface = nm_device_get_iface (dev);
	security = nm_wired_network_get_security (wired_net);

	if (!nm_ap_security_get_key (security)) {
		NMData *data = nm_act_request_get_data (req);

		nm_info ("Activation (%s): using 802.1X authentication, but NO valid key exists. New key needed.", iface);
		nm_dbus_get_user_key_for_network (data->dbus_connection, req, FALSE);

		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	nm_info ("Activation (%s): using 802.1X authentication and a key exists. No new key needed.", iface);

	self->priv->supplicant = nm_supplicant_new ();
	g_signal_connect (self->priv->supplicant, "state-changed",
				   G_CALLBACK (supplicant_state_changed),
				   self);

	g_signal_connect (self->priv->supplicant, "down",
				   G_CALLBACK (supplicant_down),
				   self);

	ctx = nm_device_get_main_context (dev);

	if (!nm_supplicant_exec (self->priv->supplicant, ctx)) {
		nm_warning ("Activation (%s): couldn't start the supplicant.", iface);
		goto out;
	}
	if (!nm_supplicant_interface_init (self->priv->supplicant, iface, "wired")) {
		nm_warning ("Activation (%s): couldn't connect to the supplicant.", iface);
		goto out;
	}
	if (!nm_supplicant_monitor_start (self->priv->supplicant, ctx, 10,
							    supplicant_timed_out, self)) {
		nm_warning ("Activation (%s): couldn't monitor the supplicant.", iface);
		goto out;
	}
	if (!supplicant_send_network_config (self, security)) {
		nm_warning ("Activation (%s): couldn't send security information"
				  " to the supplicant.", iface);
		goto out;
	}

	/* We'll get stage3 started when the supplicant connects */
	return NM_ACT_STAGE_RETURN_POSTPONE;

out:
	g_object_unref (self->priv->supplicant);
	self->priv->supplicant = NULL;

	return NM_ACT_STAGE_RETURN_FAILURE;
}

static void
real_activation_success_handler (NMDevice *dev, NMActRequest *req)
{
	NMWiredNetwork *wired_net;

	wired_net = nm_act_request_get_wired_network (req);
	if (wired_net) {
		NMData *app_data;

		app_data = nm_act_request_get_data (req);
		nm_dbus_update_wired_network_info (app_data->dbus_connection, wired_net);
	}
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
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->deactivate_quickly = real_deactivate_quickly;
	parent_class->activation_success_handler = real_activation_success_handler;

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
