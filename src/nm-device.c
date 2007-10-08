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

#include "nm-device-interface.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerSystem.h"
#include "nm-dhcp-manager.h"
#include "nm-dbus-manager.h"
#include "nm-named-manager.h"
#include "nm-utils.h"
#include "autoip.h"
#include "nm-netlink.h"

#define NM_ACT_REQUEST_IP4_CONFIG "nm-act-request-ip4-config"

static void device_interface_init (NMDeviceInterface *device_interface_class);

G_DEFINE_TYPE_EXTENDED (NMDevice, nm_device, G_TYPE_OBJECT,
						G_TYPE_FLAG_ABSTRACT,
						G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE,
											   device_interface_init))

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

struct _NMDevicePrivate
{
	gboolean	dispose_has_run;
	gboolean	initialized;

	NMDeviceState state;

	char *			dbus_path;
	char *			udi;
	int				index;   /* Should always stay the same over lifetime of device */
	char *			iface;   /* may change, could be renamed by user */
	NMDeviceType		type;
	guint32			capabilities;
	char *			driver;

	gboolean			link_active;
	guint32			ip4_address;
	struct in6_addr	ip6_address;

	NMActRequest *		act_request;
	guint           act_source_id;
	gulong          secrets_updated_id;
	gulong          secrets_failed_id;

	/* IP configuration info */
	void *			system_config_data;	/* Distro-specific config data (parsed config file, etc) */
	NMIP4Config *		ip4_config;			/* Config from DHCP, PPP, or system config files */
	NMDHCPManager *     dhcp_manager;
	gulong              dhcp_state_sigid;
	gulong              dhcp_timeout_sigid;
};

static gboolean nm_device_activate (NMDeviceInterface *device,
							 NMActRequest *req);

static void	nm_device_activate_schedule_stage5_ip_config_commit (NMDevice *self);
static void nm_device_deactivate (NMDeviceInterface *device);

static void
nm_device_set_address (NMDevice *device)
{
	if (NM_DEVICE_GET_CLASS (device)->set_hw_address)
		NM_DEVICE_GET_CLASS (device)->set_hw_address (device);
}

static void
device_interface_init (NMDeviceInterface *device_interface_class)
{
	/* interface implementation */
	device_interface_class->activate = nm_device_activate;
	device_interface_class->deactivate = nm_device_deactivate;
}


static void
nm_device_init (NMDevice * self)
{
	self->priv = NM_DEVICE_GET_PRIVATE (self);
	self->priv->dispose_has_run = FALSE;
	self->priv->initialized = FALSE;
	self->priv->udi = NULL;
	self->priv->iface = NULL;
	self->priv->index = G_MAXUINT32;
	self->priv->type = DEVICE_TYPE_UNKNOWN;
	self->priv->capabilities = NM_DEVICE_CAP_NONE;
	self->priv->driver = NULL;

	self->priv->link_active = FALSE;
	self->priv->ip4_address = 0;
	memset (&self->priv->ip6_address, 0, sizeof (struct in6_addr));

	self->priv->act_source_id = 0;

	self->priv->system_config_data = NULL;
	self->priv->ip4_config = NULL;

	self->priv->state = NM_DEVICE_STATE_DISCONNECTED;
}


static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDevice *dev;
	NMDevicePrivate *priv;
	NMDBusManager *manager;

	object = G_OBJECT_CLASS (nm_device_parent_class)->constructor (type,
																   n_construct_params,
																   construct_params);
	if (!object)
		return NULL;

	dev = NM_DEVICE (object);
	priv = NM_DEVICE_GET_PRIVATE (dev);

	if (priv->index == G_MAXUINT32) {
		nm_warning ("Interface index is a required constructor property.");
		goto error;
	}

	priv->iface = nm_netlink_index_to_iface (priv->index);
	if (priv->iface == NULL) {
		nm_warning ("(%u): Couldn't get interface name for device, ignoring.",
		            priv->index);
		goto error;
	}

	priv->capabilities |= NM_DEVICE_GET_CLASS (dev)->get_generic_capabilities (dev);
	if (!(priv->capabilities & NM_DEVICE_CAP_NM_SUPPORTED)) {
		nm_warning ("(%s): Device unsupported, ignoring.",
		            nm_device_get_iface (dev));
		goto error;
	}

	/* Grab IP config data for this device from the system configuration files */
	priv->system_config_data = nm_system_device_get_system_config (dev);

	/* Allow distributions to flag devices as disabled */
	if (nm_system_device_get_disabled (dev)) {
		nm_warning ("(%s): Device otherwise managed, ignoring.",
		            nm_device_get_iface (dev));
		goto error;
	}

	nm_print_device_capabilities (dev);

	manager = nm_dbus_manager_get ();
	priv->dbus_path = g_strdup_printf ("%s/%d",
	                                   NM_DBUS_PATH_DEVICE,
	                                   nm_device_get_index (dev));
	if (priv->dbus_path == NULL) {
		nm_warning ("(%s): Not enough memory to initialize device.",
		            nm_device_get_iface (dev));
		goto error;
	}

	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (manager),
										 nm_device_get_dbus_path (dev),
										 object);
	priv->initialized = TRUE;
	return object;

error:
	g_object_unref (dev);
	return NULL;
}


static gboolean
real_is_up (NMDevice *self)
{
	NMSock *		sk;
	struct ifreq	ifr;
	int			err;
	const char *iface;

	iface = nm_device_get_iface (self);
	if ((sk = nm_dev_sock_open (iface, DEV_GENERAL, __FUNCTION__, NULL)) == NULL)
		return FALSE;

	/* Get device's flags */
	strncpy (ifr.ifr_name, iface, sizeof (ifr.ifr_name) - 1);

	nm_ioctl_info ("%s: About to GET IFFLAGS.", iface);
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFFLAGS, &ifr);
	nm_ioctl_info ("%s: Done with GET IFFLAGS.", iface);

	nm_dev_sock_close (sk);
	if (!err)
		return (!((ifr.ifr_flags^IFF_UP) & IFF_UP));

	if (errno != ENODEV) {
		nm_warning ("%s: could not get flags for device %s.  errno = %d", 
		            __func__, iface, errno);
	}

	return FALSE;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return 0;
}


const char *
nm_device_get_dbus_path (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->dbus_path;
}

const char *
nm_device_get_udi (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->udi;
}

guint32
nm_device_get_index (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, G_MAXUINT32);

	return self->priv->index;
}

/*
 * Get/set functions for iface
 */
const char *
nm_device_get_iface (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->iface;
}


/*
 * Get/set functions for driver
 */
const char *
nm_device_get_driver (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->driver;
}


/*
 * Get/set functions for type
 */
NMDeviceType
nm_device_get_device_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), DEVICE_TYPE_UNKNOWN);

	return self->priv->type;
}


void
nm_device_set_device_type (NMDevice *dev, NMDeviceType type)
{
	g_return_if_fail (NM_IS_DEVICE (dev));
	g_return_if_fail (NM_DEVICE_GET_PRIVATE (dev)->type == DEVICE_TYPE_UNKNOWN);

	NM_DEVICE_GET_PRIVATE (dev)->type = type;
}


/*
 * Accessor for capabilities
 */
guint32
nm_device_get_capabilities (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NM_DEVICE_CAP_NONE);

	return self->priv->capabilities;
}

/*
 * Accessor for type-specific capabilities
 */
guint32
nm_device_get_type_capabilities (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NM_DEVICE_CAP_NONE);

	return NM_DEVICE_GET_CLASS (self)->get_type_capabilities (self);
}

static guint32
real_get_type_capabilities (NMDevice *self)
{
	return NM_DEVICE_CAP_NONE;
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

	return self->priv->act_request;
}


/*
 * Get/set functions for link_active
 */
gboolean
nm_device_has_active_link (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return self->priv->link_active;
}

void
nm_device_set_active_link (NMDevice *self,
                           const gboolean link_active)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->link_active != link_active) {
		priv->link_active = link_active;
		g_signal_emit_by_name (self, "carrier-changed", link_active);
	}
}


NMConnection *
nm_device_get_best_connection (NMDevice *dev,
			       GSList *connections,
                               char **specific_object)
{
	guint32 caps;

	g_return_val_if_fail (NM_IS_DEVICE (dev), NULL);
	g_return_val_if_fail (specific_object != NULL, NULL);
	g_return_val_if_fail (*specific_object == NULL, NULL);

	caps = nm_device_get_capabilities (dev);
	/* Don't use devices that SUCK */
	if (!(caps & NM_DEVICE_CAP_NM_SUPPORTED))
		return NULL;

	if (!NM_DEVICE_GET_CLASS (dev)->get_best_connection)
		return NULL;

	return NM_DEVICE_GET_CLASS (dev)->get_best_connection (dev, connections, specific_object);
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
	const char *     iface;
	NMActStageReturn ret;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 1 of 5 (Device Prepare) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage1_prepare (self);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
		goto out;
	} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

	nm_device_activate_schedule_stage2_device_config (self);

out:
	nm_info ("Activation (%s) Stage 1 of 5 (Device Prepare) complete.", iface);
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

	priv->act_source_id = g_idle_add (nm_device_activate_stage1_device_prepare, self);

	nm_info ("Activation (%s) Stage 1 of 5 (Device Prepare) scheduled...",
	         nm_device_get_iface (self));
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev)
{
	/* Nothing to do */
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *dev)
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
	const char *     iface;
	NMActStageReturn ret;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) starting...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_CONFIG);

	if (!nm_device_bring_up (self, FALSE)) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
		goto out;
	}

	ret = NM_DEVICE_GET_CLASS (self)->act_stage2_config (self);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) successful.", iface);

	nm_device_activate_schedule_stage3_ip_config_start (self);

out:
	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) complete.", iface);
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

	priv->act_source_id = g_idle_add (nm_device_activate_stage2_device_config, self);

	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) scheduled...",
	         nm_device_get_iface (self));
}


static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *self)
{
	NMSettingIP4Config *setting;
	NMActRequest *req;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;

	req = nm_device_get_act_request (self);
	setting = (NMSettingIP4Config *) nm_connection_get_setting (nm_act_request_get_connection (req), "ipv4");

	/* If we did not receive IP4 configuration information, default to DHCP */
	if (!setting || setting->manual == FALSE) {
		/* Begin a DHCP transaction on the interface */
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
		gboolean success;

		nm_device_set_use_dhcp (self, TRUE);

		/* DHCP manager will cancel any transaction already in progress and we do not
		   want to cancel this activation if we get "down" state from that. */
		g_signal_handler_block (priv->dhcp_manager, priv->dhcp_state_sigid);

		success = nm_dhcp_manager_begin_transaction (priv->dhcp_manager,
													 nm_device_get_iface (self),
													 45);

		g_signal_handler_unblock (priv->dhcp_manager, priv->dhcp_state_sigid);

		if (success) {
			/* DHCP devices will be notified by the DHCP manager when
			 * stuff happens.	
			 */
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		} else
			ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}


/*
 * nm_device_activate_stage3_ip_config_start
 *
 * Begin IP configuration with either DHCP or static IP.
 *
 */
static gboolean
nm_device_activate_stage3_ip_config_start (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	const char *     iface;
	NMActStageReturn ret;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip_config_start (self);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	nm_device_activate_schedule_stage4_ip_config_get (self);

out:
	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) complete.", iface);
	return FALSE;
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

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	self->priv->act_source_id = g_idle_add (nm_device_activate_stage3_ip_config_start, self);

	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) scheduled.",
	         nm_device_get_iface (self));
}


/*
 * nm_device_new_ip4_autoip_config
 *
 * Build up an IP config with a Link Local address
 *
 */
NMIP4Config *
nm_device_new_ip4_autoip_config (NMDevice *self)
{
	struct in_addr		ip;
	NMIP4Config *		config = NULL;

	g_return_val_if_fail (self != NULL, NULL);

	if (get_autoip (self, &ip))
	{
		#define LINKLOCAL_BCAST		0xa9feffff

		config = nm_ip4_config_new ();
		nm_ip4_config_set_address (config, (guint32)(ip.s_addr));
		nm_ip4_config_set_netmask (config, (guint32)(ntohl (0xFFFF0000)));
		nm_ip4_config_set_broadcast (config, (guint32)(ntohl (LINKLOCAL_BCAST)));
		nm_ip4_config_set_gateway (config, 0);
	}

	return config;
}


static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *self,
                                NMIP4Config **config)
{
	NMActRequest *req;
	NMIP4Config *		real_config = NULL;
	NMActStageReturn	ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMSettingIP4Config *setting;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (nm_device_get_use_dhcp (self)) {
		real_config = nm_dhcp_manager_get_ip4_config (NM_DEVICE_GET_PRIVATE (self)->dhcp_manager,
													  nm_device_get_iface (self));

		if (real_config && nm_ip4_config_get_mtu (real_config) == 0)
			/* If the DHCP server doesn't set the MTU, get it from backend. */
			nm_ip4_config_set_mtu (real_config, nm_system_get_mtu (self));
	} else {
		real_config = nm_ip4_config_new ();
	}

	req = nm_device_get_act_request (self);
	setting = (NMSettingIP4Config *) nm_connection_get_setting (nm_act_request_get_connection (req), "ipv4");

	if (real_config && setting) {
		/* If settings are provided, use them, even if it means overriding the values we got from DHCP */
		nm_ip4_config_set_address (real_config, setting->address);
		nm_ip4_config_set_netmask (real_config, setting->netmask);

		if (setting->gateway)
			nm_ip4_config_set_gateway (real_config, setting->gateway);
	}

	if (real_config) {
		*config = real_config;
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else {
		/* Make sure device is up even if config fails */
		if (!nm_device_bring_up (self, FALSE))
			ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}


/*
 * nm_device_activate_stage4_ip_config_get
 *
 * Retrieve the correct IP config.
 *
 */
static gboolean
nm_device_activate_stage4_ip_config_get (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMIP4Config *    ip4_config = NULL;
	NMActStageReturn ret;
	const char *     iface = NULL;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Get) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_get_ip4_config (self, &ip4_config);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (!ip4_config || (ret == NM_ACT_STAGE_RETURN_FAILURE))
	{
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	g_object_set_data (G_OBJECT (nm_device_get_act_request (self)),
					   NM_ACT_REQUEST_IP4_CONFIG, ip4_config);

	nm_device_activate_schedule_stage5_ip_config_commit (self);

out:
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Get) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage4_ip_config_get
 *
 * Schedule creation of the IP config
 *
 */
void
nm_device_activate_schedule_stage4_ip_config_get (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	priv->act_source_id = g_idle_add (nm_device_activate_stage4_ip_config_get, self);

	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Get) scheduled...",
	         nm_device_get_iface (self));
}


static NMActStageReturn
real_act_stage4_ip_config_timeout (NMDevice *self,
                                   NMIP4Config **config)
{
	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Wired network, no DHCP reply.  Let's get an IP via Zeroconf. */
	nm_info ("No DHCP reply received.  Automatically obtaining IP via Zeroconf.");
	*config = nm_device_new_ip4_autoip_config (self);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}


/*
 * nm_device_activate_stage4_ip_config_timeout
 *
 * Retrieve the correct IP config.
 *
 */
static gboolean
nm_device_activate_stage4_ip_config_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMIP4Config *    ip4_config = NULL;
	const char *     iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Timeout) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip_config_timeout (self, &ip4_config);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
		goto out;
	} else if (!ip4_config || (ret == NM_ACT_STAGE_RETURN_FAILURE)) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	
	g_assert (ip4_config);

	g_object_set_data (G_OBJECT (nm_device_get_act_request (self)),
					   NM_ACT_REQUEST_IP4_CONFIG, ip4_config);

	nm_device_activate_schedule_stage5_ip_config_commit (self);

out:
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Timeout) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage4_ip_config_timeout
 *
 * Deal with a timed out DHCP transaction
 *
 */
void
nm_device_activate_schedule_stage4_ip_config_timeout (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	priv->act_source_id = g_idle_add (nm_device_activate_stage4_ip_config_timeout, self);

	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Timeout) scheduled...",
	         nm_device_get_iface (self));
}


/*
 * nm_device_activate_stage5_ip_config_commit
 *
 * Commit the IP config on the device
 *
 */
static gboolean
nm_device_activate_stage5_ip_config_commit (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMIP4Config *  ip4_config = NULL;
	const char *   iface;

	ip4_config = g_object_get_data (G_OBJECT (nm_device_get_act_request (self)),
									NM_ACT_REQUEST_IP4_CONFIG);
	g_assert (ip4_config);

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) started...",
	         iface);

	nm_device_set_ip4_config (self, ip4_config);
	if (nm_system_device_set_from_ip4_config (self)) {
		nm_device_update_ip4_address (self);
		nm_system_device_add_ip6_link_address (self);
		nm_system_restart_mdns_responder ();
		nm_system_set_hostname (self->priv->ip4_config);
		nm_system_activate_nis (self->priv->ip4_config);
		nm_system_set_mtu (self);

		if (NM_DEVICE_GET_CLASS (self)->update_link)
			NM_DEVICE_GET_CLASS (self)->update_link (self);

		nm_device_state_changed (self, NM_DEVICE_STATE_ACTIVATED);
	} else {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
	}

	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) complete.",
	         iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage5_ip_config_commit
 *
 * Schedule commit of the IP config
 */
static void
nm_device_activate_schedule_stage5_ip_config_commit (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	priv->act_source_id = g_idle_add (nm_device_activate_stage5_ip_config_commit, self);

	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) scheduled...",
	         nm_device_get_iface (self));
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

	g_object_unref (priv->act_request);
	priv->act_request = NULL;
}

static void
real_activation_cancel_handler (NMDevice *self)
{
	if (nm_device_get_state (self) == NM_DEVICE_STATE_IP_CONFIG  &&
		nm_device_get_use_dhcp (self)) {

		nm_dhcp_manager_cancel_transaction (NM_DEVICE_GET_PRIVATE (self)->dhcp_manager,
											nm_device_get_iface (self));
	}
}


/*
 * nm_device_activation_cancel
 *
 * Signal activation worker that it should stop and die.
 *
 */
void
nm_device_activation_cancel (NMDevice *self)
{
	NMDeviceClass *klass;

	g_return_if_fail (self != NULL);

	if (!nm_device_is_activating (self))
		return;

	nm_info ("Activation (%s): cancelling...", nm_device_get_iface (self));

	/* Break the activation chain */
	if (self->priv->act_source_id) {
		g_source_remove (self->priv->act_source_id);
		self->priv->act_source_id = 0;
	}

	klass = NM_DEVICE_CLASS (g_type_class_peek (NM_TYPE_DEVICE));
	if (klass->activation_cancel_handler)
		klass->activation_cancel_handler (self);

	clear_act_request (self);

	nm_info ("Activation (%s): cancelled.", nm_device_get_iface (self));
}


/*
 * nm_device_deactivate_quickly
 *
 * Quickly deactivate a device, for things like sleep, etc.  Doesn't
 * clean much stuff up, and nm_device_deactivate() should be called
 * on the device eventually.
 *
 */
gboolean
nm_device_deactivate_quickly (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	nm_system_shutdown_nis ();

	if (nm_device_is_activating (self))
		nm_device_activation_cancel (self);

	/* Stop any ongoing DHCP transaction on this device */
	if (nm_device_get_act_request (self) && nm_device_get_use_dhcp (self)) {
		nm_dhcp_manager_cancel_transaction (NM_DEVICE_GET_PRIVATE (self)->dhcp_manager,
											nm_device_get_iface (self));		
	}

	/* Tear down an existing activation request, which may not have happened
	 * in nm_device_activation_cancel() above, for various reasons.
	 */
	clear_act_request (self);

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate_quickly)
		NM_DEVICE_GET_CLASS (self)->deactivate_quickly (self);

	return TRUE;
}

/*
 * nm_device_deactivate
 *
 * Remove a device's routing table entries and IP address.
 *
 */
static void
nm_device_deactivate (NMDeviceInterface *device)
{
	NMDevice *self = NM_DEVICE (device);
	NMIP4Config *	config;
	NMNamedManager * named_mgr;

	g_return_if_fail (self != NULL);

	nm_info ("Deactivating device %s.", nm_device_get_iface (self));

	nm_device_deactivate_quickly (self);

	/* Remove any device nameservers and domains */
	if ((config = nm_device_get_ip4_config (self))) {
		named_mgr = nm_named_manager_get ();
		nm_named_manager_remove_ip4_config (named_mgr, config);
		nm_device_set_ip4_config (self, NULL);
		g_object_unref (named_mgr);
	}

	/* Take out any entries in the routing table and any IP address the device had. */
	nm_system_device_flush_routes (self);
	nm_system_device_flush_addresses (self);
	nm_device_update_ip4_address (self);	

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate)
		NM_DEVICE_GET_CLASS (self)->deactivate (self);

	nm_device_state_changed (self, NM_DEVICE_STATE_DISCONNECTED);
}

static void
connection_secrets_updated_cb (NMActRequest *req,
                               NMConnection *connection,
                               const char *setting_name,
                               gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	if (NM_DEVICE_GET_CLASS (self)->connection_secrets_updated)
		NM_DEVICE_GET_CLASS (self)->connection_secrets_updated (self, connection, setting_name);
}

static void
connection_secrets_failed_cb (NMActRequest *req,
                              NMConnection *connection,
                              const char *setting_name,
                              gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);
}

static gboolean
device_activation_precheck (NMDevice *self, NMConnection *connection)
{
	NMConnection *current_connection;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (!NM_DEVICE_GET_CLASS (self)->check_connection (self, connection))
		/* connection is invalid */
		return FALSE;

	if (nm_device_get_state (self) != NM_DEVICE_STATE_ACTIVATED)
		return TRUE;

	if (!nm_device_is_activating (self))
		return TRUE;

	current_connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	if (nm_connection_compare (connection, current_connection))
		/* Already activating or activated with the same connection */
		return FALSE;

	return TRUE;
}

static gboolean
nm_device_activate (NMDeviceInterface *device,
				NMActRequest *req)
{
	NMDevice *self = NM_DEVICE (device);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!device_activation_precheck (self, nm_act_request_get_connection (req)))
		return FALSE;

	priv->act_request = g_object_ref (req);
	priv->secrets_updated_id = g_signal_connect (req,
										"connection-secrets-updated",
										G_CALLBACK (connection_secrets_updated_cb),
										device);
	priv->secrets_failed_id = g_signal_connect (req,
									    "connection-secrets-failed",
									    G_CALLBACK (connection_secrets_failed_cb),
									    device);

	/* HACK: update the state a bit early to avoid a race between the 
	 * scheduled stage1 handler and nm_policy_device_change_check() thinking
	 * that the activation request isn't deferred because the deferred bit
	 * gets cleared a bit too early, when the connection becomes valid.
	 */
	nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE);
	nm_device_activate_schedule_stage1_device_prepare (self);

	return TRUE;
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

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	switch (nm_device_get_state (device)) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
		return TRUE;
		break;
	default:
		break;
	}

	/* There's a small race between the time when stage 1 is scheduled
	 * and when the device actually sets STATE_PREPARE when the activation
	 * handler is actually run.  If there's an activation handler scheduled
	 * we're activating anyway.
	 */
	if (priv->act_source_id)
		return TRUE;

	return FALSE;
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

static void
dhcp_state_changed (NMDHCPManager *dhcp_manager,
					const char *iface,
					NMDHCPState state,
					gpointer user_data)
{
	NMDevice * device = NM_DEVICE (user_data);

	if (strcmp (nm_device_get_iface (device), iface) != 0)
		return;

	if (!nm_device_get_act_request (device))
		return;

	switch (state) {
	case DHC_BOUND:	/* lease obtained */
	case DHC_RENEW:	/* lease renewed */
	case DHC_REBOOT:	/* have valid lease, but now obtained a different one */
	case DHC_REBIND:	/* new, different lease */
		if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_activate_schedule_stage4_ip_config_get (device);
		break;
	case DHC_TIMEOUT: /* timed out contacting DHCP server */
		if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_activate_schedule_stage4_ip_config_timeout (device);
		break;
	case DHC_FAIL: /* all attempts to contact server timed out, sleeping */
	case DHC_ABEND: /* dhclient exited abnormally */
	case DHC_END: /* dhclient exited normally */
		if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG) {
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED);
		} else if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
			if (nm_device_get_use_dhcp (device)) {
				/* dhclient quit and therefore can't renew our lease, kill the conneciton */
				nm_device_deactivate (NM_DEVICE_INTERFACE (device));
			}
		}
		break;
	default:
		break;
	}
}

static void
dhcp_timeout (NMDHCPManager *dhcp_manager,
              const char *iface,
              gpointer user_data)
{
	NMDevice * device = NM_DEVICE (user_data);

	if (strcmp (nm_device_get_iface (device), iface) != 0)
		return;

	if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_activate_schedule_stage4_ip_config_timeout (device);
}

gboolean
nm_device_get_use_dhcp (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_PRIVATE (self)->dhcp_manager ? TRUE : FALSE;
}

void
nm_device_set_use_dhcp (NMDevice *self,
                        gboolean use_dhcp)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (use_dhcp) {
		if (!priv->dhcp_manager) {
			priv->dhcp_manager = nm_dhcp_manager_get ();
			priv->dhcp_state_sigid = g_signal_connect (priv->dhcp_manager,
			                                           "state-changed",
			                                           G_CALLBACK (dhcp_state_changed),
			                                           self);
			priv->dhcp_timeout_sigid = g_signal_connect (priv->dhcp_manager,
			                                             "timeout",
			                                             G_CALLBACK (dhcp_timeout),
			                                             self);
		}
	} else if (priv->dhcp_manager) {
		g_signal_handler_disconnect (priv->dhcp_manager, priv->dhcp_state_sigid);
		priv->dhcp_state_sigid = 0;
		g_signal_handler_disconnect (priv->dhcp_manager, priv->dhcp_timeout_sigid);
		priv->dhcp_timeout_sigid = 0;
		g_object_unref (priv->dhcp_manager);
		priv->dhcp_manager = NULL;
	}
}


NMIP4Config *
nm_device_get_ip4_config (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->ip4_config;
}


void
nm_device_set_ip4_config (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_DEVICE (self));

	if (priv->ip4_config) {
		g_object_unref (priv->ip4_config);
		priv->ip4_config = NULL;
	}

	if (config)
		priv->ip4_config = g_object_ref (config);
}


/*
 * nm_device_get_ip4_address
 *
 * Get a device's IPv4 address
 *
 */
guint32
nm_device_get_ip4_address (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, 0);

	return self->priv->ip4_address;
}


void
nm_device_update_ip4_address (NMDevice *self)
{
	guint32		new_address;
	struct ifreq	req;
	NMSock *		sk;
	int			err;
	const char *	iface;
	
	g_return_if_fail (self  != NULL);

	iface = nm_device_get_iface (self);
	g_return_if_fail (iface != NULL);

	if ((sk = nm_dev_sock_open (iface, DEV_GENERAL, __func__, NULL)) == NULL)
		return;

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, iface, sizeof (req.ifr_name) - 1);

	nm_ioctl_info ("%s: About to GET IFADDR.", iface);
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFADDR, &req);
	nm_ioctl_info ("%s: Done with GET IFADDR.", iface);

	nm_dev_sock_close (sk);
	if (err != 0)
		return;

	new_address = ((struct sockaddr_in *)(&req.ifr_addr))->sin_addr.s_addr;
	if (new_address != nm_device_get_ip4_address (self))
		self->priv->ip4_address = new_address;
}


gboolean
nm_device_is_up (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (NM_DEVICE_GET_CLASS (self)->is_up)
		return NM_DEVICE_GET_CLASS (self)->is_up (self);

	return TRUE;
}

/* I really wish nm_v_wait_for_completion_or_timeout could translate these
 * to first class args instead of a all this void * arg stuff, so these
 * helpers could be nice and _tiny_. */
static gboolean
nm_completion_device_is_up_test (int tries,
                                 nm_completion_args args)
{
	NMDevice *self = NM_DEVICE (args[0]);

	if (nm_device_is_up (self))
		return TRUE;
	return FALSE;
}

gboolean
nm_device_bring_up (NMDevice *self, gboolean wait)
{
	gboolean success;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (nm_device_is_up (self))
		return TRUE;

	nm_info ("Bringing up device %s", nm_device_get_iface (self));

	nm_system_device_set_up_down (self, TRUE);
	nm_device_update_ip4_address (self);
	nm_device_set_address (self);

	if (NM_DEVICE_GET_CLASS (self)->bring_up) {
		success = NM_DEVICE_GET_CLASS (self)->bring_up (self);
		if (!success)
			return FALSE;
	}

	if (wait) {
		nm_completion_args args;

		args[0] = self;
		nm_wait_for_completion (400, G_USEC_PER_SEC / 200, NULL, nm_completion_device_is_up_test, args);
	}

	nm_device_state_changed (self, NM_DEVICE_STATE_DISCONNECTED);

	return TRUE;
}

void
nm_device_bring_down (NMDevice *self, gboolean wait)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	if (!nm_device_is_up (self))
		return;

	nm_info ("Bringing down device %s", nm_device_get_iface (self));

	if (nm_device_get_state (self) == NM_DEVICE_STATE_ACTIVATED)
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (self));

	if (NM_DEVICE_GET_CLASS (self)->bring_down)
		NM_DEVICE_GET_CLASS (self)->bring_down (self);

	nm_system_device_set_up_down (self, FALSE);

	if (wait) {
		nm_completion_args args;

		args[0] = self;
		nm_wait_for_completion (400, G_USEC_PER_SEC / 200, NULL, nm_completion_device_is_up_test, args);
	}

	nm_device_state_changed (self, NM_DEVICE_STATE_DOWN);
}

/*
 * nm_device_get_system_config_data
 *
 * Return distro-specific system configuration data for this device.
 *
 */
void *
nm_device_get_system_config_data (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->system_config_data;
}


static void
nm_device_dispose (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);

	if (self->priv->dispose_has_run) {
		/* If dispose already ran, return. */
		return;
	}

	if (!self->priv->initialized) {
		/* Don't tear down stuff that might not yet be set up */
		goto out;
	}

	/* Make sure dispose does not run twice. */
	self->priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */

	nm_device_bring_down (self, FALSE);

	nm_system_device_free_system_config (self, self->priv->system_config_data);
	nm_device_set_ip4_config (self, NULL);

	clear_act_request (self);

	if (self->priv->act_source_id) {
		g_source_remove (self->priv->act_source_id);
		self->priv->act_source_id = 0;
	}

	nm_device_set_use_dhcp (self, FALSE);

out:
	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
nm_device_finalize (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);

	g_free (self->priv->udi);
	g_free (self->priv->iface);
	g_free (self->priv->driver);

	G_OBJECT_CLASS (nm_device_parent_class)->finalize (object);
}


static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
 
	switch (prop_id) {
	case NM_DEVICE_INTERFACE_PROP_UDI:
		/* construct-only */
		priv->udi = g_strdup (g_value_get_string (value));
		break;
	case NM_DEVICE_INTERFACE_PROP_INDEX:
		priv->index = g_value_get_uint (value);
		break;
	case NM_DEVICE_INTERFACE_PROP_DRIVER:
		priv->driver = g_strdup (g_value_get_string (value));
		break;
	case NM_DEVICE_INTERFACE_PROP_CAPABILITIES:
		priv->capabilities = g_value_get_uint (value);
		break;
	case NM_DEVICE_INTERFACE_PROP_IP4_ADDRESS:
		priv->ip4_address = g_value_get_uint (value);
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
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case NM_DEVICE_INTERFACE_PROP_UDI:
		g_value_set_string (value, priv->udi);
		break;
	case NM_DEVICE_INTERFACE_PROP_INDEX:
		g_value_set_uint (value, priv->index);
		break;
	case NM_DEVICE_INTERFACE_PROP_IFACE:
		g_value_set_string (value, priv->iface);
		break;
	case NM_DEVICE_INTERFACE_PROP_DRIVER:
		g_value_set_string (value, priv->driver);
		break;
	case NM_DEVICE_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case NM_DEVICE_INTERFACE_PROP_IP4_ADDRESS:
		g_value_set_uint (value, priv->ip4_address);
		break;
	case NM_DEVICE_INTERFACE_PROP_IP4_CONFIG:
		g_value_set_object (value, priv->ip4_config);
		break;
	case NM_DEVICE_INTERFACE_PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE:
		g_value_set_uint (value, priv->type);
		break;
	case NM_DEVICE_INTERFACE_PROP_CARRIER:
		g_value_set_boolean (value, priv->link_active);
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
	object_class->dispose = nm_device_dispose;
	object_class->finalize = nm_device_finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->constructor = constructor;

	klass->is_up = real_is_up;
	klass->activation_cancel_handler = real_activation_cancel_handler;
	klass->get_type_capabilities = real_get_type_capabilities;
	klass->get_generic_capabilities = real_get_generic_capabilities;
	klass->act_stage1_prepare = real_act_stage1_prepare;
	klass->act_stage2_config = real_act_stage2_config;
	klass->act_stage3_ip_config_start = real_act_stage3_ip_config_start;
	klass->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	klass->act_stage4_ip_config_timeout = real_act_stage4_ip_config_timeout;

	/* Properties */

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_UDI,
									  NM_DEVICE_INTERFACE_UDI);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_INDEX,
									  NM_DEVICE_INTERFACE_INDEX);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_IFACE,
									  NM_DEVICE_INTERFACE_IFACE);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_DRIVER,
									  NM_DEVICE_INTERFACE_DRIVER);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_CAPABILITIES,
									  NM_DEVICE_INTERFACE_CAPABILITIES);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_IP4_ADDRESS,
									  NM_DEVICE_INTERFACE_IP4_ADDRESS);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_IP4_CONFIG,
									  NM_DEVICE_INTERFACE_IP4_CONFIG);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_STATE,
									  NM_DEVICE_INTERFACE_STATE);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE,
									  NM_DEVICE_INTERFACE_DEVICE_TYPE);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_CARRIER,
									  NM_DEVICE_INTERFACE_CARRIER);
}

void
nm_device_state_changed (NMDevice *device, NMDeviceState state)
{
	const char *iface;
	NMDeviceState old_state;

	g_return_if_fail (NM_IS_DEVICE (device));

	iface = nm_device_get_iface (device);
	old_state = device->priv->state;
	device->priv->state = state;

	g_signal_emit_by_name (device, "state-changed", state);

	switch (state) {
	case NM_DEVICE_STATE_DOWN:
		if (old_state == NM_DEVICE_STATE_ACTIVATED)
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		nm_info ("Activation (%s) successful, device activated.", iface);
		break;
	case NM_DEVICE_STATE_FAILED:
		nm_info ("Activation (%s) failed.", nm_device_get_iface (device));
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
		break;
	default:
		break;
	}
}


NMDeviceState
nm_device_get_state (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (device)->state;
}
