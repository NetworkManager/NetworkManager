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
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

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
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"

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
	guint		start_timer;

	NMDeviceState state;

	char *			udi;
	char *			iface;   /* may change, could be renamed by user */
	char *			ip_iface;
	NMDeviceType		type;
	guint32			capabilities;
	char *			driver;
	gboolean		managed; /* whether managed by NM or not */

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

static gboolean check_connection_compatible (NMDeviceInterface *device,
                                             NMConnection *connection,
                                             GError **error);

static gboolean nm_device_activate (NMDeviceInterface *device,
                                    NMActRequest *req,
                                    GError **error);

static void	nm_device_activate_schedule_stage5_ip_config_commit (NMDevice *self);
static void nm_device_deactivate (NMDeviceInterface *device);

static void
device_interface_init (NMDeviceInterface *device_interface_class)
{
	/* interface implementation */
	device_interface_class->check_connection_compatible = check_connection_compatible;
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
	self->priv->type = DEVICE_TYPE_UNKNOWN;
	self->priv->capabilities = NM_DEVICE_CAP_NONE;
	self->priv->driver = NULL;

	self->priv->ip4_address = 0;
	memset (&self->priv->ip6_address, 0, sizeof (struct in6_addr));

	self->priv->act_source_id = 0;

	self->priv->system_config_data = NULL;
	self->priv->ip4_config = NULL;

	self->priv->state = NM_DEVICE_STATE_UNMANAGED;
}

static gboolean
device_start (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	self->priv->start_timer = 0;
	nm_device_state_changed (self, NM_DEVICE_STATE_UNAVAILABLE);
	return FALSE;
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
		nm_warning ("No device udi provided, ignoring");
		goto error;
	}

	if (!priv->iface) {
		nm_warning ("No device interface provided, ignoring");
		goto error;
	}

	priv->capabilities |= NM_DEVICE_GET_CLASS (dev)->get_generic_capabilities (dev);
	if (!(priv->capabilities & NM_DEVICE_CAP_NM_SUPPORTED)) {
		nm_warning ("(%s): Device unsupported, ignoring.", priv->iface);
		goto error;
	}

	nm_print_device_capabilities (dev);

	/* Delay transition from UNMANAGED to UNAVAILABLE until we've given the
	 * system settings service a chance to figure out whether the device is
	 * managed or not.
	 */
	priv->start_timer = g_timeout_add (4000, device_start, dev);

	priv->initialized = TRUE;
	return object;

error:
	g_object_unref (dev);
	return NULL;
}


static gboolean
real_is_up (NMDevice *self)
{
	struct ifreq ifr;
	const char *iface;
	int err, fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_warning ("couldn't open control socket.");
		return FALSE;
	}

	/* Get device's flags */
	iface = nm_device_get_iface (self);
	strncpy (ifr.ifr_name, iface, IFNAMSIZ);
	err = ioctl (fd, SIOCGIFFLAGS, &ifr);
	close (fd);

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
nm_device_get_udi (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->udi;
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


const char *
nm_device_get_ip_iface (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	/* If it's not set, default to iface */
	return self->priv->ip_iface ? self->priv->ip_iface : self->priv->iface;
}


void
nm_device_set_ip_iface (NMDevice *self, const char *iface)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	g_free (self->priv->ip_iface);
	self->priv->ip_iface = iface ? g_strdup (iface) : NULL;
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


gboolean
nm_device_can_activate (NMDevice *self)
{
	if (NM_DEVICE_GET_CLASS (self)->can_activate)
		return NM_DEVICE_GET_CLASS (self)->can_activate (self);
	return TRUE;
}

NMConnection *
nm_device_get_best_auto_connection (NMDevice *dev,
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

	if (!NM_DEVICE_GET_CLASS (dev)->get_best_auto_connection)
		return NULL;

	return NM_DEVICE_GET_CLASS (dev)->get_best_auto_connection (dev, connections, specific_object);
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
	setting = (NMSettingIP4Config *) nm_connection_get_setting (nm_act_request_get_connection (req),
													NM_TYPE_SETTING_IP4_CONFIG);

	/* If we did not receive IP4 configuration information, default to DHCP */
	if (!setting || !strcmp (setting->method, NM_SETTING_IP4_CONFIG_METHOD_DHCP)) {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
		gboolean success;

		/* Begin a DHCP transaction on the interface */
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

	// FIXME: make our autoip implementation not suck; use avahi-autoip
	if (get_autoip (self, &ip)) {
		#define LINKLOCAL_BCAST		0xa9feffff

		config = nm_ip4_config_new ();
		nm_ip4_config_set_address (config, (guint32)(ip.s_addr));
		nm_ip4_config_set_netmask (config, (guint32)(ntohl (0xFFFF0000)));
		nm_ip4_config_set_broadcast (config, (guint32)(ntohl (LINKLOCAL_BCAST)));
		nm_ip4_config_set_gateway (config, 0);
	}

	return config;
}


static void
merge_ip4_config (NMIP4Config *ip4_config, NMSettingIP4Config *setting)
{
	if (!setting)
		return; /* Defaults are just fine */

	if (setting->dns) {
		int i, j;

		for (i = 0; i < setting->dns->len; i++) {
			guint32 ns;
			gboolean found = FALSE;

			/* Avoid dupes */
			ns = g_array_index (setting->dns, guint32, i);
			for (j = 0; j < nm_ip4_config_get_num_nameservers (ip4_config); j++) {
				if (nm_ip4_config_get_nameserver (ip4_config, j) == ns) {
					found = TRUE;
					break;
				}
			}

			if (!found)
				nm_ip4_config_add_nameserver (ip4_config, ns);
		}
	}

	if (setting->dns_search) {
		GSList *iter;

		for (iter = setting->dns_search; iter; iter = iter->next) {
			int i;
			gboolean found = FALSE;

			/* Avoid dupes */
			for (i = 0; i < nm_ip4_config_get_num_searches (ip4_config); i++) {
				const char *search = nm_ip4_config_get_search (ip4_config, i);

				if (!strcmp (search, (char *) iter->data)) {
					found = TRUE;
					break;
				}
			}

			if (!found)
				nm_ip4_config_add_search (ip4_config, (char *) iter->data);
		}
	}

	if (setting->addresses) {
		/* FIXME; add support for more than one set of address/netmask/gateway for NMIP4Config */
		NMSettingIP4Address *addr = (NMSettingIP4Address *) setting->addresses->data;

		/* Avoid dupes, but override if anything is different */
		if (   (nm_ip4_config_get_address (ip4_config) != addr->address)
		    || (nm_ip4_config_get_netmask (ip4_config) != addr->netmask)
		    || (addr->gateway && (nm_ip4_config_get_gateway (ip4_config) != addr->gateway))) {
			nm_ip4_config_set_address (ip4_config, addr->address);
			nm_ip4_config_set_netmask (ip4_config, addr->netmask);

			if (addr->gateway)
				nm_ip4_config_set_gateway (ip4_config, addr->gateway);
		}
	}
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *self,
                                NMIP4Config **config)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	g_assert (connection);

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);

	if (nm_device_get_use_dhcp (self)) {
		*config = nm_dhcp_manager_get_ip4_config (NM_DEVICE_GET_PRIVATE (self)->dhcp_manager,
											 nm_device_get_iface (self));
		merge_ip4_config (*config, s_ip4);
	} else {
		g_assert (s_ip4);

		if (!strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_AUTOIP)) {
			nm_device_new_ip4_autoip_config (self);
		} else if (!strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			*config = nm_ip4_config_new ();
			merge_ip4_config (*config, s_ip4);
		}
	}

	if (!*config) {
		/* Make sure device is up even if config fails */
		nm_device_bring_up (self, FALSE);
	} else
		ret = NM_ACT_STAGE_RETURN_SUCCESS;

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

	/* DHCP failed; connection must fail */
	return NM_ACT_STAGE_RETURN_FAILURE;
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

	if (nm_device_set_ip4_config (self, ip4_config))
		nm_device_state_changed (self, NM_DEVICE_STATE_ACTIVATED);
	else
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED);

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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	nm_system_shutdown_nis ();

	/* Break the activation chain */
	if (priv->act_source_id) {
		g_source_remove (priv->act_source_id);
		priv->act_source_id = 0;
	}

	/* Stop any ongoing DHCP transaction on this device */
	if (nm_device_get_act_request (self) && nm_device_get_use_dhcp (self)) {
		nm_dhcp_manager_cancel_transaction (priv->dhcp_manager, nm_device_get_iface (self));
		nm_device_set_use_dhcp (self, FALSE);
	}

	/* Tear down an existing activation request */
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

	g_return_if_fail (self != NULL);

	nm_info ("Deactivating device %s.", nm_device_get_iface (self));

	nm_device_deactivate_quickly (self);

	/* Clean up nameservers and addresses */
	nm_device_set_ip4_config (self, NULL);

	/* Take out any entries in the routing table and any IP address the device had. */
	nm_system_device_flush_ip4_routes (self);
	nm_system_device_flush_ip4_addresses (self);
	nm_device_update_ip4_address (self);	

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate)
		NM_DEVICE_GET_CLASS (self)->deactivate (self);
}

static gboolean
check_connection_compatible (NMDeviceInterface *dev_iface,
                             NMConnection *connection,
                             GError **error)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (NM_DEVICE (dev_iface));

	if (klass->check_connection_compatible)
		return klass->check_connection_compatible (NM_DEVICE (dev_iface), connection, error);

	return TRUE;
}

static void
connection_secrets_updated_cb (NMActRequest *req,
                               NMConnection *connection,
                               GSList *updated_settings,
                               gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	if (NM_DEVICE_GET_CLASS (self)->connection_secrets_updated)
		NM_DEVICE_GET_CLASS (self)->connection_secrets_updated (self, connection, updated_settings);
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
device_activation_precheck (NMDevice *self, NMConnection *connection, GError **error)
{
	NMConnection *current_connection;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (nm_device_get_state (self) != NM_DEVICE_STATE_ACTIVATED)
		return TRUE;

	if (!nm_device_is_activating (self))
		return TRUE;

	// FIXME: why not just check connection path & service?
	current_connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	if (nm_connection_compare (connection, current_connection, COMPARE_FLAGS_EXACT)) {
		/* Already activating or activated with the same connection */
		g_set_error (error,
		             NM_DEVICE_INTERFACE_ERROR,
		             NM_DEVICE_INTERFACE_ERROR_CONNECTION_ACTIVATING,
		             "%s", "Connection is already activating");
		return FALSE;
	}

	return TRUE;
}

static gboolean
nm_device_activate (NMDeviceInterface *device,
                    NMActRequest *req,
                    GError **error)
{
	NMDevice *self = NM_DEVICE (device);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!device_activation_precheck (self, nm_act_request_get_connection (req), error)) {
		g_assert (*error);
		return FALSE;
	}

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
handle_dhcp_lease_change (NMDevice *device)
{
	NMIP4Config *config;
	NMSettingIP4Config *s_ip4;
	NMConnection *connection;
	NMActRequest *req;

	if (!nm_device_get_use_dhcp (device)) {
		nm_warning ("got DHCP rebind for device that wasn't using DHCP.");
		return;
	}

	config = nm_dhcp_manager_get_ip4_config (NM_DEVICE_GET_PRIVATE (device)->dhcp_manager,
											 nm_device_get_iface (device));
	if (!config) {
		nm_warning ("failed to get DHCP config for rebind");
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED);
		return;
	}

	req = nm_device_get_act_request (device);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	merge_ip4_config (config, s_ip4);

	g_object_set_data (G_OBJECT (req), NM_ACT_REQUEST_IP4_CONFIG, config);

	if (!nm_device_set_ip4_config (device, config)) {
		nm_warning ("Failed to update IP4 config in response to DHCP event.");
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED);
	}
}

static void
dhcp_state_changed (NMDHCPManager *dhcp_manager,
					const char *iface,
					NMDHCPState state,
					gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceState dev_state;

	if (strcmp (nm_device_get_iface (device), iface) != 0)
		return;

	if (!nm_device_get_act_request (device))
		return;

	dev_state = nm_device_get_state (device);

	switch (state) {
	case DHC_BOUND:	/* lease obtained */
	case DHC_RENEW:	/* lease renewed */
	case DHC_REBOOT:	/* have valid lease, but now obtained a different one */
	case DHC_REBIND:	/* new, different lease */
		if (dev_state == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_activate_schedule_stage4_ip_config_get (device);
		else if (dev_state == NM_DEVICE_STATE_ACTIVATED)
			handle_dhcp_lease_change (device);
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
				nm_device_state_changed (device, NM_DEVICE_STATE_FAILED);
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

	return NM_DEVICE_GET_PRIVATE (self)->ip4_config;
}


gboolean
nm_device_set_ip4_config (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	gboolean route_to_iface;
	gboolean success;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ip4_config) {
		NMNamedManager *named_mgr;

		/* Remove any previous IP4 Config from the named manager */
		named_mgr = nm_named_manager_get ();
		nm_named_manager_remove_ip4_config (named_mgr, priv->ip4_config);
		g_object_unref (named_mgr);

		g_object_unref (priv->ip4_config);
		priv->ip4_config = NULL;
	}

	if (!config)
		return TRUE;

	priv->ip4_config = g_object_ref (config);

	ip_iface = nm_device_get_ip_iface (self);

	/* FIXME: Not sure if the following makes any sense. */
	/* If iface and ip_iface are the same, it's a regular network device and we
	   treat it as such. However, if they differ, it's most likely something like
	   a serial device with ppp interface, so route all the traffic to it. */
	if (strcmp (ip_iface, nm_device_get_iface (self)))
		route_to_iface = TRUE;
	else
		route_to_iface = FALSE;

	success = nm_system_device_set_from_ip4_config (ip_iface, config, route_to_iface);
	if (success) {
		nm_device_update_ip4_address (self);
		nm_system_set_hostname (config);
		nm_system_activate_nis (config);
	}

	g_object_notify (G_OBJECT (self), NM_DEVICE_INTERFACE_IP4_CONFIG);

	return success;
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
	struct ifreq req;
	guint32 new_address;
	int fd, err;
	
	g_return_if_fail (self  != NULL);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_warning ("couldn't open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (self), IFNAMSIZ);
	err = ioctl (fd, SIOCGIFADDR, &req);
	close (fd);

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

gboolean
nm_device_bring_up (NMDevice *self, gboolean wait)
{
	gboolean success;
	guint32 tries = 0;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (nm_device_is_up (self))
		return TRUE;

	nm_info ("Bringing up device %s", nm_device_get_iface (self));

	nm_system_device_set_up_down (self, TRUE);
	nm_device_update_ip4_address (self);

	/* Can only get HW address of some devices when they are up */
	if (NM_DEVICE_GET_CLASS (self)->update_hw_address)
		NM_DEVICE_GET_CLASS (self)->update_hw_address (self);

	if (NM_DEVICE_GET_CLASS (self)->bring_up) {
		success = NM_DEVICE_GET_CLASS (self)->bring_up (self);
		if (!success)
			return FALSE;
	}

	/* Wait for the device to come up if requested */
	while (wait && !nm_device_is_up (self) && (tries++ < 50))
		g_usleep (200);

	return TRUE;
}

void
nm_device_bring_down (NMDevice *self, gboolean wait)
{
	NMDeviceState state;
	guint32 tries = 0;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (!nm_device_is_up (self))
		return;

	nm_info ("Bringing down device %s", nm_device_get_iface (self));

	state = nm_device_get_state (self);
	if ((state == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (self))
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (self));

	if (NM_DEVICE_GET_CLASS (self)->bring_down)
		NM_DEVICE_GET_CLASS (self)->bring_down (self);

	nm_system_device_set_up_down (self, FALSE);

	/* Wait for the device to come up if requested */
	while (wait && nm_device_is_up (self) && (tries++ < 50))
		g_usleep (200);
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

	if (self->priv->dispose_has_run || !self->priv->initialized)
		goto out;

	if (self->priv->start_timer) {
		g_source_remove (self->priv->start_timer);
		self->priv->start_timer = 0;
	}

	self->priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */

	if (self->priv->managed) {
		nm_device_bring_down (self, FALSE);
		nm_device_set_ip4_config (self, NULL);
	}

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
	g_free (self->priv->ip_iface);
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
	case NM_DEVICE_INTERFACE_PROP_IFACE:
		g_free (priv->iface);
		priv->iface = g_value_dup_string (value);
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
	case NM_DEVICE_INTERFACE_PROP_MANAGED:
		priv->managed = g_value_get_boolean (value);
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
	NMDeviceState state;

	switch (prop_id) {
	case NM_DEVICE_INTERFACE_PROP_UDI:
		g_value_set_string (value, priv->udi);
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
		state = nm_device_get_state (NM_DEVICE (object));
		if (   (state == NM_DEVICE_STATE_ACTIVATED)
		    || (state == NM_DEVICE_STATE_IP_CONFIG))
			g_value_set_object (value, priv->ip4_config);
		else
			g_value_set_object (value, NULL);
		break;
	case NM_DEVICE_INTERFACE_PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE:
		g_value_set_uint (value, priv->type);
		break;
	case NM_DEVICE_INTERFACE_PROP_MANAGED:
		g_value_set_boolean (value, priv->managed);
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
									  NM_DEVICE_INTERFACE_PROP_MANAGED,
									  NM_DEVICE_INTERFACE_MANAGED);
}

void
nm_device_state_changed (NMDevice *device, NMDeviceState state)
{
	const char *iface;
	NMDeviceState old_state;

	g_return_if_fail (NM_IS_DEVICE (device));

	if (device->priv->state == state)
		return;

	iface = nm_device_get_iface (device);
	old_state = device->priv->state;
	device->priv->state = state;

	g_object_notify (G_OBJECT (device), NM_DEVICE_INTERFACE_STATE);
	g_signal_emit_by_name (device, "state-changed", state);

	switch (state) {
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state == NM_DEVICE_STATE_UNMANAGED)
			nm_device_bring_up (device, TRUE);
		/* Fall through */
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state != NM_DEVICE_STATE_UNAVAILABLE)
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		nm_info ("Activation (%s) successful, device activated.", iface);
		break;
	case NM_DEVICE_STATE_FAILED:
		nm_info ("Activation (%s) failed.", nm_device_get_iface (device));
		nm_device_state_changed (device, NM_DEVICE_STATE_DISCONNECTED);
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

gboolean
nm_device_get_managed (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return NM_DEVICE_GET_PRIVATE (device)->managed;
}

void
nm_device_set_managed (NMDevice *device, gboolean managed)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->managed != managed) {
		priv->managed = managed;
		nm_info ("(%s): now %s", nm_device_get_iface (device), managed ? "managed" : "unmanaged");

		if (priv->start_timer) {
			g_source_remove (priv->start_timer);
			priv->start_timer = 0;
		}

		g_object_notify (G_OBJECT (device), NM_DEVICE_INTERFACE_MANAGED);

		/* If now managed, jump to unavailable */
		nm_device_state_changed (device, managed ? NM_DEVICE_STATE_UNAVAILABLE : NM_DEVICE_STATE_UNMANAGED);
	}
}

