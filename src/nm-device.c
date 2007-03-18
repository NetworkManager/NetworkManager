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

#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerSystem.h"
#include "nm-vpn-manager.h"
#include "nm-dhcp-manager.h"
#include "nm-dbus-nmi.h"
#include "nm-utils.h"
#include "autoip.h"

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

struct _NMDevicePrivate
{
	gboolean	dispose_has_run;

	char *			udi;
	char *			iface;
	NMDeviceType		type;
	guint32			capabilities;
	char *			driver;
	gboolean			removed;

	struct ether_addr	hw_addr;

	gboolean			link_active;
	guint32			ip4_address;
	struct in6_addr	ip6_address;
	NMData *			app_data;

	NMActRequest *		act_request;
	gboolean			quit_activation;

	/* IP configuration info */
	void *			system_config_data;	/* Distro-specific config data (parsed config file, etc) */
	gboolean			use_dhcp;
	NMIP4Config *		ip4_config;			/* Config from DHCP, PPP, or system config files */

	GMainContext *		context;
	GMainLoop *		loop;
	GThread *			worker;
	gboolean			worker_started;
};

static gpointer	nm_device_worker (gpointer user_data);

static void		nm_device_activate_schedule_stage5_ip_config_commit (NMActRequest *req);

/*
 * nm_device_test_wireless_extensions
 *
 * Test whether a given device is a wireless one or not.
 *
 */
static NMDeviceType
discover_device_type (LibHalContext *ctx, const char *udi)
{
	char * category = NULL;
	NMDeviceType type = DEVICE_TYPE_UNKNOWN;

	if (libhal_device_property_exists (ctx, udi, "info.category", NULL))
		category = libhal_device_get_property_string(ctx, udi, "info.category", NULL);

	if (category)
	{
		if (!strcmp (category, "net.80211"))
			type = DEVICE_TYPE_802_11_WIRELESS;
		else if (!strcmp (category, "net.80203"))
			type = DEVICE_TYPE_802_3_ETHERNET;

		libhal_free_string (category);
	}

	return type;
}

/*
 * nm_get_device_driver_name
 *
 * Get the device's driver name from HAL.
 *
 */
static char *
nm_get_device_driver_name (LibHalContext *ctx, const char *udi)
{
	char	*	driver_name = NULL;
	char *	physdev_udi = NULL;

	g_return_val_if_fail (ctx != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);

	physdev_udi = libhal_device_get_property_string (ctx, udi, "net.physical_device", NULL);
	if (physdev_udi && libhal_device_property_exists (ctx, physdev_udi, "info.linux.driver", NULL))
	{
		char *drv = libhal_device_get_property_string (ctx, physdev_udi, "info.linux.driver", NULL);
		driver_name = g_strdup (drv);
		g_free (drv);
	}
	g_free (physdev_udi);

	return driver_name;
}


NMDevice *
nm_device_new (const char *iface, 
               const char *udi,
               gboolean test_dev,
               NMDeviceType test_dev_type,
               NMData *app_data)
{
	NMDevice * 	dev;
	NMDeviceType	type;
	nm_completion_args args;

	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (strlen (iface) > 0, NULL);
	g_return_val_if_fail (app_data != NULL, NULL);

	type = discover_device_type (app_data->hal_ctx, udi);
	switch (type)
	{
		case DEVICE_TYPE_802_11_WIRELESS:
			dev = NM_DEVICE (g_object_new (NM_TYPE_DEVICE_802_11_WIRELESS, NULL));
			break;
		case DEVICE_TYPE_802_3_ETHERNET:
			dev = NM_DEVICE (g_object_new (NM_TYPE_DEVICE_802_3_ETHERNET, NULL));
			break;

		default:
			g_assert_not_reached ();
	}

	g_assert (dev);
	dev->priv->iface = g_strdup (iface);
	dev->priv->udi = g_strdup (udi);
	dev->priv->driver = nm_get_device_driver_name (app_data->hal_ctx, udi);
	dev->priv->app_data = app_data;
	dev->priv->type = type;

	dev->priv->capabilities |= NM_DEVICE_GET_CLASS (dev)->get_generic_capabilities (dev);
	if (!(dev->priv->capabilities & NM_DEVICE_CAP_NM_SUPPORTED))
	{
		g_object_unref (G_OBJECT (dev));
		return NULL;
	}

	/* Device thread's main loop */
	dev->priv->context = g_main_context_new ();
	dev->priv->loop = g_main_loop_new (dev->priv->context, FALSE);

	/* Have to bring the device up before checking link status and other stuff */
	nm_device_bring_up_wait (dev, FALSE);

	nm_device_update_ip4_address (dev);
	nm_device_update_hw_address (dev);

	/* Grab IP config data for this device from the system configuration files */
	dev->priv->system_config_data = nm_system_device_get_system_config (dev, app_data);
	dev->priv->use_dhcp = nm_system_device_get_use_dhcp (dev);

	/* Allow distributions to flag devices as disabled */
	if (nm_system_device_get_disabled (dev))
	{
		g_object_unref (G_OBJECT (dev));
		return NULL;
	}

	nm_print_device_capabilities (dev);

	/* Call type-specific initialization */
	if (NM_DEVICE_GET_CLASS (dev)->init)
		NM_DEVICE_GET_CLASS (dev)->init (dev);

	/* This ref should logically go in nm_device_worker, but we need the
	   ref to be taken before the worker thread is scheduled on a cpu. */
	g_object_ref (G_OBJECT (dev));
	dev->priv->worker = g_thread_create (nm_device_worker, dev, TRUE, NULL);
	g_assert (dev->priv->worker);

	/* Block until our device thread has actually had a chance to start. */
	args[0] = &dev->priv->worker_started;
	args[1] = (gpointer) "nm_device_init(): waiting for device's worker thread to start";
	args[2] = GINT_TO_POINTER (LOG_INFO);
	args[3] = GINT_TO_POINTER (0);
	nm_wait_for_completion (NM_COMPLETION_TRIES_INFINITY,
			G_USEC_PER_SEC / 20, nm_completion_boolean_test, NULL, args);

	nm_info ("nm_device_init(): device's worker thread started, continuing.");

	return dev;
}


static void
nm_device_init (NMDevice * self)
{
	self->priv = NM_DEVICE_GET_PRIVATE (self);
	self->priv->dispose_has_run = FALSE;
	self->priv->udi = NULL;
	self->priv->iface = NULL;
	self->priv->type = DEVICE_TYPE_UNKNOWN;
	self->priv->capabilities = NM_DEVICE_CAP_NONE;
	self->priv->driver = NULL;
	self->priv->removed = FALSE;

	self->priv->link_active = FALSE;
	self->priv->ip4_address = 0;
	memset (&self->priv->ip6_address, 0, sizeof (struct in6_addr));
	self->priv->app_data = NULL;

	self->priv->act_request = NULL;
	self->priv->quit_activation = FALSE;

	self->priv->system_config_data = NULL;
	self->priv->use_dhcp = TRUE;
	self->priv->ip4_config = NULL;

	self->priv->context = NULL;
	self->priv->loop = NULL;
	self->priv->worker = NULL;
	self->priv->worker_started = FALSE;

	memset (&(self->priv->hw_addr), 0, sizeof (struct ether_addr));
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return 0;
}


static void
real_start (NMDevice *dev)
{
}


/*
 * nm_device_worker
 *
 * Main thread of the device.
 *
 */
static gpointer
nm_device_worker (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	g_assert (self);

	NM_DEVICE_GET_CLASS (self)->start (self);

	self->priv->worker_started = TRUE;
	g_main_loop_run (self->priv->loop);

	g_main_loop_unref (self->priv->loop);
	g_main_context_unref (self->priv->context);

	self->priv->loop = NULL;
	self->priv->context = NULL;

	g_object_unref (G_OBJECT (self));

	return NULL;
}


void
nm_device_stop (NMDevice *self)
{
	g_return_if_fail (self != NULL);

	nm_device_deactivate (self);
	nm_device_bring_down (self);

	if (self->priv->loop)
		g_main_loop_quit (self->priv->loop);
	if (self->priv->worker)
	{
		g_thread_join (self->priv->worker);
		self->priv->worker = NULL;
	}
}

GMainContext *
nm_device_get_main_context (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->context;
}


/*
 * nm_get_device_by_udi
 *
 * Search through the device list for a device with a given UDI.
 *
 * NOTE: the caller MUST hold the device list mutex already to make
 * this routine thread-safe.
 *
 */
NMDevice *
nm_get_device_by_udi (NMData *data,
                      const char *udi)
{
	GSList	*elt;
	
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (udi  != NULL, NULL);

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		NMDevice	*dev = NULL;
		if ((dev = NM_DEVICE (elt->data)))
		{
			if (nm_null_safe_strcmp (nm_device_get_udi (dev), udi) == 0)
				return dev;
		}
	}

	return NULL;
}


/*
 * nm_get_device_by_iface
 *
 * Search through the device list for a device with a given iface.
 *
 * NOTE: the caller MUST hold the device list mutex already to make
 * this routine thread-safe.
 *
 */
NMDevice *
nm_get_device_by_iface (NMData *data,
                        const char *iface)
{
	GSList	*elt;
	
	g_return_val_if_fail (data  != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		NMDevice	*dev = NULL;
		if ((dev = NM_DEVICE (elt->data)))
		{
			if (nm_null_safe_strcmp (nm_device_get_iface (dev), iface) == 0)
				return dev;
		}
	}

	return NULL;
}


/*
 * nm_get_device_by_iface_locked
 *
 * Search through the device list for a device with a given iface.
 * NOTE: refs the device, caller must unref when done.
 *
 */
NMDevice *
nm_get_device_by_iface_locked (NMData *data,
                               const char *iface)
{
	GSList *	elt;
	NMDevice *dev = NULL;
	
	g_return_val_if_fail (data  != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	nm_lock_mutex (data->dev_list_mutex, __func__);
	for (elt = data->dev_list; elt; elt = g_slist_next (elt))
	{
		NMDevice	*tmp_dev = NULL;
		if ((tmp_dev = NM_DEVICE (elt->data)))
		{
			if (nm_null_safe_strcmp (nm_device_get_iface (tmp_dev), iface) == 0)
			{
				g_object_ref (G_OBJECT (tmp_dev));
				dev = tmp_dev;
				break;
			}
		}
	}
	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);

	return dev;
}


/*
 * Get/set functions for UDI
 */
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
	g_return_val_if_fail (self != NULL, DEVICE_TYPE_UNKNOWN);

	return self->priv->type;
}


static gboolean
real_is_test_device (NMDevice *dev)
{
	return FALSE;
}

gboolean
nm_device_is_test_device (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return NM_DEVICE_GET_CLASS (self)->is_test_device (self);
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
 * nm_device_get_app_data
 *
 */
struct NMData *
nm_device_get_app_data (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return self->priv->app_data;
}


/*
 * Get/Set for "removed" flag
 */
gboolean
nm_device_get_removed (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, TRUE);

	return self->priv->removed;
}

void
nm_device_set_removed (NMDevice *self,
                       const gboolean removed)
{
	g_return_if_fail (self != NULL);

	self->priv->removed = removed;
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
	NMData *		app_data;
	NMActRequest *	req;

	g_return_if_fail (self != NULL);
	g_return_if_fail (self->priv->app_data != NULL);

	app_data = self->priv->app_data;
	req = nm_device_get_act_request (self);

	if (self->priv->link_active == link_active)
		return;

	self->priv->link_active = link_active;

	/* Deactivate a currently active device */
	if (!link_active && req)
		nm_policy_schedule_device_change_check (app_data);
	else if (link_active && !req)
	{
		NMDevice *	act_dev = nm_get_active_device (app_data);
		NMActRequest *	act_dev_req = act_dev ? nm_device_get_act_request (act_dev) : NULL;

		/* Should we switch to this device now that it has a link?
		 *
		 * Only auto-switch for wired devices, AND...
		 *
		 * only switch to fully-supported devices, since ones that don't have carrier detection
		 * capability usually report the carrier as "always on" even if its not really on.  User
		 * must manually choose semi-supported devices.
		 *
		 */
		if (nm_device_is_802_3_ethernet (self) && (nm_device_get_capabilities (self) & NM_DEVICE_CAP_CARRIER_DETECT))
		{
			gboolean do_switch = act_dev ? FALSE : TRUE;	/* If no currently active device, switch to this one */

			/* If active device is wireless, switch to this one */
			if (act_dev && nm_device_is_802_11_wireless (act_dev) && act_dev_req && !nm_act_request_get_user_requested (act_dev_req))
				do_switch = TRUE;

			/* FIXME: Why is this activation request created here and never used? */
			/* if (do_switch && (act_req = nm_act_request_new (app_data, self, NULL, TRUE))) */
			if (do_switch)
			{
				nm_info ("Will activate wired connection '%s' because it now has a link.", nm_device_get_iface (self));
				nm_policy_schedule_device_change_check (app_data);
			}
		}
	}
	nm_dbus_schedule_device_status_change_signal (app_data, self, NULL, link_active ? DEVICE_CARRIER_ON : DEVICE_CARRIER_OFF);
}


/*
 * nm_device_activation_start
 *
 * Tell the device thread to begin activation.
 *
 * Returns:	TRUE on success activation beginning
 *			FALSE on error beginning activation (bad params, couldn't create thread)
 *
 */
gboolean
nm_device_activation_start (NMActRequest *req)
{
	NMData *		data = NULL;
	NMDevice *	self = NULL;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	g_return_val_if_fail (!nm_device_is_activating (self), TRUE);	/* Return if activation has already begun */

	nm_act_request_ref (req);
	self->priv->act_request = req;
	self->priv->quit_activation = FALSE;

	nm_info ("Activation (%s) started...", nm_device_get_iface (self));

	nm_act_request_set_stage (req, NM_ACT_STAGE_DEVICE_PREPARE);
	nm_device_activate_schedule_stage1_device_prepare (req);

	nm_schedule_state_change_signal_broadcast (data);
	nm_dbus_schedule_device_status_change_signal (data, self, NULL, DEVICE_ACTIVATING);

	return TRUE;
}


/*
 * nm_device_activate_stage1_device_prepare
 *
 * Prepare for device activation
 *
 */
static gboolean
nm_device_activate_stage1_device_prepare (NMActRequest *req)
{
	NMDevice *	self;
	NMData *		data;
	const char *	iface;
	NMActStageReturn	ret;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 1 of 5 (Device Prepare) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage1_prepare (self, req);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_policy_schedule_activation_failed (req);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

	if (nm_device_activation_should_cancel (self))
		goto out;

	nm_device_activate_schedule_stage2_device_config (req);

out:
	nm_act_request_unref (req);
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
nm_device_activate_schedule_stage1_device_prepare (NMActRequest *req)
{
	GSource *		source = NULL;
	NMDevice *	self = NULL;

	g_return_if_fail (req != NULL);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_act_request_set_stage (req, NM_ACT_STAGE_DEVICE_PREPARE);
	nm_act_request_ref (req);
	nm_info ("Activation (%s) Stage 1 of 5 (Device Prepare) scheduled...", nm_device_get_iface (self));

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_device_activate_stage1_device_prepare, req, NULL);
	g_source_attach (source, self->priv->context);
	g_source_unref (source);
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev, NMActRequest *req)
{
	/* Nothing to do */
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *dev, NMActRequest *req)
{
	/* Nothing to do */
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*
 * nm_device_activate_stage2_device_config
 *
 * Determine device parameters and set those on the device, ie
 * for wireless devices, set essid, keys, etc.
 *
 */
static gboolean
nm_device_activate_stage2_device_config (NMActRequest *req)
{
	NMDevice *	self;
	NMData *		data;
	const char *	iface;
	NMActStageReturn	ret;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) starting...", iface);

	/* Bring the device up */
	if (!nm_device_is_up (self))
		nm_device_bring_up (self);

	if (nm_device_activation_should_cancel (self))
		goto out;

	ret = NM_DEVICE_GET_CLASS (self)->act_stage2_config (self, req);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_policy_schedule_activation_failed (req);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) successful.", iface);

	if (nm_device_activation_should_cancel (self))
		goto out;

	nm_device_activate_schedule_stage3_ip_config_start (req);

out:
	nm_act_request_unref (req);
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
nm_device_activate_schedule_stage2_device_config (NMActRequest *req)
{
	GSource *		source = NULL;
	NMDevice *	self = NULL;

	g_return_if_fail (req != NULL);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_act_request_set_stage (req, NM_ACT_STAGE_DEVICE_CONFIG);
	nm_act_request_ref (req);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_device_activate_stage2_device_config, req, NULL);
	g_source_attach (source, self->priv->context);
	g_source_unref (source);
	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) scheduled...", nm_device_get_iface (self));
}


static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *self,
                                 NMActRequest *req)
{	
	NMData *			data = NULL;
	NMActStageReturn	ret = NM_ACT_STAGE_RETURN_SUCCESS;

	data = nm_act_request_get_data (req);
	g_assert (data);

	/* DHCP devices try DHCP, non-DHCP default to SUCCESS */
	if (nm_device_get_use_dhcp (self))
	{
		/* Begin a DHCP transaction on the interface */
		if (!nm_dhcp_manager_begin_transaction (data->dhcp_manager, req))
		{
			ret = NM_ACT_STAGE_RETURN_FAILURE;
			goto out;
		}	

		/* DHCP devices will be notified by the DHCP manager when
		 * stuff happens.
		 */
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}
	
out:
	return ret;
}


/*
 * nm_device_activate_stage3_ip_config_start
 *
 * Begin IP configuration with either DHCP or static IP.
 *
 */
static gboolean
nm_device_activate_stage3_ip_config_start (NMActRequest *req)
{
	NMData *			data = NULL;
	NMDevice *		self = NULL;
	const char *		iface;
	NMActStageReturn	ret;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) started...", iface);

	if (nm_device_activation_should_cancel (self))
		goto out;

	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip_config_start (self, req);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_policy_schedule_activation_failed (req);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	if (nm_device_activation_should_cancel (self))
		goto out;

	nm_device_activate_schedule_stage4_ip_config_get (req);

out:
	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) complete.", iface);
	nm_act_request_unref (req);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage3_ip_config_start
 *
 * Schedule IP configuration start
 */
void
nm_device_activate_schedule_stage3_ip_config_start (NMActRequest *req)
{
	GSource *		source = NULL;
	NMDevice *	self = NULL;

	g_return_if_fail (req != NULL);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_act_request_set_stage (req, NM_ACT_STAGE_IP_CONFIG_START);
	nm_act_request_ref (req);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_device_activate_stage3_ip_config_start, req, NULL);
	g_source_attach (source, self->priv->context);
	g_source_unref (source);
	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) scheduled.", nm_device_get_iface (self));
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
                                NMActRequest *req,
                                NMIP4Config **config)
{
	NMData *			data;
	NMIP4Config *		real_config = NULL;
	NMActStageReturn	ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	g_assert (req);
	data = nm_act_request_get_data (req);
	g_assert (data);

	if (nm_device_get_use_dhcp (self))
		real_config = nm_dhcp_manager_get_ip4_config (data->dhcp_manager, req);
	else
		real_config = nm_system_device_new_ip4_system_config (self);

	if (real_config)
	{
		*config = real_config;
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	}
	else
	{
		/* Make sure device is up even if config fails */
		if (!nm_device_is_up (self))
			nm_device_bring_up (self);
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
nm_device_activate_stage4_ip_config_get (NMActRequest *req)
{
	NMData *			data = NULL;
	NMDevice *		self = NULL;
	NMIP4Config *		ip4_config = NULL;
	NMActStageReturn	ret;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Get) started...", nm_device_get_iface (self));

	if (nm_device_activation_should_cancel (self))
		goto out;

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_get_ip4_config (self, req, &ip4_config);

	if (nm_device_activation_should_cancel (self))
		goto out;

	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (!ip4_config || (ret == NM_ACT_STAGE_RETURN_FAILURE))
	{
		nm_policy_schedule_activation_failed (req);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	

	if (nm_device_activation_should_cancel (self))
		goto out;

	nm_act_request_set_ip4_config (req, ip4_config);
	nm_ip4_config_unref (ip4_config);
	nm_device_activate_schedule_stage5_ip_config_commit (req);

out:
	nm_act_request_unref (req);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Get) complete.", nm_device_get_iface (self));
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage4_ip_config_get
 *
 * Schedule creation of the IP config
 *
 */
void
nm_device_activate_schedule_stage4_ip_config_get (NMActRequest *req)
{
	GSource *		source = NULL;
	NMDevice *	self = NULL;

	g_return_if_fail (req != NULL);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_act_request_set_stage (req, NM_ACT_STAGE_IP_CONFIG_GET);
	nm_act_request_ref (req);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Get) scheduled...",
			nm_device_get_iface (self));

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_device_activate_stage4_ip_config_get, req, NULL);
	g_source_attach (source, self->priv->context);
	g_source_unref (source);
}


static NMActStageReturn
real_act_stage4_ip_config_timeout (NMDevice *self,
                                   NMActRequest *req,
                                   NMIP4Config **config)
{
	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	g_assert (req);

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
nm_device_activate_stage4_ip_config_timeout (NMActRequest *req)
{
	NMData *		data = NULL;
	NMDevice *	self = NULL;
	NMIP4Config *	ip4_config = NULL;
	const char *	iface;
	NMActStageReturn	ret = NM_ACT_STAGE_RETURN_FAILURE;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Timeout) started...", iface);

	if (nm_device_activation_should_cancel (self))
		goto out;

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip_config_timeout (self, req, &ip4_config);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (!ip4_config || (ret == NM_ACT_STAGE_RETURN_FAILURE))
	{
		nm_policy_schedule_activation_failed (req);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);	
	g_assert (ip4_config);

	nm_act_request_set_ip4_config (req, ip4_config);
	nm_ip4_config_unref (ip4_config);
	nm_device_activate_schedule_stage5_ip_config_commit (req);

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
nm_device_activate_schedule_stage4_ip_config_timeout (NMActRequest *req)
{
	GSource *		source = NULL;
	NMDevice *	self = NULL;

	g_return_if_fail (req != NULL);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_act_request_set_stage (req, NM_ACT_STAGE_IP_CONFIG_GET);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_device_activate_stage4_ip_config_timeout, req, NULL);
	g_source_attach (source, self->priv->context);
	g_source_unref (source);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Timeout) scheduled...", nm_device_get_iface (self));
}


/*
 * nm_device_activate_stage5_ip_config_commit
 *
 * Commit the IP config on the device
 *
 */
static gboolean
nm_device_activate_stage5_ip_config_commit (NMActRequest *req)
{
	NMData *		data = NULL;
	NMDevice *	self = NULL;
	NMIP4Config *	ip4_config = NULL;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	ip4_config = nm_act_request_get_ip4_config (req);
	g_assert (ip4_config);

	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) started...",
			nm_device_get_iface (self));

	if (nm_device_activation_should_cancel (self))
		goto out;

	nm_device_set_ip4_config (self, ip4_config);
	if (nm_system_device_set_from_ip4_config (self))
	{
		nm_device_update_ip4_address (self);
		nm_system_device_add_ip6_link_address (self);
		nm_system_restart_mdns_responder ();
		nm_system_set_hostname (self->priv->ip4_config);
		nm_system_activate_nis (self->priv->ip4_config);
		nm_system_set_mtu (self);
		if (NM_DEVICE_GET_CLASS (self)->update_link)
			NM_DEVICE_GET_CLASS (self)->update_link (self);
		nm_policy_schedule_activation_finish (req);
	}
	else
		nm_policy_schedule_activation_failed (req);

out:
	nm_act_request_unref (req);
	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) complete.",
			nm_device_get_iface (self));
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage5_ip_config_commit
 *
 * Schedule commit of the IP config
 */
static void
nm_device_activate_schedule_stage5_ip_config_commit (NMActRequest *req)
{
	GSource *		source = NULL;
	NMDevice *	self = NULL;

	g_return_if_fail (req != NULL);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_act_request_set_stage (req, NM_ACT_STAGE_IP_CONFIG_COMMIT);
	nm_act_request_ref (req);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_device_activate_stage5_ip_config_commit, req, NULL);
	g_source_attach (source, self->priv->context);
	g_source_unref (source);
	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) scheduled...", nm_device_get_iface (self));
}


static void
real_activation_cancel_handler (NMDevice *self,
                                NMActRequest *req)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (req != NULL);

	if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START)
		nm_dhcp_manager_cancel_transaction (self->priv->app_data->dhcp_manager, req);
}

/*
 * activation_handle_cancel_helper
 *
 * Allow specific device types to clean up their own cancellation
 *
 */
static gboolean
activation_handle_cancel_helper (NMActRequest *req)
{
	NMDevice * self;
	NMDeviceClass *klass;

	g_assert (req);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	klass = NM_DEVICE_CLASS (g_type_class_peek (NM_TYPE_DEVICE));
	if (klass->activation_cancel_handler)
		klass->activation_cancel_handler (self, req);

	if ((req = nm_device_get_act_request (self)))
	{
		self->priv->act_request = NULL;
		nm_act_request_unref (req);
	}
	nm_schedule_state_change_signal_broadcast (self->priv->app_data);

	nm_info ("Activation (%s) cancellation handled.", nm_device_get_iface (self));
	return FALSE;
}


/*
 * nm_device_schedule_activation_handle_cancel
 *
 * Schedule the activation cancel handler
 *
 */
static void
nm_device_schedule_activation_handle_cancel (NMActRequest *req)
{
	NMDevice *	self;
	NMData *		data;
	GSource *		source;

	g_return_if_fail (req != NULL);

	data = nm_act_request_get_data (req);
	g_assert (data);

	self = nm_act_request_get_dev (req);
	g_assert (self);

	nm_info ("Activation (%s) cancellation handler scheduled...", nm_device_get_iface (self));
	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) activation_handle_cancel_helper, req, NULL);
	g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	g_source_attach (source, self->priv->context);
	g_source_unref (source);
}


static
gboolean nm_ac_test (int tries,
                     nm_completion_args args)
{
	NMDevice * self = args[0];

	g_return_val_if_fail (self != NULL, TRUE);

	if (nm_device_is_activating (self))
	{
		if (tries % 20 == 0)
			nm_info ("Activation (%s): waiting for device to cancel activation.", nm_device_get_iface (self));
		return FALSE;
	}

	return TRUE;
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
	nm_completion_args	args;
	NMData *			app_data;

	g_return_if_fail (self != NULL);

	g_assert (self->priv->app_data);
	app_data = self->priv->app_data;

	if (nm_device_is_activating (self))
	{
		NMActRequest *	req = nm_device_get_act_request (self);

		nm_info ("Activation (%s): cancelling...", nm_device_get_iface (self));
		self->priv->quit_activation = TRUE;

		nm_device_schedule_activation_handle_cancel (req);

		/* Spin until cancelled.  Possible race conditions or deadlocks here.
		 * The other problem with waiting here is that we hold up dbus traffic
		 * that we should respond to.
		 */
		args[0] = self;
		nm_wait_for_completion (NM_COMPLETION_TRIES_INFINITY, G_USEC_PER_SEC / 20, nm_ac_test, NULL, args);
		nm_info ("Activation (%s): cancelled.", nm_device_get_iface (self));
		nm_schedule_state_change_signal_broadcast (app_data);
		self->priv->quit_activation = FALSE;
	}
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
	NMData *		app_data;
	NMActRequest *	act_request;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (self->priv->app_data != NULL, FALSE);

	nm_system_shutdown_nis ();

	app_data = self->priv->app_data;
	nm_vpn_manager_deactivate_vpn_connection (app_data->vpn_manager, self);

	if (nm_device_is_activated (self))
		nm_dbus_schedule_device_status_change_signal (app_data, self, NULL, DEVICE_NO_LONGER_ACTIVE);
	else if (nm_device_is_activating (self))
		nm_device_activation_cancel (self);

	/* Tear down an existing activation request, which may not have happened
	 * in nm_device_activation_cancel() above, for various reasons.
	 */
	if ((act_request = nm_device_get_act_request (self)))
	{
 		nm_dhcp_manager_cancel_transaction (app_data->dhcp_manager, act_request);
		nm_act_request_unref (act_request);
		self->priv->act_request = NULL;
	}

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
void
nm_device_deactivate (NMDevice *self)
{
	NMData *		app_data;
	NMIP4Config *	config;

	g_return_if_fail (self != NULL);
	g_return_if_fail (self->priv->app_data != NULL);

	nm_info ("Deactivating device %s.", nm_device_get_iface (self));

	nm_device_deactivate_quickly (self);

	app_data = self->priv->app_data;

	/* Remove any device nameservers and domains */
	if ((config = nm_device_get_ip4_config (self)))
	{
		nm_named_manager_remove_ip4_config (app_data->named_manager, config);
		nm_device_set_ip4_config (self, NULL);
	}

	/* Take out any entries in the routing table and any IP address the device had. */
	nm_system_device_flush_routes (self);
	nm_system_device_flush_addresses (self);
	nm_device_update_ip4_address (self);	

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate)
		NM_DEVICE_GET_CLASS (self)->deactivate (self);

	nm_schedule_state_change_signal_broadcast (self->priv->app_data);
}


/*
 * nm_device_is_activating
 *
 * Return whether or not the device is currently activating itself.
 *
 */
gboolean
nm_device_is_activating (NMDevice *dev)
{
	NMActRequest *	req;
	NMActStage	stage;
	gboolean		activating = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);

	if (!(req = nm_device_get_act_request (dev)))
		return FALSE;

	stage = nm_act_request_get_stage (req);
	switch (stage)
	{
		case NM_ACT_STAGE_DEVICE_PREPARE:
		case NM_ACT_STAGE_DEVICE_CONFIG:
		case NM_ACT_STAGE_NEED_USER_KEY:
		case NM_ACT_STAGE_IP_CONFIG_START:
		case NM_ACT_STAGE_IP_CONFIG_GET:
		case NM_ACT_STAGE_IP_CONFIG_COMMIT:
			activating = TRUE;
			break;

		case NM_ACT_STAGE_ACTIVATED:
		case NM_ACT_STAGE_FAILED:
		case NM_ACT_STAGE_CANCELLED:
		case NM_ACT_STAGE_UNKNOWN:
		default:
			break;
	}

	return activating;
}


/*
 * nm_device_is_activated
 *
 * Return whether or not the device is successfully activated.
 *
 */
gboolean
nm_device_is_activated (NMDevice *dev)
{
	NMActRequest *	req;
	NMActStage	stage;
	gboolean		activated = FALSE;

	g_return_val_if_fail (dev != NULL, FALSE);

	if (!(req = nm_device_get_act_request (dev)))
		return FALSE;

	stage = nm_act_request_get_stage (req);
	switch (stage)
	{
		case NM_ACT_STAGE_ACTIVATED:
			activated = TRUE;
			break;

		case NM_ACT_STAGE_DEVICE_PREPARE:
		case NM_ACT_STAGE_DEVICE_CONFIG:
		case NM_ACT_STAGE_NEED_USER_KEY:
		case NM_ACT_STAGE_IP_CONFIG_START:
		case NM_ACT_STAGE_IP_CONFIG_GET:
		case NM_ACT_STAGE_IP_CONFIG_COMMIT:
		case NM_ACT_STAGE_FAILED:
		case NM_ACT_STAGE_CANCELLED:
		case NM_ACT_STAGE_UNKNOWN:
		default:
			break;
	}

	return activated;
}


/*
 * nm_device_activation_should_cancel
 *
 * Return whether or not we've been told to cancel activation
 *
 */
gboolean
nm_device_activation_should_cancel (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return (self->priv->quit_activation);
}


void
nm_device_activation_failure_handler (NMDevice *self,
                                      struct NMActRequest *req)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (req != NULL);

	if (NM_DEVICE_GET_CLASS (self)->activation_failure_handler)
		NM_DEVICE_GET_CLASS (self)->activation_failure_handler (self, req);
}


void nm_device_activation_success_handler (NMDevice *self,
                                           struct NMActRequest *req)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (req != NULL);

	if (NM_DEVICE_GET_CLASS (self)->activation_success_handler)
		NM_DEVICE_GET_CLASS (self)->activation_success_handler (self, req);
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

gboolean
nm_device_get_use_dhcp (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return self->priv->use_dhcp;
}

void
nm_device_set_use_dhcp (NMDevice *self,
                        gboolean use_dhcp)
{
	g_return_if_fail (self != NULL);

	self->priv->use_dhcp = use_dhcp;
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
	NMIP4Config *old_config;

	g_return_if_fail (self != NULL);

	old_config = self->priv->ip4_config;
	if (config)
		nm_ip4_config_ref (config);
	self->priv->ip4_config = config;
	if (old_config)
		nm_ip4_config_unref (old_config);
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
	g_return_if_fail (self->priv->app_data != NULL);
	g_return_if_fail (nm_device_get_iface (self) != NULL);

	if ((sk = nm_dev_sock_open (self, DEV_GENERAL, __func__, NULL)) == NULL)
		return;

	iface = nm_device_get_iface (self);
	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, iface, sizeof (req.ifr_name) - 1);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET IFADDR.", iface);
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFADDR, &req);
#ifdef IOCTL_DEBUG
	nm_info ("%s: Done with GET IFADDR.", iface);
#endif
	nm_dev_sock_close (sk);
	if (err != 0)
		return;

	new_address = ((struct sockaddr_in *)(&req.ifr_addr))->sin_addr.s_addr;
	if (new_address != nm_device_get_ip4_address (self))
		self->priv->ip4_address = new_address;
}


void
nm_device_get_hw_address (NMDevice *self,
                          struct ether_addr *addr)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	memcpy (addr, &(self->priv->hw_addr), sizeof (struct ether_addr));
}

void
nm_device_update_hw_address (NMDevice *self)
{
	struct ifreq req;
	NMSock *sk;
	int ret;

	g_return_if_fail (self != NULL);

	sk = nm_dev_sock_open (self, DEV_GENERAL, __FUNCTION__, NULL);
	if (!sk)
		return;
	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (self), sizeof (req.ifr_name) - 1);

	ret = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFHWADDR, &req);
	if (ret)
		goto out;

	memcpy (&(self->priv->hw_addr), &(req.ifr_hwaddr.sa_data), sizeof (struct ether_addr));

out:
	nm_dev_sock_close (sk);
}


/*
 * nm_device_set_up_down
 *
 * Set the up flag on the device on or off
 *
 */
static void
nm_device_set_up_down (NMDevice *self,
                       gboolean up)
{
	g_return_if_fail (self != NULL);

	nm_system_device_set_up_down (self, up);

	/*
	 * Make sure that we have a valid MAC address, some cards reload firmware when they
	 * are brought up.
	 */
	nm_device_update_hw_address (self);
}


/*
 * Interface state functions: bring up, down, check
 *
 */
gboolean
nm_device_is_up (NMDevice *self)
{
	NMSock *		sk;
	struct ifreq	ifr;
	int			err;

	g_return_val_if_fail (self != NULL, FALSE);

	if ((sk = nm_dev_sock_open (self, DEV_GENERAL, __FUNCTION__, NULL)) == NULL)
		return (FALSE);

	/* Get device's flags */
	strncpy (ifr.ifr_name, nm_device_get_iface (self), sizeof (ifr.ifr_name) - 1);
#ifdef IOCTL_DEBUG
	nm_info ("%s: About to GET IFFLAGS.", nm_device_get_iface (self));
#endif
	err = ioctl (nm_dev_sock_get_fd (sk), SIOCGIFFLAGS, &ifr);
#ifdef IOCTL_DEBUG
	nm_info ("%s: Done with GET IFFLAGS.", nm_device_get_iface (self));
#endif
	nm_dev_sock_close (sk);
	if (!err)
		return (!((ifr.ifr_flags^IFF_UP) & IFF_UP));

	if (errno != ENODEV)
	{
		nm_warning ("nm_device_is_up() could not get flags for device %s.  errno = %d",
				nm_device_get_iface (self), errno );
	}

	return FALSE;
}

/* I really wish nm_v_wait_for_completion_or_timeout could translate these
 * to first class args instead of a all this void * arg stuff, so these
 * helpers could be nice and _tiny_. */
static gboolean
nm_completion_device_is_up_test (int tries,
                                 nm_completion_args args)
{
	NMDevice *self = NM_DEVICE (args[0]);
	gboolean *err = args[1];
	gboolean cancelable = GPOINTER_TO_INT (args[2]);

	g_return_val_if_fail (self != NULL, TRUE);
	g_return_val_if_fail (err != NULL, TRUE);

	*err = FALSE;
	if (cancelable && nm_device_activation_should_cancel (self)) {
		*err = TRUE;
		return TRUE;
	}
	if (nm_device_is_up (self))
		return TRUE;
	return FALSE;
}

void
nm_device_bring_up (NMDevice *self)
{
	g_return_if_fail (self != NULL);

	nm_device_set_up_down (self, TRUE);
}

gboolean
nm_device_bring_up_wait (NMDevice *self,
                         gboolean cancelable)
{
	gboolean err = FALSE;
	nm_completion_args args;

	g_return_val_if_fail (self != NULL, TRUE);

	nm_device_bring_up (self);

	args[0] = self;
	args[1] = &err;
	args[2] = GINT_TO_POINTER (cancelable);
	nm_wait_for_completion (400, G_USEC_PER_SEC / 200, NULL, nm_completion_device_is_up_test, args);
	if (err)
		nm_info ("failed to bring up device %s", self->priv->iface);
	return err;
}

void
nm_device_bring_down (NMDevice *self)
{
	g_return_if_fail (self != NULL);

	nm_device_set_up_down (self, FALSE);
}

static gboolean
nm_completion_device_is_down_test (int tries,
                                   nm_completion_args args)
{
	NMDevice *self = NM_DEVICE (args[0]);
	gboolean *err = args[1];
	gboolean cancelable = GPOINTER_TO_INT (args[2]);

	g_return_val_if_fail (self != NULL, TRUE);
	g_return_val_if_fail (err != NULL, TRUE);

	*err = FALSE;
	if (cancelable && nm_device_activation_should_cancel (self)) {
		*err = TRUE;
		return TRUE;
	}
	if (!nm_device_is_up (self))
		return TRUE;
	return FALSE;
}

gboolean
nm_device_bring_down_wait (NMDevice *self,
                           gboolean cancelable)
{
	gboolean err = FALSE;
	nm_completion_args args;

	g_return_val_if_fail (self != NULL, TRUE);

	nm_device_bring_down (self);

	args[0] = self;
	args[1] = &err;
	args[2] = GINT_TO_POINTER (cancelable);
	nm_wait_for_completion(400, G_USEC_PER_SEC / 200, NULL,
			nm_completion_device_is_down_test, args);
	if (err)
		nm_info ("failed to bring down device %s", self->priv->iface);
	return err;
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
	NMDevice *		self = NM_DEVICE (object);
	NMDeviceClass *	klass;
	GObjectClass *		parent_class;  

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

	nm_system_device_free_system_config (self, self->priv->system_config_data);
	if (self->priv->ip4_config)
	{
		nm_ip4_config_unref (self->priv->ip4_config);
		self->priv->ip4_config = NULL;
	}

	if (self->priv->act_request)
	{
		nm_act_request_unref (self->priv->act_request);
		self->priv->act_request = NULL;
	}

	/* Chain up to the parent class */
	klass = NM_DEVICE_CLASS (g_type_class_peek (NM_TYPE_DEVICE));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->dispose (object);
}

static void
nm_device_finalize (GObject *object)
{
	NMDevice *		self = NM_DEVICE (object);
	NMDeviceClass *	klass;
	GObjectClass *		parent_class;  

	g_free (self->priv->udi);
	g_free (self->priv->iface);
	g_free (self->priv->driver);

	/* Chain up to the parent class */
	klass = NM_DEVICE_CLASS (g_type_class_peek (NM_TYPE_DEVICE));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->finalize (object);
}


static void
nm_device_class_init (NMDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_device_dispose;
	object_class->finalize = nm_device_finalize;

	klass->is_test_device = real_is_test_device;
	klass->activation_cancel_handler = real_activation_cancel_handler;
	klass->get_type_capabilities = real_get_type_capabilities;
	klass->get_generic_capabilities = real_get_generic_capabilities;
	klass->start = real_start;
	klass->act_stage1_prepare = real_act_stage1_prepare;
	klass->act_stage2_config = real_act_stage2_config;
	klass->act_stage3_ip_config_start = real_act_stage3_ip_config_start;
	klass->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	klass->act_stage4_ip_config_timeout = real_act_stage4_ip_config_timeout;

	g_type_class_add_private (object_class, sizeof (NMDevicePrivate));
}

GType
nm_device_get_type (void)
{
	static GType type = 0;
	if (type == 0)
	{
		static const GTypeInfo info =
		{
			sizeof (NMDeviceClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_device_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMDevice),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_device_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (G_TYPE_OBJECT,
					       "NMDevice",
					       &info, 0);
	}
	return type;
}
