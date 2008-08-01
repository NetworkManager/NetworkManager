/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 - 2008 Red Hat, Inc.
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
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

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
#include "nm-netlink.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"
#include "nm-dnsmasq-manager.h"
#include "nm-dhcp4-config.h"

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
	guint         failed_to_disconnected_id;

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
	NMIP4Config *		ip4_config;			/* Config from DHCP, PPP, or system config files */
	NMDHCPManager *     dhcp_manager;
	gulong              dhcp_state_sigid;
	gulong              dhcp_timeout_sigid;
	NMDHCP4Config *     dhcp4_config;

	/* dnsmasq stuff for shared connections */
	NMDnsMasqManager *  dnsmasq_manager;
	gulong              dnsmasq_state_id;

	/* avahi-autoipd stuff */
	GPid		aipd_pid;
	guint		aipd_watch;
	guint		aipd_timeout;
	guint32     aipd_addr;
};

static gboolean check_connection_compatible (NMDeviceInterface *device,
                                             NMConnection *connection,
                                             GError **error);

static gboolean nm_device_activate (NMDeviceInterface *device,
                                    NMActRequest *req,
                                    GError **error);

static void	nm_device_activate_schedule_stage5_ip_config_commit (NMDevice *self);
static void nm_device_deactivate (NMDeviceInterface *device);

static gboolean nm_device_bring_up (NMDevice *self, gboolean wait);
static gboolean nm_device_is_up (NMDevice *self);

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
	self->priv->type = NM_DEVICE_TYPE_UNKNOWN;
	self->priv->capabilities = NM_DEVICE_CAP_NONE;
	self->priv->driver = NULL;

	self->priv->ip4_address = 0;
	memset (&self->priv->ip6_address, 0, sizeof (struct in6_addr));

	self->priv->act_source_id = 0;

	self->priv->ip4_config = NULL;

	self->priv->state = NM_DEVICE_STATE_UNMANAGED;
}

static gboolean
device_start (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	self->priv->start_timer = 0;
	nm_device_state_changed (self, NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_NOW_MANAGED);
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
nm_device_hw_is_up (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (NM_DEVICE_GET_CLASS (self)->hw_is_up)
		return NM_DEVICE_GET_CLASS (self)->hw_is_up (self);

	return TRUE;
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
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_TYPE_UNKNOWN);

	return self->priv->type;
}


void
nm_device_set_device_type (NMDevice *dev, NMDeviceType type)
{
	g_return_if_fail (NM_IS_DEVICE (dev));
	g_return_if_fail (NM_DEVICE_GET_PRIVATE (dev)->type == NM_DEVICE_TYPE_UNKNOWN);

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
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 1 of 5 (Device Prepare) started...", iface);
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
real_act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	/* Nothing to do */
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *dev, NMDeviceStateReason *reason)
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
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) starting...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	if (!nm_device_bring_up (self, FALSE)) {
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
		/* Ensure child is reaped */
		waitpid (priv->aipd_pid, NULL, WNOHANG);
		priv->aipd_pid = -1;
	}

	aipd_timeout_remove (self);

	priv->aipd_addr = 0;
}

static NMIP4Config *
aipd_get_ip4_config (NMDevice *self, NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMIP4Config *config = NULL;
	NMSettingIP4Address *addr;

	g_return_val_if_fail (priv->aipd_addr > 0, NULL);

	config = nm_ip4_config_new ();
	if (!config) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NULL;
	}

	addr = g_malloc0 (sizeof (NMSettingIP4Address));
	addr->address = (guint32) priv->aipd_addr;
	addr->prefix = 16;
	nm_ip4_config_take_address (config, addr);

	return config;	
}

static gboolean
handle_autoip_change (NMDevice *self, NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMConnection *connection;
	NMIP4Config *config;

	g_return_val_if_fail (reason != NULL, FALSE);

	config = aipd_get_ip4_config (self, reason);
	if (!config) {
		nm_warning ("failed to get autoip config for rebind");
		return FALSE;
	}

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	g_object_set_data (G_OBJECT (req), NM_ACT_REQUEST_IP4_CONFIG, config);

	if (!nm_device_set_ip4_config (self, config, reason)) {
		nm_warning ("(%s): failed to update IP4 config in response to autoip event.",
		            nm_device_get_iface (self));
		return FALSE;
	}

	return TRUE;
}

#define IPV4LL_NETWORK (htonl (0xA9FE0000L))
#define IPV4LL_NETMASK (htonl (0xFFFF0000L))

void
nm_device_handle_autoip4_event (NMDevice *self,
                                const char *event,
                                const char *address)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	NMConnection *connection = NULL;
	NMSettingIP4Config *s_ip4 = NULL;
	NMDeviceState state;
	const char *iface;

	g_return_if_fail (event != NULL);

	req = nm_device_get_act_request (self);
	if (!req)
		return;

	connection = nm_act_request_get_connection (req);
	if (!connection)
		return;

	/* Ignore if the connection isn't an AutoIP connection */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (!s_ip4 || !s_ip4->method || strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
		return;

	iface = nm_device_get_iface (self);
	state = nm_device_get_state (self);

	if (strcmp (event, "BIND") == 0) {
		struct in_addr ip;
		NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

		if (inet_pton (AF_INET, address, &ip) <= 0) {
			nm_warning ("(%s): invalid address %s received from avahi-autoipd.",
			            iface, address);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_AUTOIP_ERROR);
			return;
		}

		if ((ip.s_addr & IPV4LL_NETMASK) != IPV4LL_NETWORK) {
			nm_warning ("(%s): invalid address %s received from avahi-autoipd.",
			            iface, address);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_AUTOIP_ERROR);
			return;
		}

		switch (state) {
		case NM_DEVICE_STATE_IP_CONFIG:
			if (priv->aipd_addr) {
				nm_warning ("(%s): already have autoip address!", iface);
				return;
			}

			priv->aipd_addr = ip.s_addr;
			aipd_timeout_remove (self);
			nm_device_activate_schedule_stage4_ip_config_get (self);
			break;
		case NM_DEVICE_STATE_ACTIVATED:
			priv->aipd_addr = ip.s_addr;
			if (!handle_autoip_change (self, &reason))
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
			break;
		default:
			nm_warning ("(%s): unexpected avahi-autoip event %s for %s.",
			            iface, event, address);
			break;
		}
	} else {
		nm_warning ("%s: autoip address %s no longer valid because '%s'.",
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

	if (WIFEXITED (status))
		nm_warning ("%s: avahi-autoipd exited with error code %d", iface, WEXITSTATUS (status));
	else if (WIFSTOPPED (status)) 
		nm_warning ("%s: avahi-autoipd stopped unexpectedly with signal %d", iface, WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("%s: avahi-autoipd died with signal %d", iface, WTERMSIG (status));
	else
		nm_warning ("%s: avahi-autoipd died from an unknown cause", iface);

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

	if (!priv->aipd_timeout)
		return FALSE;
	priv->aipd_timeout = 0;

	nm_info ("%s: avahi-autoipd timed out.", nm_device_get_iface (self));
	aipd_cleanup (self);

	if (nm_device_get_state (self) == NM_DEVICE_STATE_IP_CONFIG)
		nm_device_activate_schedule_stage4_ip_config_timeout (self);

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
}

static gboolean
aipd_exec (NMDevice *self, GError **error)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	char *argv[5];
	gboolean success = FALSE;
	const char **aipd_binary = NULL;
	static const char *aipd_paths[] = {
		"/usr/sbin/avahi-autoipd",
		"/usr/local/sbin/avahi-autoipd",
		NULL
	};

	aipd_cleanup (self);

	/* Find avahi-autoipd */
	aipd_binary = aipd_paths;
	while (*aipd_binary != NULL) {
		if (g_file_test (*aipd_binary, G_FILE_TEST_EXISTS))
			break;
		aipd_binary++;
	}

	if (!*aipd_binary) {
		g_set_error (error, 0, 0, "%s", "couldn't find avahi-autoipd");
		return FALSE;
	}

	argv[0] = (char *) (*aipd_binary);
	argv[1] = "--script";
	argv[2] = LIBEXECDIR "/nm-avahi-autoipd.action";
	argv[3] = (char *) nm_device_get_iface (self);
	argv[4] = NULL;

	success = g_spawn_async ("/", argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                         &aipd_child_setup, NULL, &(priv->aipd_pid), error);
	if (!success)
		return FALSE;

	/* Monitor the child process so we know when it dies */
	priv->aipd_watch = g_child_watch_add (priv->aipd_pid, aipd_watch_cb, self);

	/* Start a timeout to bound the address attempt */
	priv->aipd_timeout = g_timeout_add (20000, aipd_timeout_cb, self);

	return TRUE;
}

static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *self, NMDeviceStateReason *reason)
{
	NMSettingIP4Config *s_ip4;
	NMActRequest *req;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	const char *iface;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	iface = nm_device_get_iface (self);

	req = nm_device_get_act_request (self);
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (nm_act_request_get_connection (req),
													NM_TYPE_SETTING_IP4_CONFIG);

	/* If we did not receive IP4 configuration information, default to DHCP */
	if (!s_ip4 || !strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
		gboolean success;

		/* Begin a DHCP transaction on the interface */
		nm_device_set_use_dhcp (self, TRUE);

		/* DHCP manager will cancel any transaction already in progress and we do not
		   want to cancel this activation if we get "down" state from that. */
		g_signal_handler_block (priv->dhcp_manager, priv->dhcp_state_sigid);
		success = nm_dhcp_manager_begin_transaction (priv->dhcp_manager, iface, s_ip4, 45);
		g_signal_handler_unblock (priv->dhcp_manager, priv->dhcp_state_sigid);

		if (success) {
			/* DHCP devices will be notified by the DHCP manager when
			 * stuff happens.	
			 */
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		} else {
			*reason = NM_DEVICE_STATE_REASON_DHCP_START_FAILED;
			ret = NM_ACT_STAGE_RETURN_FAILURE;
		}
	} else if (s_ip4 && !strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
		GError *error = NULL;

		/* Start avahi-autoipd */
		if (aipd_exec (self, &error)) {
			nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) started"
			         " avahi-autoipd...", iface);
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		} else {
			nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) failed"
			         " to start avahi-autoipd: %s", iface, error->message);
			g_error_free (error);
			aipd_cleanup (self);
			*reason = NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED;
			ret = NM_ACT_STAGE_RETURN_FAILURE;
		}
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
	const char *iface;
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip_config_start (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
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

static GHashTable *shared_ips = NULL;

static void
release_shared_ip (gpointer data)
{
	g_hash_table_remove (shared_ips, data);
}

static guint32
reserve_shared_ip (void)
{
	guint32 start = (guint32) ntohl (0x0a2a2b01); /* 10.42.43.1 */
	guint32 count = 0;

	while (g_hash_table_lookup (shared_ips, GUINT_TO_POINTER (start + count))) {
		count += ntohl (0x100);
		if (count > ntohl (0xFE00)) {
			nm_warning ("%s: ran out of shared IP addresses!", __func__);
			return 0;
		}
	}

	g_hash_table_insert (shared_ips, GUINT_TO_POINTER (start + count), GUINT_TO_POINTER (TRUE));
	return start + count;
}

static NMIP4Config *
nm_device_new_ip4_shared_config (NMDevice *self, NMDeviceStateReason *reason)
{
	NMIP4Config *config = NULL;
	NMSettingIP4Address *addr;
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
	addr = g_malloc0 (sizeof (NMSettingIP4Address));
	addr->address = tmp_addr;
	addr->prefix = 24; /* 255.255.255.0 */
	nm_ip4_config_take_address (config, addr);

	/* Remove the address lock when the object gets disposed */
	g_object_set_data_full (G_OBJECT (config), "shared-ip",
	                        GUINT_TO_POINTER (addr->address), release_shared_ip);

	return config;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *self,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	const char *iface;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	iface = nm_device_get_iface (self);

	connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	g_assert (connection);

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);

	if (nm_device_get_use_dhcp (self)) {
		*config = nm_dhcp_manager_get_ip4_config (priv->dhcp_manager, iface);
		if (*config) {
			nm_utils_merge_ip4_config (*config, s_ip4);

			nm_dhcp_manager_set_dhcp4_config (priv->dhcp_manager, iface, priv->dhcp4_config);
			/* Notify of new DHCP4 config */
			g_object_notify (G_OBJECT (self), NM_DEVICE_INTERFACE_DHCP4_CONFIG);
		} else
			*reason = NM_DEVICE_STATE_REASON_DHCP_ERROR;
	} else {
		g_assert (s_ip4);
		g_assert (s_ip4->method);

		if (!strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
			*config = aipd_get_ip4_config (self, reason);
		} else if (!strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			*config = nm_ip4_config_new ();
			if (*config)
				nm_utils_merge_ip4_config (*config, s_ip4);
			else
				*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		} else if (!strcmp (s_ip4->method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)) {
			*config = nm_device_new_ip4_shared_config (self, reason);
			if (*config)
				priv->dnsmasq_manager = nm_dnsmasq_manager_new (iface);
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
	NMIP4Config *ip4_config = NULL;
	NMActStageReturn ret;
	const char *iface = NULL;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Get) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_get_ip4_config (self, &ip4_config, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (!ip4_config || (ret == NM_ACT_STAGE_RETURN_FAILURE))
	{
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
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
                                   NMIP4Config **config,
                                   NMDeviceStateReason *reason)
{
	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Notify of invalid DHCP4 config object */
	g_object_notify (G_OBJECT (self), NM_DEVICE_INTERFACE_DHCP4_CONFIG);

	/* DHCP failed; connection must fail */
	*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
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
	NMIP4Config *ip4_config = NULL;
	const char *iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	if (self->priv->act_source_id > 0)
		self->priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP Configure Timeout) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip_config_timeout (self, &ip4_config, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
		goto out;
	} else if (!ip4_config || (ret == NM_ACT_STAGE_RETURN_FAILURE)) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
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
 * Deal with a timeout of the IP configuration
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
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMIP4Config *ip4_config = NULL;
	const char *iface;
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	ip4_config = g_object_get_data (G_OBJECT (nm_device_get_act_request (self)),
									NM_ACT_REQUEST_IP4_CONFIG);
	g_assert (ip4_config);

	/* Clear the activation source ID now that this stage has run */
	if (priv->act_source_id > 0)
		priv->act_source_id = 0;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) started...",
	         iface);

	if (!nm_device_set_ip4_config (self, ip4_config, &reason)) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}

	connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (s_ip4 && !strcmp (s_ip4->method, "shared")) {
		GError *error = NULL;

		if (!nm_dnsmasq_manager_start (priv->dnsmasq_manager, ip4_config, &error)) {
			nm_warning ("(%s): failed to start dnsmasq: %s", iface, error->message);
			g_error_free (error);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
			goto out;
		}

		priv->dnsmasq_state_id = g_signal_connect (priv->dnsmasq_manager, "state-changed",
		                                           G_CALLBACK (dnsmasq_state_changed_cb),
		                                           self);
	}

	nm_device_state_changed (self, NM_DEVICE_STATE_ACTIVATED, NM_DEVICE_STATE_REASON_NONE);

out:
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

	nm_act_request_set_default (priv->act_request, FALSE);

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

	if (priv->failed_to_disconnected_id) {
		g_source_remove (priv->failed_to_disconnected_id);
		priv->failed_to_disconnected_id = 0;
	}

	/* Stop any ongoing DHCP transaction on this device */
	if (nm_device_get_act_request (self)) {
		if (nm_device_get_use_dhcp (self)) {
			nm_dhcp_manager_cancel_transaction (priv->dhcp_manager, nm_device_get_iface (self));
			nm_device_set_use_dhcp (self, FALSE);
			/* Notify of invalid DHCP4 config */
			g_object_notify (G_OBJECT (self), NM_DEVICE_INTERFACE_DHCP4_CONFIG);
		} else if (priv->dnsmasq_manager) {
			if (priv->dnsmasq_state_id) {
				g_signal_handler_disconnect (priv->dnsmasq_manager, priv->dnsmasq_state_id);
				priv->dnsmasq_state_id = 0;
			}

			nm_dnsmasq_manager_stop (priv->dnsmasq_manager);
			g_object_unref (priv->dnsmasq_manager);
			priv->dnsmasq_manager = NULL;
		}
	}

	aipd_cleanup (self);

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
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	g_return_if_fail (self != NULL);

	nm_info ("(%s): deactivating device.", nm_device_get_iface (self));

	nm_device_deactivate_quickly (self);

	/* Clean up nameservers and addresses */
	nm_device_set_ip4_config (self, NULL, &reason);

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
                               RequestSecretsCaller caller,
                               gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	if (NM_DEVICE_GET_CLASS (self)->connection_secrets_updated)
		NM_DEVICE_GET_CLASS (self)->connection_secrets_updated (self, connection, updated_settings, caller);
}

static void
connection_secrets_failed_cb (NMActRequest *req,
                              NMConnection *connection,
                              const char *setting_name,
                              RequestSecretsCaller caller,
                              gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);
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
	nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE, NM_DEVICE_STATE_REASON_NONE);
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
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMIP4Config *config;
	NMSettingIP4Config *s_ip4;
	NMConnection *connection;
	NMActRequest *req;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	if (!nm_device_get_use_dhcp (device)) {
		nm_warning ("got DHCP rebind for device that wasn't using DHCP.");
		return;
	}

	config = nm_dhcp_manager_get_ip4_config (NM_DEVICE_GET_PRIVATE (device)->dhcp_manager,
											 nm_device_get_iface (device));
	if (!config) {
		nm_warning ("failed to get DHCP config for rebind");
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
		return;
	}

	req = nm_device_get_act_request (device);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	nm_utils_merge_ip4_config (config, s_ip4);

	g_object_set_data (G_OBJECT (req), NM_ACT_REQUEST_IP4_CONFIG, config);

	if (!nm_device_set_ip4_config (device, config, &reason)) {
		nm_warning ("Failed to update IP4 config in response to DHCP event.");
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
	}

	nm_dhcp_manager_set_dhcp4_config (priv->dhcp_manager, nm_device_get_iface (device), priv->dhcp4_config);
}

static void
dhcp_state_changed (NMDHCPManager *dhcp_manager,
					const char *iface,
					NMDHCPState state,
					gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
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
		nm_dhcp4_config_reset (priv->dhcp4_config);

		if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_activate_schedule_stage4_ip_config_timeout (device);
		break;
	case DHC_FAIL: /* all attempts to contact server timed out, sleeping */
	case DHC_ABEND: /* dhclient exited abnormally */
	case DHC_END: /* dhclient exited normally */
		nm_dhcp4_config_reset (priv->dhcp4_config);

		if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG) {
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_DHCP_FAILED);
		} else if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
			if (nm_device_get_use_dhcp (device)) {
				/* dhclient quit and therefore can't renew our lease, kill the conneciton */
				nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
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
		/* New exported DHCP4 config */
		if (priv->dhcp4_config)
			g_object_unref (priv->dhcp4_config);
		priv->dhcp4_config = nm_dhcp4_config_new ();

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
	} else {
		if (priv->dhcp4_config) {
			g_object_notify (G_OBJECT (self), NM_DEVICE_INTERFACE_DHCP4_CONFIG);
			g_object_unref (priv->dhcp4_config);
			priv->dhcp4_config = NULL;
		}

		if (priv->dhcp_manager) {
			g_signal_handler_disconnect (priv->dhcp_manager, priv->dhcp_state_sigid);
			priv->dhcp_state_sigid = 0;
			g_signal_handler_disconnect (priv->dhcp_manager, priv->dhcp_timeout_sigid);
			priv->dhcp_timeout_sigid = 0;
			g_object_unref (priv->dhcp_manager);
			priv->dhcp_manager = NULL;
		}
	}
}


NMIP4Config *
nm_device_get_ip4_config (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->ip4_config;
}


gboolean
nm_device_set_ip4_config (NMDevice *self, NMIP4Config *config, NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	gboolean success;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (reason != NULL, FALSE);

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

	success = nm_system_device_set_from_ip4_config (ip_iface, config);
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

static gboolean
nm_device_is_up (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (NM_DEVICE_GET_CLASS (self)->is_up)
		return NM_DEVICE_GET_CLASS (self)->is_up (self);

	return TRUE;
}

gboolean
nm_device_hw_bring_up (NMDevice *self, gboolean do_wait)
{
	gboolean success;
	guint32 tries = 0;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (nm_device_hw_is_up (self))
		goto out;

	nm_info ("(%s): bringing up device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->hw_bring_up) {
		success = NM_DEVICE_GET_CLASS (self)->hw_bring_up (self);
		if (!success)
			return FALSE;
	}

	/* Wait for the device to come up if requested */
	while (do_wait && !nm_device_hw_is_up (self) && (tries++ < 50))
		g_usleep (200);

	if (!nm_device_hw_is_up (self)) {
		nm_warning ("(%s): device not up after timeout!", nm_device_get_iface (self));
		return FALSE;
	}

out:
	/* Can only get HW address of some devices when they are up */
	if (NM_DEVICE_GET_CLASS (self)->update_hw_address)
		NM_DEVICE_GET_CLASS (self)->update_hw_address (self);

	nm_device_update_ip4_address (self);
	return TRUE;
}

void
nm_device_hw_take_down (NMDevice *self, gboolean do_wait)
{
	guint32 tries = 0;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (!nm_device_hw_is_up (self))
		return;

	nm_info ("(%s): taking down device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->hw_take_down)
		NM_DEVICE_GET_CLASS (self)->hw_take_down (self);

	/* Wait for the device to come up if requested */
	while (do_wait && nm_device_hw_is_up (self) && (tries++ < 50))
		g_usleep (200);
}

static gboolean
nm_device_bring_up (NMDevice *self, gboolean do_wait)
{
	gboolean success;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (!nm_device_hw_bring_up (self, do_wait))
		return FALSE;

	if (nm_device_is_up (self))
		return TRUE;

	nm_info ("(%s): preparing device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->bring_up) {
		success = NM_DEVICE_GET_CLASS (self)->bring_up (self);
		if (!success)
			return FALSE;
	}

	return TRUE;
}

void
nm_device_take_down (NMDevice *self, gboolean do_wait)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	if (nm_device_get_act_request (self))
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (self));

	if (nm_device_is_up (self)) {
		nm_info ("(%s): cleaning up...", nm_device_get_iface (self));

		if (NM_DEVICE_GET_CLASS (self)->take_down)
			NM_DEVICE_GET_CLASS (self)->take_down (self);
	}

	nm_device_hw_take_down (self, do_wait);
}

static void
nm_device_dispose (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);

	if (self->priv->dispose_has_run || !self->priv->initialized)
		goto out;

	self->priv->dispose_has_run = TRUE;

	if (self->priv->start_timer) {
		g_source_remove (self->priv->start_timer);
		self->priv->start_timer = 0;
	}

	if (self->priv->failed_to_disconnected_id) {
		g_source_remove (self->priv->failed_to_disconnected_id);
		self->priv->failed_to_disconnected_id = 0;
	}

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */

	if (self->priv->managed) {
		NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

		nm_device_take_down (self, FALSE);
		nm_device_set_ip4_config (self, NULL, &reason);
	}

	clear_act_request (self);

	if (self->priv->act_source_id) {
		g_source_remove (self->priv->act_source_id);
		self->priv->act_source_id = 0;
	}

	nm_device_set_use_dhcp (self, FALSE);

	if (self->priv->dnsmasq_manager) {
		if (self->priv->dnsmasq_state_id) {
			g_signal_handler_disconnect (self->priv->dnsmasq_manager, self->priv->dnsmasq_state_id);
			self->priv->dnsmasq_state_id = 0;
		}

		nm_dnsmasq_manager_stop (self->priv->dnsmasq_manager);
		g_object_unref (self->priv->dnsmasq_manager);
		self->priv->dnsmasq_manager = NULL;
	}

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
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState state;

	state = nm_device_get_state (self);

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
		if ((state == NM_DEVICE_STATE_ACTIVATED) || (state == NM_DEVICE_STATE_IP_CONFIG))
			g_value_set_object (value, priv->ip4_config);
		else
			g_value_set_object (value, NULL);
		break;
	case NM_DEVICE_INTERFACE_PROP_DHCP4_CONFIG:
		if (   ((state == NM_DEVICE_STATE_ACTIVATED) || (state == NM_DEVICE_STATE_IP_CONFIG))
		    && nm_device_get_use_dhcp (self))
			g_value_set_object (value, priv->dhcp4_config);
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
									  NM_DEVICE_INTERFACE_PROP_DHCP4_CONFIG,
									  NM_DEVICE_INTERFACE_DHCP4_CONFIG);

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

static gboolean
failed_to_disconnected (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	device->priv->failed_to_disconnected_id = 0;
	nm_device_state_changed (device, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
	return FALSE;
}

void
nm_device_state_changed (NMDevice *device,
                         NMDeviceState state,
                         NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	NMDeviceState old_state;
	NMActRequest *req;

	g_return_if_fail (NM_IS_DEVICE (device));
	priv = device->priv;

	if (priv->state == state)
		return;

	old_state = priv->state;
	priv->state = state;
nm_info ("(%s): device state change: %d -> %d", nm_device_get_iface (device), old_state, state);

	if (priv->failed_to_disconnected_id) {
		g_source_remove (priv->failed_to_disconnected_id);
		priv->failed_to_disconnected_id = 0;
	}

	/* Cache the activation request for the dispatcher */
	req = priv->act_request ? g_object_ref (priv->act_request) : NULL;

	/* Handle the new state here; but anything that could trigger
	 * another state change should be done below.
	 */
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		if (old_state > NM_DEVICE_STATE_UNMANAGED)
			nm_device_take_down (device, TRUE);
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state == NM_DEVICE_STATE_UNMANAGED)
			nm_device_bring_up (device, TRUE);
		/* Fall through, so when the device needs to be deactivated due to
		 * eg carrier changes we actually deactivate it */
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state != NM_DEVICE_STATE_UNAVAILABLE)
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
		break;
	default:
		break;
	}

	g_object_notify (G_OBJECT (device), NM_DEVICE_INTERFACE_STATE);
	g_signal_emit_by_name (device, "state-changed", state, old_state, 0);

	/* Post-process the event after internal notification */

	switch (state) {
	case NM_DEVICE_STATE_ACTIVATED:
		nm_info ("Activation (%s) successful, device activated.", nm_device_get_iface (device));
		nm_utils_call_dispatcher ("up", nm_act_request_get_connection (req), device, NULL);
		break;
	case NM_DEVICE_STATE_FAILED:
		nm_info ("Activation (%s) failed.", nm_device_get_iface (device));
		priv->failed_to_disconnected_id = g_idle_add (failed_to_disconnected, device);
		break;
	default:
		break;
	}

	if (old_state == NM_DEVICE_STATE_ACTIVATED)
		nm_utils_call_dispatcher ("down", nm_act_request_get_connection (req), device, NULL);

	/* Dispose of the cached activation request */
	if (req)
		g_object_unref (req);
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
	if (priv->managed == managed)
		return;

	priv->managed = managed;
	nm_info ("(%s): now %s", nm_device_get_iface (device), managed ? "managed" : "unmanaged");

	if (priv->start_timer) {
		g_source_remove (priv->start_timer);
		priv->start_timer = 0;
	}

	g_object_notify (G_OBJECT (device), NM_DEVICE_INTERFACE_MANAGED);

	/* If now managed, jump to unavailable */
	if (managed)
		nm_device_state_changed (device, NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_NOW_MANAGED);
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_UNMANAGED, NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
}

