/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2005 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
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
#include <fcntl.h>

#include "nm-glib-compat.h"
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
#include "nm-setting-ip6-config.h"
#include "nm-setting-connection.h"
#include "nm-dnsmasq-manager.h"
#include "nm-dhcp4-config.h"
#include "nm-marshal.h"

#define NM_ACT_REQUEST_IP4_CONFIG "nm-act-request-ip4-config"
#define NM_ACT_REQUEST_IP6_CONFIG "nm-act-request-ip6-config"

static void device_interface_init (NMDeviceInterface *device_interface_class);

G_DEFINE_TYPE_EXTENDED (NMDevice, nm_device, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT,
						G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE, device_interface_init))

enum {
	AUTOCONNECT_ALLOWED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

typedef struct {
	gboolean disposed;
	gboolean initialized;

	NMDeviceState state;
	guint         failed_to_disconnected_id;

	char *        udi;
	char *        path;
	char *        iface;   /* may change, could be renamed by user */
	char *        ip_iface;
	NMDeviceType  type;
	char *        type_desc;
	guint32       capabilities;
	char *        driver;
	gboolean      managed; /* whether managed by NM or not */

	guint32         ip4_address;

	NMActRequest *  act_request;
	guint           act_source_id;
	gpointer        act_source_func;
	guint           act_source6_id;
	gpointer        act_source6_func;
	gulong          secrets_updated_id;
	gulong          secrets_failed_id;

	gboolean        ip4_ready;
	gboolean        ip6_ready;

	/* IP4 configuration info */
	NMIP4Config *   ip4_config;			/* Config from DHCP, PPP, or system config files */
	NMDHCPManager * dhcp_manager;
	guint32         dhcp_timeout;
	gulong          dhcp_state_sigid;
	gulong          dhcp_timeout_sigid;
	GByteArray *    dhcp_anycast_address;
	NMDHCP4Config * dhcp4_config;

	/* dnsmasq stuff for shared connections */
	NMDnsMasqManager *dnsmasq_manager;
	gulong            dnsmasq_state_id;

	/* avahi-autoipd stuff */
	GPid    aipd_pid;
	guint   aipd_watch;
	guint   aipd_timeout;
	guint32 aipd_addr;

	/* IP6 configuration info */
	NMIP6Config *ip6_config;
} NMDevicePrivate;

static gboolean check_connection_compatible (NMDeviceInterface *device,
                                             NMConnection *connection,
                                             GError **error);
static gboolean nm_device_activate (NMDeviceInterface *device,
                                    NMActRequest *req,
                                    GError **error);
static void nm_device_deactivate (NMDeviceInterface *device, NMDeviceStateReason reason);
static gboolean nm_device_spec_match_list (NMDeviceInterface *device, const GSList *specs);

static void nm_device_activate_schedule_stage5_ip_config_commit (NMDevice *self, int family);

static void nm_device_take_down (NMDevice *dev, gboolean wait, NMDeviceStateReason reason);

static gboolean nm_device_bring_up (NMDevice *self, gboolean block, gboolean *no_firmware);
static gboolean nm_device_is_up (NMDevice *self);

static gboolean nm_device_set_ip4_config (NMDevice *dev, NMIP4Config *config, NMDeviceStateReason *reason);
static gboolean nm_device_set_ip6_config (NMDevice *dev, NMIP6Config *config, NMDeviceStateReason *reason);

static void
device_interface_init (NMDeviceInterface *device_interface_class)
{
	/* interface implementation */
	device_interface_class->check_connection_compatible = check_connection_compatible;
	device_interface_class->activate = nm_device_activate;
	device_interface_class->deactivate = nm_device_deactivate;
	device_interface_class->spec_match_list = nm_device_spec_match_list;
}


static void
nm_device_init (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->type = NM_DEVICE_TYPE_UNKNOWN;
	priv->capabilities = NM_DEVICE_CAP_NONE;
	priv->state = NM_DEVICE_STATE_UNMANAGED;
	priv->dhcp_timeout = 0;
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

	if (NM_DEVICE_GET_CLASS (dev)->update_hw_address)
		NM_DEVICE_GET_CLASS (dev)->update_hw_address (dev);

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

void
nm_device_set_path (NMDevice *self, const char *path)
{
	NMDevicePrivate *priv;

	g_return_if_fail (self != NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->path == NULL);

	priv->path = g_strdup (path);
}

const char *
nm_device_get_path (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->path;
}

const char *
nm_device_get_udi (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->udi;
}

/*
 * Get/set functions for iface
 */
const char *
nm_device_get_iface (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->iface;
}


const char *
nm_device_get_ip_iface (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (self != NULL, NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);
	/* If it's not set, default to iface */
	return priv->ip_iface ? priv->ip_iface : priv->iface;
}


void
nm_device_set_ip_iface (NMDevice *self, const char *iface)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	g_free (NM_DEVICE_GET_PRIVATE (self)->ip_iface);
	NM_DEVICE_GET_PRIVATE (self)->ip_iface = iface ? g_strdup (iface) : NULL;
}


/*
 * Get/set functions for driver
 */
const char *
nm_device_get_driver (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->driver;
}


/*
 * Get/set functions for type
 */
NMDeviceType
nm_device_get_device_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_TYPE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->type;
}


int
nm_device_get_priority (NMDevice *dev)
{
	g_return_val_if_fail (NM_IS_DEVICE (dev), -1);

	return (int) nm_device_get_device_type (dev);
}


/*
 * Accessor for capabilities
 */
guint32
nm_device_get_capabilities (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NM_DEVICE_CAP_NONE);

	return NM_DEVICE_GET_PRIVATE (self)->capabilities;
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


const char *
nm_device_get_type_desc (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->type_desc;
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

	return NM_DEVICE_GET_PRIVATE (self)->act_request;
}


gboolean
nm_device_can_activate (NMDevice *self)
{
	if (NM_DEVICE_GET_CLASS (self)->can_activate)
		return NM_DEVICE_GET_CLASS (self)->can_activate (self);
	return TRUE;
}

static gboolean
autoconnect_allowed_accumulator (GSignalInvocationHint *ihint,
                                 GValue *return_accu,
                                 const GValue *handler_return, gpointer data)
{
	if (!g_value_get_boolean (handler_return))
		g_value_set_boolean (return_accu, FALSE);
	return TRUE;
}

gboolean
nm_device_autoconnect_allowed (NMDevice *self)
{
	GValue instance = { 0, };
	GValue retval = { 0, };

	g_value_init (&instance, G_TYPE_OBJECT);
	g_value_take_object (&instance, self);

	g_value_init (&retval, G_TYPE_BOOLEAN);
	g_value_set_boolean (&retval, TRUE);

	/* Use g_signal_emitv() rather than g_signal_emit() to avoid the return
	 * value being changed if no handlers are connected */
	g_signal_emitv (&instance, signals[AUTOCONNECT_ALLOWED], 0, &retval);
	return g_value_get_boolean (&retval);
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

static void
activation_source_clear (NMDevice *self, gboolean remove_source, int family)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint *act_source_id;
	gpointer *act_source_func;

	if (family == AF_INET6) {
		act_source_id = &priv->act_source6_id;
		act_source_func = &priv->act_source6_func;
	} else {
		act_source_id = &priv->act_source_id;
		act_source_func = &priv->act_source_func;
	}

	if (*act_source_id) {
		if (remove_source)
			g_source_remove (*act_source_id);
		*act_source_id = 0;
		*act_source_func = NULL;
	}
}

static void
activation_source_schedule (NMDevice *self, GSourceFunc func, int family)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint *act_source_id;
	gpointer *act_source_func;

	if (family == AF_INET6) {
		act_source_id = &priv->act_source6_id;
		act_source_func = &priv->act_source6_func;
	} else {
		act_source_id = &priv->act_source_id;
		act_source_func = &priv->act_source_func;
	}

	if (*act_source_id)
		nm_warning ("activation stage already scheduled");

	/* Don't bother rescheduling the same function that's about to
	 * run anyway.  Fixes issues with crappy wireless drivers sending
	 * streams of associate events before NM has had a chance to process
	 * the first one.
	 */
	if (!*act_source_id || (*act_source_func != func)) {
		activation_source_clear (self, TRUE, family);
		*act_source_id = g_idle_add (func, self);
		*act_source_func = func;
	}
}

static void
configure_ip6_router_advertisements (NMDevice *dev)
{
	NMActRequest *req;
	NMConnection *connection;
	const char *iface, *method = NULL;
	NMSettingIP6Config *s_ip6;
	gboolean accept_ra = TRUE;
	char *sysctl_path;

	req = nm_device_get_act_request (dev);
	if (!req)
		return;
	connection = nm_act_request_get_connection (req);
	if (!connection)
		return;

	s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (s_ip6)
		method = nm_setting_ip6_config_get_method (s_ip6);

	if (!method || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE))
		return;

	if (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)
		|| !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL))
			accept_ra = FALSE;

	iface = nm_device_get_iface (dev);
	g_return_if_fail (strchr (iface, '/') == NULL &&
					  strcmp (iface, "all") != 0 &&
					  strcmp (iface, "default") != 0);

	sysctl_path = g_strdup_printf ("/proc/sys/net/ipv6/conf/%s/accept_ra", iface);
	nm_utils_do_sysctl (sysctl_path, accept_ra ? "1\n" : "0\n");
	g_free (sysctl_path);
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
	const char *iface;
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 1 of 5 (Device Prepare) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE, NM_DEVICE_STATE_REASON_NONE);

   /* Ensure that IPv6 Router Advertisement handling is properly
	* enabled/disabled before bringing up the interface.
	*/
	configure_ip6_router_advertisements (self);

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

	activation_source_schedule (self, nm_device_activate_stage1_device_prepare, 0);

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
	gboolean no_firmware = FALSE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 2 of 5 (Device Configure) starting...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	if (!nm_device_bring_up (self, FALSE, &no_firmware)) {
		if (no_firmware)
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_FIRMWARE_MISSING);
		else
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

	activation_source_schedule (self, nm_device_activate_stage2_device_config, 0);

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

		/* ensure the child is reaped */
		nm_debug ("waiting for ppp pid %d to exit", priv->aipd_pid);
		waitpid (priv->aipd_pid, NULL, 0);
		nm_debug ("ppp pid %d cleaned up", priv->aipd_pid);

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
	NMIP4Address *addr;

	g_return_val_if_fail (priv->aipd_addr > 0, NULL);

	config = nm_ip4_config_new ();
	if (!config) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NULL;
	}

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, (guint32) priv->aipd_addr);
	nm_ip4_address_set_prefix (addr, 16);
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
	const char *iface, *method = NULL;

	g_return_if_fail (event != NULL);

	req = nm_device_get_act_request (self);
	if (!req)
		return;

	connection = nm_act_request_get_connection (req);
	if (!connection)
		return;

	/* Ignore if the connection isn't an AutoIP connection */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	if (!s_ip4 || !method || strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
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
			nm_device_activate_schedule_stage4_ip4_config_get (self);
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
		nm_device_activate_schedule_stage4_ip4_config_timeout (self);

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
	argv[3] = (char *) nm_device_get_ip_iface (self);
	argv[4] = NULL;

	success = g_spawn_async ("/", argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                         &aipd_child_setup, NULL, &(priv->aipd_pid), error);
	if (!success)
		return FALSE;

	/* Monitor the child process so we know when it dies */
	priv->aipd_watch = g_child_watch_add (priv->aipd_pid, aipd_watch_cb, self);

	/* Start a timeout to bound the address attempt */
	priv->aipd_timeout = g_timeout_add_seconds (20, aipd_timeout_cb, self);

	return TRUE;
}

static NMActStageReturn
real_act_stage3_ip4_config_start (NMDevice *self, NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMActRequest *req;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	const char *ip_iface, *method = NULL, *uuid;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Use the IP interface (not the control interface) for IP stuff */
	ip_iface = nm_device_get_ip_iface (self);

	req = nm_device_get_act_request (self);
	connection = nm_act_request_get_connection (req);
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);

	/* If we did not receive IP4 configuration information, default to DHCP */
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	if (!s_ip4 || !method || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
		gboolean success;
		guint8 *anycast = NULL;

		if (priv->dhcp_anycast_address)
			anycast = priv->dhcp_anycast_address->data;

		/* Begin a DHCP transaction on the interface */
		nm_device_set_use_dhcp (self, TRUE);

		/* DHCP manager will cancel any transaction already in progress and we do not
		   want to cancel this activation if we get "down" state from that. */
		g_signal_handler_block (priv->dhcp_manager, priv->dhcp_state_sigid);
		success = nm_dhcp_manager_begin_transaction (priv->dhcp_manager, ip_iface, uuid, s_ip4, priv->dhcp_timeout, anycast);
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
	} else if (s_ip4 && !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
		GError *error = NULL;
		const char *iface = nm_device_get_iface (self);

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

static NMActStageReturn
real_act_stage3_ip6_config_start (NMDevice *self, NMDeviceStateReason *reason)
{
	return NM_ACT_STAGE_RETURN_SUCCESS;
}


/*
 * nm_device_activate_stage3_ip_config_start
 *
 * Begin automatic/manual IP configuration
 *
 */
static gboolean
nm_device_activate_stage3_ip_config_start (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *iface;
	NMActStageReturn ret;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	priv->ip4_ready = priv->ip6_ready = FALSE;

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 3 of 5 (IP Configure Start) started...", iface);
	nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip4_config_start (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS)
		nm_device_activate_schedule_stage4_ip4_config_get (self);
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	} else
		g_assert (ret == NM_ACT_STAGE_RETURN_POSTPONE);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip6_config_start (self, &reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS)
		nm_device_activate_schedule_stage4_ip6_config_get (self);
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	} else
		g_assert (ret == NM_ACT_STAGE_RETURN_POSTPONE);

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

	activation_source_schedule (self, nm_device_activate_stage3_ip_config_start, 0);

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
	NMIP4Address *addr;
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
	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, tmp_addr);
	nm_ip4_address_set_prefix (addr, 24);
	nm_ip4_config_take_address (config, addr);

	/* Remove the address lock when the object gets disposed */
	g_object_set_data_full (G_OBJECT (config), "shared-ip",
	                        GUINT_TO_POINTER (tmp_addr), release_shared_ip);

	return config;
}

static void
dhcp4_add_option_cb (gpointer key, gpointer value, gpointer user_data)
{
	nm_dhcp4_config_add_option (NM_DHCP4_CONFIG (user_data),
	                            (const char *) key,
	                            (const char *) value);
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
	const char *ip_iface;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Use the IP interface (not the control interface) for IP stuff */
	ip_iface = nm_device_get_ip_iface (self);

	connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	g_assert (connection);

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);

	if (nm_device_get_use_dhcp (self)) {
		*config = nm_dhcp_manager_get_ip4_config (priv->dhcp_manager, ip_iface);
		if (*config) {
			nm_utils_merge_ip4_config (*config, s_ip4);

			nm_dhcp4_config_reset (priv->dhcp4_config);
			nm_dhcp_manager_foreach_dhcp4_option (priv->dhcp_manager,
			                                      ip_iface,
			                                      dhcp4_add_option_cb,
			                                      priv->dhcp4_config);

			/* Notify of new DHCP4 config */
			g_object_notify (G_OBJECT (self), NM_DEVICE_INTERFACE_DHCP4_CONFIG);
		} else
			*reason = NM_DEVICE_STATE_REASON_DHCP_ERROR;
	} else {
		const char *method;

		g_assert (s_ip4);

		method = nm_setting_ip4_config_get_method (s_ip4);
		g_assert (method);

		if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
			*config = aipd_get_ip4_config (self, reason);
		} else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			*config = nm_ip4_config_new ();
			if (*config)
				nm_utils_merge_ip4_config (*config, s_ip4);
			else
				*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		} else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)) {
			*config = nm_device_new_ip4_shared_config (self, reason);
			if (*config)
				priv->dnsmasq_manager = nm_dnsmasq_manager_new (ip_iface);
		}
	}

	if (!*config) {
		/* Make sure device is up even if config fails */
		nm_device_bring_up (self, FALSE, NULL);
	} else
		ret = NM_ACT_STAGE_RETURN_SUCCESS;

	return ret;
}

/*
 * nm_device_activate_stage4_ip4_config_get
 *
 * Retrieve the correct IPv4 config.
 *
 */
static gboolean
nm_device_activate_stage4_ip4_config_get (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMIP4Config *ip4_config = NULL;
	NMActStageReturn ret;
	const char *iface = NULL;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP4 Configure Get) started...", iface);

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

	nm_device_activate_schedule_stage5_ip_config_commit (self, AF_INET);

out:
	nm_info ("Activation (%s) Stage 4 of 5 (IP4 Configure Get) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage4_ip4_config_get
 *
 * Schedule creation of the IPv4 config
 *
 */
void
nm_device_activate_schedule_stage4_ip4_config_get (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_stage4_ip4_config_get, AF_INET);

	nm_info ("Activation (%s) Stage 4 of 5 (IP4 Configure Get) scheduled...",
	         nm_device_get_iface (self));
}


static NMActStageReturn
real_act_stage4_ip4_config_timeout (NMDevice *self,
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
 * nm_device_activate_stage4_ip4_config_timeout
 *
 * Time out on retrieving the IPv4 config.
 *
 */
static gboolean
nm_device_activate_stage4_ip4_config_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMIP4Config *ip4_config = NULL;
	const char *iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP4 Configure Timeout) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip4_config_timeout (self, &ip4_config, &reason);
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

	nm_device_activate_schedule_stage5_ip_config_commit (self, AF_INET);

out:
	nm_info ("Activation (%s) Stage 4 of 5 (IP4 Configure Timeout) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage4_ip4_config_timeout
 *
 * Deal with a timeout of the IPv4 configuration
 *
 */
void
nm_device_activate_schedule_stage4_ip4_config_timeout (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_stage4_ip4_config_timeout, AF_INET);

	nm_info ("Activation (%s) Stage 4 of 5 (IP4 Configure Timeout) scheduled...",
	         nm_device_get_iface (self));
}

static NMActStageReturn
real_act_stage4_get_ip6_config (NMDevice *self,
                                NMIP6Config **config,
                                NMDeviceStateReason *reason)
{
	NMConnection *connection;
	NMSettingIP6Config *s_ip6;
	const char *ip_iface;
	const char *method = NULL;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* Use the IP interface (not the control interface) for IP stuff */
	ip_iface = nm_device_get_ip_iface (self);

	connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	g_assert (connection);

	s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (s_ip6)
		method = nm_setting_ip6_config_get_method (s_ip6);

	if (!method || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
		*config = NULL;
		return NM_ACT_STAGE_RETURN_SUCCESS;
	}

	*config = nm_ip6_config_new ();
	if (!*config) {
		*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
		nm_utils_merge_ip6_config (*config, s_ip6);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*
 * nm_device_activate_stage4_ip6_config_get
 *
 * Retrieve the correct IPv6 config.
 *
 */
static gboolean
nm_device_activate_stage4_ip6_config_get (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMIP6Config *ip6_config = NULL;
	NMActStageReturn ret;
	const char *iface = NULL;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET6);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP6 Configure Get) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_get_ip6_config (self, &ip6_config, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		goto out;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE)
	{
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

	g_object_set_data (G_OBJECT (nm_device_get_act_request (self)),
					   NM_ACT_REQUEST_IP6_CONFIG, ip6_config);

	nm_device_activate_schedule_stage5_ip_config_commit (self, AF_INET6);

out:
	nm_info ("Activation (%s) Stage 4 of 5 (IP6 Configure Get) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage4_ip6_config_get
 *
 * Schedule creation of the IPv6 config
 *
 */
void
nm_device_activate_schedule_stage4_ip6_config_get (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_stage4_ip6_config_get, AF_INET6);

	nm_info ("Activation (%s) Stage 4 of 5 (IP6 Configure Get) scheduled...",
	         nm_device_get_iface (self));
}


static NMActStageReturn
real_act_stage4_ip6_config_timeout (NMDevice *self,
									NMIP6Config **config,
									NMDeviceStateReason *reason)
{
	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	*reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
	return NM_ACT_STAGE_RETURN_FAILURE;
}


/*
 * nm_device_activate_stage4_ip6_config_timeout
 *
 * Time out on retrieving the IPv6 config.
 *
 */
static gboolean
nm_device_activate_stage4_ip6_config_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMIP6Config *ip6_config = NULL;
	const char *iface;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, AF_INET6);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 4 of 5 (IP6 Configure Timeout) started...", iface);

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip6_config_timeout (self, &ip6_config, &reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
		goto out;
	} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);
	/* FIXME g_assert (ip6_config); */

	g_object_set_data (G_OBJECT (nm_device_get_act_request (self)),
					   NM_ACT_REQUEST_IP6_CONFIG, ip6_config);

	nm_device_activate_schedule_stage5_ip_config_commit (self, AF_INET6);

out:
	nm_info ("Activation (%s) Stage 4 of 5 (IP6 Configure Timeout) complete.", iface);
	return FALSE;
}


/*
 * nm_device_activate_schedule_stage4_ip6_config_timeout
 *
 * Deal with a timeout of the IPv6 configuration
 *
 */
void
nm_device_activate_schedule_stage4_ip6_config_timeout (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, nm_device_activate_stage4_ip6_config_timeout, AF_INET6);

	nm_info ("Activation (%s) Stage 4 of 5 (IP6 Configure Timeout) scheduled...",
	         nm_device_get_iface (self));
}

static void
share_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static gboolean
share_init (void)
{
	int status;
	char *modules[] = { "ip_tables", "iptable_nat", "nf_nat_ftp", "nf_nat_irc",
	                    "nf_nat_sip", "nf_nat_tftp", "nf_nat_pptp", "nf_nat_h323",
	                    NULL };
	char **iter;

	if (!nm_utils_do_sysctl ("/proc/sys/net/ipv4/ip_forward", "1\n")) {
		nm_warning ("%s: Error starting IP forwarding: (%d) %s",
					__func__, errno, strerror (errno));
		return FALSE;
	}

	if (!nm_utils_do_sysctl ("/proc/sys/net/ipv4/ip_dynaddr", "1\n")) {
		nm_warning ("%s: Error starting IP forwarding: (%d) %s",
					__func__, errno, strerror (errno));
	}

	for (iter = modules; *iter; iter++) {
		char *argv[3] = { "/sbin/modprobe", *iter, NULL };
		char *envp[1] = { NULL };
		GError *error = NULL;

		if (!g_spawn_sync ("/", argv, envp, G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
		                   share_child_setup, NULL, NULL, NULL, &status, &error)) {
			nm_info ("%s: Error loading NAT module %s: (%d) %s",
			         __func__, *iter, error ? error->code : 0,
			         (error && error->message) ? error->message : "unknown");
			if (error)
				g_error_free (error);
		}
	}

	return TRUE;
}

static void
add_share_rule (NMActRequest *req, const char *table, const char *fmt, ...)
{
	va_list args;
	char *cmd;

	va_start (args, fmt);
	cmd = g_strdup_vprintf (fmt, args);
	va_end (args);

	nm_act_request_add_share_rule (req, table, cmd);
	g_free (cmd);
}

static gboolean
start_sharing (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	GError *error = NULL;
	char str_addr[INET_ADDRSTRLEN + 1];
	char str_mask[INET_ADDRSTRLEN + 1];
	guint32 netmask, network;
	NMIP4Config *ip4_config;
	NMIP4Address *ip4_addr;
	const char *ip_iface;

	ip_iface = nm_device_get_ip_iface (self);

	ip4_config = nm_device_get_ip4_config (self);
	if (!ip4_config)
		return FALSE;

	ip4_addr = nm_ip4_config_get_address (ip4_config, 0);
	if (!ip4_addr || !nm_ip4_address_get_address (ip4_addr))
		return FALSE;

	netmask = nm_utils_ip4_prefix_to_netmask (nm_ip4_address_get_prefix (ip4_addr));
	if (!inet_ntop (AF_INET, &netmask, str_mask, sizeof (str_mask)))
		return FALSE;

	network = nm_ip4_address_get_address (ip4_addr) & netmask;
	if (!inet_ntop (AF_INET, &network, str_addr, sizeof (str_addr)))
		return FALSE;

	if (!share_init ())
		return FALSE;

	req = nm_device_get_act_request (self);
	g_assert (req);

	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol tcp --destination-port 53 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol udp --destination-port 53 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol tcp --destination-port 67 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol udp --destination-port 67 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "FORWARD --in-interface %s --jump REJECT", ip_iface);
	add_share_rule (req, "filter", "FORWARD --out-interface %s --jump REJECT", ip_iface);
	add_share_rule (req, "filter", "FORWARD --in-interface %s --out-interface %s --jump ACCEPT", ip_iface, ip_iface);
	add_share_rule (req, "filter", "FORWARD --source %s/%s --in-interface %s --jump ACCEPT", str_addr, str_mask, ip_iface);
	add_share_rule (req, "filter", "FORWARD --destination %s/%s --out-interface %s --match state --state ESTABLISHED,RELATED --jump ACCEPT", str_addr, str_mask, ip_iface);
	add_share_rule (req, "nat", "POSTROUTING --source %s/%s --destination ! %s/%s --jump MASQUERADE", str_addr, str_mask, str_addr, str_mask);

	nm_act_request_set_shared (req, TRUE);

	if (!nm_dnsmasq_manager_start (priv->dnsmasq_manager, ip4_config, &error)) {
		nm_warning ("(%s/%s): failed to start dnsmasq: %s",
		            nm_device_get_iface (self), ip_iface, error->message);
		g_error_free (error);
		nm_act_request_set_shared (req, FALSE);
		return FALSE;
	}

	priv->dnsmasq_state_id = g_signal_connect (priv->dnsmasq_manager, "state-changed",
	                                           G_CALLBACK (dnsmasq_state_changed_cb),
	                                           self);
	return TRUE;
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
	NMIP4Config *ip4_config = NULL;
	NMIP6Config *ip6_config = NULL;
	const char *iface, *method = NULL;
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;

	ip4_config = g_object_get_data (G_OBJECT (nm_device_get_act_request (self)),
									NM_ACT_REQUEST_IP4_CONFIG);
	g_assert (ip4_config);
	ip6_config = g_object_get_data (G_OBJECT (nm_device_get_act_request (self)),
									NM_ACT_REQUEST_IP6_CONFIG);
	/* FIXME g_assert (ip6_config); */

	/* Clear the activation source ID now that this stage has run */
	activation_source_clear (self, FALSE, 0);

	iface = nm_device_get_iface (self);
	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) started...",
	         iface);

	if (!nm_device_set_ip4_config (self, ip4_config, &reason)) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
		goto out;
	}

	if (!nm_device_set_ip6_config (self, ip6_config, &reason)) {
		nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) IPv6 failed",
				 iface);
	}

	connection = nm_act_request_get_connection (nm_device_get_act_request (self));
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (s_ip4)
		method = nm_setting_ip4_config_get_method (s_ip4);

	if (s_ip4 && !strcmp (method, "shared")) {
		if (!start_sharing (self)) {
			nm_warning ("Activation (%s) Stage 5 of 5 (IP Configure Commit) start sharing failed.", iface);
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
			goto out;
		}
	}

	nm_device_state_changed (self, NM_DEVICE_STATE_ACTIVATED, NM_DEVICE_STATE_REASON_NONE);

out:
	nm_info ("Activation (%s) Stage 5 of 5 (IP Configure Commit) complete.",
	         iface);

	/* Balance IP config creation; device takes ownership in set_ip*_config() */
	g_object_unref (ip4_config);
	g_object_unref (ip6_config);

	return FALSE;
}


/*
 * nm_device_activate_schedule_stage5_ip_config_commit
 *
 * Schedule commit of the IP config
 */
static void
nm_device_activate_schedule_stage5_ip_config_commit (NMDevice *self, int family)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	if (family == AF_INET)
		priv->ip4_ready = TRUE;
	else if (family == AF_INET6)
		priv->ip6_ready = TRUE;

	if (!priv->ip4_ready || !priv->ip6_ready)
		return;

	activation_source_schedule (self, nm_device_activate_stage5_ip_config_commit, 0);

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

	/* Break the activation chain */
	activation_source_clear (self, TRUE, AF_INET);
	activation_source_clear (self, TRUE, AF_INET6);

	if (priv->failed_to_disconnected_id) {
		g_source_remove (priv->failed_to_disconnected_id);
		priv->failed_to_disconnected_id = 0;
	}

	/* Stop any ongoing DHCP transaction on this device */
	if (nm_device_get_act_request (self)) {
		if (nm_device_get_use_dhcp (self)) {
			nm_dhcp_manager_cancel_transaction (priv->dhcp_manager, nm_device_get_ip_iface (self));
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

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate_quickly)
		NM_DEVICE_GET_CLASS (self)->deactivate_quickly (self);

	/* Tear down an existing activation request */
	clear_act_request (self);

	return TRUE;
}

/*
 * nm_device_deactivate
 *
 * Remove a device's routing table entries and IP address.
 *
 */
static void
nm_device_deactivate (NMDeviceInterface *device, NMDeviceStateReason reason)
{
	NMDevice *self = NM_DEVICE (device);
	NMDeviceStateReason ignored = NM_DEVICE_STATE_REASON_NONE;

	g_return_if_fail (self != NULL);

	nm_info ("(%s): deactivating device (reason: %d).",
	         nm_device_get_iface (self),
	         reason);

	nm_device_deactivate_quickly (self);

	/* Clean up nameservers and addresses */
	nm_device_set_ip4_config (self, NULL, &ignored);
	nm_device_set_ip6_config (self, NULL, &ignored);

	/* Take out any entries in the routing table and any IP address the device had. */
	nm_system_device_flush_routes (self);
	nm_system_device_flush_addresses (self);
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
	if (nm_connection_compare (connection, current_connection, NM_SETTING_COMPARE_FLAG_EXACT)) {
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
	const char *ip_iface;

	if (!nm_device_get_use_dhcp (device)) {
		nm_warning ("got DHCP rebind for device that wasn't using DHCP.");
		return;
	}

	ip_iface = nm_device_get_ip_iface (device);

	config = nm_dhcp_manager_get_ip4_config (priv->dhcp_manager, ip_iface);
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

	if (nm_device_set_ip4_config (device, config, &reason)) {
		nm_dhcp4_config_reset (priv->dhcp4_config);
		nm_dhcp_manager_foreach_dhcp4_option (priv->dhcp_manager,
		                                      ip_iface,
		                                      dhcp4_add_option_cb,
		                                      priv->dhcp4_config);
	} else {
		nm_warning ("Failed to update IP4 config in response to DHCP event.");
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
	}
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

	if (strcmp (nm_device_get_ip_iface (device), iface) != 0)
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
			nm_device_activate_schedule_stage4_ip4_config_get (device);
		else if (dev_state == NM_DEVICE_STATE_ACTIVATED)
			handle_dhcp_lease_change (device);
		break;
	case DHC_TIMEOUT: /* timed out contacting DHCP server */
		nm_dhcp4_config_reset (priv->dhcp4_config);

		if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_activate_schedule_stage4_ip4_config_timeout (device);
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

	if (strcmp (nm_device_get_ip_iface (device), iface) != 0)
		return;

	if (nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG)
		nm_device_activate_schedule_stage4_ip4_config_timeout (device);
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

NMDHCP4Config *
nm_device_get_dhcp4_config (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dhcp_manager)
		return priv->dhcp4_config;
	return NULL;
}

NMIP4Config *
nm_device_get_ip4_config (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->ip4_config;
}


static gboolean
nm_device_set_ip4_config (NMDevice *self,
                          NMIP4Config *new_config,
                          NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	NMIP4Config *old_config = NULL;
	gboolean success = TRUE;
	NMIP4ConfigCompareFlags diff = NM_IP4_COMPARE_FLAG_ALL;
	NMNamedManager *named_mgr;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (reason != NULL, FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);

	old_config = priv->ip4_config;

	if (new_config && old_config)
		diff = nm_ip4_config_diff (new_config, old_config);

	/* No actual change, do nothing */
	if (diff == NM_IP4_COMPARE_FLAG_NONE)
		return TRUE;

	named_mgr = nm_named_manager_get ();
	if (old_config) {
		/* Remove any previous IP4 Config from the named manager */
		nm_named_manager_remove_ip4_config (named_mgr, ip_iface, old_config);
		g_object_unref (old_config);
		priv->ip4_config = NULL;
	}

	if (new_config) {
		priv->ip4_config = g_object_ref (new_config);

		success = nm_system_apply_ip4_config (ip_iface, new_config, nm_device_get_priority (self), diff);
		if (success) {
			/* Export over D-Bus */
			if (!nm_ip4_config_get_dbus_path (new_config))
				nm_ip4_config_export (new_config);

			/* Add the DNS information to the named manager */
			nm_named_manager_add_ip4_config (named_mgr, ip_iface, new_config, NM_NAMED_IP_CONFIG_TYPE_DEFAULT);

			nm_device_update_ip4_address (self);
		}
	}
	g_object_unref (named_mgr);

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

	return NM_DEVICE_GET_PRIVATE (self)->ip4_address;
}


void
nm_device_update_ip4_address (NMDevice *self)
{
	struct ifreq req;
	guint32 new_address;
	int fd;
	
	g_return_if_fail (self  != NULL);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_warning ("couldn't open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_ip_iface (self), IFNAMSIZ);
	if (ioctl (fd, SIOCGIFADDR, &req) == 0) {
		new_address = ((struct sockaddr_in *)(&req.ifr_addr))->sin_addr.s_addr;
		if (new_address != nm_device_get_ip4_address (self))
			NM_DEVICE_GET_PRIVATE (self)->ip4_address = new_address;
	}
	close (fd);
}

static gboolean
nm_device_set_ip6_config (NMDevice *self,
                          NMIP6Config *new_config,
                          NMDeviceStateReason *reason)
{
	NMDevicePrivate *priv;
	const char *ip_iface;
	NMIP6Config *old_config = NULL;
	gboolean success = TRUE;
	NMIP6ConfigCompareFlags diff = NM_IP6_COMPARE_FLAG_ALL;
	NMNamedManager *named_mgr;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (reason != NULL, FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	ip_iface = nm_device_get_ip_iface (self);

	old_config = priv->ip6_config;

	if (new_config && old_config)
		diff = nm_ip6_config_diff (new_config, old_config);

	/* No actual change, do nothing */
	if (diff == NM_IP6_COMPARE_FLAG_NONE)
		return TRUE;

	named_mgr = nm_named_manager_get ();
	if (old_config) {
		/* Remove any previous IP6 Config from the named manager */
		nm_named_manager_remove_ip6_config (named_mgr, ip_iface, old_config);
		g_object_unref (old_config);
		priv->ip6_config = NULL;
	}

	if (new_config) {
		priv->ip6_config = g_object_ref (new_config);

		success = nm_system_apply_ip6_config (ip_iface, new_config, nm_device_get_priority (self), diff);
		if (success) {
			/* Export over D-Bus */
			if (!nm_ip6_config_get_dbus_path (new_config))
				nm_ip6_config_export (new_config);

			/* Add the DNS information to the named manager */
			nm_named_manager_add_ip6_config (named_mgr, ip_iface, new_config, NM_NAMED_IP_CONFIG_TYPE_DEFAULT);
		}
	}
	g_object_unref (named_mgr);

	g_object_notify (G_OBJECT (self), NM_DEVICE_INTERFACE_IP6_CONFIG);

	return success;
}

NMIP6Config *
nm_device_get_ip6_config (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->ip6_config;
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
nm_device_hw_bring_up (NMDevice *self, gboolean block, gboolean *no_firmware)
{
	gboolean success;
	guint32 tries = 0;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (nm_device_hw_is_up (self))
		goto out;

	nm_info ("(%s): bringing up device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->hw_bring_up) {
		success = NM_DEVICE_GET_CLASS (self)->hw_bring_up (self, no_firmware);
		if (!success)
			return FALSE;
	}

	/* Wait for the device to come up if requested */
	while (block && !nm_device_hw_is_up (self) && (tries++ < 50))
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
nm_device_hw_take_down (NMDevice *self, gboolean block)
{
	guint32 tries = 0;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (!nm_device_hw_is_up (self))
		return;

	nm_info ("(%s): taking down device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->hw_take_down)
		NM_DEVICE_GET_CLASS (self)->hw_take_down (self);

	/* Wait for the device to come up if requested */
	while (block && nm_device_hw_is_up (self) && (tries++ < 50))
		g_usleep (200);
}

static gboolean
nm_device_bring_up (NMDevice *self, gboolean block, gboolean *no_firmware)
{
	gboolean success = FALSE;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (!nm_device_hw_bring_up (self, block, no_firmware))
		return FALSE;

	if (nm_device_is_up (self))
		return TRUE;

	nm_info ("(%s): preparing device.", nm_device_get_iface (self));

	if (NM_DEVICE_GET_CLASS (self)->bring_up)
		success = NM_DEVICE_GET_CLASS (self)->bring_up (self);

	return success;
}

static void
nm_device_take_down (NMDevice *self, gboolean block, NMDeviceStateReason reason)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	if (nm_device_get_act_request (self))
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (self), reason);

	if (nm_device_is_up (self)) {
		nm_info ("(%s): cleaning up...", nm_device_get_iface (self));

		if (NM_DEVICE_GET_CLASS (self)->take_down)
			NM_DEVICE_GET_CLASS (self)->take_down (self);
	}

	nm_device_hw_take_down (self, block);
}

static void
dispose (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->disposed || !priv->initialized)
		goto out;

	priv->disposed = TRUE;

	if (priv->failed_to_disconnected_id) {
		g_source_remove (priv->failed_to_disconnected_id);
		priv->failed_to_disconnected_id = 0;
	}

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */

	if (priv->managed) {
		NMDeviceStateReason ignored = NM_DEVICE_STATE_REASON_NONE;

		nm_device_take_down (self, FALSE, NM_DEVICE_STATE_REASON_REMOVED);
		nm_device_set_ip4_config (self, NULL, &ignored);
	}

	clear_act_request (self);

	activation_source_clear (self, TRUE, AF_INET);
	activation_source_clear (self, TRUE, AF_INET6);

	nm_device_set_use_dhcp (self, FALSE);

	if (priv->dnsmasq_manager) {
		if (priv->dnsmasq_state_id) {
			g_signal_handler_disconnect (priv->dnsmasq_manager, priv->dnsmasq_state_id);
			priv->dnsmasq_state_id = 0;
		}

		nm_dnsmasq_manager_stop (priv->dnsmasq_manager);
		g_object_unref (priv->dnsmasq_manager);
		priv->dnsmasq_manager = NULL;
	}

out:
	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_free (priv->udi);
	g_free (priv->iface);
	g_free (priv->ip_iface);
	g_free (priv->driver);
	g_free (priv->type_desc);
	if (priv->dhcp_anycast_address)
		g_byte_array_free (priv->dhcp_anycast_address, TRUE);

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
	case NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE:
		g_return_if_fail (priv->type == NM_DEVICE_TYPE_UNKNOWN);
		priv->type = g_value_get_uint (value);
		break;
	case NM_DEVICE_INTERFACE_PROP_TYPE_DESC:
		g_free (priv->type_desc);
		priv->type_desc = g_value_dup_string (value);
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
		if ((state == NM_DEVICE_STATE_ACTIVATED) || (state == NM_DEVICE_STATE_IP_CONFIG)) {
			if (priv->ip4_config) {
				g_value_set_boxed (value, nm_ip4_config_get_dbus_path (priv->ip4_config));
				break;
			}
		}
		g_value_set_boxed (value, "/");
		break;
	case NM_DEVICE_INTERFACE_PROP_DHCP4_CONFIG:
		if (   ((state == NM_DEVICE_STATE_ACTIVATED) || (state == NM_DEVICE_STATE_IP_CONFIG))
		    && nm_device_get_use_dhcp (self))
			g_value_set_boxed (value, nm_dhcp4_config_get_dbus_path (priv->dhcp4_config));
		else
			g_value_set_boxed (value, "/");
		break;
	case NM_DEVICE_INTERFACE_PROP_IP6_CONFIG:
		if ((state == NM_DEVICE_STATE_ACTIVATED) || (state == NM_DEVICE_STATE_IP_CONFIG)) {
			if (priv->ip6_config) {
				g_value_set_boxed (value, nm_ip6_config_get_dbus_path (priv->ip6_config));
				break;
			}
		}
		g_value_set_boxed (value, "/");
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
	case NM_DEVICE_INTERFACE_PROP_TYPE_DESC:
		g_value_set_string (value, priv->type_desc);
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
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->constructor = constructor;

	klass->get_type_capabilities = real_get_type_capabilities;
	klass->get_generic_capabilities = real_get_generic_capabilities;
	klass->act_stage1_prepare = real_act_stage1_prepare;
	klass->act_stage2_config = real_act_stage2_config;
	klass->act_stage3_ip4_config_start = real_act_stage3_ip4_config_start;
	klass->act_stage3_ip6_config_start = real_act_stage3_ip6_config_start;
	klass->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	klass->act_stage4_get_ip6_config = real_act_stage4_get_ip6_config;
	klass->act_stage4_ip4_config_timeout = real_act_stage4_ip4_config_timeout;
	klass->act_stage4_ip6_config_timeout = real_act_stage4_ip6_config_timeout;

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
									  NM_DEVICE_INTERFACE_PROP_IP6_CONFIG,
									  NM_DEVICE_INTERFACE_IP6_CONFIG);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_STATE,
									  NM_DEVICE_INTERFACE_STATE);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE,
									  NM_DEVICE_INTERFACE_DEVICE_TYPE);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_MANAGED,
									  NM_DEVICE_INTERFACE_MANAGED);

	g_object_class_override_property (object_class,
									  NM_DEVICE_INTERFACE_PROP_TYPE_DESC,
									  NM_DEVICE_INTERFACE_TYPE_DESC);

	signals[AUTOCONNECT_ALLOWED] =
		g_signal_new ("autoconnect-allowed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              0,
		              autoconnect_allowed_accumulator, NULL,
		              _nm_marshal_BOOLEAN__VOID,
		              G_TYPE_BOOLEAN, 0);
}

static gboolean
failed_to_disconnected (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->failed_to_disconnected_id = 0;
	nm_device_state_changed (self, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
	return FALSE;
}

void
nm_device_state_changed (NMDevice *device,
                         NMDeviceState state,
                         NMDeviceStateReason reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	NMDeviceState old_state;
	NMActRequest *req;
	gboolean no_firmware = FALSE;

	g_return_if_fail (NM_IS_DEVICE (device));

	if (priv->state == state)
		return;

	old_state = priv->state;
	priv->state = state;

	nm_info ("(%s): device state change: %d -> %d (reason %d)",
	         nm_device_get_iface (device), old_state, state, reason);

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
			nm_device_take_down (device, TRUE, reason);
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state == NM_DEVICE_STATE_UNMANAGED) {
			if (!nm_device_bring_up (device, TRUE, &no_firmware) && no_firmware)
				nm_warning ("%s: firmware may be missing.", nm_device_get_iface (device));
		}
		/* Fall through, so when the device needs to be deactivated due to
		 * eg carrier changes we actually deactivate it */
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state != NM_DEVICE_STATE_UNAVAILABLE)
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device), reason);
		break;
	default:
		break;
	}

	g_object_notify (G_OBJECT (device), NM_DEVICE_INTERFACE_STATE);
	g_signal_emit_by_name (device, "state-changed", state, old_state, reason);

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
nm_device_set_managed (NMDevice *device,
                       gboolean managed,
                       NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->managed == managed)
		return;

	priv->managed = managed;
	nm_info ("(%s): now %s", nm_device_get_iface (device), managed ? "managed" : "unmanaged");

	g_object_notify (G_OBJECT (device), NM_DEVICE_INTERFACE_MANAGED);

	/* If now managed, jump to unavailable */
	if (managed)
		nm_device_state_changed (device, NM_DEVICE_STATE_UNAVAILABLE, reason);
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_UNMANAGED, reason);
}

static gboolean
nm_device_spec_match_list (NMDeviceInterface *device, const GSList *specs)
{
	NMDevice *self;

	g_return_val_if_fail (device != NULL, FALSE);

	self = NM_DEVICE (device);
	if (NM_DEVICE_GET_CLASS (self)->spec_match_list)
		return NM_DEVICE_GET_CLASS (self)->spec_match_list (self, specs);

	return FALSE;
}

void
nm_device_set_dhcp_timeout (NMDevice *device, guint32 timeout)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	NM_DEVICE_GET_PRIVATE (device)->dhcp_timeout = timeout;
}

void
nm_device_set_dhcp_anycast_address (NMDevice *device, guint8 *addr)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (priv->dhcp_anycast_address) {
		g_byte_array_free (priv->dhcp_anycast_address, TRUE);
		priv->dhcp_anycast_address = NULL;
	}

	if (addr) {
		priv->dhcp_anycast_address = g_byte_array_sized_new (ETH_ALEN);
		g_byte_array_append (priv->dhcp_anycast_address, addr, ETH_ALEN);
	}
}


