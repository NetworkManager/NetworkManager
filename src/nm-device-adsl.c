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
 * Pantelis Koukousoulas <pktoss@gmail.com>
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <stdlib.h>
#include <string.h>

#include "nm-glib-compat.h"
#include "nm-device-adsl.h"
#include "nm-device-private.h"
#include "nm-properties-changed-signal.h"
#include "nm-glib-compat.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"
#include "nm-enum-types.h"
#include "nm-system.h"

#include "ppp-manager/nm-ppp-manager.h"
#include "br2684-manager/nm-br2684-manager.h"
#include "nm-setting-adsl.h"

#include "nm-device-adsl-glue.h"

G_DEFINE_TYPE (NMDeviceAdsl, nm_device_adsl, NM_TYPE_DEVICE)

#define NM_DEVICE_ADSL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ADSL, NMDeviceAdslPrivate))

#define NM_ADSL_ERROR (nm_adsl_error_quark ())

static GQuark
nm_adsl_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-adsl-error");
	return quark;
}

typedef struct {
	gboolean      disposed;
	gboolean      carrier;
	guint         carrier_poll_id;

	/* PPP */
	NMPPPManager *ppp_manager;
	NMIP4Config  *pending_ip4_config;

	/* RFC 2684 bridging (PPPoE over ATM) */
	NMBr2684Manager *br2684_manager;
} NMDeviceAdslPrivate;

enum {
	PROPERTIES_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_CARRIER,

	LAST_PROP
};

/* FIXME: Move it to nm-device.c and then get rid of all foo_device_get_setting() all around.
   It's here now to keep the patch short. */
static NMSetting *
device_get_setting (NMDevice *device, GType setting_type)
{
	NMActRequest *req;
	NMSetting *setting = NULL;
	NMConnection *connection;

	req = nm_device_get_act_request (device);
	if (req) {
		connection = nm_act_request_get_connection (req);
		if (connection)
			setting = nm_connection_get_setting (connection, setting_type);
	}

	return setting;
}

static void
set_carrier (NMDeviceAdsl *self, const gboolean carrier)
{
	NMDeviceAdslPrivate *priv;
	NMDeviceState state;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	if (priv->carrier == carrier)
		return;

	priv->carrier = carrier;
	g_object_notify (G_OBJECT (self), NM_DEVICE_ADSL_CARRIER);

	state = nm_device_get_state (NM_DEVICE (self));
	nm_log_info (LOGD_HW, "(%s): carrier now %s (device state %d)",
	             nm_device_get_iface (NM_DEVICE (self)),
	             carrier ? "ON" : "OFF",
	             state);

	if (state == NM_DEVICE_STATE_UNAVAILABLE) {
		if (priv->carrier)
			nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_CARRIER);
	} else if (state >= NM_DEVICE_STATE_DISCONNECTED) {
		if (!priv->carrier)
			nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_UNAVAILABLE, NM_DEVICE_STATE_REASON_CARRIER);
	}
}

static gboolean
carrier_update_cb (gpointer user_data)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (user_data);
	GError *error = NULL;
	gboolean carrier = FALSE;
	char *path, *contents;
	const char *iface;
	gboolean success;

	iface = nm_device_get_iface (NM_DEVICE (self));

	path  = g_strdup_printf ("/sys/class/atm/%s/carrier", iface);
	success = g_file_get_contents(path, &contents, NULL, &error);
	g_free (path);

	if (!success) {
		nm_log_dbg (LOGD_DEVICE, "error reading %s: (%d) %s",
		            path,
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return TRUE;
	}

	carrier = (gboolean) atoi (contents);
	g_free (contents);
	set_carrier (self, carrier);
	return TRUE;
}


NMDevice *
nm_device_adsl_new (const char *udi,
                    const char *iface,
                    const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_ADSL,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, driver,
	                                  NM_DEVICE_TYPE_DESC, "ADSL",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_ADSL,
	                                  NULL);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceAdslPrivate *priv;
	NMDevice *self;

	object = G_OBJECT_CLASS (nm_device_adsl_parent_class)->constructor (type,
	                                                                    n_construct_params,
	                                                                    construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE (object);
	priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	priv->carrier = FALSE;
	priv->carrier_poll_id = g_timeout_add_seconds(5, carrier_update_cb, self);

	return object;
}

static void
dispose (GObject *object)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (object);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_adsl_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	if (priv->carrier_poll_id) {
		g_source_remove (priv->carrier_poll_id);
		priv->carrier_poll_id = 0;
	}

	G_OBJECT_CLASS (nm_device_adsl_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (object);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);

	switch (prop_id) {
	case PROP_CARRIER:
		g_value_set_boolean (value, priv->carrier);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_adsl_init (NMDeviceAdsl * self)
{
}


static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	guint32 caps = NM_DEVICE_CAP_NM_SUPPORTED;
	caps |= NM_DEVICE_CAP_CARRIER_DETECT;
	return caps;
}

static gboolean
real_can_interrupt_activation (NMDevice *dev)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (dev);
	gboolean interrupt = FALSE;

	/* Devices that support carrier detect can interrupt activation
	 * if the link becomes inactive.
	 */
	if (NM_DEVICE_ADSL_GET_PRIVATE (self)->carrier == FALSE)
		interrupt = TRUE;

	return interrupt;
}

static gboolean
real_is_available (NMDevice *dev)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (dev);

	/* Can't do anything if there isn't a carrier */
	if (!NM_DEVICE_ADSL_GET_PRIVATE (self)->carrier)
		return FALSE;

	return TRUE;
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMSettingAdsl *s_adsl;
	const char *protocol;

	if (!nm_connection_is_type (connection, NM_SETTING_ADSL_SETTING_NAME)) {
		g_set_error (error,
		             NM_ADSL_ERROR, NM_ADSL_ERROR_CONNECTION_NOT_ADSL,
		             "The connection was not an ADSL connection.");
		return FALSE;
	}

	s_adsl = (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);

	if (!s_adsl) {
		g_set_error (error,
		             NM_ADSL_ERROR, NM_ADSL_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid ADSL connection.");
		return FALSE;
	}

	/* FIXME: we don't yet support IPoATM */
	protocol = nm_setting_adsl_get_protocol (s_adsl);
	if (g_strcmp0 (protocol, NM_SETTING_ADSL_PROTOCOL_IPOATM) == 0) {
		g_set_error (error,
		             NM_ADSL_ERROR, NM_ADSL_ERROR_CONNECTION_INVALID,
		             "IPoATM connections are not yet supported.");
		return FALSE;
	}

	return TRUE;
}

static gboolean
real_complete_connection (NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          const GSList *existing_connections,
                          GError **error)
{
	NMSettingAdsl *s_adsl;

	s_adsl = (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);

	/*
	 * We can't telepathically figure out the username, so if
	 * it wasn't given, we can't complete the connection.
	 */
	if (s_adsl && !nm_setting_verify (NM_SETTING (s_adsl), NULL, error))
		return FALSE;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_ADSL_SETTING_NAME,
	                           existing_connections,
	                           _("ADSL connection %d"),
	                           NULL,
	                           FALSE); /* No IPv6 yet by default */


	return TRUE;
}

static void
real_deactivate (NMDevice *device)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (device);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	if (priv->br2684_manager) {
		g_object_unref (priv->br2684_manager);
		priv->br2684_manager = NULL;
	}
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
                               GSList *connections,
                               char **specific_object)
{
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		NMSettingAdsl *s_adsl;
		const char *connection_type;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		connection_type = nm_setting_connection_get_connection_type (s_con);
		if (strcmp (connection_type, NM_SETTING_ADSL_SETTING_NAME))
			continue;

		s_adsl = (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);
		if (!s_adsl)
			continue;

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		return connection;
	}
	return NULL;
}

static void
br2684_state_changed (NMBr2684Manager *manager, guint status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	if (status) {
		nm_system_device_set_up_down_with_iface ("nas0", TRUE, NULL);
		nm_device_activate_schedule_stage2_device_config (device);
	} else {
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_BR2684_FAILED);
	}
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	NMDeviceAdsl *self = NM_DEVICE_ADSL (dev);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMActRequest *req;
	NMSettingAdsl *s_adsl;
	GError *err = NULL;
	const char *protocol;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_adsl = NM_SETTING_ADSL (device_get_setting (dev, NM_TYPE_SETTING_ADSL));
	g_assert (s_adsl);

	protocol = nm_setting_adsl_get_protocol (s_adsl);
	if (!strcmp (protocol, "pppoe")) {
		priv->br2684_manager = nm_br2684_manager_new();
		if (!nm_br2684_manager_start (priv->br2684_manager, req, 30, &err)) {
			nm_log_warn (LOGD_DEVICE, "(%s): RFC 2684 bridge failed to start: %s",
					             nm_device_get_iface (NM_DEVICE (self)), err->message);
			ret = NM_ACT_STAGE_RETURN_FAILURE;
			goto out;
		}
		g_signal_connect (priv->br2684_manager, "state-changed",
					   G_CALLBACK (br2684_state_changed),
					   self);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}

out:
	return ret;
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	return ret;
}

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
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

	/* Ignore PPP IP4 events that come in after initial configuration */
	if (nm_device_get_state (device) != NM_DEVICE_STATE_IP_CONFIG)
		return;

	nm_device_set_ip_iface (device, iface);
	NM_DEVICE_ADSL_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip4_config_get (device);
}

static NMActStageReturn
pppoa_stage3_ip4_config_start (NMDeviceAdsl *self, NMDeviceStateReason *reason)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingAdsl *s_adsl;
	NMActRequest *req;
	GError *err = NULL;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (req);

	s_adsl = (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);
	g_assert (s_adsl);

	priv->ppp_manager = nm_ppp_manager_new (nm_device_get_iface (NM_DEVICE (self)));
	if (nm_ppp_manager_start (priv->ppp_manager, req, nm_setting_adsl_get_username (s_adsl), 30, &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
		                  G_CALLBACK (ppp_state_changed),
		                  self);
		g_signal_connect (priv->ppp_manager, "ip4-config",
		                  G_CALLBACK (ppp_ip4_config),
		                  self);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_log_warn (LOGD_DEVICE, "(%s): ADSL failed to start: %s",
		             nm_device_get_iface (NM_DEVICE (self)), err->message);
		g_error_free (err);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		*reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
	}

	return ret;
}

static NMActStageReturn
real_act_stage3_ip4_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	NMSettingConnection *s_con;
	const char *connection_type;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_con = NM_SETTING_CONNECTION (device_get_setting (device, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);

	return pppoa_stage3_ip4_config_start (NM_DEVICE_ADSL (device), reason);
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (device);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	/* PPP */
	*config = priv->pending_ip4_config;
	priv->pending_ip4_config = NULL;

	/* Merge user-defined overrides into the IP4Config to be applied */
	connection = nm_act_request_get_connection (nm_device_get_act_request (device));
	g_assert (connection);
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	nm_utils_merge_ip4_config (*config, s_ip4);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
nm_device_adsl_class_init (NMDeviceAdslClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceAdslPrivate));

	object_class->constructor  = constructor;
	object_class->dispose      = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->can_interrupt_activation = real_can_interrupt_activation;
	parent_class->is_available = real_is_available;

	parent_class->check_connection_compatible = real_check_connection_compatible;
	parent_class->get_best_auto_connection = real_get_best_auto_connection;
	parent_class->complete_connection = real_complete_connection;

	parent_class->act_stage1_prepare = real_act_stage1_prepare;
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage3_ip4_config_start = real_act_stage3_ip4_config_start;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->deactivate = real_deactivate;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_ADSL_CARRIER,
							   "Carrier",
							   "Carrier",
							   FALSE,
							   G_PARAM_READABLE));

	/* Signals */
	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceAdslClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
	                                 &dbus_glib_nm_device_adsl_object_info);
}
