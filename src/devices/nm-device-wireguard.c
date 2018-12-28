/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Javier Arteaga <jarteaga@jbeta.is>
 */

#include "nm-default.h"

#include "nm-device-wireguard.h"

#include "nm-setting-wireguard.h"
#include "nm-core-internal.h"
#include "nm-utils/nm-secret-utils.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-active-connection.h"
#include "nm-act-request.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceWireGuard);

/*****************************************************************************/

G_STATIC_ASSERT (NM_WIREGUARD_PUBLIC_KEY_LEN   == NMP_WIREGUARD_PUBLIC_KEY_LEN);
G_STATIC_ASSERT (NM_WIREGUARD_SYMMETRIC_KEY_LEN == NMP_WIREGUARD_SYMMETRIC_KEY_LEN);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceWireGuard,
	PROP_PUBLIC_KEY,
	PROP_LISTEN_PORT,
	PROP_FWMARK,
);

typedef struct {
	NMPlatformLnkWireGuard lnk_curr;
	NMPlatformLnkWireGuard lnk_want;
	NMActRequestGetSecretsCallId *secrets_call_id;
} NMDeviceWireGuardPrivate;

struct _NMDeviceWireGuard {
	NMDevice parent;
	NMDeviceWireGuardPrivate _priv;
};

struct _NMDeviceWireGuardClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceWireGuard, nm_device_wireguard, NM_TYPE_DEVICE)

#define NM_DEVICE_WIREGUARD_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceWireGuard, NM_IS_DEVICE_WIREGUARD, NMDevice)

/*****************************************************************************/

static void
update_properties (NMDevice *device)
{
	NMDeviceWireGuard *self;
	NMDeviceWireGuardPrivate *priv;
	const NMPlatformLink *plink;
	const NMPlatformLnkWireGuard *props = NULL;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE_WIREGUARD (device));
	self = NM_DEVICE_WIREGUARD (device);
	priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	ifindex = nm_device_get_ifindex (device);
	props = nm_platform_link_get_lnk_wireguard (nm_device_get_platform (device), ifindex, &plink);
	if (!props) {
		_LOGW (LOGD_PLATFORM, "could not get wireguard properties");
		return;
	}

	g_object_freeze_notify (G_OBJECT (device));

#define CHECK_PROPERTY_CHANGED(field, prop) \
	G_STMT_START { \
		if (priv->lnk_curr.field != props->field) { \
			priv->lnk_curr.field = props->field; \
			_notify (self, prop); \
		} \
	} G_STMT_END

#define CHECK_PROPERTY_CHANGED_ARRAY(field, prop) \
	G_STMT_START { \
		if (memcmp (&priv->lnk_curr.field, &props->field, sizeof (priv->lnk_curr.field)) != 0) { \
			memcpy (&priv->lnk_curr.field, &props->field, sizeof (priv->lnk_curr.field)); \
			_notify (self, prop); \
		} \
	} G_STMT_END

	CHECK_PROPERTY_CHANGED_ARRAY (public_key, PROP_PUBLIC_KEY);
	CHECK_PROPERTY_CHANGED (listen_port, PROP_LISTEN_PORT);
	CHECK_PROPERTY_CHANGED (fwmark, PROP_FWMARK);

	g_object_thaw_notify (G_OBJECT (device));
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_wireguard_parent_class)->link_changed (device, pllink);
	update_properties (device);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

/*****************************************************************************/

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	int r;

	g_return_val_if_fail (iface, FALSE);

	r = nm_platform_link_wireguard_add (nm_device_get_platform (device), iface, out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create WireGuard interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
_secrets_cancel (NMDeviceWireGuard *self)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	if (priv->secrets_call_id)
		nm_act_request_cancel_secrets (NULL, priv->secrets_call_id);
	nm_assert (!priv->secrets_call_id);
}

static void
_secrets_cb (NMActRequest *req,
             NMActRequestGetSecretsCallId *call_id,
             NMSettingsConnection *connection,
             GError *error,
             gpointer user_data)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (user_data);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceWireGuardPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_WIREGUARD (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	g_return_if_fail (priv->secrets_call_id == call_id);

	priv->secrets_call_id = NULL;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	g_return_if_fail (req == nm_device_get_act_request (device));
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_settings_connection (req) == connection);

	if (error) {
		_LOGW (LOGD_ETHER, "%s", error->message);
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else
		nm_device_activate_schedule_stage1_device_prepare (device);
}

static void
_secrets_get_secrets (NMDeviceWireGuard *self,
                      const char *setting_name,
                      NMSecretAgentGetSecretsFlags flags)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	NMActRequest *req;

	_secrets_cancel (self);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv->secrets_call_id = nm_act_request_get_secrets (req,
	                                                    TRUE,
	                                                    setting_name,
	                                                    flags,
	                                                    NULL,
	                                                    _secrets_cb,
	                                                    self);
	g_return_if_fail (priv->secrets_call_id);
}

static NMActStageReturn
_secrets_handle_auth_or_fail (NMDeviceWireGuard *self,
                              NMActRequest *req,
                              gboolean new_secrets)
{
	NMConnection *applied_connection;
	const char *setting_name;

	if (!nm_device_auth_retries_try_next (NM_DEVICE (self)))
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (req));

	applied_connection = nm_act_request_get_applied_connection (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name) {
		_LOGI (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	_secrets_get_secrets (self,
	                      setting_name,
	                        NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION
	                      | (new_secrets ? NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW : 0));
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static NMActStageReturn
link_config (NMDeviceWireGuard *self,
             gboolean allow_rate_limit,
             gboolean fail_state_on_failure,
             const char *reason,
             NMDeviceStateReason *out_failure_reason)
{
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);
	NMSettingWireGuard *s_wg;
	NMConnection *connection;
	NMActStageReturn ret;
	const char *setting_name;
	NMDeviceStateReason failure_reason;
	int ifindex;
	int r;

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	s_wg = NM_SETTING_WIREGUARD (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIREGUARD));
	g_return_val_if_fail (s_wg, NM_ACT_STAGE_RETURN_FAILURE);

	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		_LOGD (LOGD_DEVICE,
		       "Activation: connection '%s' has security, but secrets are required.",
		       nm_connection_get_id (connection));

		ret = _secrets_handle_auth_or_fail (self, req, FALSE);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
			return ret;
		if (ret != NM_ACT_STAGE_RETURN_SUCCESS) {
			failure_reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
			goto out_ret;
		}
	}

	ifindex = nm_device_get_ip_ifindex (NM_DEVICE (self));
	if (ifindex <= 0) {
		failure_reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		goto out_ret_fail;
	}

	priv->lnk_want = (NMPlatformLnkWireGuard) {
		.listen_port = nm_setting_wireguard_get_listen_port (s_wg),
		.fwmark      = nm_setting_wireguard_get_fwmark (s_wg),
	};

	if (!_nm_utils_wireguard_decode_key (nm_setting_wireguard_get_private_key (s_wg),
	                                     sizeof (priv->lnk_want.private_key),
	                                     priv->lnk_want.private_key)) {
		_LOGD (LOGD_DEVICE, "the provided private-key is invalid");
		failure_reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		goto out_ret_fail;
	}

	r = nm_platform_link_wireguard_change (nm_device_get_platform (NM_DEVICE (self)),
	                                       ifindex,
	                                       &priv->lnk_want,
	                                       NULL,
	                                       0,
	                                       TRUE);
	if (r < 0) {
		failure_reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		goto out_ret_fail;
	}

	NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_NONE);
	return NM_ACT_STAGE_RETURN_SUCCESS;

out_ret_fail:
	ret = NM_ACT_STAGE_RETURN_FAILURE;
out_ret:
	NM_SET_OUT (out_failure_reason, failure_reason);
	if (fail_state_on_failure) {
		nm_device_state_changed (NM_DEVICE (self),
		                         NM_DEVICE_STATE_FAILED,
		                         failure_reason);
	}
	return ret;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	return link_config (NM_DEVICE_WIREGUARD (device), FALSE, TRUE, "configure", out_failure_reason);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	if (new_state <= NM_DEVICE_STATE_ACTIVATED)
		return;

	_secrets_cancel (NM_DEVICE_WIREGUARD (device));
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (object);
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_PUBLIC_KEY:
		g_value_take_variant (value,
		                      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                 priv->lnk_curr.public_key,
		                                                 sizeof (priv->lnk_curr.public_key),
		                                                 1));
		break;
	case PROP_LISTEN_PORT:
		g_value_set_uint (value, priv->lnk_curr.listen_port);
		break;
	case PROP_FWMARK:
		g_value_set_uint (value, priv->lnk_curr.fwmark);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_wireguard_init (NMDeviceWireGuard *self)
{
}

static void
dispose (GObject *object)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (object);

	_secrets_cancel (self);

	G_OBJECT_CLASS (nm_device_wireguard_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceWireGuard *self = NM_DEVICE_WIREGUARD (object);
	NMDeviceWireGuardPrivate *priv = NM_DEVICE_WIREGUARD_GET_PRIVATE (self);

	nm_explicit_bzero (priv->lnk_want.private_key, sizeof (priv->lnk_want.private_key));
	nm_explicit_bzero (priv->lnk_curr.private_key, sizeof (priv->lnk_curr.private_key));

	G_OBJECT_CLASS (nm_device_wireguard_parent_class)->finalize (object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_wireguard = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_WIREGUARD,
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("PublicKey",  "ay", NM_DEVICE_WIREGUARD_PUBLIC_KEY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("ListenPort", "q", NM_DEVICE_WIREGUARD_LISTEN_PORT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("FwMark",     "u", NM_DEVICE_WIREGUARD_FWMARK),
		),
	),
};

static void
nm_device_wireguard_class_init (NMDeviceWireGuardClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_wireguard);

	device_class->connection_type_supported = NM_SETTING_WIREGUARD_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_WIREGUARD_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_WIREGUARD);

	device_class->state_changed = device_state_changed;
	device_class->create_and_realize = create_and_realize;
	device_class->act_stage2_config = act_stage2_config;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->link_changed = link_changed;

	obj_properties[PROP_PUBLIC_KEY] =
	    g_param_spec_variant (NM_DEVICE_WIREGUARD_PUBLIC_KEY,
	                          "", "",
	                          G_VARIANT_TYPE ("ay"),
	                          NULL,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_LISTEN_PORT] =
	    g_param_spec_uint (NM_DEVICE_WIREGUARD_LISTEN_PORT,
	                       "", "",
	                       0, G_MAXUINT16, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FWMARK] =
	    g_param_spec_uint (NM_DEVICE_WIREGUARD_FWMARK,
	                       "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*************************************************************/

#define NM_TYPE_WIREGUARD_DEVICE_FACTORY (nm_wireguard_device_factory_get_type ())
#define NM_WIREGUARD_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIREGUARD_DEVICE_FACTORY, NMWireGuardDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_WIREGUARD,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "WireGuard",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WIREGUARD,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_WIREGUARD,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (WIREGUARD, WireGuard, wireguard,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_WIREGUARD)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_WIREGUARD_SETTING_NAME),
	factory_class->create_device = create_device;
)
