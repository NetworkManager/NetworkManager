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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-macsec.h"

#include "nm-act-request.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-manager.h"
#include "nm-setting-macsec.h"
#include "nm-core-internal.h"
#include "supplicant/nm-supplicant-manager.h"
#include "supplicant/nm-supplicant-interface.h"
#include "supplicant/nm-supplicant-config.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceMacsec);

/*****************************************************************************/

typedef struct Supplicant {
	NMSupplicantManager *mgr;
	NMSupplicantInterface *iface;

	/* signal handler ids */
	gulong iface_state_id;

	/* Timeouts and idles */
	guint con_timeout_id;
} Supplicant;

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceMacsec,
	PROP_SCI,
	PROP_CIPHER_SUITE,
	PROP_ICV_LENGTH,
	PROP_WINDOW,
	PROP_ENCODING_SA,
	PROP_ENCRYPT,
	PROP_PROTECT,
	PROP_INCLUDE_SCI,
	PROP_ES,
	PROP_SCB,
	PROP_REPLAY_PROTECT,
	PROP_VALIDATION,
);

typedef struct {
	NMPlatformLnkMacsec props;
	gulong parent_state_id;
	Supplicant supplicant;
	guint supplicant_timeout_id;
	NMActRequestGetSecretsCallId *macsec_secrets_id;
} NMDeviceMacsecPrivate;

struct _NMDeviceMacsec {
	NMDevice parent;
	NMDeviceMacsecPrivate _priv;
};

struct _NMDeviceMacsecClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceMacsec, nm_device_macsec, NM_TYPE_DEVICE)

#define NM_DEVICE_MACSEC_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceMacsec, NM_IS_DEVICE_MACSEC)

/******************************************************************/

static void macsec_secrets_cancel (NMDeviceMacsec *self);

/******************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (validation_mode_to_string, guint8,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("<unknown>"),
	NM_UTILS_LOOKUP_STR_ITEM (0, "disable"),
	NM_UTILS_LOOKUP_STR_ITEM (1, "check"),
	NM_UTILS_LOOKUP_STR_ITEM (2, "strict"),
);

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (user_data);

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (nm_device_state_reason_check (reason) == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	nm_device_set_unmanaged_by_flags (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent, FALSE), reason);
}

static void
parent_changed_notify (NMDevice *device,
                       int old_ifindex,
                       NMDevice *old_parent,
                       int new_ifindex,
                       NMDevice *new_parent)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (device);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	NM_DEVICE_CLASS (nm_device_macsec_parent_class)->parent_changed_notify (device,
	                                                                        old_ifindex,
	                                                                        old_parent,
	                                                                        new_ifindex,
	                                                                        new_parent);

	/*  note that @self doesn't have to clear @parent_state_id on dispose,
	 *  because NMDevice's dispose() will unset the parent, which in turn calls
	 *  parent_changed_notify(). */
	nm_clear_g_signal_handler (old_parent, &priv->parent_state_id);

	if (new_parent) {
		priv->parent_state_id = g_signal_connect (new_parent,
		                                          NM_DEVICE_STATE_CHANGED,
		                                          G_CALLBACK (parent_state_changed),
		                                          device);

		/* Set parent-dependent unmanaged flag */
		nm_device_set_unmanaged_by_flags (device,
		                                  NM_UNMANAGED_PARENT,
		                                  !nm_device_get_managed (new_parent, FALSE),
		                                  NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED);
	}

	/* Recheck availability now that the parent has changed */
	if (new_ifindex > 0) {
		nm_device_queue_recheck_available (device,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED);
	}
}

static void
update_properties (NMDevice *device)
{
	NMDeviceMacsec *self;
	NMDeviceMacsecPrivate *priv;
	const NMPlatformLink *plink = NULL;
	const NMPlatformLnkMacsec *props = NULL;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE_MACSEC (device));
	self = NM_DEVICE_MACSEC (device);
	priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	ifindex = nm_device_get_ifindex (device);
	g_return_if_fail (ifindex > 0);
	props = nm_platform_link_get_lnk_macsec (nm_device_get_platform (device), ifindex, &plink);

	if (!props) {
		_LOGW (LOGD_PLATFORM, "could not get macsec properties");
		return;
	}

	g_object_freeze_notify ((GObject *) device);

	if (priv->props.parent_ifindex != props->parent_ifindex)
		nm_device_parent_set_ifindex (device, props->parent_ifindex);

#define CHECK_PROPERTY_CHANGED(field, prop) \
	G_STMT_START { \
		if (priv->props.field != props->field) { \
			priv->props.field = props->field; \
			_notify (self, prop); \
		} \
	} G_STMT_END

	CHECK_PROPERTY_CHANGED (sci, PROP_SCI);
	CHECK_PROPERTY_CHANGED (cipher_suite, PROP_CIPHER_SUITE);
	CHECK_PROPERTY_CHANGED (window, PROP_WINDOW);
	CHECK_PROPERTY_CHANGED (icv_length, PROP_ICV_LENGTH);
	CHECK_PROPERTY_CHANGED (encoding_sa, PROP_ENCODING_SA);
	CHECK_PROPERTY_CHANGED (validation, PROP_VALIDATION);
	CHECK_PROPERTY_CHANGED (encrypt, PROP_ENCRYPT);
	CHECK_PROPERTY_CHANGED (protect, PROP_PROTECT);
	CHECK_PROPERTY_CHANGED (include_sci, PROP_INCLUDE_SCI);
	CHECK_PROPERTY_CHANGED (es, PROP_ES);
	CHECK_PROPERTY_CHANGED (scb, PROP_SCB);
	CHECK_PROPERTY_CHANGED (replay_protect, PROP_REPLAY_PROTECT);

	g_object_thaw_notify ((GObject *) device);
}

static NMSupplicantConfig *
build_supplicant_config (NMDeviceMacsec *self, GError **error)
{
	gs_unref_object NMSupplicantConfig *config = NULL;
	NMSettingMacsec *s_macsec;
	NMSetting8021x *s_8021x;
	NMConnection *connection;
	const char *con_uuid;
	guint32 mtu;

	connection = nm_device_get_applied_connection (NM_DEVICE (self));

	g_return_val_if_fail (connection, NULL);

	con_uuid = nm_connection_get_uuid (connection);
	mtu = nm_platform_link_get_mtu (nm_device_get_platform (NM_DEVICE (self)),
	                                nm_device_get_ifindex (NM_DEVICE (self)));

	config = nm_supplicant_config_new (FALSE, FALSE);

	s_macsec = nm_device_get_applied_setting (NM_DEVICE (self), NM_TYPE_SETTING_MACSEC);

	g_return_val_if_fail (s_macsec, NULL);

	if (!nm_supplicant_config_add_setting_macsec (config, s_macsec, error)) {
		g_prefix_error (error, "macsec-setting: ");
		return NULL;
	}

	if (nm_setting_macsec_get_mode (s_macsec) == NM_SETTING_MACSEC_MODE_EAP) {
		s_8021x = nm_connection_get_setting_802_1x (connection);
		if (!nm_supplicant_config_add_setting_8021x (config, s_8021x, con_uuid, mtu, TRUE, error)) {
			g_prefix_error (error, "802-1x-setting: ");
			return NULL;
		}
	}

	return g_steal_pointer (&config);
}

static void
supplicant_interface_release (NMDeviceMacsec *self)
{
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	nm_clear_g_source (&priv->supplicant_timeout_id);
	nm_clear_g_source (&priv->supplicant.con_timeout_id);
	nm_clear_g_signal_handler (priv->supplicant.iface, &priv->supplicant.iface_state_id);

	if (priv->supplicant.iface) {
		nm_supplicant_interface_disconnect (priv->supplicant.iface);
		g_clear_object (&priv->supplicant.iface);
	}
}

static void
supplicant_iface_assoc_cb (NMSupplicantInterface *iface,
                           GError *error,
                           gpointer user_data)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (user_data);

	if (error && !nm_utils_error_is_cancelled (error, TRUE)) {
		supplicant_interface_release (self);
		nm_device_queue_state (NM_DEVICE (self),
		                       NM_DEVICE_STATE_FAILED,
		                       NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
	}
}

static void
macsec_secrets_cb (NMActRequest *req,
                   NMActRequestGetSecretsCallId *call_id,
                   NMSettingsConnection *connection,
                   GError *error,
                   gpointer user_data)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (user_data);
	NMDevice *device = NM_DEVICE (self);
	NMDeviceMacsecPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE_MACSEC (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	g_return_if_fail (priv->macsec_secrets_id == call_id);

	priv->macsec_secrets_id = NULL;

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
macsec_secrets_cancel (NMDeviceMacsec *self)
{
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	if (priv->macsec_secrets_id)
		nm_act_request_cancel_secrets (NULL, priv->macsec_secrets_id);
	nm_assert (!priv->macsec_secrets_id);
}

static void
macsec_secrets_get_secrets (NMDeviceMacsec *self,
                            const char *setting_name,
                            NMSecretAgentGetSecretsFlags flags)
{
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);
	NMActRequest *req;

	macsec_secrets_cancel (self);

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	priv->macsec_secrets_id = nm_act_request_get_secrets (req,
	                                                      TRUE,
	                                                      setting_name,
	                                                      flags,
	                                                      NULL,
	                                                      macsec_secrets_cb,
	                                                      self);
	g_return_if_fail (priv->macsec_secrets_id);
}

static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (user_data);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);
	NMDevice *dev = NM_DEVICE (self);
	NMActRequest *req;
	NMConnection *applied_connection;
	const char *setting_name;

	priv->supplicant_timeout_id = 0;

	req = nm_device_get_act_request (dev);

	if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
		nm_device_state_changed (dev,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
		return FALSE;
	}

	/* Disconnect event during initial authentication and credentials
	 * ARE checked - we are likely to have wrong key.  Ask the user for
	 * another one.
	 */
	if (nm_device_get_state (dev) != NM_DEVICE_STATE_CONFIG)
		goto time_out;

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (req));

	applied_connection = nm_act_request_get_applied_connection (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name)
		goto time_out;

	_LOGI (LOGD_DEVICE | LOGD_ETHER,
	       "Activation: disconnected during authentication, asking for new key.");
	supplicant_interface_release (self);

	nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
	macsec_secrets_get_secrets (self, setting_name, NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW);

	return FALSE;

time_out:
	_LOGW (LOGD_DEVICE | LOGD_ETHER, "link timed out.");
	nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);

	return FALSE;
}

static void
supplicant_iface_state_cb (NMSupplicantInterface *iface,
                           int new_state_i,
                           int old_state_i,
                           int disconnect_reason,
                           gpointer user_data)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (user_data);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMSupplicantConfig *config;
	NMDeviceState devstate;
	GError *error = NULL;
	NMSupplicantInterfaceState new_state = new_state_i;
	NMSupplicantInterfaceState old_state = old_state_i;

	if (new_state == old_state)
		return;

	_LOGI (LOGD_DEVICE, "supplicant interface state: %s -> %s",
	       nm_supplicant_interface_state_to_string (old_state),
	       nm_supplicant_interface_state_to_string (new_state));

	devstate = nm_device_get_state (device);

	switch (new_state) {
	case NM_SUPPLICANT_INTERFACE_STATE_READY:
		config = build_supplicant_config (self, &error);
		if (config) {
			nm_supplicant_interface_assoc (priv->supplicant.iface, config,
			                               supplicant_iface_assoc_cb, self);
			g_object_unref (config);
		} else {
			_LOGE (LOGD_DEVICE,
			       "Activation: couldn't build security configuration: %s",
			       error->message);
			g_clear_error (&error);

			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		nm_clear_g_source (&priv->supplicant_timeout_id);
		nm_clear_g_source (&priv->supplicant.con_timeout_id);
		nm_device_bring_up (device, TRUE, NULL);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (devstate == NM_DEVICE_STATE_CONFIG) {
			_LOGI (LOGD_DEVICE,
			       "Activation: Stage 2 of 5 (Device Configure) successful.");
			nm_device_activate_schedule_stage3_ip_config_start (device);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			/* Start the link timeout so we allow some time for reauthentication */
			if (!priv->supplicant_timeout_id)
				priv->supplicant_timeout_id = g_timeout_add_seconds (15, link_timeout_cb, device);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
		supplicant_interface_release (self);

		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
		break;
	default:
		;
	}
}

static NMActStageReturn
handle_auth_or_fail (NMDeviceMacsec *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	const char *setting_name;
	NMConnection *applied_connection;

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

	macsec_secrets_get_secrets (self, setting_name,
	                              NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION
	                            | (new_secrets ? NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW : 0));
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static gboolean
supplicant_connection_timeout_cb (gpointer user_data)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (user_data);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	NMSettingsConnection *connection;
	guint64 timestamp = 0;
	gboolean new_secrets = TRUE;

	priv->supplicant.con_timeout_id = 0;

	/* Authentication failed; either driver problems, the encryption key is
	 * wrong, the passwords or certificates were wrong or the Ethernet switch's
	 * port is not configured for 802.1x. */
	_LOGW (LOGD_DEVICE,
	       "Activation: (macsec) association took too long.");

	supplicant_interface_release (self);
	req = nm_device_get_act_request (device);
	g_assert (req);

	connection = nm_act_request_get_settings_connection (req);
	g_assert (connection);

	/* Ask for new secrets only if we've never activated this connection
	 * before.  If we've connected before, don't bother the user with dialogs,
	 * just retry or fail, and if we never connect the user can fix the
	 * password somewhere else. */
	if (nm_settings_connection_get_timestamp (connection, &timestamp))
		new_secrets = !timestamp;

	if (handle_auth_or_fail (self, req, new_secrets) == NM_ACT_STAGE_RETURN_POSTPONE)
		_LOGW (LOGD_DEVICE, "Activation: (macsec) asking for new secrets");
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);

	return FALSE;
}

static gboolean
supplicant_interface_init (NMDeviceMacsec *self)
{
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);
	NMDevice *parent;
	guint timeout;

	parent = nm_device_parent_get_device (NM_DEVICE (self));
	g_return_val_if_fail (parent, FALSE);

	supplicant_interface_release (self);

	priv->supplicant.iface = nm_supplicant_manager_create_interface (priv->supplicant.mgr,
	                                                                 nm_device_get_iface (parent),
	                                                                 NM_SUPPLICANT_DRIVER_MACSEC);

	if (!priv->supplicant.iface) {
		_LOGE (LOGD_DEVICE,
		       "Couldn't initialize supplicant interface");
		return FALSE;
	}

	/* Listen for its state signals */
	priv->supplicant.iface_state_id = g_signal_connect (priv->supplicant.iface,
	                                                    NM_SUPPLICANT_INTERFACE_STATE,
	                                                    G_CALLBACK (supplicant_iface_state_cb),
	                                                    self);

	/* Set up a timeout on the connection attempt  */
	timeout = nm_device_get_supplicant_timeout (NM_DEVICE (self));
	priv->supplicant.con_timeout_id = g_timeout_add_seconds (timeout,
	                                                         supplicant_connection_timeout_cb,
	                                                         self);
	return TRUE;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (device);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);
	NMConnection *connection;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *setting_name;

	connection = nm_device_get_applied_connection (NM_DEVICE (self));

	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	if (!priv->supplicant.mgr)
		priv->supplicant.mgr = g_object_ref (nm_supplicant_manager_get ());

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		_LOGI (LOGD_DEVICE,
		       "Activation: connection '%s' has security, but secrets are required.",
		       nm_connection_get_id (connection));

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret != NM_ACT_STAGE_RETURN_POSTPONE)
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else {
		_LOGI (LOGD_DEVICE | LOGD_ETHER,
		       "Activation: connection '%s' requires no security. No secrets needed.",
		       nm_connection_get_id (connection));

		if (supplicant_interface_init (self))
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		else
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
	}

	return ret;
}

static void
deactivate (NMDevice *device)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (device);

	supplicant_interface_release (self);
}

/******************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	/* We assume MACsec interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

/******************************************************************/

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!nm_device_parent_get_device (device))
		return FALSE;
	return NM_DEVICE_CLASS (nm_device_macsec_parent_class)->is_available (device, flags);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMSettingMacsec *s_macsec;
	NMPlatformLnkMacsec lnk = { };
	int parent_ifindex;
	const char *hw_addr;
	union {
		struct {
			guint8 mac[6];
			guint16 port;
		} s;
		guint64 u;
	} sci;
	int r;

	s_macsec = nm_connection_get_setting_macsec (connection);
	g_assert (s_macsec);

	if (!parent) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "MACsec devices can not be created without a parent interface");
		return FALSE;
	}

	lnk.encrypt = nm_setting_macsec_get_encrypt (s_macsec);

	hw_addr = nm_device_get_hw_address (parent);
	if (!hw_addr) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "can't read parent MAC");
		return FALSE;
	}

	nm_utils_hwaddr_aton (hw_addr, sci.s.mac, ETH_ALEN);
	sci.s.port = htons (nm_setting_macsec_get_port (s_macsec));
	lnk.sci = be64toh (sci.u);
	lnk.validation = nm_setting_macsec_get_validation (s_macsec);
	lnk.include_sci = nm_setting_macsec_get_send_sci (s_macsec);

	parent_ifindex = nm_device_get_ifindex (parent);
	g_warn_if_fail (parent_ifindex > 0);

	r = nm_platform_link_macsec_add (nm_device_get_platform (device), iface, parent_ifindex, &lnk, out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create macsec interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	nm_device_parent_set_ifindex (device, parent_ifindex);

	return TRUE;
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_macsec_parent_class)->link_changed (device, pllink);
	update_properties (device);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	if (new_state > NM_DEVICE_STATE_ACTIVATED)
		macsec_secrets_cancel (NM_DEVICE_MACSEC (device));
}

/******************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (object);
	NMDeviceMacsecPrivate *priv = NM_DEVICE_MACSEC_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_SCI:
		g_value_set_uint64 (value, priv->props.sci);
		break;
	case PROP_CIPHER_SUITE:
		g_value_set_uint64 (value, priv->props.cipher_suite);
		break;
	case PROP_ICV_LENGTH:
		g_value_set_uchar (value, priv->props.icv_length);
		break;
	case PROP_WINDOW:
		g_value_set_uint (value, priv->props.window);
		break;
	case PROP_ENCODING_SA:
		g_value_set_uchar (value, priv->props.encoding_sa);
		break;
	case PROP_ENCRYPT:
		g_value_set_boolean (value, priv->props.encrypt);
		break;
	case PROP_PROTECT:
		g_value_set_boolean (value, priv->props.protect);
		break;
	case PROP_INCLUDE_SCI:
		g_value_set_boolean (value, priv->props.include_sci);
		break;
	case PROP_ES:
		g_value_set_boolean (value, priv->props.es);
		break;
	case PROP_SCB:
		g_value_set_boolean (value, priv->props.scb);
		break;
	case PROP_REPLAY_PROTECT:
		g_value_set_boolean (value, priv->props.replay_protect);
		break;
	case PROP_VALIDATION:
		g_value_set_string (value,
		                    validation_mode_to_string (priv->props.validation));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_macsec_init (NMDeviceMacsec *self)
{
}

static void
dispose (GObject *object)
{
	NMDeviceMacsec *self = NM_DEVICE_MACSEC (object);

	macsec_secrets_cancel (self);
	supplicant_interface_release (self);

	G_OBJECT_CLASS (nm_device_macsec_parent_class)->dispose (object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_macsec = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_MACSEC,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Parent",        "o",  NM_DEVICE_PARENT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Sci",           "t",  NM_DEVICE_MACSEC_SCI),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("IcvLength",     "y",  NM_DEVICE_MACSEC_ICV_LENGTH),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("CipherSuite",   "t",  NM_DEVICE_MACSEC_CIPHER_SUITE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Window",        "u",  NM_DEVICE_MACSEC_WINDOW),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("EncodingSa",    "y",  NM_DEVICE_MACSEC_ENCODING_SA),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Validation",    "s",  NM_DEVICE_MACSEC_VALIDATION),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Encrypt",       "b",  NM_DEVICE_MACSEC_ENCRYPT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Protect",       "b",  NM_DEVICE_MACSEC_PROTECT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("IncludeSci",    "b",  NM_DEVICE_MACSEC_INCLUDE_SCI),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Es",            "b",  NM_DEVICE_MACSEC_ES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Scb",           "b",  NM_DEVICE_MACSEC_SCB),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("ReplayProtect", "b",  NM_DEVICE_MACSEC_REPLAY_PROTECT),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_macsec_class_init (NMDeviceMacsecClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->dispose = dispose;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_macsec);

	device_class->connection_type_supported = NM_SETTING_MACSEC_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_MACSEC_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_MACSEC);

	device_class->act_stage2_config = act_stage2_config;
	device_class->create_and_realize = create_and_realize;
	device_class->deactivate = deactivate;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->link_changed = link_changed;
	device_class->is_available = is_available;
	device_class->parent_changed_notify = parent_changed_notify;
	device_class->state_changed = device_state_changed;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;

	obj_properties[PROP_SCI] =
	    g_param_spec_uint64 (NM_DEVICE_MACSEC_SCI, "", "",
	                         0, G_MAXUINT64, 0,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_CIPHER_SUITE] =
	    g_param_spec_uint64 (NM_DEVICE_MACSEC_CIPHER_SUITE, "", "",
	                         0, G_MAXUINT64, 0,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ICV_LENGTH] =
	    g_param_spec_uchar (NM_DEVICE_MACSEC_ICV_LENGTH, "", "",
	                        0, G_MAXUINT8, 0,
	                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_WINDOW] =
	    g_param_spec_uint (NM_DEVICE_MACSEC_WINDOW, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ENCODING_SA] =
	    g_param_spec_uchar (NM_DEVICE_MACSEC_ENCODING_SA, "", "",
	                        0, 3, 0,
	                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_VALIDATION] =
	    g_param_spec_string (NM_DEVICE_MACSEC_VALIDATION, "", "",
	                         NULL,
	                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ENCRYPT] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_ENCRYPT, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PROTECT] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_PROTECT, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_INCLUDE_SCI] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_INCLUDE_SCI, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ES] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_ES, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_SCB] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_SCB, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_REPLAY_PROTECT] =
	    g_param_spec_boolean (NM_DEVICE_MACSEC_REPLAY_PROTECT, "", "",
	                          FALSE,
	                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*************************************************************/

#define NM_TYPE_MACSEC_DEVICE_FACTORY (nm_macsec_device_factory_get_type ())
#define NM_MACSEC_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MACSEC_DEVICE_FACTORY, NMMacsecDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_MACSEC,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Macsec",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_MACSEC,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_MACSEC,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSettingMacsec *s_macsec;
	NMSettingWired *s_wired;
	const char *parent = NULL;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_MACSEC_SETTING_NAME), NULL);

	s_macsec = nm_connection_get_setting_macsec (connection);
	g_assert (s_macsec);

	parent = nm_setting_macsec_get_parent (s_macsec);
	if (parent)
		return parent;

	/* Try the hardware address from the MACsec connection's hardware setting */
	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired)
		return nm_setting_wired_get_mac_address (s_wired);

	return NULL;
}

static char *
get_connection_iface (NMDeviceFactory *factory,
                      NMConnection *connection,
                      const char *parent_iface)
{
	NMSettingMacsec *s_macsec;
	const char *ifname;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_MACSEC_SETTING_NAME), NULL);

	s_macsec = nm_connection_get_setting_macsec (connection);
	g_assert (s_macsec);

	if (!parent_iface)
		return NULL;

	ifname = nm_connection_get_interface_name (connection);
	return g_strdup (ifname);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (MACSEC, Macsec, macsec,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_MACSEC)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_MACSEC_SETTING_NAME),
	factory_class->create_device = create_device;
	factory_class->get_connection_parent = get_connection_parent;
	factory_class->get_connection_iface = get_connection_iface;
)
