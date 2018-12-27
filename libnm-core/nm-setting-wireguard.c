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
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-wireguard.h"

#include "nm-setting-private.h"
#include "nm-connection-private.h"
#include "nm-utils/nm-secret-utils.h"

/*****************************************************************************/

/**
 * SECTION:nm-setting-wireguard
 * @short_description: Describes connection properties for wireguard related options
 *
 * The #NMSettingWireGuard object is a #NMSetting subclass that contains settings
 * for configuring WireGuard.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PRIVATE_KEY,
	PROP_PRIVATE_KEY_FLAGS,
	PROP_LISTEN_PORT,
	PROP_FWMARK,
);

typedef struct {
	char *private_key;
	NMSettingSecretFlags private_key_flags;
	guint32 fwmark;
	guint16 listen_port;
	bool private_key_valid:1;
} NMSettingWireGuardPrivate;

/**
 * NMSettingWireGuard:
 *
 * WireGuard Ethernet Settings
 *
 * Since: 1.16
 */
struct _NMSettingWireGuard {
	NMSetting parent;
	NMSettingWireGuardPrivate _priv;
};

struct _NMSettingWireGuardClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingWireGuard, nm_setting_wireguard, NM_TYPE_SETTING)

#define NM_SETTING_WIREGUARD_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSettingWireGuard, NM_IS_SETTING_WIREGUARD, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_wireguard_get_private_key:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: (transfer none): the set private-key or %NULL.
 *
 * Since: 1.16
 */
const char *
nm_setting_wireguard_get_private_key (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), NULL);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->private_key;
}

/**
 * nm_setting_wireguard_get_private_key_flags:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the secret-flags for #NMSettingWireGuard:private-key.
 *
 * Since: 1.16
 */
NMSettingSecretFlags
nm_setting_wireguard_get_private_key_flags (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->private_key_flags;
}

/**
 * nm_setting_wireguard_get_fwmark:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the set firewall mark.
 *
 * Since: 1.16
 */
guint32
nm_setting_wireguard_get_fwmark (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->fwmark;
}

/**
 * nm_setting_wireguard_get_listen_port:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the set UDP listen port.
 *
 * Since: 1.16
 */
guint16
nm_setting_wireguard_get_listen_port (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->listen_port;
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	/* private-key is a secret, hence we cannot verify it like a regular property. */
	return TRUE;
}

static gboolean
verify_secrets (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);

	if (   priv->private_key
	    && !priv->private_key_valid) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("key must be 32 bytes base64 encoded"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIREGUARD_SETTING_NAME, NM_SETTING_WIREGUARD_PRIVATE_KEY);
		return FALSE;
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;

	if (   !priv->private_key
	    || !priv->private_key_valid) {
		secrets = g_ptr_array_new_full (1, NULL);
		g_ptr_array_add (secrets, NM_SETTING_WIREGUARD_PRIVATE_KEY);
	}

	return secrets;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingWireGuard *setting = NM_SETTING_WIREGUARD (object);
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PRIVATE_KEY:
		g_value_set_string (value, priv->private_key);
		break;
	case PROP_PRIVATE_KEY_FLAGS:
		g_value_set_flags (value, priv->private_key_flags);
		break;
	case PROP_LISTEN_PORT:
		g_value_set_uint (value, priv->listen_port);
		break;
	case PROP_FWMARK:
		g_value_set_uint (value, priv->fwmark);
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
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (object);
	const char *str;

	switch (prop_id) {
	case PROP_PRIVATE_KEY:
		nm_clear_pointer (&priv->private_key, nm_free_secret);
		str = g_value_get_string (value);
		if (str) {
			if (_nm_utils_wireguard_normalize_key (str,
		                                           NM_WIREGUARD_PUBLIC_KEY_LEN,
		                                           &priv->private_key))
				priv->private_key_valid = TRUE;
			else {
				priv->private_key = g_strdup (str);
				priv->private_key_valid = FALSE;
			}
		}
		break;
	case PROP_PRIVATE_KEY_FLAGS:
		priv->private_key_flags = g_value_get_flags (value);
		break;
	case PROP_LISTEN_PORT:
		priv->listen_port = g_value_get_uint (value);
		break;
	case PROP_FWMARK:
		priv->fwmark = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_wireguard_init (NMSettingWireGuard *setting)
{
}

/**
 * nm_setting_wireguard_new:
 *
 * Creates a new #NMSettingWireGuard object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWireGuard object
 *
 * Since: 1.16
 **/
NMSetting *
nm_setting_wireguard_new (void)
{
	return g_object_new (NM_TYPE_SETTING_WIREGUARD, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (object);

	nm_free_secret (priv->private_key);

	G_OBJECT_CLASS (nm_setting_wireguard_parent_class)->finalize (object);
}

static void
nm_setting_wireguard_class_init (NMSettingWireGuardClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify         = verify;
	setting_class->verify_secrets = verify_secrets;
	setting_class->need_secrets   = need_secrets;

	/**
	 * NMSettingWireGuard:private-key:
	 *
	 * The 256 bit private-key in base64 encoding.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_PRIVATE_KEY] =
	    g_param_spec_string (NM_SETTING_WIREGUARD_PRIVATE_KEY, "", "",
	                         NULL,
	                           G_PARAM_READWRITE
	                         | NM_SETTING_PARAM_SECRET
	                         | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:private-key-flags:
	 *
	 * Flags indicating how to handle the #NMSettingWirelessSecurity:private-key
	 * property.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_PRIVATE_KEY_FLAGS] =
	    g_param_spec_flags (NM_SETTING_WIREGUARD_PRIVATE_KEY_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                          G_PARAM_READWRITE
	                        | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:fwmark:
	 *
	 * The use of fwmark is optional and is by default off; setting it to 0 or
	 * disables it. Otherwise it is a 32-bit fwmark for outgoing packets.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_FWMARK] =
	    g_param_spec_uint (NM_SETTING_WIREGUARD_FWMARK, "", "",
	                       0, G_MAXUINT32, 0,
	                         G_PARAM_READWRITE
	                       | NM_SETTING_PARAM_INFERRABLE
	                       | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:listen-port:
	 *
	 * The listen-port. If listen-port is not specified, the port will be chosen
	 * randomly when the interface comes up.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_LISTEN_PORT] =
	    g_param_spec_uint (NM_SETTING_WIREGUARD_LISTEN_PORT, "", "",
	                       0, 65535, 0,
	                         G_PARAM_READWRITE
	                       | NM_SETTING_PARAM_INFERRABLE
	                       | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_WIREGUARD);
}
