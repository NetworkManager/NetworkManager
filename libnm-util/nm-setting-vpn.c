/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <dbus/dbus-glib.h>
#include "nm-setting-vpn.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_vpn_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-vpn-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_vpn_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_VPN_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_VPN_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_VPN_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingVpnError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingVPN, nm_setting_vpn, NM_TYPE_SETTING)

#define NM_SETTING_VPN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_VPN, NMSettingVPNPrivate))

typedef struct {
	char *service_type;

	/* username of the user requesting this connection, thus
	 * it's really only valid for user connections, and it also
	 * should never be saved out to persistent config.
	 */
	char *user_name;

	/* The hash table is created at setting object
	 * init time and should not be replaced.  It is
	 * a char * -> char * mapping, and both the key
	 * and value are owned by the hash table, and should
	 * be allocated with functions whose value can be
	 * freed with g_free().  Should not contain secrets.
	 */
	GHashTable *data;

	/* The hash table is created at setting object
	 * init time and should not be replaced.  It is
	 * a char * -> char * mapping, and both the key
	 * and value are owned by the hash table, and should
	 * be allocated with functions whose value can be
	 * freed with g_free().  Should contain secrets only.
	 */
	GHashTable *secrets;
} NMSettingVPNPrivate;

enum {
	PROP_0,
	PROP_SERVICE_TYPE,
	PROP_USER_NAME,
	PROP_DATA,
	PROP_SECRETS,

	LAST_PROP
};

NMSetting *
nm_setting_vpn_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_VPN, NULL);
}

const char *
nm_setting_vpn_get_service_type (NMSettingVPN *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->service_type;
}

const char *
nm_setting_vpn_get_user_name (NMSettingVPN *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->user_name;
}

void
nm_setting_vpn_add_data_item (NMSettingVPN *setting,
                              const char *key,
                              const char *item)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key != NULL);
	g_return_if_fail (strlen (key) > 0);
	g_return_if_fail (item != NULL);
	g_return_if_fail (strlen (item) > 0);

	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->data,
	                     g_strdup (key), g_strdup (item));
}

const char *
nm_setting_vpn_get_data_item (NMSettingVPN *setting, const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return (const char *) g_hash_table_lookup (NM_SETTING_VPN_GET_PRIVATE (setting)->data, key);
}

void
nm_setting_vpn_remove_data_item (NMSettingVPN *setting, const char *key)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));

	g_hash_table_remove (NM_SETTING_VPN_GET_PRIVATE (setting)->data, key);
}

void
nm_setting_vpn_foreach_data_item (NMSettingVPN *setting,
                                  VPNIterFunc func,
                                  gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));

	g_hash_table_foreach (NM_SETTING_VPN_GET_PRIVATE (setting)->data,
	                      (GHFunc) func, user_data);
}

void
nm_setting_vpn_add_secret (NMSettingVPN *setting,
                           const char *key,
                           const char *secret)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key != NULL);
	g_return_if_fail (strlen (key) > 0);
	g_return_if_fail (secret != NULL);
	g_return_if_fail (strlen (secret) > 0);

	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets,
	                     g_strdup (key), g_strdup (secret));
}

const char *
nm_setting_vpn_get_secret (NMSettingVPN *setting, const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return (const char *) g_hash_table_lookup (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets, key);
}

void
nm_setting_vpn_remove_secret (NMSettingVPN *setting, const char *key)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));

	g_hash_table_remove (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets, key);
}

void
nm_setting_vpn_foreach_secret (NMSettingVPN *setting,
                               VPNIterFunc func,
                               gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));

	g_hash_table_foreach (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets,
	                      (GHFunc) func, user_data);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	if (!priv->service_type) {
		g_set_error (error,
		             NM_SETTING_VPN_ERROR,
		             NM_SETTING_VPN_ERROR_MISSING_PROPERTY,
		             NM_SETTING_VPN_SERVICE_TYPE);
		return FALSE;
	}

	if (!strlen (priv->service_type)) {
		g_set_error (error,
		             NM_SETTING_VPN_ERROR,
		             NM_SETTING_VPN_ERROR_INVALID_PROPERTY,
		             NM_SETTING_VPN_SERVICE_TYPE);
		return FALSE;
	}

	/* default username can be NULL, but can't be zero-length */
	if (priv->user_name && !strlen (priv->user_name)) {
		g_set_error (error,
		             NM_SETTING_VPN_ERROR,
		             NM_SETTING_VPN_ERROR_INVALID_PROPERTY,
		             NM_SETTING_VPN_USER_NAME);
		return FALSE;
	}

	return TRUE;
}

static gboolean
update_one_secret (NMSetting *setting, const char *key, GValue *value, GError **error)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	char *str;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	if (!G_VALUE_HOLDS_STRING (value)) {
		g_set_error (error, NM_SETTING_ERROR,
		             NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH,
		             "%s", key);
		return FALSE;
	}

	str = g_value_dup_string (value);
	if (!str || !strlen (str)) {
		g_set_error (error, NM_SETTING_ERROR,
		             NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH,
		             "Secret %s was empty", key);
		g_free (str);
		return FALSE;
	}

	g_hash_table_insert (priv->secrets, g_strdup (key), str);
	return TRUE;
}

static void
destroy_one_secret (gpointer data)
{
	char *secret = (char *) data;

	/* Don't leave the secret lying around in memory */
	memset (secret, 0, strlen (secret));
	g_free (secret);
}

static void
nm_setting_vpn_init (NMSettingVPN *setting)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_VPN_SETTING_NAME, NULL);
	priv->data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	priv->secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_one_secret);
}

static void
finalize (GObject *object)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (object);

	g_free (priv->service_type);
	g_free (priv->user_name);
	g_hash_table_destroy (priv->data);
	g_hash_table_destroy (priv->secrets);

	G_OBJECT_CLASS (nm_setting_vpn_parent_class)->finalize (object);
}

static void
copy_hash (gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), g_strdup (value));
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (object);
	GHashTable *new_hash;

	switch (prop_id) {
	case PROP_SERVICE_TYPE:
		g_free (priv->service_type);
		priv->service_type = g_value_dup_string (value);
		break;
	case PROP_USER_NAME:
		g_free (priv->user_name);
		priv->user_name = g_value_dup_string (value);
		break;
	case PROP_DATA:
		/* Must make a deep copy of the hash table here... */
		g_hash_table_remove_all (priv->data);
		new_hash = g_value_get_boxed (value);
		if (new_hash)
			g_hash_table_foreach (new_hash, copy_hash, priv->data);
		break;
	case PROP_SECRETS:
		/* Must make a deep copy of the hash table here... */
		g_hash_table_remove_all (priv->secrets);
		new_hash = g_value_get_boxed (value);
		if (new_hash)
			g_hash_table_foreach (new_hash, copy_hash, priv->secrets);
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
	NMSettingVPN *setting = NM_SETTING_VPN (object);
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_SERVICE_TYPE:
		g_value_set_string (value, nm_setting_vpn_get_service_type (setting));
		break;
	case PROP_USER_NAME:
		g_value_set_string (value, nm_setting_vpn_get_user_name (setting));
		break;
	case PROP_DATA:
		g_value_set_boxed (value, priv->data);
		break;
	case PROP_SECRETS:
		g_value_set_boxed (value, priv->secrets);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_vpn_class_init (NMSettingVPNClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingVPNPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->update_one_secret = update_one_secret;

	/* Properties */
	/**
	 * NMSettingVPN:service-type:
	 *
	 * D-Bus service name of the VPN plugin that this setting uses to connect
	 * to its network.  i.e. org.freedesktop.NetworkManager.vpnc for the vpnc
 	 * plugin.
	 **/
	g_object_class_install_property
		(object_class, PROP_SERVICE_TYPE,
		 g_param_spec_string (NM_SETTING_VPN_SERVICE_TYPE,
						  "Service type",
						  "D-Bus service name of the VPN plugin that this "
						  "setting uses to connect to its network.  i.e. "
						  "org.freedesktop.NetworkManager.vpnc for the vpnc "
						  "plugin.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettinVPN:user-name:
	 *
	 * User name of the currently logged in user for connections provided by the
	 * user settings service.  This name is provided to the VPN plugin to use in
	 * lieu of a custom username provided by that VPN plugins specific
	 * configuration.  The VPN plugin itself decides which user name to use.
	 **/
	g_object_class_install_property
		(object_class, PROP_USER_NAME,
		 g_param_spec_string (NM_SETTING_VPN_USER_NAME,
						  "User name",
						  "User name of the currently logged in user for "
						  "connections provided by the user settings service.  "
						  "This name is provided to the VPN plugin to use in "
						  "lieu of a custom username provided by that VPN "
						  "plugins specific configuration.  The VPN plugin "
						  "itself decides which user name to use.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingVPN:data:
	 *
	 * Dictionary of key/value pairs of VPN plugin specific data.  Both keys
	 * and values must be strings.
	 **/
	g_object_class_install_property
		(object_class, PROP_DATA,
		 _nm_param_spec_specialized (NM_SETTING_VPN_DATA,
							   "Data",
							   "Dictionary of key/value pairs of VPN plugin "
							   "specific data.  Both keys and values must be "
							   "strings.",
							   DBUS_TYPE_G_MAP_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingVPN:secrets:
	 *
	 * Dictionary of key/value pairs of VPN plugin specific secrets like
	 * passwords or private keys.  Both keys and values must be strings.
	 **/
	g_object_class_install_property
		(object_class, PROP_SECRETS,
		 _nm_param_spec_specialized (NM_SETTING_VPN_SECRETS,
							   "Secrets",
							   "Dictionary of key/value pairs of VPN plugin "
							   "specific secrets like passwords or private keys."
							   "  Both keys and values must be strings.",
							   DBUS_TYPE_G_MAP_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));
}

