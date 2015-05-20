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
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2013 Thomas Bechtold <thomasbechtold@jpberlin.de>
 */

#include "nm-config-data.h"

#include <string.h>

#include "nm-config.h"
#include "gsystem-local-alloc.h"
#include "nm-device.h"
#include "nm-core-internal.h"

typedef struct {
	char *config_main_file;
	char *config_description;

	GKeyFile *keyfile;

	struct {
		char *uri;
		char *response;
		guint interval;
	} connectivity;

	struct {
		char **arr;
		GSList *specs;
	} no_auto_default;

	GSList *ignore_carrier;
	GSList *assume_ipv6ll_only;

	char *dns_mode;
	char *rc_manager;
} NMConfigDataPrivate;


enum {
	PROP_0,
	PROP_CONFIG_MAIN_FILE,
	PROP_CONFIG_DESCRIPTION,
	PROP_KEYFILE,
	PROP_CONNECTIVITY_URI,
	PROP_CONNECTIVITY_INTERVAL,
	PROP_CONNECTIVITY_RESPONSE,
	PROP_NO_AUTO_DEFAULT,

	LAST_PROP
};

G_DEFINE_TYPE (NMConfigData, nm_config_data, G_TYPE_OBJECT)

#define NM_CONFIG_DATA_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONFIG_DATA, NMConfigDataPrivate))

/************************************************************************/

const char *
nm_config_data_get_config_main_file (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->config_main_file;
}

const char *
nm_config_data_get_config_description (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->config_description;
}

char *
nm_config_data_get_value (const NMConfigData *self, const char *group, const char *key, GError **error)
{
	g_return_val_if_fail (self, NULL);

	return g_key_file_get_string (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, group, key, error);
}

const char *
nm_config_data_get_connectivity_uri (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.uri;
}

const guint
nm_config_data_get_connectivity_interval (const NMConfigData *self)
{
	g_return_val_if_fail (self, 0);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.interval;
}

const char *
nm_config_data_get_connectivity_response (const NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.response;
}

const char *const*
nm_config_data_get_no_auto_default (const NMConfigData *self)
{
	g_return_val_if_fail (self, FALSE);

	return (const char *const*) NM_CONFIG_DATA_GET_PRIVATE (self)->no_auto_default.arr;
}

const GSList *
nm_config_data_get_no_auto_default_list (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->no_auto_default.specs;
}

const char *
nm_config_data_get_dns_mode (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->dns_mode;
}

const char *
nm_config_data_get_rc_manager (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->rc_manager;
}

gboolean
nm_config_data_get_ignore_carrier (const NMConfigData *self, NMDevice *device)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return nm_device_spec_match_list (device, NM_CONFIG_DATA_GET_PRIVATE (self)->ignore_carrier);
}

gboolean
nm_config_data_get_assume_ipv6ll_only (const NMConfigData *self, NMDevice *device)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return nm_device_spec_match_list (device, NM_CONFIG_DATA_GET_PRIVATE (self)->assume_ipv6ll_only);
}

/************************************************************************/

static gboolean
_keyfile_a_contains_all_in_b (GKeyFile *kf_a, GKeyFile *kf_b)
{
	gs_strfreev char **groups = NULL;
	guint i, j;

	if (kf_a == kf_b)
		return TRUE;

	groups = g_key_file_get_groups (kf_a, NULL);
	for (i = 0; groups && groups[i]; i++) {
		gs_strfreev char **keys = NULL;

		keys = g_key_file_get_keys (kf_a, groups[i], NULL, NULL);
		if (keys) {
			for (j = 0; keys[j]; j++) {
				gs_free char *key_a = g_key_file_get_value (kf_a, groups[i], keys[j], NULL);
				gs_free char *key_b = g_key_file_get_value (kf_b, groups[i], keys[j], NULL);

				if (g_strcmp0 (key_a, key_b) != 0)
					return FALSE;
			}
		}
	}
	return TRUE;
}

NMConfigChangeFlags
nm_config_data_diff (NMConfigData *old_data, NMConfigData *new_data)
{
	NMConfigChangeFlags changes = NM_CONFIG_CHANGE_NONE;
	NMConfigDataPrivate *priv_old, *priv_new;
	GSList *spec_old, *spec_new;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (old_data), NM_CONFIG_CHANGE_NONE);
	g_return_val_if_fail (NM_IS_CONFIG_DATA (new_data), NM_CONFIG_CHANGE_NONE);

	priv_old = NM_CONFIG_DATA_GET_PRIVATE (old_data);
	priv_new = NM_CONFIG_DATA_GET_PRIVATE (new_data);

	if (   !_keyfile_a_contains_all_in_b (priv_old->keyfile, priv_new->keyfile)
	    || !_keyfile_a_contains_all_in_b (priv_new->keyfile, priv_old->keyfile))
		changes |= NM_CONFIG_CHANGE_VALUES;

	if (   g_strcmp0 (nm_config_data_get_config_main_file (old_data), nm_config_data_get_config_main_file (new_data)) != 0
	    || g_strcmp0 (nm_config_data_get_config_description (old_data), nm_config_data_get_config_description (new_data)) != 0)
		changes |= NM_CONFIG_CHANGE_CONFIG_FILES;

	if (   nm_config_data_get_connectivity_interval (old_data) != nm_config_data_get_connectivity_interval (new_data)
	    || g_strcmp0 (nm_config_data_get_connectivity_uri (old_data), nm_config_data_get_connectivity_uri (new_data))
	    || g_strcmp0 (nm_config_data_get_connectivity_response (old_data), nm_config_data_get_connectivity_response (new_data)))
		changes |= NM_CONFIG_CHANGE_CONNECTIVITY;

	spec_old = priv_old->no_auto_default.specs;
	spec_new = priv_new->no_auto_default.specs;
	while (spec_old && spec_new && strcmp (spec_old->data, spec_new->data) == 0) {
		spec_old = spec_old->next;
		spec_new = spec_new->next;
	}
	if (spec_old || spec_new)
		changes |= NM_CONFIG_CHANGE_NO_AUTO_DEFAULT;

	if (g_strcmp0 (nm_config_data_get_dns_mode (old_data), nm_config_data_get_dns_mode (new_data)))
		changes |= NM_CONFIG_CHANGE_DNS_MODE;

	if (g_strcmp0 (nm_config_data_get_rc_manager (old_data), nm_config_data_get_rc_manager (new_data)))
		changes |= NM_CONFIG_CHANGE_RC_MANAGER;

	return changes;
}

/************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMConfigData *self = NM_CONFIG_DATA (object);

	switch (prop_id) {
	case PROP_CONFIG_MAIN_FILE:
		g_value_set_string (value, nm_config_data_get_config_main_file (self));
		break;
	case PROP_CONFIG_DESCRIPTION:
		g_value_set_string (value, nm_config_data_get_config_description (self));
		break;
	case PROP_NO_AUTO_DEFAULT:
		g_value_take_boxed (value, g_strdupv ((char **) nm_config_data_get_no_auto_default (self)));
		break;
	case PROP_CONNECTIVITY_URI:
		g_value_set_string (value, nm_config_data_get_connectivity_uri (self));
		break;
	case PROP_CONNECTIVITY_INTERVAL:
		g_value_set_uint (value, nm_config_data_get_connectivity_interval (self));
		break;
	case PROP_CONNECTIVITY_RESPONSE:
		g_value_set_string (value, nm_config_data_get_connectivity_response (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMConfigData *self = NM_CONFIG_DATA (object);
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (self);
	guint i;

	/* This type is immutable. All properties are construct only. */
	switch (prop_id) {
	case PROP_CONFIG_MAIN_FILE:
		priv->config_main_file = g_value_dup_string (value);
		break;
	case PROP_CONFIG_DESCRIPTION:
		priv->config_description = g_value_dup_string (value);
		break;
	case PROP_KEYFILE:
		priv->keyfile = g_value_dup_boxed (value);
		if (!priv->keyfile)
			priv->keyfile = nm_config_create_keyfile ();
		break;
	case PROP_NO_AUTO_DEFAULT:
		priv->no_auto_default.arr = g_strdupv (g_value_get_boxed (value));
		if (!priv->no_auto_default.arr)
			priv->no_auto_default.arr = g_new0 (char *, 1);
		for (i = 0; priv->no_auto_default.arr[i]; i++)
			priv->no_auto_default.specs = g_slist_prepend (priv->no_auto_default.specs, priv->no_auto_default.arr[i]);
		priv->no_auto_default.specs = g_slist_reverse (priv->no_auto_default.specs);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
}

static void
finalize (GObject *gobject)
{
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (gobject);

	g_free (priv->config_main_file);
	g_free (priv->config_description);

	g_free (priv->connectivity.uri);
	g_free (priv->connectivity.response);

	g_slist_free (priv->no_auto_default.specs);
	g_strfreev (priv->no_auto_default.arr);

	g_free (priv->dns_mode);
	g_free (priv->rc_manager);

	g_slist_free_full (priv->ignore_carrier, g_free);
	g_slist_free_full (priv->assume_ipv6ll_only, g_free);

	g_key_file_unref (priv->keyfile);

	G_OBJECT_CLASS (nm_config_data_parent_class)->finalize (gobject);
}

static void
nm_config_data_init (NMConfigData *self)
{
}

static void
constructed (GObject *object)
{
	NMConfigData *self = NM_CONFIG_DATA (object);
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (self);
	char *interval;

	priv->connectivity.uri = g_key_file_get_value (priv->keyfile, "connectivity", "uri", NULL);
	priv->connectivity.response = g_key_file_get_value (priv->keyfile, "connectivity", "response", NULL);

	/* On missing config value, fallback to 300. On invalid value, disable connectivity checking by setting
	 * the interval to zero. */
	interval = g_key_file_get_value (priv->keyfile, "connectivity", "interval", NULL);
	priv->connectivity.interval = interval
	    ? _nm_utils_ascii_str_to_int64 (interval, 10, 0, G_MAXUINT, 0)
	    : NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL;
	g_free (interval);

	priv->dns_mode = g_key_file_get_value (priv->keyfile, "main", "dns", NULL);
	priv->rc_manager = g_key_file_get_value (priv->keyfile, "main", "rc-manager", NULL);

	priv->ignore_carrier = nm_config_get_device_match_spec (priv->keyfile, "main", "ignore-carrier");
	priv->assume_ipv6ll_only = nm_config_get_device_match_spec (priv->keyfile, "main", "assume-ipv6ll-only");

	G_OBJECT_CLASS (nm_config_data_parent_class)->constructed (object);
}

NMConfigData *
nm_config_data_new (const char *config_main_file,
                    const char *config_description,
                    const char *const*no_auto_default,
                    GKeyFile *keyfile)
{
	return g_object_new (NM_TYPE_CONFIG_DATA,
	                     NM_CONFIG_DATA_CONFIG_MAIN_FILE, config_main_file,
	                     NM_CONFIG_DATA_CONFIG_DESCRIPTION, config_description,
	                     NM_CONFIG_DATA_KEYFILE, keyfile,
	                     NM_CONFIG_DATA_NO_AUTO_DEFAULT, no_auto_default,
	                     NULL);
}

NMConfigData *
nm_config_data_new_update_no_auto_default (const NMConfigData *base,
                                           const char *const*no_auto_default)
{
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (base);

	return g_object_new (NM_TYPE_CONFIG_DATA,
	                     NM_CONFIG_DATA_CONFIG_MAIN_FILE, priv->config_main_file,
	                     NM_CONFIG_DATA_CONFIG_DESCRIPTION, priv->config_description,
	                     NM_CONFIG_DATA_KEYFILE, priv->keyfile, /* the keyfile is unchanged. It's safe to share it. */
	                     NM_CONFIG_DATA_NO_AUTO_DEFAULT, no_auto_default,
	                     NULL);
}

static void
nm_config_data_class_init (NMConfigDataClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMConfigDataPrivate));

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	g_object_class_install_property
	    (object_class, PROP_CONFIG_MAIN_FILE,
	     g_param_spec_string (NM_CONFIG_DATA_CONFIG_MAIN_FILE, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_CONFIG_DESCRIPTION,
	     g_param_spec_string (NM_CONFIG_DATA_CONFIG_DESCRIPTION, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	      (object_class, PROP_KEYFILE,
	       g_param_spec_boxed (NM_CONFIG_DATA_KEYFILE, "", "",
	                           G_TYPE_KEY_FILE,
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_CONNECTIVITY_URI,
	     g_param_spec_string (NM_CONFIG_DATA_CONNECTIVITY_URI, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_CONNECTIVITY_INTERVAL,
	     g_param_spec_uint (NM_CONFIG_DATA_CONNECTIVITY_INTERVAL, "", "",
	                        0, G_MAXUINT, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_CONNECTIVITY_RESPONSE,
	     g_param_spec_string (NM_CONFIG_DATA_CONNECTIVITY_RESPONSE, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_NO_AUTO_DEFAULT,
	     g_param_spec_boxed (NM_CONFIG_DATA_NO_AUTO_DEFAULT, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS));

}

