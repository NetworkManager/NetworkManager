/* NetworkManager user session tracker -- per-session data
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
 * (C) Copyright 2010 Daniel Gnoutcheff <daniel@gnoutcheff.name>
 */

#include "nm-session-info.h"
#include "nm-dbus-glib-types.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMSessionInfo, nm_session_info, G_TYPE_OBJECT);

typedef struct {
	char *id;
	char *user;
	GSList *groups;
	gboolean is_default;
} NMSessionInfoPrivate;

#define NM_SESSION_INFO_GET_PRIVATE(self) (G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_SESSION_INFO, NMSessionInfoPrivate))

enum {
	PROP_0,
	PROP_ID,
	PROP_USER,
	PROP_GROUPS,
	PROP_IS_DEFAULT
};

char * 
nm_session_info_get_id (NMSessionInfo *self)
{
	g_return_val_if_fail (NM_IS_SESSION_INFO (self), NULL);

	return NM_SESSION_INFO_GET_PRIVATE (self)->id;
}

char * 
nm_session_info_get_unix_user (NMSessionInfo *self)
{
	g_return_val_if_fail (NM_IS_SESSION_INFO (self), NULL);

	return NM_SESSION_INFO_GET_PRIVATE (self)->user;
}

GSList * 
nm_session_info_get_unix_groups (NMSessionInfo *self)
{
	g_return_val_if_fail (NM_IS_SESSION_INFO (self), NULL);

	return NM_SESSION_INFO_GET_PRIVATE (self)->groups;
}

gboolean
nm_session_info_is_default_session (NMSessionInfo *self)
{
	g_return_val_if_fail (NM_IS_SESSION_INFO (self), FALSE);

	return NM_SESSION_INFO_GET_PRIVATE (self)->is_default;
}

static void
set_property (GObject *object, 
              guint property_id,
              const GValue *value,
              GParamSpec *pspec) {
    NMSessionInfoPrivate *priv = NM_SESSION_INFO_GET_PRIVATE (object);

    switch (property_id) {
    	case PROP_ID:
    		g_free (priv->id);
    		priv->id = g_value_dup_string (value);
    		break;
    	case PROP_USER:
    		g_free (priv->user);
    		priv->user = g_value_dup_string (value);
    		break;
    	case PROP_GROUPS:
    		nm_utils_slist_free (priv->groups, g_free);
    		priv->groups = g_value_dup_boxed (value);
    		break;
    	case PROP_IS_DEFAULT:
    		priv->is_default = g_value_get_boolean (value);
    		break;

    	default:
    		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    		break;
    }
}

static void
get_property (GObject *object, 
              guint property_id,
              GValue *value,
              GParamSpec *pspec) {
	NMSessionInfoPrivate *priv = NM_SESSION_INFO_GET_PRIVATE (object);

    switch (property_id) {
    	case PROP_ID:
    		g_value_set_string (value, priv->id);
    		break;
    	case PROP_USER:
    		g_value_set_string (value, priv->user);
    		break;
    	case PROP_GROUPS:
    		g_value_set_boxed (value, priv->groups);
    		break;
    	case PROP_IS_DEFAULT:
    		g_value_set_boolean (value, priv->is_default);
    		break;

    	default:
    		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    		break;
    }
}

static void
nm_session_info_init (NMSessionInfo *self) {
}

static void
dispose (GObject *object)
{
	NMSessionInfoPrivate *priv = NM_SESSION_INFO_GET_PRIVATE (object);

	if (priv->id) {
		g_free (priv->id);
		priv->id = NULL;
	}

	if (priv->user) {
		g_free (priv->user);
		priv->user = NULL;
	}

	if (priv->groups) {
		nm_utils_slist_free (priv->groups, g_free);
		priv->groups = NULL;
	}

	G_OBJECT_CLASS (nm_session_info_parent_class)->dispose (object);		
}

static void
nm_session_info_class_init (NMSessionInfoClass *info_class) {
	GObjectClass *g_class = G_OBJECT_CLASS (info_class);

	g_type_class_add_private (g_class, sizeof(NMSessionInfoPrivate));
	g_class->set_property = set_property;
	g_class->get_property = get_property;
	g_class->dispose = dispose;

	g_object_class_install_property
		(g_class, PROP_ID,
		 g_param_spec_string (
		 	 NM_SESSION_INFO_ID,
		 	 "ConsoleKitSID",
		 	 "ConsoleKit session ID, or \"[none]\" if this is the \"default\" "
		 	 "session.",
		 	 NM_SESSION_INFO_DEFAULT_ID,
		 	 G_PARAM_READABLE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(g_class, PROP_USER,
		 g_param_spec_string (
		 	 NM_SESSION_INFO_UNIX_USER,
		 	 "UnixUser",
		 	 "String name of the unix user who owns this session, or NULL if "
		 	 "this is the default session.",
		 	 NULL,
		 	 G_PARAM_READABLE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(g_class, PROP_GROUPS,
		 g_param_spec_boxed (
		 	 NM_SESSION_INFO_UNIX_GROUPS,
		 	 "UnixGroups",
		 	 "List of strings representing the groups that this session's user "
		 	 "belonged to at login time. This represents our best guess as to "
		 	 "what groups the session's processes belong to. If this is the "
		 	 "default session, this is NULL.",
		 	 DBUS_TYPE_G_LIST_OF_STRING,
		 	 G_PARAM_READABLE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property
		(g_class, PROP_IS_DEFAULT,
		 g_param_spec_boolean (
		 	 NM_SESSION_INFO_IS_DEFAULT,
		 	 "IsDefaultSession",
		 	 "Indicates if this NMSessionInfo instance represents the "
		 	 "\"default\" session, the session containing all processes that "
		 	 "do not belong to a ConsoleKit-recognized session.",
		 	 TRUE,
		 	 G_PARAM_READABLE | G_PARAM_CONSTRUCT_ONLY));

	g_signal_new (
			NM_SESSION_INFO_REMOVED,
			NM_TYPE_SESSION_INFO,
			G_SIGNAL_RUN_FIRST,
			0,
			NULL, NULL,
			g_cclosure_marshal_VOID__VOID,
			G_TYPE_NONE,
			0);
}
