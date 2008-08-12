/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>
#include <nm-utils.h>
#include "NetworkManager.h"
#include "nm-object.h"
#include "nm-object-cache.h"
#include "nm-object-private.h"
#include "nm-dbus-glib-types.h"


G_DEFINE_ABSTRACT_TYPE (NMObject, nm_object, G_TYPE_OBJECT)

#define NM_OBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OBJECT, NMObjectPrivate))

typedef struct {
	PropChangedMarshalFunc func;
	gpointer field;
} PropChangedInfo;

typedef struct {
	DBusGConnection *connection;
	char *path;
	DBusGProxy *properties_proxy;
	GSList *pcs;
	NMObject *parent;

	GSList *notify_props;
	gulong notify_id;
	gboolean disposed;
} NMObjectPrivate;

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_PATH,

	LAST_PROP
};

static void
nm_object_init (NMObject *object)
{
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMObjectPrivate *priv;

	object = G_OBJECT_CLASS (nm_object_parent_class)->constructor (type,
																   n_construct_params,
																   construct_params);
	if (!object)
		return NULL;

	nm_object_cache_add (NM_OBJECT (object));

	priv = NM_OBJECT_GET_PRIVATE (object);

	if (priv->connection == NULL || priv->path == NULL) {
		g_warning ("Connection or path not received.");
		g_object_unref (object);
		return NULL;
	}

	priv->properties_proxy = dbus_g_proxy_new_for_name (priv->connection,
														NM_DBUS_SERVICE,
														priv->path,
														"org.freedesktop.DBus.Properties");

	return object;
}

static void
dispose (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_object_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	if (priv->notify_id) {
		g_source_remove (priv->notify_id);
		priv->notify_id = 0;
	}

	g_slist_foreach (priv->notify_props, (GFunc) g_free, NULL);
	g_slist_free (priv->notify_props);

	g_object_unref (priv->properties_proxy);
	dbus_g_connection_unref (priv->connection);

	G_OBJECT_CLASS (nm_object_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	g_slist_foreach (priv->pcs, (GFunc) g_hash_table_destroy, NULL);
	g_slist_free (priv->pcs);
	g_free (priv->path);

	G_OBJECT_CLASS (nm_object_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		/* Construct only */
		priv->connection = dbus_g_connection_ref ((DBusGConnection *) g_value_get_boxed (value));
		break;
	case PROP_PATH:
		/* Construct only */
		priv->path = g_value_dup_string (value);
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
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_boxed (value, priv->connection);
		break;
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_object_class_init (NMObjectClass *nm_object_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (nm_object_class);

	g_type_class_add_private (nm_object_class, sizeof (NMObjectPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* porperties */

	/**
	 * NMObject:connection:
	 *
	 * The #DBusGConnection of the object.
	 **/
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_boxed (NM_OBJECT_DBUS_CONNECTION,
							 "Connection",
							 "Connection",
							 DBUS_TYPE_G_CONNECTION,
							 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * NMObject:path:
	 *
	 * The DBus object path.
	 **/
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_OBJECT_DBUS_PATH,
							  "Object Path",
							  "DBus Object Path",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/**
 * nm_object_get_connection:
 * @object: a #NMObject
 *
 * Gets the #NMObject's DBusGConnection.
 *
 * Returns: the connection
 **/
DBusGConnection *
nm_object_get_connection (NMObject *object)
{
	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	return NM_OBJECT_GET_PRIVATE (object)->connection;
}

/**
 * nm_object_get_path:
 * @object: a #NMObject
 *
 * Gets the DBus path of the #NMObject.
 *
 * Returns: the object's path. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_object_get_path (NMObject *object)
{
	g_return_val_if_fail (NM_IS_OBJECT (object), NULL);

	return NM_OBJECT_GET_PRIVATE (object)->path;
}

static gboolean
deferred_notify_cb (gpointer data)
{
	NMObject *object = NM_OBJECT (data);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	GSList *iter;

	priv->notify_id = 0;

	priv->notify_props = g_slist_reverse (priv->notify_props);
	for (iter = priv->notify_props; iter; iter = g_slist_next (iter)) {
		g_object_notify (G_OBJECT (object), (const char *) iter->data);
		g_free (iter->data);
	}
	g_slist_free (priv->notify_props);
	priv->notify_props = NULL;

	return FALSE;
}

void
nm_object_queue_notify (NMObject *object, const char *property)
{
	NMObjectPrivate *priv;
	gboolean found = FALSE;
	GSList *iter;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (property != NULL);

	priv = NM_OBJECT_GET_PRIVATE (object);
	if (!priv->notify_id)
		priv->notify_id = g_idle_add_full (G_PRIORITY_LOW, deferred_notify_cb, object, NULL);

	for (iter = priv->notify_props; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((char *) iter->data, property)) {
			found = TRUE;
			break;
		}
	}

	if (!found)
		priv->notify_props = g_slist_prepend (priv->notify_props, g_strdup (property));
}

/* Stolen from dbus-glib */
static char*
wincaps_to_dash (const char *caps)
{
	const char *p;
	GString *str;

	str = g_string_new (NULL);
	p = caps;
	while (*p) {
		if (g_ascii_isupper (*p)) {
			if (str->len > 0 && (str->len < 2 || str->str[str->len-2] != '-'))
				g_string_append_c (str, '-');
			g_string_append_c (str, g_ascii_tolower (*p));
		} else
			g_string_append_c (str, *p);
		++p;
	}

	return g_string_free (str, FALSE);
}

static void
handle_property_changed (gpointer key, gpointer data, gpointer user_data)
{
	NMObject *self = NM_OBJECT (user_data);
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (self);
	char *prop_name;
	PropChangedInfo *pci;
	GParamSpec *pspec;
	gboolean success = FALSE, found = FALSE;
	GSList *iter;

	prop_name = wincaps_to_dash ((char *) key);
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (self)), prop_name);
	if (!pspec) {
		g_warning ("Property '%s' change detected but couldn't be found on the object.", prop_name);
		goto out;
	}

	/* Iterate through the object and it's parents to find the property */
	for (iter = priv->pcs; iter; iter = g_slist_next (iter)) {
		pci = g_hash_table_lookup ((GHashTable *) iter->data, prop_name);
		if (pci) {
			found = TRUE;
			success = (*(pci->func)) (self, pspec, (GValue *) data, pci->field);
			if (success)
				break;
		}
	}

	if (!found) {
#if DEBUG
		g_warning ("Property '%s' unhandled.", prop_name);
#endif
	} else if (!success)
		g_warning ("Property '%s' could not be set due to errors.", prop_name);

out:
	g_free (prop_name);
}

static void
properties_changed_proxy (DBusGProxy *proxy,
                          GHashTable *properties,
                          gpointer user_data)
{
	g_hash_table_foreach (properties, handle_property_changed, user_data);
}

void
nm_object_handle_properties_changed (NMObject *object,
                                     DBusGProxy *proxy,
                                     const NMPropertiesChangedInfo *info)
{
	NMObjectPrivate *priv = NM_OBJECT_GET_PRIVATE (object);
	NMPropertiesChangedInfo *tmp;
	GHashTable *instance;

	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (proxy != NULL);
	g_return_if_fail (info != NULL);

	dbus_g_proxy_add_signal (proxy, "PropertiesChanged", DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy,
						    "PropertiesChanged",
						    G_CALLBACK (properties_changed_proxy),
						    object,
						    NULL);

	instance = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	priv->pcs = g_slist_prepend (priv->pcs, instance);

	for (tmp = (NMPropertiesChangedInfo *) info; tmp->name; tmp++) {
		PropChangedInfo *pci;

		if (!tmp->name || !tmp->func || !tmp->field) {
			g_warning ("%s: missing field in NMPropertiesChangedInfo", __func__);
			continue;
		}

		pci = g_malloc0 (sizeof (PropChangedInfo));
		if (!pci) {
			g_warning ("%s: not enough memory for PropChangedInfo", __func__);
			continue;
		}
		pci->func = tmp->func;
		pci->field = tmp->field;
		g_hash_table_insert (instance, g_strdup (tmp->name), pci);
	}
}

#define HANDLE_TYPE(ucase, lcase) \
	} else if (pspec->value_type == G_TYPE_##ucase) { \
		if (G_VALUE_HOLDS_##ucase (value)) { \
			g##lcase *param = (g##lcase *) field; \
			*param = g_value_get_##lcase (value); \
		} else { \
			success = FALSE; \
			goto done; \
		}

gboolean
nm_object_demarshal_generic (NMObject *object,
                             GParamSpec *pspec,
                             GValue *value,
                             gpointer field)
{
	gboolean success = TRUE;

	if (pspec->value_type == G_TYPE_STRING) {
		if (G_VALUE_HOLDS_STRING (value)) {
			char **param = (char **) field;
			g_free (*param);
			*param = g_value_dup_string (value);
		} else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH)) {
			char **param = (char **) field;
			g_free (*param);
			*param = g_strdup (g_value_get_boxed (value));
		} else {
			success = FALSE;
			goto done;
		}
	HANDLE_TYPE(BOOLEAN, boolean)
	HANDLE_TYPE(CHAR, char)
	HANDLE_TYPE(UCHAR, uchar)
	HANDLE_TYPE(DOUBLE, double)
	HANDLE_TYPE(INT, int)
	HANDLE_TYPE(UINT, uint)
	HANDLE_TYPE(INT64, int)
	HANDLE_TYPE(UINT64, uint)
	HANDLE_TYPE(LONG, long)
	HANDLE_TYPE(ULONG, ulong)
	} else {
		g_warning ("%s: %s/%s unhandled type %s.",
		           __func__, G_OBJECT_TYPE_NAME (object), pspec->name,
		           g_type_name (pspec->value_type));
		success = FALSE;
	}

done:
	if (success) {
		nm_object_queue_notify (object, pspec->name);
	} else {
		g_warning ("%s: %s/%s (type %s) couldn't be set with type %s.",
		           __func__, G_OBJECT_TYPE_NAME (object), pspec->name,
		           g_type_name (pspec->value_type), G_VALUE_TYPE_NAME (value));
	}
	return success;
}

gboolean
nm_object_get_property (NMObject *object,
						const char *interface,
						const char *prop_name,
						GValue *value)
{
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (interface != NULL, FALSE);
	g_return_val_if_fail (prop_name != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	if (!dbus_g_proxy_call_with_timeout (NM_OBJECT_GET_PRIVATE (object)->properties_proxy,
							"Get", 15000, &err,
							G_TYPE_STRING, interface,
							G_TYPE_STRING, prop_name,
							G_TYPE_INVALID,
							G_TYPE_VALUE, value,
							G_TYPE_INVALID)) {
		g_warning ("%s: Error getting '%s' for %s: %s\n",
		           __func__,
		           prop_name,
		           nm_object_get_path (object),
		           err->message);
		g_error_free (err);
		return FALSE;
	}

	return TRUE;
}

void
nm_object_set_property (NMObject *object,
						const char *interface,
						const char *prop_name,
						GValue *value)
{
	g_return_if_fail (NM_IS_OBJECT (object));
	g_return_if_fail (interface != NULL);
	g_return_if_fail (prop_name != NULL);
	g_return_if_fail (G_IS_VALUE (value));

	dbus_g_proxy_call_no_reply (NM_OBJECT_GET_PRIVATE (object)->properties_proxy,
								"Set",
								G_TYPE_STRING, interface,
								G_TYPE_STRING, prop_name,
								G_TYPE_VALUE, value,
								G_TYPE_INVALID);
}

char *
nm_object_get_string_property (NMObject *object,
							   const char *interface,
							   const char *prop_name)
{
	char *str = NULL;
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		if (G_VALUE_HOLDS_STRING (&value))
			str = g_strdup (g_value_get_string (&value));
		else if (G_VALUE_HOLDS (&value, DBUS_TYPE_G_OBJECT_PATH))
			str = g_strdup (g_value_get_boxed (&value));
		g_value_unset (&value);
	}

	return str;
}

char *
nm_object_get_object_path_property (NMObject *object,
									const char *interface,
									const char *prop_name)
{
	char *path = NULL;
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		path = g_strdup (g_value_get_boxed (&value));
		g_value_unset (&value);
	}

	return path;
}

gint32
nm_object_get_int_property (NMObject *object,
							const char *interface,
							const char *prop_name)
{
	gint32 i = 0;
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		i = g_value_get_int (&value);
		g_value_unset (&value);
	}

	return i;
}

guint32
nm_object_get_uint_property (NMObject *object,
							 const char *interface,
							 const char *prop_name)
{
	guint32 i = 0;
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		i = g_value_get_uint (&value);
		g_value_unset (&value);
	}

	return i;
}

gboolean
nm_object_get_boolean_property (NMObject *object,
								const char *interface,
								const char *prop_name)
{
	gboolean b = FALSE;  // FIXME: somehow convey failure if needed
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		b = g_value_get_boolean (&value);
		g_value_unset (&value);
	}

	return b;
}

gint8
nm_object_get_byte_property (NMObject *object,
							 const char *interface,
							 const char *prop_name)
{
	gint8 b = G_MAXINT8;
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		b = g_value_get_uchar (&value);
		g_value_unset (&value);
	}

	return b;
}

gdouble
nm_object_get_double_property (NMObject *object,
							   const char *interface,
							   const char *prop_name)
{
	gdouble d = G_MAXDOUBLE;
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		d = g_value_get_double (&value);
		g_value_unset (&value);
	}

	return d;
}

GByteArray *
nm_object_get_byte_array_property (NMObject *object,
								   const char *interface,
								   const char *prop_name)
{
	GByteArray * array = NULL;
	GValue value = {0,};

	if (nm_object_get_property (object, interface, prop_name, &value)) {
		GArray * tmp = g_value_get_boxed (&value);
		int i;
		unsigned char byte;

		array = g_byte_array_sized_new (tmp->len);
		for (i = 0; i < tmp->len; i++) {
			byte = g_array_index (tmp, unsigned char, i);
			g_byte_array_append (array, &byte, 1);
		}
		g_value_unset (&value);
	}

	return array;
}
