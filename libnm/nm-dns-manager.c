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
 * Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dns-manager.h"

#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-client.h"
#include "nm-object-private.h"
#include "nm-dbus-helpers.h"
#include "nm-core-internal.h"

#include "introspection/org.freedesktop.NetworkManager.DnsManager.h"

G_DEFINE_TYPE (NMDnsManager, nm_dns_manager, NM_TYPE_OBJECT)

#define NM_DNS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_MANAGER, NMDnsManagerPrivate))

typedef struct {
	NMDBusDnsManager *proxy;
	char *mode;
	char *rc_manager;
	GPtrArray *configuration;
} NMDnsManagerPrivate;

enum {
	PROP_0,
	PROP_MODE,
	PROP_RC_MANAGER,
	PROP_CONFIGURATION,

	LAST_PROP
};

/*****************************************************************************
 * NMDnsEntry
 *****************************************************************************/

G_DEFINE_BOXED_TYPE (NMDnsEntry, nm_dns_entry, nm_dns_entry_dup, nm_dns_entry_unref)

struct NMDnsEntry {
	guint refcount;

	char *interface;
	char **nameservers;
	char **domains;
	int priority;
	gboolean vpn;
};

/**
 * nm_dns_entry_new:
 *
 * Creates a new #NMDnsEntry object.
 *
 * Returns: (transfer full): the new #NMDnsEntry object, or %NULL on error
 **/
NMDnsEntry *
nm_dns_entry_new (const char *interface,
                  const char * const *nameservers,
                  const char * const *domains,
                  int priority,
                  gboolean vpn)
{
	NMDnsEntry *entry;
	guint i, len;

	entry = g_slice_new0 (NMDnsEntry);
	entry->refcount = 1;

	entry->interface = g_strdup (interface);

	if (nameservers) {
		len = g_strv_length ((char **) nameservers);
		entry->nameservers = g_new (char *, len + 1);
		for (i = 0; i < len + 1; i++)
			entry->nameservers[i] = g_strdup (nameservers[i]);
	}

	if (domains) {
		len = g_strv_length ((char **) domains);
		entry->domains = g_new (char *, len + 1);
		for (i = 0; i < len + 1; i++)
			entry->domains[i] = g_strdup (domains[i]);
	}

	entry->priority = priority;
	entry->vpn = vpn;

	return entry;
}

/**
 * nm_dns_entry_dup:
 * @entry: the #NMDnsEntry
 *
 * Creates a copy of @entry
 *
 * Returns: (transfer full): a copy of @entry
 **/
NMDnsEntry *
nm_dns_entry_dup (NMDnsEntry *entry)
{
	NMDnsEntry *copy;

	g_return_val_if_fail (entry != NULL, NULL);
	g_return_val_if_fail (entry->refcount > 0, NULL);

	copy = nm_dns_entry_new (entry->interface,
	                         (const char * const *) entry->nameservers,
	                         (const char * const *) entry->domains,
	                         entry->priority,
	                         entry->vpn);

	return copy;
}

/**
 * nm_dns_entry_unref:
 * @entry: the #NMDnsEntry
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.6
 **/
void
nm_dns_entry_unref (NMDnsEntry *entry)
{
	g_return_if_fail (entry != NULL);
	g_return_if_fail (entry->refcount > 0);

	entry->refcount--;
	if (entry->refcount == 0) {
		g_free (entry->interface);
		g_strfreev (entry->nameservers);
		g_strfreev (entry->domains);
		g_slice_free (NMDnsEntry, entry);
	}
}

/**
 * nm_dns_entry_get_interface:
 * @entry: the #NMDnsEntry
 *
 * Gets the interface on which name servers are contacted.
 *
 * Returns: (transfer none): the interface name
 *
 * Since: 1.6
 **/
const char *
nm_dns_entry_get_interface (NMDnsEntry *entry)
{
	g_return_val_if_fail (entry, 0);
	g_return_val_if_fail (entry->refcount > 0, 0);

	return entry->interface;
}

/**
 * nm_dns_entry_get_nameservers:
 * @entry: the #NMDnsEntry
 *
 * Gets the list of name servers for this entry.
 *
 * Returns: (transfer none): the list of name servers
 *
 * Since: 1.6
 **/
const char * const *
nm_dns_entry_get_nameservers (NMDnsEntry *entry)
{
	g_return_val_if_fail (entry, 0);
	g_return_val_if_fail (entry->refcount > 0, 0);

	return (const char * const *) entry->nameservers;
}

/**
 * nm_dns_entry_get_domains:
 * @entry: the #NMDnsEntry
 *
 * Gets the list of DNS domains.
 *
 * Returns: (transfer none): the list of DNS domains
 *
 * Since: 1.6
 **/
const char * const *
nm_dns_entry_get_domains (NMDnsEntry *entry)
{
	g_return_val_if_fail (entry, 0);
	g_return_val_if_fail (entry->refcount > 0, 0);

	return (const char * const *)entry->domains;
}

/**
 * nm_dns_entry_get_vpn:
 * @entry: the #NMDnsEntry
 *
 * Gets whether the entry refers to VPN name servers.
 *
 * Returns: %TRUE if the entry refers to VPN name servers
 *
 * Since: 1.6
 **/
gboolean
nm_dns_entry_get_vpn (NMDnsEntry *entry)
{
	g_return_val_if_fail (entry, 0);
	g_return_val_if_fail (entry->refcount > 0, 0);

	return entry->vpn;
}

/**
 * nm_dns_entry_get_priority:
 * @entry: the #NMDnsEntry
 *
 * Gets the priority of the entry
 *
 * Returns: the priority of the entry
 *
 * Since: 1.6
 **/
int
nm_dns_entry_get_priority (NMDnsEntry *entry)
{
	g_return_val_if_fail (entry, 0);
	g_return_val_if_fail (entry->refcount > 0, 0);

	return entry->priority;
}

/*****************************************************************************/

static gboolean
demarshal_dns_configuration (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (object);
	GVariant *entry_var;
	GVariantIter iter, *iterp;
	NMDnsEntry *entry;
	GPtrArray *array;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), FALSE);

	g_variant_iter_init (&iter, value);
	g_ptr_array_unref (priv->configuration);
	priv->configuration = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_dns_entry_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &entry_var)) {
		char **nameservers = NULL, **domains = NULL;
		gboolean vpn = FALSE;
		char *interface = NULL, *str;
		int priority;

		if (   !g_variant_lookup (entry_var, "nameservers", "as", &iterp)
		    || !g_variant_lookup (entry_var, "priority", "i", &priority)) {
			g_warning ("Ignoring invalid DNS configuration");
			g_variant_unref (entry_var);
			continue;
		}

		array = g_ptr_array_new ();
		while (g_variant_iter_next (iterp, "&s", &str))
			g_ptr_array_add (array, str);
		g_ptr_array_add (array, NULL);
		nameservers = (char **) g_ptr_array_free (array, FALSE);
		g_variant_iter_free (iterp);

		if (g_variant_lookup (entry_var, "domains", "as", &iterp)) {
			array = g_ptr_array_new ();
			while (g_variant_iter_next (iterp, "&s", &str))
				g_ptr_array_add (array, str);
			g_ptr_array_add (array, NULL);
			domains = (char **) g_ptr_array_free (array, FALSE);
			g_variant_iter_free (iterp);
		}

		g_variant_lookup (entry_var, "interface", "&s", &interface);
		g_variant_lookup (entry_var, "priority", "i", &priority);
		g_variant_lookup (entry_var, "vpn", "b", &vpn);

		entry = nm_dns_entry_new (interface,
		                          (const char * const *) nameservers,
		                          (const char * const *) domains,
		                          priority,
		                          vpn);
		g_free (domains);
		g_free (nameservers);
		g_variant_unref (entry_var);
		if (!entry) {
			g_warning ("Ignoring invalid DNS entry");
			continue;
		}

		g_ptr_array_add (priv->configuration, entry);
	}

	_nm_object_queue_notify (object, NM_DNS_MANAGER_CONFIGURATION);

	return TRUE;
}

/*****************************************************************************/
const char *
nm_dns_manager_get_mode (NMDnsManager *manager)
{
	return NM_DNS_MANAGER_GET_PRIVATE (manager)->mode;
}

const char *
nm_dns_manager_get_rc_manager (NMDnsManager *manager)
{
	return NM_DNS_MANAGER_GET_PRIVATE (manager)->rc_manager;
}

const GPtrArray *
nm_dns_manager_get_configuration (NMDnsManager *manager)
{
	return NM_DNS_MANAGER_GET_PRIVATE (manager)->configuration;
}
/*****************************************************************************/

static void
nm_dns_manager_init (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	priv->configuration = g_ptr_array_new ();
}

static void
init_dbus (NMObject *object)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DNS_MANAGER_MODE,          &priv->mode },
		{ NM_DNS_MANAGER_RC_MANAGER,    &priv->rc_manager },
		{ NM_DNS_MANAGER_CONFIGURATION, &priv->configuration, demarshal_dns_configuration },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_dns_manager_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_DNS_MANAGER (_nm_object_get_proxy (object, NM_DBUS_INTERFACE_DNS_MANAGER));
	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DNS_MANAGER,
	                                property_info);
}

static void
dispose (GObject *object)
{
	NMDnsManager *self = NM_DNS_MANAGER (object);
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	g_clear_pointer (&priv->mode, g_free);
	g_clear_pointer (&priv->rc_manager, g_free);
	g_clear_pointer (&priv->configuration, g_ptr_array_unref);

	G_OBJECT_CLASS (nm_dns_manager_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MODE:
		g_value_set_string (value, priv->mode);
		break;
	case PROP_RC_MANAGER:
		g_value_set_string (value, priv->rc_manager);
		break;
	case PROP_CONFIGURATION:
		g_value_take_boxed (value, _nm_utils_copy_array (priv->configuration,
		                                                 (NMUtilsCopyFunc) nm_dns_entry_dup,
		                                                 (GDestroyNotify) nm_dns_entry_unref));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dns_manager_class_init (NMDnsManagerClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMDnsManagerPrivate));

	/* Virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	nm_object_class->init_dbus = init_dbus;

	/* Properties */

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_DNS_MANAGER_MODE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_RC_MANAGER,
		 g_param_spec_string (NM_DNS_MANAGER_RC_MANAGER, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CONFIGURATION,
		 g_param_spec_boxed (NM_DNS_MANAGER_CONFIGURATION, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}
