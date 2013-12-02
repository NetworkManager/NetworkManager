/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-address-list
 * @short_description: An editable list of IP addresses or hostnames
 *
 * #NmtAddressList is a subclass of #NmtWidgetList that contains
 * entries displaying IP addresses, address/prefix strings, or
 * hostnames. This is designed for binding its #NmtAddressList:strings
 * property to an appropriate #NMSettingIP4Config or
 * #NMSettingIP6Config property via one of the nm-editor-bindings
 * functions.
 */

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus-glib.h>
#include <glib/gi18n-lib.h>

#include "nmt-address-list.h"
#include "nmt-ip-entry.h"

G_DEFINE_TYPE (NmtAddressList, nmt_address_list, NMT_TYPE_WIDGET_LIST)

#define NMT_ADDRESS_LIST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_ADDRESS_LIST, NmtAddressListPrivate))

typedef struct {
	NmtAddressListType list_type;
	char **strings;
} NmtAddressListPrivate;

enum {
	PROP_0,
	PROP_LIST_TYPE,
	PROP_STRINGS,

	LAST_PROP
};

/**
 * NmtAddressListType:
 * @NMT_ADDRESS_LIST_IP4_WITH_PREFIX: IPv4 address/prefix strings
 * @NMT_ADDRESS_LIST_IP4: IPv4 addresses
 * @NMT_ADDRESS_LIST_IP6_WITH_PREFIX: IPv6 address/prefix strings
 * @NMT_ADDRESS_LIST_IP6: IPv6 addresses
 * @NMT_ADDRESS_LIST_HOSTNAME: hostnames
 *
 * The type of address in an #NmtAddressList
 */

/**
 * nmt_address_list_new:
 * @list_type: the type of address the list will contain
 *
 * Creates a new #NmtAddressList
 *
 * Returns: a new #NmtAddressList
 */
NmtNewtWidget *
nmt_address_list_new (NmtAddressListType list_type)
{
	return g_object_new (NMT_TYPE_ADDRESS_LIST,
	                     "list-type", list_type,
	                     NULL);
}

static void
nmt_address_list_init (NmtAddressList *list)
{
}

static gboolean
strings_transform_to_entry (GBinding     *binding,
                            const GValue *source_value,
                            GValue       *target_value,
                            gpointer      user_data)
{
	int n = GPOINTER_TO_INT (user_data);
	char **strings;

	strings = g_value_get_boxed (source_value);
	if (n >= g_strv_length (strings))
		return FALSE;

	g_value_set_string (target_value, strings[n]);
	return TRUE;
}

static gboolean
strings_transform_from_entry (GBinding     *binding,
                              const GValue *source_value,
                              GValue       *target_value,
                              gpointer      user_data)
{
	NmtAddressList *list = NMT_ADDRESS_LIST (g_binding_get_source (binding));
	NmtAddressListPrivate *priv = NMT_ADDRESS_LIST_GET_PRIVATE (list);
	int n = GPOINTER_TO_INT (user_data);

	if (n >= g_strv_length (priv->strings))
		return FALSE;

	g_free (priv->strings[n]);
	priv->strings[n] = g_value_dup_string (source_value);

	g_value_set_boxed (target_value, priv->strings);
	return TRUE;
}

static gboolean
hostname_filter (NmtNewtEntry *entry,
                 const char   *text,
                 int           ch,
                 int           position,
                 gpointer      user_data)
{
	return g_ascii_isalnum (ch) || ch == '.' || ch == '-';
}

static NmtNewtWidget *
nmt_address_list_create_widget (NmtWidgetList *list,
                                int            num)
{
	NmtAddressListPrivate *priv = NMT_ADDRESS_LIST_GET_PRIVATE (list);
	NmtNewtWidget *entry;

	if (priv->list_type == NMT_ADDRESS_LIST_IP4_WITH_PREFIX)
		entry = nmt_ip_entry_new (25, AF_INET, TRUE, FALSE);
	else if (priv->list_type == NMT_ADDRESS_LIST_IP4)
		entry = nmt_ip_entry_new (25, AF_INET, FALSE, FALSE);
	else if (priv->list_type == NMT_ADDRESS_LIST_IP6_WITH_PREFIX)
		entry = nmt_ip_entry_new (25, AF_INET6, TRUE, FALSE);
	else if (priv->list_type == NMT_ADDRESS_LIST_IP6)
		entry = nmt_ip_entry_new (25, AF_INET6, FALSE, FALSE);
	else if (priv->list_type == NMT_ADDRESS_LIST_HOSTNAME) {
		entry = nmt_newt_entry_new (25, NMT_NEWT_ENTRY_NONEMPTY);
		nmt_newt_entry_set_filter (NMT_NEWT_ENTRY (entry), hostname_filter, list);
	} else
		g_assert_not_reached ();

	g_object_bind_property_full (list, "strings", entry, "text",
	                             G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                             strings_transform_to_entry,
	                             strings_transform_from_entry,
	                             GINT_TO_POINTER (num), NULL);

	return entry;
}

static void
nmt_address_list_add_clicked (NmtWidgetList *list)
{
	NmtAddressListPrivate *priv = NMT_ADDRESS_LIST_GET_PRIVATE (list);
	int len;

	len = g_strv_length (priv->strings);
	priv->strings = g_renew (char *, priv->strings, len + 2);
	priv->strings[len] = g_strdup ("");
	priv->strings[len + 1] = NULL;

	nmt_widget_list_set_length (list, len + 1);
	g_object_notify (G_OBJECT (list), "strings");
}

static void
nmt_address_list_remove_clicked (NmtWidgetList *list,
                                 int            num)
{
	NmtAddressListPrivate *priv = NMT_ADDRESS_LIST_GET_PRIVATE (list);
	int len;

	len = g_strv_length (priv->strings);
	g_free (priv->strings[num]);
	memmove (priv->strings + num, priv->strings + num + 1, (len - num) * sizeof (char *));

	nmt_widget_list_set_length (list, len - 1);
	g_object_notify (G_OBJECT (list), "strings");
}

static void
nmt_address_list_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
	NmtAddressListPrivate *priv = NMT_ADDRESS_LIST_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LIST_TYPE:
		priv->list_type = g_value_get_uint (value);
		break;
	case PROP_STRINGS:
		g_strfreev (priv->strings);
		priv->strings = g_value_dup_boxed (value);
		if (!priv->strings)
			priv->strings = g_new0 (char *, 1);
		nmt_widget_list_set_length (NMT_WIDGET_LIST (object),
		                            g_strv_length (priv->strings));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_address_list_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
	NmtAddressListPrivate *priv = NMT_ADDRESS_LIST_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LIST_TYPE:
		g_value_set_uint (value, priv->list_type);
		break;
	case PROP_STRINGS:
		g_value_set_boxed (value, priv->strings);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_address_list_class_init (NmtAddressListClass *list_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (list_class);
	NmtWidgetListClass *widget_list_class = NMT_WIDGET_LIST_CLASS (list_class);

	g_type_class_add_private (list_class, sizeof (NmtAddressListPrivate));

	/* virtual methods */
	object_class->set_property = nmt_address_list_set_property;
	object_class->get_property = nmt_address_list_get_property;

	widget_list_class->create_widget  = nmt_address_list_create_widget;
	widget_list_class->add_clicked    = nmt_address_list_add_clicked;
	widget_list_class->remove_clicked = nmt_address_list_remove_clicked;

	/**
	 * NmtAddressList:list-type:
	 *
	 * The type of address the list holds.
	 */
	g_object_class_install_property (object_class, PROP_LIST_TYPE,
	                                 g_param_spec_uint ("list-type", "", "",
	                                                    0, G_MAXUINT, 0,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_CONSTRUCT_ONLY |
	                                                    G_PARAM_STATIC_STRINGS));
	/**
	 * NmtAddressList:strings:
	 *
	 * The strings in the list's entries.
	 */
	g_object_class_install_property (object_class, PROP_STRINGS,
	                                 g_param_spec_boxed ("strings", "", "",
	                                                     G_TYPE_STRV,
	                                                     G_PARAM_READWRITE |
	                                                     G_PARAM_STATIC_STRINGS));
}
