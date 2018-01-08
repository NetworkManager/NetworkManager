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
 * SECTION:nmt-route-table
 * @short_description: An editable list of IP4 or IP6 routes
 *
 * #NmtRouteTable implements a list of #NmtRouteEntry, plus headers,
 * and buttons to add and remove entries.
 */

#include "nm-default.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "nmt-route-table.h"
#include "nmt-route-entry.h"
#include "nmt-widget-list.h"

G_DEFINE_TYPE (NmtRouteTable, nmt_route_table, NMT_TYPE_NEWT_GRID)

#define NMT_ROUTE_TABLE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_ROUTE_TABLE, NmtRouteTablePrivate))

typedef struct {
	int family;

	int ip_entry_width;
	int metric_entry_width;

	GPtrArray *routes;
	NmtNewtWidget *list;
} NmtRouteTablePrivate;

enum {
	PROP_0,
	PROP_FAMILY,
	PROP_ROUTES,

	LAST_PROP
};

/**
 * nmt_route_table_new:
 * @family: the address family, eg %AF_INET
 *
 * Creates a new #NmtRouteTable
 *
 * Returns: a new #NmtRouteTable
 */
NmtNewtWidget *
nmt_route_table_new (int family)
{
	return g_object_new (NMT_TYPE_ROUTE_TABLE,
	                     "family", family,
	                     NULL);
}

static gboolean
route_list_transform_to_route (GBinding     *binding,
                               const GValue *source_value,
                               GValue       *target_value,
                               gpointer      user_data)
{
	NmtRouteTable *table = NMT_ROUTE_TABLE (g_binding_get_source (binding));
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (table);
	int n = GPOINTER_TO_INT (user_data);
	NMIPRoute *route;

	if (n >= priv->routes->len)
		return FALSE;

	route = priv->routes->pdata[n];
	g_value_set_boxed (target_value, route);
	return TRUE;
}

static gboolean
route_list_transform_from_route (GBinding     *binding,
                                 const GValue *source_value,
                                 GValue       *target_value,
                                 gpointer      user_data)
{
	NmtRouteTable *table = NMT_ROUTE_TABLE (g_binding_get_source (binding));
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (table);
	int n = GPOINTER_TO_INT (user_data);
	GPtrArray *routes;
	NMIPRoute *route;

	if (n >= priv->routes->len)
		return FALSE;
	route = priv->routes->pdata[n];

	routes = priv->routes;
	priv->routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	if (route)
		nm_ip_route_unref (route);
	routes->pdata[n] = g_value_dup_boxed (source_value);

	g_value_take_boxed (target_value, routes);
	return TRUE;
}

static NmtNewtWidget *
create_route_entry (NmtWidgetList *list,
                    int            num,
                    gpointer       table)
{
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (table);
	NmtNewtWidget *entry;

	entry = nmt_route_entry_new (priv->family,
	                             priv->ip_entry_width,
	                             priv->metric_entry_width);

	g_object_bind_property_full (table, "routes",
	                             entry, "route",
	                             G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                             route_list_transform_to_route,
	                             route_list_transform_from_route,
	                             GINT_TO_POINTER (num), NULL);
	return entry;
}

static void
add_route (NmtWidgetList *list,
           gpointer       table)
{
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (table);
	NMIPRoute *route;

	if (priv->family == AF_INET)
		route = nm_ip_route_new (AF_INET, "0.0.0.0", 32, NULL, -1, NULL);
	else
		route = nm_ip_route_new (AF_INET6, "::", 128, NULL, -1, NULL);
	g_ptr_array_add (priv->routes, route);
	nmt_widget_list_set_length (list, priv->routes->len);
	g_object_notify (table, "routes");
}

static void
remove_route (NmtWidgetList *list,
              int            num,
              gpointer       table)
{
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (table);

	if (num >= priv->routes->len)
		return;

	g_ptr_array_remove_index (priv->routes, num);
	nmt_widget_list_set_length (list, priv->routes->len);

	g_object_notify (table, "routes");
}

static void
nmt_route_table_init (NmtRouteTable *table)
{
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (table);
	NmtNewtWidget *header, *empty;
	NmtNewtWidget *dest_prefix_label, *next_hop_label, *metric_label;
	int dest_prefix_width, next_hop_width, metric_width;
	char *text;

	priv->routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	header = nmt_newt_grid_new ();

	text = g_strdup_printf ("%s/%s", _("Destination"), _("Prefix"));
	dest_prefix_width = nmt_newt_text_width (text);
	dest_prefix_label = g_object_new (NMT_TYPE_NEWT_LABEL,
	                                  "text", text,
	                                  "style", NMT_NEWT_LABEL_PLAIN,
	                                  NULL);
	g_free (text);
	nmt_newt_grid_add (NMT_NEWT_GRID (header), dest_prefix_label, 0, 0);

	text = _("Next Hop");
	next_hop_label = g_object_new (NMT_TYPE_NEWT_LABEL,
	                               "text", text,
	                               "style", NMT_NEWT_LABEL_PLAIN,
	                               NULL);
	next_hop_width = nmt_newt_text_width (text);
	nmt_newt_grid_add (NMT_NEWT_GRID (header), next_hop_label, 1, 0);

	text = _("Metric");
	metric_label = g_object_new (NMT_TYPE_NEWT_LABEL,
	                             "text", text,
	                             "style", NMT_NEWT_LABEL_PLAIN,
	                             NULL);
	metric_width = nmt_newt_text_width (text);
	nmt_newt_grid_add (NMT_NEWT_GRID (header), metric_label, 2, 0);

	priv->ip_entry_width = MAX (20, MAX (dest_prefix_width, next_hop_width));
	priv->metric_entry_width = MAX (7, metric_width);

	nmt_newt_widget_set_padding (dest_prefix_label,
	                           0, 0, priv->ip_entry_width - dest_prefix_width, 0);
	nmt_newt_widget_set_padding (next_hop_label,
	                           2, 0, priv->ip_entry_width - next_hop_width, 0);
	nmt_newt_widget_set_padding (metric_label,
	                           2, 0, priv->metric_entry_width - metric_width, 0);

	nmt_newt_grid_add (NMT_NEWT_GRID (table), header, 0, 0);

	empty = nmt_newt_label_new (_("No custom routes are defined."));
	priv->list = nmt_widget_list_new (create_route_entry, table, NULL, empty);
	g_signal_connect (priv->list, "add-clicked", G_CALLBACK (add_route), table);
	g_signal_connect (priv->list, "remove-clicked", G_CALLBACK (remove_route), table);
	nmt_newt_grid_add (NMT_NEWT_GRID (table), priv->list, 0, 1);
}

static void
nmt_route_table_finalize (GObject *object)
{
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (object);

	g_ptr_array_unref (priv->routes);

	G_OBJECT_CLASS (nmt_route_table_parent_class)->finalize (object);
}

static void
nmt_route_table_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (object);
	GPtrArray *array;
	int i;

	switch (prop_id) {
	case PROP_FAMILY:
		priv->family = g_value_get_int (value);
		break;
	case PROP_ROUTES:
		array = g_value_get_boxed (value);
		g_ptr_array_set_size (priv->routes, 0);
		for (i = 0; i < array->len; i++) {
			nm_ip_route_ref (array->pdata[i]);
			g_ptr_array_add (priv->routes, array->pdata[i]);
		}
		nmt_widget_list_set_length (NMT_WIDGET_LIST (priv->list), priv->routes->len);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_route_table_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
	NmtRouteTablePrivate *priv = NMT_ROUTE_TABLE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FAMILY:
		g_value_set_int (value, priv->family);
		break;
	case PROP_ROUTES:
		g_value_set_boxed (value, priv->routes);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_route_table_class_init (NmtRouteTableClass *table_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (table_class);

	g_type_class_add_private (table_class, sizeof (NmtRouteTablePrivate));

	/* virtual methods */
	object_class->set_property = nmt_route_table_set_property;
	object_class->get_property = nmt_route_table_get_property;
	object_class->finalize = nmt_route_table_finalize;

	/**
	 * NmtRouteTable:family:
	 *
	 * The network address family of the routes, eg %AF_INET
	 */
	g_object_class_install_property
		(object_class, PROP_FAMILY,
		 g_param_spec_int ("family", "", "",
		                   -1, G_MAXINT, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtRouteTable:routes:
	 *
	 * The array of routes, suitable for binding to #NMSettingIP4Config:routes
	 * or #NMSettingIP6Config:routes.
	 *
	 * Element-type: NMIPRoute
	 */
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 g_param_spec_boxed ("routes", "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
}
