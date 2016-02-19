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
 * SECTION:nmt-route-entry
 * @short_description: A set of widgets describing a single route.
 *
 * #NmtRouteEntry provides a set of three entry widgets, for entering
 * a network/prefix, a next hop, and a metric.
 *
 * This is used as a building block by #NmtRouteTable.
 */

#include "nm-default.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "NetworkManager.h"

#include "nmt-route-entry.h"
#include "nmt-ip-entry.h"

#include "nm-editor-bindings.h"

G_DEFINE_TYPE (NmtRouteEntry, nmt_route_entry, NMT_TYPE_NEWT_GRID)

#define NMT_ROUTE_ENTRY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_ROUTE_ENTRY, NmtRouteEntryPrivate))

typedef struct {
	NmtNewtWidget *dest, *next_hop, *metric;

	int family;
	int ip_entry_width, metric_entry_width;
	NMIPRoute *route;
} NmtRouteEntryPrivate;

enum {
	PROP_0,
	PROP_FAMILY,
	PROP_IP_ENTRY_WIDTH,
	PROP_METRIC_ENTRY_WIDTH,
	PROP_ROUTE,

	LAST_PROP
};

/**
 * nmt_route_entry_new:
 * @family: the address family, eg %AF_INET
 * @ip_entry_width: the width in characters for the IP address entries
 * @metric_entry_width: the width in characters for the metric entry
 *
 * Creates a new #NmtRouteEntry
 *
 * Returns: a new #NmtRouteEntry
 */
NmtNewtWidget *
nmt_route_entry_new (int family,
                     int ip_entry_width,
                     int metric_entry_width)
{
	return g_object_new (NMT_TYPE_ROUTE_ENTRY,
	                     "family", family,
	                     "ip-entry-width", ip_entry_width,
	                     "metric-entry-width", metric_entry_width,
	                     NULL);
}

static void
nmt_route_entry_init (NmtRouteEntry *entry)
{
}

static gboolean
entry_validity_transform_to_warning_label (GBinding     *binding,
                                           const GValue *source_value,
                                           GValue       *target_value,
                                           gpointer      user_data)
{
	if (g_value_get_boolean (source_value))
		g_value_set_string (target_value, " ");
	else
		g_value_set_string (target_value, "!");
	return TRUE;
}

static NmtNewtWidget *
create_warning_label (NmtNewtWidget *entry)
{
	NmtNewtWidget *label;

	label = g_object_new (NMT_TYPE_NEWT_LABEL,
	                      "highlight", TRUE,
	                      NULL);
	g_object_bind_property_full (entry, "valid",
	                             label, "text",
	                             G_BINDING_SYNC_CREATE,
	                             entry_validity_transform_to_warning_label,
	                             NULL, NULL, NULL);
	return label;
}

static void
nmt_route_entry_constructed (GObject *object)
{
	NmtRouteEntryPrivate *priv = NMT_ROUTE_ENTRY_GET_PRIVATE (object);
	NmtNewtGrid *grid = NMT_NEWT_GRID (object);
	NmtNewtWidget *warning_label;

	priv->dest = nmt_ip_entry_new (priv->ip_entry_width, priv->family, TRUE, FALSE);
	priv->next_hop = nmt_ip_entry_new (priv->ip_entry_width, priv->family, FALSE, TRUE);
	priv->metric = nmt_newt_entry_numeric_new (priv->metric_entry_width, 0, 65535);

	nmt_newt_grid_add (grid, priv->dest, 0, 0);
	warning_label = create_warning_label (priv->dest);
	nmt_newt_grid_add (grid, warning_label, 1, 0);

	nmt_newt_grid_add (grid, priv->next_hop, 2, 0);
	nmt_newt_widget_set_padding (priv->next_hop, 1, 0, 0, 0);
	warning_label = create_warning_label (priv->next_hop);
	nmt_newt_grid_add (grid, warning_label, 3, 0);

	nmt_newt_grid_add (grid, priv->metric, 4, 0);
	nmt_newt_widget_set_padding (priv->metric, 1, 0, 0, 0);

	nm_editor_bind_ip_route_to_strings (priv->family,
	                                    object, "route",
	                                    priv->dest, "text",
	                                    priv->next_hop, "text",
	                                    priv->metric, "text",
	                                    G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	G_OBJECT_CLASS (nmt_route_entry_parent_class)->constructed (object);
}

static newtComponent
nmt_route_entry_get_focus_component (NmtNewtWidget *widget)
{
	NmtRouteEntryPrivate *priv = NMT_ROUTE_ENTRY_GET_PRIVATE (widget);
	
	return nmt_newt_widget_get_focus_component (priv->dest);
}

static void
nmt_route_entry_finalize (GObject *object)
{
	NmtRouteEntryPrivate *priv = NMT_ROUTE_ENTRY_GET_PRIVATE (object);

	g_clear_pointer (&priv->route, nm_ip_route_unref);

	G_OBJECT_CLASS (nmt_route_entry_parent_class)->finalize (object);
}

static void
nmt_route_entry_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	NmtRouteEntryPrivate *priv = NMT_ROUTE_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FAMILY:
		priv->family = g_value_get_int (value);
		break;
	case PROP_IP_ENTRY_WIDTH:
		priv->ip_entry_width = g_value_get_int (value);
		break;
	case PROP_METRIC_ENTRY_WIDTH:
		priv->metric_entry_width = g_value_get_int (value);
		break;
	case PROP_ROUTE:
		if (priv->route)
			nm_ip_route_unref (priv->route);
		priv->route = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_route_entry_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
	NmtRouteEntryPrivate *priv = NMT_ROUTE_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FAMILY:
		g_value_set_int (value, priv->family);
		break;
	case PROP_IP_ENTRY_WIDTH:
		g_value_set_int (value, priv->ip_entry_width);
		break;
	case PROP_METRIC_ENTRY_WIDTH:
		g_value_set_int (value, priv->metric_entry_width);
		break;
	case PROP_ROUTE:
		g_value_set_boxed (value, priv->route);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_route_entry_class_init (NmtRouteEntryClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtRouteEntryPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_route_entry_constructed;
	object_class->set_property = nmt_route_entry_set_property;
	object_class->get_property = nmt_route_entry_get_property;
	object_class->finalize     = nmt_route_entry_finalize;

	widget_class->get_focus_component = nmt_route_entry_get_focus_component;

	/**
	 * NmtRouteEntry:family:
	 *
	 * The address family of the route, eg, %AF_INET
	 */
	g_object_class_install_property
		(object_class, PROP_FAMILY,
		 g_param_spec_int ("family", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtRouteEntry:ip-entry-width:
	 *
	 * The width in characters of the IP address entries
	 */
	g_object_class_install_property
		(object_class, PROP_IP_ENTRY_WIDTH,
		 g_param_spec_int ("ip-entry-width", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtRouteEntry:metric-entry-width:
	 *
	 * The width in characters of the metric entry
	 */
	g_object_class_install_property
		(object_class, PROP_METRIC_ENTRY_WIDTH,
		 g_param_spec_int ("metric-entry-width", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtRouteEntry:route:
	 *
	 * The contents of the entries, as an #NMIPRoute.
	 */
	g_object_class_install_property
		(object_class, PROP_ROUTE,
		 g_param_spec_boxed ("route", "", "",
		                     nm_ip_route_get_type (),
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
}
