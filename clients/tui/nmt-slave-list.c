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
 * SECTION:nmt-slave-list:
 * @short_description: An editable list of a connection's slaves
 *
 * #NmtSlaveList implements an #NmtEditConnectionList for the
 * slaves of a connection.
 */

#include "nm-default.h"

#include "nmt-slave-list.h"

G_DEFINE_TYPE (NmtSlaveList, nmt_slave_list, NMT_TYPE_EDIT_CONNECTION_LIST)

#define NMT_SLAVE_LIST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_SLAVE_LIST, NmtSlaveListPrivate))

typedef struct {
	NMConnection *master;
	const char *master_type, *master_uuid;

	NmtAddConnectionTypeFilter type_filter;
	gpointer type_filter_data;
} NmtSlaveListPrivate;

enum {
	PROP_0,
	PROP_MASTER,
	PROP_TYPE_FILTER,
	PROP_TYPE_FILTER_DATA,

	LAST_PROP
};

static gboolean nmt_slave_list_connection_filter (NmtEditConnectionList *list,
                                                  NMConnection          *connection,
                                                  gpointer               user_data);

/**
 * nmt_slave_list_new:
 * @master: the master #NMConnection whose slaves are being listed
 * @type_filter: (allow-none): a function to limit the availble slave types
 * @type_filter_data: (allow-none): data for @type_filter.
 *
 * Creates a new #NmtSlaveList.
 *
 * If @type_filter is non-%NULL, it will be used to limit the connection
 * types that are available when the user clicks on the "Add" button to add
 * a new slave. If the @type_filter filters the list down to only a single
 * connection type, then the user will not be presented with a connection-type
 * dialog, and will instead be immediately taken to an editor window for the
 * new slave after clicking "Add".
 *
 * Returns: a new #NmtSlaveList.
 */
NmtNewtWidget *
nmt_slave_list_new (NMConnection               *master,
                    NmtAddConnectionTypeFilter  type_filter,
                    gpointer                    type_filter_data)
{
	return g_object_new (NMT_TYPE_SLAVE_LIST,
	                     "master", master,
	                     "type-filter", type_filter,
	                     "type-filter-data", type_filter_data,
	                     "grouped", FALSE,
	                     "connection-filter", nmt_slave_list_connection_filter,
	                     NULL);
}

static void
nmt_slave_list_init (NmtSlaveList *list)
{
}

static void
nmt_slave_list_finalize (GObject *object)
{
	NmtSlaveListPrivate *priv = NMT_SLAVE_LIST_GET_PRIVATE (object);

	g_object_unref (priv->master);

	G_OBJECT_CLASS (nmt_slave_list_parent_class)->finalize (object);
}

static gboolean
nmt_slave_list_connection_filter (NmtEditConnectionList *list,
                                  NMConnection          *connection,
                                  gpointer               user_data)
{
	NmtSlaveListPrivate *priv = NMT_SLAVE_LIST_GET_PRIVATE (list);
	NMSettingConnection *s_con;
	const char *master, *master_ifname, *slave_type;

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, FALSE);

	slave_type = nm_setting_connection_get_slave_type (s_con);
	if (g_strcmp0 (slave_type, priv->master_type) != 0)
		return FALSE;

	master = nm_setting_connection_get_master (s_con);
	if (!master)
		return FALSE;

	master_ifname = nm_connection_get_interface_name (priv->master);
	if (g_strcmp0 (master, master_ifname) != 0 && g_strcmp0 (master, priv->master_uuid) != 0)
		return FALSE;

	return TRUE;
}

static void
nmt_slave_list_add_connection (NmtEditConnectionList *list)
{
	NmtSlaveListPrivate *priv = NMT_SLAVE_LIST_GET_PRIVATE (list);

	nmt_add_connection_full (_("Select the type of slave connection you wish to add."), NULL,
	                         priv->master, priv->type_filter, priv->type_filter_data);
}

static void
nmt_slave_list_edit_connection (NmtEditConnectionList *list,
                                NMConnection          *connection)
{
	nmt_edit_connection (connection);
}

static void
nmt_slave_list_remove_connection (NmtEditConnectionList  *list,
                                  NMRemoteConnection     *connection)
{
	nmt_remove_connection (connection);
}

static void
nmt_slave_list_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
	NmtSlaveListPrivate *priv = NMT_SLAVE_LIST_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MASTER:
		priv->master = g_value_dup_object (value);
		if (priv->master) {
			NMSettingConnection *s_con = nm_connection_get_setting_connection (priv->master);

			priv->master_type = nm_setting_connection_get_connection_type (s_con);
			priv->master_uuid = nm_setting_connection_get_uuid (s_con);
		}
		break;
	case PROP_TYPE_FILTER:
		priv->type_filter = g_value_get_pointer (value);
		break;
	case PROP_TYPE_FILTER_DATA:
		priv->type_filter_data = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_slave_list_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
	NmtSlaveListPrivate *priv = NMT_SLAVE_LIST_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MASTER:
		g_value_set_object (value, priv->master);
		break;
	case PROP_TYPE_FILTER:
		g_value_set_pointer (value, priv->type_filter);
		break;
	case PROP_TYPE_FILTER_DATA:
		g_value_set_pointer (value, priv->type_filter_data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_slave_list_class_init (NmtSlaveListClass *list_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (list_class);
	NmtEditConnectionListClass *connection_list_class = NMT_EDIT_CONNECTION_LIST_CLASS (list_class);

	g_type_class_add_private (list_class, sizeof (NmtSlaveListPrivate));

	/* virtual methods */
	object_class->set_property = nmt_slave_list_set_property;
	object_class->get_property = nmt_slave_list_get_property;
	object_class->finalize     = nmt_slave_list_finalize;

	connection_list_class->add_connection    = nmt_slave_list_add_connection;
	connection_list_class->edit_connection   = nmt_slave_list_edit_connection;
	connection_list_class->remove_connection = nmt_slave_list_remove_connection;

	/**
	 * NmtSlaveList:master:
	 *
	 * The master #NMConnection whose slaves are being displayed.
	 */
	g_object_class_install_property
		(object_class, PROP_MASTER,
		 g_param_spec_object ("master", "", "",
		                      NM_TYPE_CONNECTION,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtSlaveList:type-filter:
	 *
	 * If non-%NULL, this will be used to limit the connection types
	 * that are available when the user clicks on the "Add" button to
	 * add a new slave. If the filter filters the list down to only a
	 * single connection type, then the user will not be presented
	 * with a connection-type dialog, and will instead be immediately
	 * taken to an editor window for the new slave after clicking
	 * "Add".
	 */
	g_object_class_install_property
		(object_class, PROP_TYPE_FILTER,
		 g_param_spec_pointer ("type-filter", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtSlaveList:type-filter-data:
	 *
	 * User data passed to #NmtSlaveList:type-filter
	 */
	g_object_class_install_property
		(object_class, PROP_TYPE_FILTER_DATA,
		 g_param_spec_pointer ("type-filter-data", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
}
