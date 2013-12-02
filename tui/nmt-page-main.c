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
 * SECTION:nmt-page-main
 * @short_description: The top-level #NmtEditorPage for a connection
 *
 * #NmtPageMain is the top-level #NmtEditorPage for a connection. It
 * handles #NMSettingConnection properties, and embeds the other pages
 * within itself.
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include <nm-device.h>
#include <nm-utils.h>

#include "nmt-page-main.h"
#include "nmt-device-entry.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"
#include "nmtui.h"

#include "nmt-page-bond.h"
#include "nmt-page-bridge.h"
#include "nmt-page-bridge-port.h"
#include "nmt-page-ethernet.h"
#include "nmt-page-infiniband.h"
#include "nmt-page-ip4.h"
#include "nmt-page-ip6.h"
#include "nmt-page-team.h"
#include "nmt-page-team-port.h"
#include "nmt-page-vlan.h"
#include "nmt-page-wifi.h"

G_DEFINE_TYPE (NmtPageMain, nmt_page_main, NMT_TYPE_EDITOR_PAGE)

#define NMT_PAGE_MAIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_MAIN, NmtPageMainPrivate))

typedef struct {
	NMEditorConnectionTypeData *type_data;
} NmtPageMainPrivate;

enum {
	PROP_0,

	PROP_TYPE_DATA,

	LAST_PROP
};

/**
 * nmt_page_main_new:
 * @conn: the #NMConnection to display
 * @type_data: @conn's #NMEditorConnectionTypeData
 *
 * Creates a new #NmtPageMain
 *
 * Returns: a new #NmtPageMain
 */
NmtNewtWidget *
nmt_page_main_new (NMConnection               *conn,
                   NMEditorConnectionTypeData *type_data)
{
	return g_object_new (NMT_TYPE_PAGE_MAIN,
	                     "connection", conn,
	                     "type-data", type_data,
	                     NULL);
}

static void
nmt_page_main_init (NmtPageMain *page)
{
}

static gboolean
permissions_transform_to_allusers (GBinding     *binding,
                                   const GValue *source_value,
                                   GValue       *target_value,
                                   gpointer      user_data)
{
	GSList *perms = g_value_get_boxed (source_value);

	g_value_set_boolean (target_value, perms == NULL);
	return TRUE;
}

static gboolean
permissions_transform_from_allusers (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	gboolean allusers = g_value_get_boolean (source_value);
	GSList *perms = NULL;

	if (allusers) {
		char *perm = g_strdup_printf ("user:%s:", g_get_user_name ());

		perms = g_slist_prepend (perms, perm);
	}
	g_value_take_boxed (target_value, perms);
	return TRUE;
}

static NmtNewtWidget *
build_section_for_page (NmtEditorPage *page,
                        gboolean       open)
{
	NmtNewtWidget *section, *header, *toggle;

	g_return_val_if_fail (nmt_newt_widget_get_parent (NMT_NEWT_WIDGET (page)) == NULL, NULL);

	section = nmt_newt_section_new ();

	toggle = nmt_newt_toggle_button_new (_("Hide"), _("Show"));

	header = nmt_page_grid_new ();
	nmt_page_grid_append (NMT_PAGE_GRID (header),
	                      nmt_editor_page_get_title (page),
	                      nmt_editor_page_get_header_widget (page),
	                      toggle);
	nmt_page_grid_set_row_flags (NMT_PAGE_GRID (header),
	                             nmt_editor_page_get_header_widget (page),
	                             NMT_PAGE_GRID_ROW_LABEL_ALIGN_LEFT |
	                             NMT_PAGE_GRID_ROW_EXTRA_ALIGN_RIGHT);
	nmt_newt_section_set_header (NMT_NEWT_SECTION (section), header);

	nmt_newt_section_set_body (NMT_NEWT_SECTION (section), NMT_NEWT_WIDGET (page));

	g_object_bind_property (toggle, "active",
	                        section, "open",
	                        G_BINDING_SYNC_CREATE);

	if (open || !nmt_newt_widget_get_valid (section))
		nmt_newt_toggle_button_set_active (NMT_NEWT_TOGGLE_BUTTON (toggle), TRUE);

	return section;
}

static void
nmt_page_main_constructed (GObject *object)
{
	NmtPageMain *page_main = NMT_PAGE_MAIN (object);
	NmtPageMainPrivate *priv = NMT_PAGE_MAIN_GET_PRIVATE (page_main);
	NmtPageGrid *grid;
	NMConnection *conn;
	NMSettingConnection *s_con;
	NmtNewtWidget *widget, *section, *page, *separator;
	NmtDeviceEntry *deventry;
	GType hardware_type;
	const char *slave_type;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (page_main));
	s_con = nm_connection_get_setting_connection (conn);

	grid = NMT_PAGE_GRID (page_main);

	widget = nmt_newt_entry_new (40, NMT_NEWT_ENTRY_NONEMPTY);
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_ID,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_page_grid_append (grid, _("Profile name"), widget, NULL);

	if (priv->type_data->virtual)
		hardware_type = G_TYPE_NONE;
	else
		hardware_type = priv->type_data->device_type;

	widget = nmt_device_entry_new (_("Device"), 40, hardware_type);
	nmt_page_grid_append (grid, NULL, widget, NULL);
	deventry = NMT_DEVICE_ENTRY (widget);
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME,
	                        deventry, "interface-name",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	nmt_page_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	if (nm_connection_is_type (conn, NM_SETTING_BOND_SETTING_NAME))
		page = nmt_page_bond_new (conn, deventry);
	else if (nm_connection_is_type (conn, NM_SETTING_BRIDGE_SETTING_NAME))
		page = nmt_page_bridge_new (conn, deventry);
	else if (nm_connection_is_type (conn, NM_SETTING_INFINIBAND_SETTING_NAME))
		page = nmt_page_infiniband_new (conn, deventry);
	else if (nm_connection_is_type (conn, NM_SETTING_TEAM_SETTING_NAME))
		page = nmt_page_team_new (conn, deventry);
	else if (nm_connection_is_type (conn, NM_SETTING_VLAN_SETTING_NAME))
		page = nmt_page_vlan_new (conn, deventry);
	else if (nm_connection_is_type (conn, NM_SETTING_WIRED_SETTING_NAME))
		page = nmt_page_ethernet_new (conn, deventry);
	else if (nm_connection_is_type (conn, NM_SETTING_WIRELESS_SETTING_NAME))
		page = nmt_page_wifi_new (conn, deventry);
	else
		page = NULL;

	if (page) {
		gboolean show_by_default = nmt_page_device_get_show_by_default (NMT_PAGE_DEVICE (page));

		section = build_section_for_page (NMT_EDITOR_PAGE (page), show_by_default);
		nmt_page_grid_append (grid, NULL, section, NULL);
	}

	nmt_page_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	slave_type = nm_setting_connection_get_slave_type (s_con);
	if (slave_type) {
		if (!strcmp (slave_type, NM_SETTING_BRIDGE_SETTING_NAME)) {
			page = nmt_page_bridge_port_new (conn);
			section = build_section_for_page (NMT_EDITOR_PAGE (page), TRUE);
			nmt_page_grid_append (grid, NULL, section, NULL);
		} else if (!strcmp (slave_type, NM_SETTING_TEAM_SETTING_NAME)) {
			page = nmt_page_team_port_new (conn);
			section = build_section_for_page (NMT_EDITOR_PAGE (page), TRUE);
			nmt_page_grid_append (grid, NULL, section, NULL);
		}
	} else {
		page = nmt_page_ip4_new (conn);
		section = build_section_for_page (NMT_EDITOR_PAGE (page),
		                                  nmt_page_ip4_is_non_empty (NMT_PAGE_IP4 (page)));
		nmt_page_grid_append (grid, NULL, section, NULL);

		/* Add a separator between ip4 and ip6 that's only visible if ip4 is open */
		separator = nmt_newt_separator_new ();
		g_object_bind_property (section, "open", separator, "visible", G_BINDING_SYNC_CREATE);
		nmt_page_grid_append (grid, NULL, separator, NULL);

		page = nmt_page_ip6_new (conn);
		section = build_section_for_page (NMT_EDITOR_PAGE (page),
		                                  nmt_page_ip6_is_non_empty (NMT_PAGE_IP6 (page)));
		nmt_page_grid_append (grid, NULL, section, NULL);
		nmt_page_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);
	}

	widget = nmt_newt_checkbox_new (_("Automatically connect"));
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_AUTOCONNECT,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_page_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Available to all users"));
	g_object_bind_property_full (s_con, NM_SETTING_CONNECTION_PERMISSIONS,
	                             widget, "active",
	                             G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                             permissions_transform_to_allusers,
	                             permissions_transform_from_allusers,
	                             NULL, NULL);
	nmt_page_grid_append (grid, NULL, widget, NULL);

	G_OBJECT_CLASS (nmt_page_main_parent_class)->constructed (object);
}

static void
nmt_page_main_set_property (GObject      *object,
                            guint         prop_id,
                            const GValue *value,
                            GParamSpec   *pspec)
{
	NmtPageMainPrivate *priv = NMT_PAGE_MAIN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_TYPE_DATA:
		priv->type_data = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_page_main_get_property (GObject    *object,
                            guint       prop_id,
                            GValue     *value,
                            GParamSpec *pspec)
{
	NmtPageMainPrivate *priv = NMT_PAGE_MAIN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_TYPE_DATA:
		g_value_set_pointer (value, priv->type_data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_page_main_class_init (NmtPageMainClass *main_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (main_class);

	g_type_class_add_private (main_class, sizeof (NmtPageMainPrivate));

	object_class->constructed = nmt_page_main_constructed;
	object_class->set_property = nmt_page_main_set_property;
	object_class->get_property = nmt_page_main_get_property;

	/**
	 * NmtPageMain:type-data:
	 *
	 * The page's connection's #NMEditorConnectionTypeData
	 */
	g_object_class_install_property (object_class, PROP_TYPE_DATA,
	                                 g_param_spec_pointer ("type-data", "", "",
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_CONSTRUCT_ONLY |
	                                                       G_PARAM_STATIC_STRINGS));
}
