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

#include <NetworkManager.h>

#include "nmt-page-main.h"
#include "nmt-device-entry.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"
#include "nmtui.h"

#include "nmt-page-bond.h"
#include "nmt-page-bridge.h"
#include "nmt-page-bridge-port.h"
#include "nmt-page-dsl.h"
#include "nmt-page-ethernet.h"
#include "nmt-page-infiniband.h"
#include "nmt-page-ip4.h"
#include "nmt-page-ip6.h"
#include "nmt-page-ppp.h"
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
	char **perms = g_value_get_boxed (source_value);

	g_value_set_boolean (target_value, g_strv_length (perms) == 0);
	return TRUE;
}

static gboolean
permissions_transform_from_allusers (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	gboolean allusers = g_value_get_boolean (source_value);
	char **perms = NULL;

	if (allusers) {
		perms = g_new (char *, 2);

		perms[0] = g_strdup_printf ("user:%s:", g_get_user_name ());
		perms[1] = NULL;
	}
	g_value_take_boxed (target_value, perms);
	return TRUE;
}

static NmtNewtWidget *
add_section_for_page (NmtEditorGrid *grid, NmtNewtWidget *widget)
{
	NmtEditorPage *page;
	NmtNewtWidget *section, *header, *toggle;

	g_return_val_if_fail (NMT_IS_EDITOR_PAGE (widget), NULL);
	g_return_val_if_fail (nmt_newt_widget_get_parent (widget) == NULL, NULL);

	page = NMT_EDITOR_PAGE (widget);

	section = nmt_newt_section_new (TRUE);

	toggle = nmt_newt_toggle_button_new (_("Hide"), _("Show"));

	header = nmt_editor_grid_new ();
	nmt_editor_grid_append (NMT_EDITOR_GRID (header),
	                      nmt_editor_page_get_title (page),
	                      nmt_editor_page_get_header_widget (page),
	                      toggle);
	nmt_editor_grid_set_row_flags (NMT_EDITOR_GRID (header),
	                             nmt_editor_page_get_header_widget (page),
	                             NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT |
	                             NMT_EDITOR_GRID_ROW_EXTRA_ALIGN_RIGHT);
	nmt_newt_section_set_header (NMT_NEWT_SECTION (section), header);

	nmt_newt_section_set_body (NMT_NEWT_SECTION (section), widget);

	g_object_bind_property (toggle, "active",
	                        section, "open",
	                        G_BINDING_SYNC_CREATE);

	if (nmt_editor_page_show_by_default (page) || !nmt_newt_widget_get_valid (section))
		nmt_newt_toggle_button_set_active (NMT_NEWT_TOGGLE_BUTTON (toggle), TRUE);

	nmt_editor_grid_append (grid, NULL, section, NULL);
	return section;
}

static void
nmt_page_main_constructed (GObject *object)
{
	NmtPageMain *page_main = NMT_PAGE_MAIN (object);
	NmtPageMainPrivate *priv = NMT_PAGE_MAIN_GET_PRIVATE (page_main);
	NmtEditorGrid *grid;
	NMConnection *conn;
	NMSettingConnection *s_con;
	NmtNewtWidget *widget, *section, *separator;
	const char *deventry_label;
	NmtDeviceEntry *deventry;
	GType hardware_type;
	const char *slave_type;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (page_main));
	s_con = nm_connection_get_setting_connection (conn);

	grid = NMT_EDITOR_GRID (page_main);

	widget = nmt_newt_entry_new (40, NMT_NEWT_ENTRY_NONEMPTY);
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_ID,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Profile name"), widget, NULL);

	if (priv->type_data->virtual)
		hardware_type = G_TYPE_NONE;
	else
		hardware_type = priv->type_data->device_type;

	/* For connections involving multiple network devices, clarify which one
	 * NMSettingConnection:interface-name refers to.
	 */
	if (nm_connection_is_type (conn, NM_SETTING_PPPOE_SETTING_NAME))
		deventry_label = _("Ethernet device");
	else
		deventry_label = _("Device");

	widget = nmt_device_entry_new (deventry_label, 40, hardware_type);
	nmt_editor_grid_append (grid, NULL, widget, NULL);
	deventry = NMT_DEVICE_ENTRY (widget);
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME,
	                        deventry, "interface-name",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	if (nm_connection_is_type (conn, NM_SETTING_BOND_SETTING_NAME))
		add_section_for_page (grid, nmt_page_bond_new (conn, deventry));
	else if (nm_connection_is_type (conn, NM_SETTING_BRIDGE_SETTING_NAME))
		add_section_for_page (grid, nmt_page_bridge_new (conn, deventry));
	else if (nm_connection_is_type (conn, NM_SETTING_INFINIBAND_SETTING_NAME))
		add_section_for_page (grid, nmt_page_infiniband_new (conn, deventry));
	else if (nm_connection_is_type (conn, NM_SETTING_PPPOE_SETTING_NAME)) {
		add_section_for_page (grid, nmt_page_dsl_new (conn));
		add_section_for_page (grid, nmt_page_ethernet_new (conn, deventry));
		add_section_for_page (grid, nmt_page_ppp_new (conn));
	} else if (nm_connection_is_type (conn, NM_SETTING_TEAM_SETTING_NAME))
		add_section_for_page (grid, nmt_page_team_new (conn, deventry));
	else if (nm_connection_is_type (conn, NM_SETTING_VLAN_SETTING_NAME))
		add_section_for_page (grid, nmt_page_vlan_new (conn, deventry));
	else if (nm_connection_is_type (conn, NM_SETTING_WIRED_SETTING_NAME))
		add_section_for_page (grid, nmt_page_ethernet_new (conn, deventry));
	else if (nm_connection_is_type (conn, NM_SETTING_WIRELESS_SETTING_NAME))
		add_section_for_page (grid, nmt_page_wifi_new (conn, deventry));

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	slave_type = nm_setting_connection_get_slave_type (s_con);
	if (slave_type) {
		if (!strcmp (slave_type, NM_SETTING_BRIDGE_SETTING_NAME))
			add_section_for_page (grid, nmt_page_bridge_port_new (conn));
		else if (!strcmp (slave_type, NM_SETTING_TEAM_SETTING_NAME))
			add_section_for_page (grid, nmt_page_team_port_new (conn));
	} else {
		section = add_section_for_page (grid, nmt_page_ip4_new (conn));

		/* Add a separator between ip4 and ip6 that's only visible if ip4 is open */
		separator = nmt_newt_separator_new ();
		g_object_bind_property (section, "open", separator, "visible", G_BINDING_SYNC_CREATE);
		nmt_editor_grid_append (grid, NULL, separator, NULL);

		add_section_for_page (grid, nmt_page_ip6_new (conn));

		nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);
	}

	widget = nmt_newt_checkbox_new (_("Automatically connect"));
	g_object_bind_property (s_con, NM_SETTING_CONNECTION_AUTOCONNECT,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Available to all users"));
	g_object_bind_property_full (s_con, NM_SETTING_CONNECTION_PERMISSIONS,
	                             widget, "active",
	                             G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                             permissions_transform_to_allusers,
	                             permissions_transform_from_allusers,
	                             NULL, NULL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

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
	g_object_class_install_property
		(object_class, PROP_TYPE_DATA,
		 g_param_spec_pointer ("type-data", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
}
