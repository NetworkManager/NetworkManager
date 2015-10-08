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
 * SECTION:nmt-page-ip6
 * @short_description: The editor page for IP6 configuration
 */

#include "config.h"

#include <stdlib.h>

#include "nm-default.h"
#include "nmt-page-ip6.h"
#include "nmt-ip-entry.h"
#include "nmt-address-list.h"
#include "nmt-route-editor.h"

#include "nm-editor-bindings.h"

G_DEFINE_TYPE (NmtPageIP6, nmt_page_ip6, NMT_TYPE_EDITOR_PAGE)

static NmtNewtPopupEntry ip6methods[] = {
	{ N_("Ignore"), NM_SETTING_IP6_CONFIG_METHOD_IGNORE },
	{ N_("Automatic"), NM_SETTING_IP6_CONFIG_METHOD_AUTO },
	{ N_("Automatic (DHCP-only)"), NM_SETTING_IP6_CONFIG_METHOD_DHCP },
	{ N_("Link-Local"), NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL },
	{ N_("Manual"), NM_SETTING_IP6_CONFIG_METHOD_MANUAL },
	{ NULL, NULL }
};

NmtEditorPage *
nmt_page_ip6_new (NMConnection *conn)
{
	return g_object_new (NMT_TYPE_PAGE_IP6,
	                     "connection", conn,
	                     NULL);
}

static void
nmt_page_ip6_init (NmtPageIP6 *ip6)
{
}

static void
edit_routes (NmtNewtButton *button,
             gpointer       user_data)
{
	NMSetting *s_ip6 = user_data;
	NmtNewtForm *form;

	form = nmt_route_editor_new (s_ip6);
	nmt_newt_form_run_sync (form);
	g_object_unref (form);
}

static gboolean
ip6_routes_transform_to_description (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	GPtrArray *routes;
	char *text;

	routes = g_value_get_boxed (source_value);
	if (!routes || !routes->len)
		text = g_strdup (_("(No custom routes)"));
	else {
		text = g_strdup_printf (g_dngettext (GETTEXT_PACKAGE,
		                                     "One custom route",
		                                     "%d custom routes",
		                                     routes->len),
		                        routes->len);
	}

	g_value_take_string (target_value, text);
	return TRUE;
}

static void
nmt_page_ip6_constructed (GObject *object)
{
	NmtPageIP6 *ip6 = NMT_PAGE_IP6 (object);
	gboolean show_by_default;
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingIPConfig *s_ip6;
	NmtNewtWidget *widget, *button;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (ip6));
	s_ip6 = nm_connection_get_setting_ip6_config (conn);
	if (!s_ip6) {
		s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
		g_object_set (G_OBJECT (s_ip6),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		              NULL);
		nm_connection_add_setting (conn, (NMSetting *) s_ip6);
	}

	widget = nmt_newt_popup_new (ip6methods);
	g_object_bind_property (s_ip6, NM_SETTING_IP_CONFIG_METHOD,
	                        widget, "active-id",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	if (!g_strcmp0 (nm_setting_ip_config_get_method (s_ip6), NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
		show_by_default = TRUE;
	else if (nm_setting_ip_config_get_num_addresses (s_ip6))
		show_by_default = TRUE;
	else
		show_by_default = FALSE;

	section = nmt_editor_section_new (_("IPv6 CONFIGURATION"), widget, show_by_default);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_address_list_new (NMT_ADDRESS_LIST_IP6_WITH_PREFIX);
	nm_editor_bind_ip_addresses_with_prefix_to_strv (AF_INET6,
	                                                 s_ip6, NM_SETTING_IP_CONFIG_ADDRESSES,
	                                                 widget, "strings",
	                                                 G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Addresses"), widget, NULL);

	widget = nmt_ip_entry_new (25, AF_INET6, FALSE, TRUE);
	nm_editor_bind_ip_gateway_to_string (AF_INET6,
	                                     s_ip6,
	                                     widget, "text", "sensitive",
	                                     G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Gateway"), widget, NULL);

	widget = nmt_address_list_new (NMT_ADDRESS_LIST_IP6);
	nm_editor_bind_ip_addresses_to_strv (AF_INET6,
	                                     s_ip6, NM_SETTING_IP_CONFIG_DNS,
	                                     widget, "strings",
	                                     G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("DNS servers"), widget, NULL);

	widget = nmt_address_list_new (NMT_ADDRESS_LIST_HOSTNAME);
	g_object_bind_property (s_ip6, NM_SETTING_IP_CONFIG_DNS_SEARCH,
	                        widget, "strings",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Search domains"), widget, NULL);

	widget = g_object_new (NMT_TYPE_NEWT_LABEL,
	                       "text", "",
	                       "style", NMT_NEWT_LABEL_PLAIN,
	                       NULL);
	g_object_bind_property_full (s_ip6, NM_SETTING_IP_CONFIG_ROUTES,
	                             widget, "text",
	                             G_BINDING_SYNC_CREATE,
	                             ip6_routes_transform_to_description,
	                             NULL, NULL, NULL);
	button = nmt_newt_button_new (_("Edit..."));
	g_signal_connect (button, "clicked", G_CALLBACK (edit_routes), s_ip6);
	nmt_editor_grid_append (grid, _("Routing"), widget, button);

	widget = nmt_newt_checkbox_new (_("Never use this network for default route"));
	g_object_bind_property (s_ip6, NM_SETTING_IP_CONFIG_NEVER_DEFAULT,
	                        widget, "active",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Ignore automatically obtained routes"));
	g_object_bind_property (s_ip6, NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES,
	                        widget, "active",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = nmt_newt_checkbox_new (_("Require IPv6 addressing for this connection"));
	g_object_bind_property (s_ip6, NM_SETTING_IP_CONFIG_MAY_FAIL,
	                        widget, "active",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (ip6), section);

	G_OBJECT_CLASS (nmt_page_ip6_parent_class)->constructed (object);
}

static void
nmt_page_ip6_class_init (NmtPageIP6Class *ip6_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ip6_class);

	object_class->constructed = nmt_page_ip6_constructed;
}
