// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-ip4
 * @short_description: The editor page for IP4 configuration
 */

#include "nm-default.h"

#include <stdlib.h>

#include "nmt-page-ip4.h"
#include "nmt-ip-entry.h"
#include "nmt-address-list.h"
#include "nmt-route-editor.h"

#include "nm-editor-bindings.h"

G_DEFINE_TYPE (NmtPageIP4, nmt_page_ip4, NMT_TYPE_EDITOR_PAGE)

static NmtNewtPopupEntry ip4methods[] = {
	{ N_("Disabled"), NM_SETTING_IP4_CONFIG_METHOD_DISABLED },
	{ N_("Automatic"), NM_SETTING_IP4_CONFIG_METHOD_AUTO },
	{ N_("Link-Local"), NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL },
	{ N_("Manual"), NM_SETTING_IP4_CONFIG_METHOD_MANUAL },
	{ N_("Shared"), NM_SETTING_IP4_CONFIG_METHOD_SHARED },
	{ NULL, NULL }
};

NmtEditorPage *
nmt_page_ip4_new (NMConnection *conn)
{
	return g_object_new (NMT_TYPE_PAGE_IP4,
	                     "connection", conn,
	                     NULL);
}

static void
nmt_page_ip4_init (NmtPageIP4 *ip4)
{
}

static void
edit_routes (NmtNewtButton *button,
             gpointer       user_data)
{
	NMSetting *s_ip4 = user_data;
	NmtNewtForm *form;

	form = nmt_route_editor_new (s_ip4);
	nmt_newt_form_run_sync (form);
	g_object_unref (form);
}

static gboolean
ip4_routes_transform_to_description (GBinding     *binding,
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
nmt_page_ip4_constructed (GObject *object)
{
	NmtPageIP4 *ip4 = NMT_PAGE_IP4 (object);
	gboolean show_by_default;
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingIPConfig *s_ip4;
	NmtNewtWidget *widget, *button;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (ip4));
	s_ip4 = nm_connection_get_setting_ip4_config (conn);
	if (!s_ip4) {
		s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
		g_object_set (G_OBJECT (s_ip4),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NULL);
		nm_connection_add_setting (conn, (NMSetting *) s_ip4);
	}

	widget = nmt_newt_popup_new (ip4methods);
	g_object_bind_property (s_ip4, NM_SETTING_IP_CONFIG_METHOD,
	                        widget, "active-id",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	if (!g_strcmp0 (nm_setting_ip_config_get_method (s_ip4), NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
		show_by_default = TRUE;
	else if (nm_setting_ip_config_get_num_addresses (s_ip4))
		show_by_default = TRUE;
	else
		show_by_default = FALSE;

	section = nmt_editor_section_new (_("IPv4 CONFIGURATION"), widget, show_by_default);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_address_list_new (NMT_ADDRESS_LIST_IP4_WITH_PREFIX);
	nm_editor_bind_ip_addresses_with_prefix_to_strv (AF_INET,
	                                                 s_ip4, NM_SETTING_IP_CONFIG_ADDRESSES,
	                                                 widget, "strings",
	                                                 G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Addresses"), widget, NULL);

	widget = nmt_ip_entry_new (25, AF_INET, FALSE, TRUE);
	nm_editor_bind_ip_gateway_to_string (AF_INET,
	                                     s_ip4,
	                                     widget, "text", "sensitive",
	                                     G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Gateway"), widget, NULL);

	widget = nmt_address_list_new (NMT_ADDRESS_LIST_IP4);
	nm_editor_bind_ip_addresses_to_strv (AF_INET,
	                                     s_ip4, NM_SETTING_IP_CONFIG_DNS,
	                                     widget, "strings",
	                                     G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("DNS servers"), widget, NULL);

	widget = nmt_address_list_new (NMT_ADDRESS_LIST_HOSTNAME);
	g_object_bind_property (s_ip4, NM_SETTING_IP_CONFIG_DNS_SEARCH,
	                        widget, "strings",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Search domains"), widget, NULL);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = g_object_new (NMT_TYPE_NEWT_LABEL,
	                       "text", "",
	                       "style", NMT_NEWT_LABEL_PLAIN,
	                       NULL);
	g_object_bind_property_full (s_ip4, NM_SETTING_IP_CONFIG_ROUTES,
	                             widget, "text",
	                             G_BINDING_SYNC_CREATE,
	                             ip4_routes_transform_to_description,
	                             NULL, NULL, NULL);
	button = nmt_newt_button_new (_("Edit..."));
	g_signal_connect (button, "clicked", G_CALLBACK (edit_routes), s_ip4);
	nmt_editor_grid_append (grid, _("Routing"), widget, button);

	widget = nmt_newt_checkbox_new (_("Never use this network for default route"));
	g_object_bind_property (s_ip4, NM_SETTING_IP_CONFIG_NEVER_DEFAULT,
	                        widget, "active",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Ignore automatically obtained routes"));
	g_object_bind_property (s_ip4, NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES,
	                        widget, "active",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Ignore automatically obtained DNS parameters"));
	g_object_bind_property (s_ip4, NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS,
	                        widget, "active",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = nmt_newt_checkbox_new (_("Require IPv4 addressing for this connection"));
	g_object_bind_property (s_ip4, NM_SETTING_IP_CONFIG_MAY_FAIL,
	                        widget, "active",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (ip4), section);

	G_OBJECT_CLASS (nmt_page_ip4_parent_class)->constructed (object);
}

static void
nmt_page_ip4_class_init (NmtPageIP4Class *ip4_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ip4_class);

	object_class->constructed = nmt_page_ip4_constructed;
}
