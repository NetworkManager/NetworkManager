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
 * Copyright 2014 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-ppp
 * @short_description: The editor page for PPP configuration
 */

#include "nm-default.h"

#include <stdlib.h>

#include "nmt-page-ppp.h"
#include "nmt-newt-section.h"
#include "nmt-newt-separator.h"

G_DEFINE_TYPE (NmtPagePpp, nmt_page_ppp, NMT_TYPE_EDITOR_PAGE)

typedef struct {
	guint32 lcp_echo_failure;
	guint32 lcp_echo_interval;
} NmtPagePppPrivate;

#define NMT_PAGE_PPP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_PPP, NmtPagePppPrivate))

NmtEditorPage *
nmt_page_ppp_new (NMConnection *conn)
{
	return g_object_new (NMT_TYPE_PAGE_PPP,
	                     "connection", conn,
	                     NULL);
}

static void
nmt_page_ppp_init (NmtPagePpp *ppp)
{
}

static gboolean
transform_lcp_echo_properties_to_checkbox (GBinding     *binding,
                                           const GValue *from_value,
                                           GValue       *to_value,
                                           gpointer      user_data)
{
	NMSettingPpp *s_ppp = NM_SETTING_PPP (g_binding_get_source (binding));

	if (   nm_setting_ppp_get_lcp_echo_interval (s_ppp) != 0
	    && nm_setting_ppp_get_lcp_echo_failure (s_ppp) != 0)
		g_value_set_boolean (to_value, TRUE);
	else
		g_value_set_boolean (to_value, FALSE);

	return TRUE;
}

static gboolean
transform_checkbox_to_lcp_echo_interval (GBinding     *binding,
                                         const GValue *from_value,
                                         GValue       *to_value,
                                         gpointer      user_data)
{
	NmtPagePpp *ppp = user_data;
	NmtPagePppPrivate *priv = NMT_PAGE_PPP_GET_PRIVATE (ppp);

	if (g_value_get_boolean (from_value))
		g_value_set_uint (to_value, priv->lcp_echo_interval);
	else
		g_value_set_uint (to_value, 0);

	return TRUE;
}

static gboolean
transform_checkbox_to_lcp_echo_failure (GBinding     *binding,
                                        const GValue *from_value,
                                        GValue       *to_value,
                                        gpointer      user_data)
{
	NmtPagePpp *ppp = user_data;
	NmtPagePppPrivate *priv = NMT_PAGE_PPP_GET_PRIVATE (ppp);

	if (g_value_get_boolean (from_value))
		g_value_set_uint (to_value, priv->lcp_echo_failure);
	else
		g_value_set_uint (to_value, 0);

	return TRUE;
}

static void
nmt_page_ppp_constructed (GObject *object)
{
	NmtPagePpp *ppp = NMT_PAGE_PPP (object);
	NmtPagePppPrivate *priv = NMT_PAGE_PPP_GET_PRIVATE (ppp);
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingPpp *s_ppp;
	NmtNewtWidget *widget, *use_mppe;
	NmtNewtGrid *auth_grid, *mppe_grid;
	NmtNewtSection *auth_section, *mppe_section;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (ppp));
	s_ppp = nm_connection_get_setting_ppp (conn);
	if (s_ppp) {
		priv->lcp_echo_interval = nm_setting_ppp_get_lcp_echo_interval (s_ppp);
		priv->lcp_echo_failure = nm_setting_ppp_get_lcp_echo_failure (s_ppp);
	} else {
		s_ppp = (NMSettingPpp *) nm_setting_ppp_new ();
		nm_connection_add_setting (conn, (NMSetting *) s_ppp);

		priv->lcp_echo_interval = 30;
		priv->lcp_echo_failure = 5;
	}

	section = nmt_editor_section_new (_("PPP CONFIGURATION"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	/* Auth methods */
	widget = nmt_newt_section_new (FALSE);
	auth_section = NMT_NEWT_SECTION (widget);
	g_object_set (auth_section, "open", TRUE, NULL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_label_new (_("Allowed authentication methods:"));
	nmt_newt_section_set_header (auth_section, widget);

	widget = nmt_newt_grid_new ();
	auth_grid = NMT_NEWT_GRID (widget);
	nmt_newt_section_set_body (auth_section, widget);

	widget = nmt_newt_checkbox_new (_("EAP"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_REFUSE_EAP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (auth_grid, widget, 0, 0);

	widget = nmt_newt_checkbox_new (_("PAP"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_REFUSE_PAP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (auth_grid, widget, 0, 1);

	widget = nmt_newt_checkbox_new (_("CHAP"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_REFUSE_CHAP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (auth_grid, widget, 0, 2);

	widget = nmt_newt_checkbox_new (_("MSCHAPv2"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_REFUSE_MSCHAPV2,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (auth_grid, widget, 0, 3);

	widget = nmt_newt_checkbox_new (_("MSCHAP"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_REFUSE_MSCHAP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (auth_grid, widget, 0, 4);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	/* MPPE */
	widget = nmt_newt_section_new (FALSE);
	mppe_section = NMT_NEWT_SECTION (widget);
	g_object_set (mppe_section, "open", TRUE, NULL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Use point-to-point encryption (MPPE)"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_REQUIRE_MPPE,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_SYNC_CREATE);
	use_mppe = widget;
	nmt_newt_section_set_header (mppe_section, widget);

	widget = nmt_newt_grid_new ();
	mppe_grid = NMT_NEWT_GRID (widget);
	nmt_newt_section_set_body (mppe_section, widget);

	widget = nmt_newt_checkbox_new (_("Require 128-bit encryption"));
	g_object_bind_property (use_mppe, "active",
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_ppp, NM_SETTING_PPP_REQUIRE_MPPE_128,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (mppe_grid, widget, 0, 0);

	widget = nmt_newt_checkbox_new (_("Use stateful MPPE"));
	g_object_bind_property (use_mppe, "active",
	                        widget, "sensitive",
	                        G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_ppp, NM_SETTING_PPP_MPPE_STATEFUL,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_SYNC_CREATE);
	nmt_newt_grid_add (mppe_grid, widget, 0, 1);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = nmt_newt_checkbox_new (_("Allow BSD data compression"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_NOBSDCOMP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Allow Deflate data compression"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_NODEFLATE,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_checkbox_new (_("Use TCP header compression"));
	g_object_bind_property (s_ppp, NM_SETTING_PPP_NO_VJ_COMP,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL |
	                        G_BINDING_INVERT_BOOLEAN |
	                        G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = nmt_newt_checkbox_new (_("Send PPP echo packets"));
	g_object_bind_property_full (s_ppp, NM_SETTING_PPP_LCP_ECHO_INTERVAL,
	                             widget, "active",
	                             G_BINDING_BIDIRECTIONAL |
	                             G_BINDING_SYNC_CREATE,
	                             transform_lcp_echo_properties_to_checkbox,
	                             transform_checkbox_to_lcp_echo_interval,
	                             ppp, NULL);
	g_object_bind_property_full (s_ppp, NM_SETTING_PPP_LCP_ECHO_FAILURE,
	                             widget, "active",
	                             G_BINDING_BIDIRECTIONAL |
	                             G_BINDING_SYNC_CREATE,
	                             transform_lcp_echo_properties_to_checkbox,
	                             transform_checkbox_to_lcp_echo_failure,
	                             ppp, NULL);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (ppp), section);

	G_OBJECT_CLASS (nmt_page_ppp_parent_class)->constructed (object);
}

static void
nmt_page_ppp_class_init (NmtPagePppClass *ppp_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ppp_class);

	g_type_class_add_private (object_class, sizeof (NmtPagePppPrivate));

	object_class->constructed = nmt_page_ppp_constructed;
}
