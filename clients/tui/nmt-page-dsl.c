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
 * SECTION:nmt-page-dsl
 * @short_description: The editor page for DSL connections
 */

#include "nm-default.h"

#include "nmt-page-dsl.h"
#include "nmt-page-ethernet.h"
#include "nmt-page-ppp.h"
#include "nmt-password-fields.h"

G_DEFINE_TYPE (NmtPageDsl, nmt_page_dsl, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_DSL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_DSL, NmtPageDslPrivate))

typedef struct {
	NmtEditorPage *ethernet_page, *ppp_page;

} NmtPageDslPrivate;

NmtEditorPage *
nmt_page_dsl_new (NMConnection *conn,
                  NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_DSL,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_dsl_init (NmtPageDsl *dsl)
{
}

static NmtEditorSection *
build_dsl_section (NmtPageDsl *dsl, NMSettingPppoe *s_pppoe)
{
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NmtNewtWidget *widget;

	section = nmt_editor_section_new (_("DSL"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Username"), widget, NULL);
	g_object_bind_property (s_pppoe, NM_SETTING_PPPOE_USERNAME,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	widget = nmt_password_fields_new (40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
	g_object_bind_property (s_pppoe, NM_SETTING_PPPOE_PASSWORD,
	                        widget, "password",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (grid, _("Password"), widget, NULL);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Service"), widget, NULL);
	g_object_bind_property (s_pppoe, NM_SETTING_PPPOE_SERVICE,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	return section;
}

static void
nmt_page_dsl_constructed (GObject *object)
{
	NmtPageDsl *dsl = NMT_PAGE_DSL (object);
	NmtPageDslPrivate *priv = NMT_PAGE_DSL_GET_PRIVATE (dsl);
	NMConnection *conn;
	NMSettingPppoe *s_pppoe;
	NmtEditorSection *section;
	const GSList *sections, *iter;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (dsl));
	s_pppoe = nm_connection_get_setting_pppoe (conn);
	if (!s_pppoe) {
		nm_connection_add_setting (conn, nm_setting_pppoe_new ());
		s_pppoe = nm_connection_get_setting_pppoe (conn);
	}

	section = build_dsl_section (dsl, s_pppoe);
	nmt_editor_page_add_section (NMT_EDITOR_PAGE (dsl), section);

	priv->ethernet_page = nmt_page_ethernet_new (conn, nmt_editor_page_device_get_device_entry (NMT_EDITOR_PAGE_DEVICE (dsl)));
	sections = nmt_editor_page_get_sections (priv->ethernet_page);
	for (iter = sections; iter; iter = iter->next)
		nmt_editor_page_add_section (NMT_EDITOR_PAGE (dsl), iter->data);

	priv->ppp_page = nmt_page_ppp_new (conn);
	sections = nmt_editor_page_get_sections (priv->ppp_page);
	for (iter = sections; iter; iter = iter->next)
		nmt_editor_page_add_section (NMT_EDITOR_PAGE (dsl), iter->data);

	G_OBJECT_CLASS (nmt_page_dsl_parent_class)->constructed (object);
}

static void
nmt_page_dsl_finalize (GObject *object)
{
	NmtPageDsl *dsl = NMT_PAGE_DSL (object);
	NmtPageDslPrivate *priv = NMT_PAGE_DSL_GET_PRIVATE (dsl);

	g_clear_object (&priv->ethernet_page);
	g_clear_object (&priv->ppp_page);

	G_OBJECT_CLASS (nmt_page_dsl_parent_class)->finalize (object);
}

static void
nmt_page_dsl_class_init (NmtPageDslClass *dsl_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dsl_class);

	g_type_class_add_private (object_class, sizeof (NmtPageDslPrivate));

	object_class->constructed = nmt_page_dsl_constructed;
	object_class->finalize = nmt_page_dsl_finalize;
}
