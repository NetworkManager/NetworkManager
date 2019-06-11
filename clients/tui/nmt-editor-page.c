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
 * SECTION:nmt-editor-page:
 * @short_description: An #NmtEditor "page"
 *
 * #NmtEditorPage is the abstract base class for #NmtEditor "pages".
 * A "page" is a set of related #NmtEditorSections.
 */

#include "nm-default.h"

#include "nmt-editor-page.h"

G_DEFINE_ABSTRACT_TYPE (NmtEditorPage, nmt_editor_page, G_TYPE_OBJECT)

#define NMT_EDITOR_PAGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDITOR_PAGE, NmtEditorPagePrivate))

typedef struct {
	NMConnection *connection;
	GSList *sections;

} NmtEditorPagePrivate;

enum {
	PROP_0,

	PROP_CONNECTION,

	LAST_PROP
};

static void
nmt_editor_page_init (NmtEditorPage *page)
{
}

static void
nmt_editor_page_finalize (GObject *object)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (object);

	g_clear_object (&priv->connection);
	g_slist_free_full (priv->sections, g_object_unref);

	G_OBJECT_CLASS (nmt_editor_page_parent_class)->finalize (object);
}

/**
 * nmt_editor_page_get_connection:
 * @page: the #NmtEditorPage
 *
 * Gets the page's #NMConnection.
 *
 * Returns: (transfer none): the page's #NMConnection.
 */
NMConnection *
nmt_editor_page_get_connection (NmtEditorPage *page)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (page);

	return priv->connection;
}

/**
 * nmt_editor_page_get_sections:
 * @page: the #NmtEditorPage
 *
 * Gets the page's list of sections to display.
 *
 * Returns: (transfer none): the list of sections; this is the internal list
 * used by the page and must not be modified or freed.
 */
GSList *
nmt_editor_page_get_sections (NmtEditorPage *page)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (page);

	return priv->sections;
}

/**
 * nmt_editor_page_add_section:
 * @page: the #NmtEditorPage
 * @section: the #NmtEditorSection
 *
 * Adds a section to the page. This should only be called by #NmtEditorPage
 * subclasses.
 */
void
nmt_editor_page_add_section (NmtEditorPage *page,
                             NmtEditorSection *section)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (page);

	priv->sections = g_slist_append (priv->sections, g_object_ref_sink (section));
}

/**
 * nmt_editor_page_saved:
 * @page: the #NmtEditorPage
 *
 * This method is called when the user saves the connection. It gives
 * the page a chance to do save its data outside the connections (such as
 * recommit the slave connections).
 */
void
nmt_editor_page_saved (NmtEditorPage *page)
{
	NmtEditorPageClass *editor_page_class = NMT_EDITOR_PAGE_GET_CLASS (page);

	if (editor_page_class->saved)
		editor_page_class->saved (page);
}

static void
nmt_editor_page_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		priv->connection = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_page_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, priv->connection);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_page_class_init (NmtEditorPageClass *page_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (page_class);

	g_type_class_add_private (page_class, sizeof (NmtEditorPagePrivate));

	/* virtual methods */
	object_class->set_property = nmt_editor_page_set_property;
	object_class->get_property = nmt_editor_page_get_property;
	object_class->finalize     = nmt_editor_page_finalize;

	/* properties */

	/**
	 * NmtEditorPage:connection:
	 *
	 * The page's #NMConnection.
	 */
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_object ("connection", "", "",
		                      NM_TYPE_CONNECTION,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
}
