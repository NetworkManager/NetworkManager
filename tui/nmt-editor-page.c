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
 * SECTION:nmt-editor-page:
 * @short_description: An #NmtEditor "page"
 *
 * #NmtEditorPage is the abstract base class for #NmtEditor "pages".
 * Note that despite the name, currently all "page" types except
 * #NmtPageMain are actually displayed as collapsible sections, not
 * separate tabs/forms.
 */

#include "config.h"

#include <glib/gi18n-lib.h>

#include "nmt-editor-page.h"

G_DEFINE_ABSTRACT_TYPE (NmtEditorPage, nmt_editor_page, NMT_TYPE_PAGE_GRID)

#define NMT_EDITOR_PAGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDITOR_PAGE, NmtEditorPagePrivate))

typedef struct {
	char *title;
	NmtNewtWidget *header_widget;
	NMConnection *connection;

} NmtEditorPagePrivate;

enum {
	PROP_0,

	PROP_CONNECTION,
	PROP_TITLE,

	LAST_PROP
};

static void
nmt_editor_page_init (NmtEditorPage *page)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (page);

	priv->header_widget = g_object_ref_sink (nmt_newt_separator_new ());
}

static void
nmt_editor_page_finalize (GObject *object)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (object);

	g_free (priv->title);
	g_clear_object (&priv->header_widget);
	g_clear_object (&priv->connection);

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
 * nmt_editor_page_set_header_widget:
 * @page: the #NmtEditorPage
 * @widget: an #NmtNewtWidget
 *
 * Sets the page's header widget. When displayed as a subpage of
 * #NmtPageMain, this widget will be put into the corresponding
 * #NmtNewtSection's header.
 *
 * FIXME: for consistency, this should be a property as well.
 */
void
nmt_editor_page_set_header_widget (NmtEditorPage *page,
                                   NmtNewtWidget *widget)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (page);

	g_clear_object (&priv->header_widget);

	if (!widget)
		widget = nmt_newt_separator_new ();
	priv->header_widget = g_object_ref_sink (widget);
}

/**
 * nmt_editor_page_get_header_widget:
 * @page: the #NmtEditorPage
 *
 * Gets the page's header widget. When displayed as a subpage of
 * #NmtPageMain, this widget will be put into the corresponding
 * #NmtNewtSection's header.
 *
 * Returns: (transfer none): the page's header widget.
 */
NmtNewtWidget *
nmt_editor_page_get_header_widget (NmtEditorPage *page)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (page);

	return priv->header_widget;
}

/**
 * nmt_editor_page_get_title:
 * @page: the #NmtEditorPage
 *
 * Gets the page's title.
 *
 * Returns: the page's title
 */
const char *
nmt_editor_page_get_title (NmtEditorPage *page)
{
	NmtEditorPagePrivate *priv = NMT_EDITOR_PAGE_GET_PRIVATE (page);

	return priv->title;
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
	case PROP_TITLE:
		priv->title = g_value_dup_string (value);
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
	case PROP_TITLE:
		g_value_set_string (value, priv->title);
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
	g_object_class_install_property (object_class, PROP_CONNECTION,
	                                 g_param_spec_object ("connection", "", "",
	                                                      NM_TYPE_CONNECTION,
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_CONSTRUCT_ONLY |
	                                                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtEditorPage:title:
	 *
	 * The page's title.
	 */
	g_object_class_install_property (object_class, PROP_TITLE,
	                                 g_param_spec_string ("title", "", "",
	                                                      NULL,
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_CONSTRUCT_ONLY |
	                                                      G_PARAM_STATIC_STRINGS));
}
