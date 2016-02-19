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
 * SECTION:nmt-newt-container
 * @short_description: Base class for containers
 *
 * #NmtNewtContainer is the base class for #NmtNewtWidgets that
 * contain other widgets.
 *
 * #NmtNewtGrid is the most generic container type.
 */

#include "nm-default.h"

#include <string.h>

#include "nmt-newt-container.h"
#include "nmt-newt-component.h"

G_DEFINE_ABSTRACT_TYPE (NmtNewtContainer, nmt_newt_container, NMT_TYPE_NEWT_WIDGET)

#define NMT_NEWT_CONTAINER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_CONTAINER, NmtNewtContainerPrivate))

typedef struct {
	GPtrArray *children;

} NmtNewtContainerPrivate;

static void child_needs_rebuild (NmtNewtWidget *widget, gpointer user_data);

static void
nmt_newt_container_init (NmtNewtContainer *container)
{
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (container);

	priv->children = g_ptr_array_new ();
}

static void
nmt_newt_container_finalize (GObject *object)
{
	NmtNewtContainer *container = NMT_NEWT_CONTAINER (object);
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (object);

	while (priv->children->len)
		nmt_newt_container_remove (container, priv->children->pdata[0]);

	G_OBJECT_CLASS (nmt_newt_container_parent_class)->finalize (object);
}

static void
nmt_newt_container_realize (NmtNewtWidget *widget)
{
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (widget);
	int i;

	for (i = 0; i < priv->children->len; i++)
		nmt_newt_widget_realize (priv->children->pdata[i]);
}

static void
nmt_newt_container_unrealize (NmtNewtWidget *widget)
{
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (widget);
	int i;

	for (i = 0; i < priv->children->len; i++)
		nmt_newt_widget_unrealize (priv->children->pdata[i]);
}

static void
child_needs_rebuild (NmtNewtWidget *widget,
                     gpointer       user_data)
{
	NmtNewtWidget *container = user_data;

	nmt_newt_widget_needs_rebuild (container);
}

static void
nmt_newt_container_real_child_validity_changed (NmtNewtContainer *container,
                                                NmtNewtWidget    *widget)
{
	NmtNewtContainerPrivate *priv;
	int i;

	if (widget) {
		if (!nmt_newt_widget_get_visible (widget))
			return;
		if (!nmt_newt_widget_get_valid (widget)) {
			nmt_newt_widget_set_valid (NMT_NEWT_WIDGET (container), FALSE);
			return;
		}
	}

	priv = NMT_NEWT_CONTAINER_GET_PRIVATE (container);
	for (i = 0; i < priv->children->len; i++) {
		widget = priv->children->pdata[i];
		if (   nmt_newt_widget_get_visible (widget)
		       && !nmt_newt_widget_get_valid (widget)) {
			nmt_newt_widget_set_valid (NMT_NEWT_WIDGET (container), FALSE);
			return;
		}
	}

	nmt_newt_widget_set_valid (NMT_NEWT_WIDGET (container), TRUE);
}

static void
nmt_newt_container_child_validity_changed (NmtNewtContainer *container,
                                           NmtNewtWidget    *widget)
{
	NMT_NEWT_CONTAINER_GET_CLASS (container)->child_validity_changed (container, widget);
}

static void
child_validity_notify (GObject    *object,
                       GParamSpec *pspec,
                       gpointer    container)
{
	nmt_newt_container_child_validity_changed (container, NMT_NEWT_WIDGET (object));
}

static void
nmt_newt_container_real_add (NmtNewtContainer *container,
                             NmtNewtWidget    *widget)
{
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (container);

	g_signal_connect (widget, "needs-rebuild", G_CALLBACK (child_needs_rebuild), container);
	g_signal_connect (widget, "notify::valid", G_CALLBACK (child_validity_notify), container);
	g_ptr_array_add (priv->children, g_object_ref_sink (widget));
	nmt_newt_widget_set_parent (widget, NMT_NEWT_WIDGET (container));

	nmt_newt_container_child_validity_changed (container, widget);
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (container));
}

static void
nmt_newt_container_real_remove (NmtNewtContainer *container,
                                NmtNewtWidget    *widget)
{
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (container);
	int i;

	for (i = 0; i < priv->children->len; i++) {
		if (widget == priv->children->pdata[i]) {
			g_ptr_array_remove_index (priv->children, i);
			g_signal_handlers_disconnect_by_func (widget, G_CALLBACK (child_needs_rebuild), container);
			g_signal_handlers_disconnect_by_func (widget, G_CALLBACK (child_validity_notify), container);
			nmt_newt_widget_set_parent (widget, NULL);
			g_object_unref (widget);

			nmt_newt_container_child_validity_changed (container, NULL);
			nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (container));
			return;
		}
	}
}

/**
 * nmt_newt_container_remove:
 * @container: the #NmtNewtContainer
 * @widget: the child to remove
 *
 * Removes @widget from @container.
 *
 * Note that there is not a corresponding
 * <literal>nmt_newt_container_add ()</literal>; you must use
 * container-type-specific methods to add widgets to containers.
 */
void
nmt_newt_container_remove (NmtNewtContainer *container,
                           NmtNewtWidget    *widget)
{
	NMT_NEWT_CONTAINER_GET_CLASS (container)->remove (container, widget);
}

static NmtNewtWidget *
nmt_newt_container_find_component (NmtNewtWidget *widget,
                                   newtComponent  co)
{
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (widget);
	NmtNewtWidget *found, *child;
	int i;

	for (i = 0; i < priv->children->len; i++) {
		child = priv->children->pdata[i];

		found = nmt_newt_widget_find_component (child, co);
		if (found)
			return found;
	}

	return NULL;
}

/**
 * nmt_newt_container_get_children:
 * @container: an #NmtNewtContainer
 *
 * Gets a list of @container's children.
 *
 * Returns: (transfer full): a list of @container's children.
 */
GSList *
nmt_newt_container_get_children (NmtNewtContainer *container)
{
	NmtNewtContainerPrivate *priv = NMT_NEWT_CONTAINER_GET_PRIVATE (container);
	GSList *ret;
	int i;

	for (i = 0, ret = NULL; i < priv->children->len; i++)
		ret = g_slist_prepend (ret, g_object_ref (priv->children->pdata[i]));
	return g_slist_reverse (ret);
}

static void
nmt_newt_container_class_init (NmtNewtContainerClass *container_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (container_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (container_class);

	g_type_class_add_private (container_class, sizeof (NmtNewtContainerPrivate));

	/* virtual methods */
	object_class->finalize = nmt_newt_container_finalize;

	widget_class->realize        = nmt_newt_container_realize;
	widget_class->unrealize      = nmt_newt_container_unrealize;
	widget_class->find_component = nmt_newt_container_find_component;

	container_class->add    = nmt_newt_container_real_add;
	container_class->remove = nmt_newt_container_real_remove;
	container_class->child_validity_changed = nmt_newt_container_real_child_validity_changed;
}
