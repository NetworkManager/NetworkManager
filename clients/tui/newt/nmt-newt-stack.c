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
 * SECTION:nmt-newt-stack
 * @short_description: A stack of alternative widgets
 *
 * #NmtNewtStack implements a stack of widgets, only one of which is
 * visible at any time.
 *
 * The height and width of the widget is determined only by its
 * visible child. Likewise, the widget's #NmtNewtWidget:valid is
 * determined only by the validity of its visible child, not its other
 * children.
 */

#include "nm-default.h"

#include "nmt-newt-stack.h"

G_DEFINE_TYPE (NmtNewtStack, nmt_newt_stack, NMT_TYPE_NEWT_CONTAINER)

#define NMT_NEWT_STACK_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_STACK, NmtNewtStackPrivate))

typedef struct {
	GPtrArray *children;
	GPtrArray *ids;

	guint active;
} NmtNewtStackPrivate;

enum {
	PROP_0,
	PROP_ACTIVE,
	PROP_ACTIVE_ID,

	LAST_PROP
};

/**
 * nmt_newt_stack_new:
 *
 * Creates a new #NmtNewtStack
 *
 * Returns: a new #NmtNewtStack
 */
NmtNewtWidget *
nmt_newt_stack_new (void)
{
	return g_object_new (NMT_TYPE_NEWT_STACK, NULL);
}

static void
nmt_newt_stack_init (NmtNewtStack *stack)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);

	priv->children = g_ptr_array_new ();
	priv->ids = g_ptr_array_new_with_free_func (g_free);
}

static void
nmt_newt_stack_finalize (GObject *object)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (object);

	g_ptr_array_unref (priv->children);
	g_ptr_array_unref (priv->ids);

	G_OBJECT_CLASS (nmt_newt_stack_parent_class)->finalize (object);
}

static newtComponent *
nmt_newt_stack_get_components (NmtNewtWidget *widget)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (widget);

	if (priv->active > priv->children->len)
		return NULL;

	return nmt_newt_widget_get_components (priv->children->pdata[priv->active]);
}

static void
nmt_newt_stack_size_request (NmtNewtWidget *widget,
                             int           *width,
                             int           *height)
{
	NmtNewtStack *stack = NMT_NEWT_STACK (widget);
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);
	int i, child_width, child_height;

	if (priv->active > priv->children->len) {
		*width = *height = 0;
		return;
	}

	/* We size-request all pages so that embedded NmtPageGrids will
	 * participate in their size-grouping (so that switching pages
	 * won't result in the column widths changing).
	 */
	for (i = 0; i < priv->children->len; i++) {
		nmt_newt_widget_size_request (priv->children->pdata[i], &child_width, &child_height);
		if (i == priv->active) {
			*width = child_width;
			*height = child_height;
		}
	}
}

static void
nmt_newt_stack_size_allocate (NmtNewtWidget *widget,
                              int            x,
                              int            y,
                              int            width,
                              int            height)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (widget);

	if (priv->active > priv->children->len)
		return;

	nmt_newt_widget_size_allocate (priv->children->pdata[priv->active], x, y, width, height);
}

/**
 * nmt_newt_stack_add:
 * @stack: an #NmtNewtStack
 * @id: the ID for the new page
 * @widget: the widget to add
 *
 * Adds @widget to @stack with the given @id.
 */
void
nmt_newt_stack_add (NmtNewtStack  *stack,
                    const char    *id,
                    NmtNewtWidget *widget)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);

	g_ptr_array_add (priv->children, widget);
	g_ptr_array_add (priv->ids, g_strdup (id));

	NMT_NEWT_CONTAINER_CLASS (nmt_newt_stack_parent_class)->add (NMT_NEWT_CONTAINER (stack), widget);
}

static void
nmt_newt_stack_remove (NmtNewtContainer *container,
                       NmtNewtWidget    *widget)
{
	NmtNewtStack *stack = NMT_NEWT_STACK (container);
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);
	int i;

	NMT_NEWT_CONTAINER_CLASS (nmt_newt_stack_parent_class)->remove (container, widget);

	for (i = 0; i < priv->children->len; i++) {
		if (priv->children->pdata[i] == widget) {
			g_ptr_array_remove_index (priv->children, i);
			g_ptr_array_remove_index (priv->ids, i);
			return;
		}
	}
}

static void
nmt_newt_stack_child_validity_changed (NmtNewtContainer *container,
                                       NmtNewtWidget    *widget)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (container);

	if (priv->active > priv->children->len)
		return;

	if (priv->children->pdata[priv->active] == (gpointer) widget) {
		NMT_NEWT_CONTAINER_CLASS (nmt_newt_stack_parent_class)->
			child_validity_changed (container, widget);
	}
}

/**
 * nmt_newt_stack_set_active:
 * @stack: an #NmtNewtStack
 * @active: the index of the new active page
 *
 * Sets the active page on @stack to @active.
 */
void
nmt_newt_stack_set_active (NmtNewtStack *stack,
                           guint         active)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);

	if (priv->active == active)
		return;

	priv->active = active;
	g_object_notify (G_OBJECT (stack), "active");
	g_object_notify (G_OBJECT (stack), "active-id");
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (stack));
}

/**
 * nmt_newt_stack_get_active:
 * @stack: an #NmtNewtStack
 *
 * Gets the index of the active page on @stack
 *
 * Returns: the index of the active page on @stack
 */
guint
nmt_newt_stack_get_active (NmtNewtStack *stack)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);

	return priv->active;
}

/**
 * nmt_newt_stack_set_active_id:
 * @stack: an #NmtNewtStack
 * @active_id: the ID of the new active page
 *
 * Sets the active page on @stack to @active_id.
 */
void
nmt_newt_stack_set_active_id (NmtNewtStack *stack,
                              const char   *id)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);
	int i;

	if (!g_strcmp0 (priv->ids->pdata[priv->active], id))
		return;

	for (i = 0; i < priv->ids->len; i++) {
		if (!g_strcmp0 (priv->ids->pdata[i], id)) {
			priv->active = i;
			g_object_notify (G_OBJECT (stack), "active");
			g_object_notify (G_OBJECT (stack), "active-id");
			nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (stack));
			return;
		}
	}
}

/**
 * nmt_newt_stack_get_active_id:
 * @stack: an #NmtNewtStack
 *
 * Gets the ID of the active page on @stack
 *
 * Returns: the ID of the active page on @stack
 */
const char *
nmt_newt_stack_get_active_id (NmtNewtStack *stack)
{
	NmtNewtStackPrivate *priv = NMT_NEWT_STACK_GET_PRIVATE (stack);

	if (priv->active > priv->children->len)
		return NULL;

	return priv->ids->pdata[priv->active];
}

static void
nmt_newt_stack_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
	NmtNewtStack *stack = NMT_NEWT_STACK (object);

	switch (prop_id) {
	case PROP_ACTIVE:
		nmt_newt_stack_set_active (stack, g_value_get_uint (value));
		break;
	case PROP_ACTIVE_ID:
		nmt_newt_stack_set_active_id (stack, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_stack_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
	NmtNewtStack *stack = NMT_NEWT_STACK (object);

	switch (prop_id) {
	case PROP_ACTIVE:
		g_value_set_uint (value, nmt_newt_stack_get_active (stack));
		break;
	case PROP_ACTIVE_ID:
		g_value_set_string (value, nmt_newt_stack_get_active_id (stack));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_stack_class_init (NmtNewtStackClass *stack_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stack_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (stack_class);
	NmtNewtContainerClass *container_class = NMT_NEWT_CONTAINER_CLASS (stack_class);

	g_type_class_add_private (stack_class, sizeof (NmtNewtStackPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_stack_set_property;
	object_class->get_property = nmt_newt_stack_get_property;
	object_class->finalize = nmt_newt_stack_finalize;

	widget_class->get_components = nmt_newt_stack_get_components;
	widget_class->size_request   = nmt_newt_stack_size_request;
	widget_class->size_allocate  = nmt_newt_stack_size_allocate;

	container_class->remove = nmt_newt_stack_remove;
	container_class->child_validity_changed = nmt_newt_stack_child_validity_changed;

	/**
	 * NmtNewtStack:active:
	 *
	 * The index of the active page
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE,
		 g_param_spec_uint ("active", "", "",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtStack:active-id:
	 *
	 * The ID of the active page
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE_ID,
		 g_param_spec_string ("active-id", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
}
