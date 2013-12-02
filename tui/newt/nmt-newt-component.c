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
 * SECTION:nmt-newt-component
 * @short_description: Base class for widgets that wrap #newtComponents
 *
 * #NmtNewtComponent is the abstract class for #NmtNewtWidgets that
 * wrap a (single) #newtComponent.
 */

#include "config.h"

#include "nmt-newt-component.h"
#include "nmt-newt-form.h"
#include "nmt-newt-hacks.h"

G_DEFINE_ABSTRACT_TYPE (NmtNewtComponent, nmt_newt_component, NMT_TYPE_NEWT_WIDGET)

#define NMT_NEWT_COMPONENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_COMPONENT, NmtNewtComponentPrivate))

typedef struct {
	newtComponent co;
	gboolean own_component;
	gboolean sensitive;
} NmtNewtComponentPrivate;

enum {
	PROP_0,

	PROP_COMPONENT,
	PROP_SENSITIVE,

	LAST_PROP
};

static void
nmt_newt_component_init (NmtNewtComponent *component)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (component);

	priv->sensitive = TRUE;
}

static void
nmt_newt_component_unrealize (NmtNewtWidget *widget)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (widget);

	if (!priv->co)
		return;

	newtComponentAddCallback (priv->co, NULL, NULL);
	newtComponentAddDestroyCallback (priv->co, NULL, NULL);

	if (priv->own_component)
		newtComponentDestroy (priv->co);
	priv->co = NULL;
}

static void
component_destroy_callback (newtComponent  co,
                            void          *component)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (component);

	priv->own_component = FALSE;
	nmt_newt_widget_unrealize (component);
	nmt_newt_widget_needs_rebuild (component);
}

static void
nmt_newt_component_realize (NmtNewtWidget *widget)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (widget);

	nmt_newt_component_unrealize (widget);
	priv->co = NMT_NEWT_COMPONENT_GET_CLASS (widget)->
		build_component (NMT_NEWT_COMPONENT (widget), priv->sensitive);
	priv->own_component = TRUE;
	if (!priv->sensitive)
		newtComponentTakesFocus (priv->co, FALSE);
	newtComponentAddDestroyCallback (priv->co, component_destroy_callback, widget);
}

static newtComponent *
nmt_newt_component_get_components (NmtNewtWidget *widget)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (widget);
	newtComponent *cos;

	priv->own_component = FALSE;
	cos = g_new0 (newtComponent, 2);
	cos[0] = priv->co;
	return cos;
}

static NmtNewtWidget *
nmt_newt_component_find_component (NmtNewtWidget *widget,
                                   newtComponent  co)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (widget);

	if (co == priv->co)
		return widget;
	else
		return NULL;
}

static void
nmt_newt_component_size_request (NmtNewtWidget *widget,
                                 int           *width,
                                 int           *height)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (widget);

	newtComponentGetSize (priv->co, width, height);
}

static void
nmt_newt_component_size_allocate (NmtNewtWidget *widget,
                                  int            x,
                                  int            y,
                                  int            width,
                                  int            height)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (widget);
	newtGrid grid;

	/* You can't directly place a newtComponent, so we create a newtGrid,
	 * position the component within that, and then place the grid.
	 */
	grid = newtCreateGrid (1, 1);
	newtGridSetField (grid, 0, 0,
	                  NEWT_GRID_COMPONENT, priv->co,
	                  x, y, 0, 0,
	                  NEWT_ANCHOR_LEFT | NEWT_ANCHOR_TOP, 0);
	newtGridPlace (grid, 0, 0);
	newtGridFree (grid, FALSE);
}

static newtComponent
nmt_newt_component_get_focus_component (NmtNewtWidget *widget)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (widget);

	return priv->co;
}

/**
 * nmt_newt_component_get_component:
 * @component: an #NmtNewtComponent
 *
 * A simpler version of nmt_newt_widget_get_components() for the
 * single-component case. Also, unlike
 * nmt_newt_widget_get_component(), this does not realize the widget
 * if it isn't already realized. FIXME: why?
 *
 * Returns: @component's #newtComponent
 */
newtComponent
nmt_newt_component_get_component (NmtNewtComponent *component)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (component);

	return priv->co;
}

/**
 * nmt_newt_component_get_sensitive:
 * @component: an #NmtNewtComponent
 *
 * Gets @component's #NmtNewtComponent:sensitive property, indicating
 * whether the widget is available for manipulation. Insensitive
 * components will be skipped over in the keyboard tab chain, and may
 * be displayed differently.
 *
 * Returns: @component's #NmtNewtComponent:sensitive property
 */
gboolean
nmt_newt_component_get_sensitive (NmtNewtComponent *component)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (component);

	return priv->sensitive;
}

/**
 * nmt_newt_component_set_sensitive:
 * @component: an #NmtNewtComponent
 * @sensitive: whether @component should be sensitive
 *
 * Sets @component's #NmtNewtComponent:sensitive property.
 */
void
nmt_newt_component_set_sensitive (NmtNewtComponent *component,
                                  gboolean          sensitive)
{
	NmtNewtComponentPrivate *priv = NMT_NEWT_COMPONENT_GET_PRIVATE (component);

	sensitive = !!sensitive;
	if (priv->sensitive == sensitive)
		return;

	priv->sensitive = sensitive;
	g_object_notify (G_OBJECT (component), "sensitive");
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (component));
}

static void
nmt_newt_component_set_property (GObject      *object,
                                 guint         prop_id,
                                 const GValue *value,
                                 GParamSpec   *pspec)
{
	NmtNewtComponent *component = NMT_NEWT_COMPONENT (object);

	switch (prop_id) {
	case PROP_SENSITIVE:
		nmt_newt_component_set_sensitive (component, g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_component_get_property (GObject    *object,
                                 guint       prop_id,
                                 GValue     *value,
                                 GParamSpec *pspec)
{
	NmtNewtComponent *component = NMT_NEWT_COMPONENT (object);

	switch (prop_id) {
	case PROP_COMPONENT:
		g_value_set_pointer (value, nmt_newt_component_get_component (component));
		break;
	case PROP_SENSITIVE:
		g_value_set_boolean (value, nmt_newt_component_get_sensitive (component));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_component_class_init (NmtNewtComponentClass *component_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (component_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (component_class);

	g_type_class_add_private (component_class, sizeof (NmtNewtComponentPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_component_set_property;
	object_class->get_property = nmt_newt_component_get_property;

	widget_class->realize             = nmt_newt_component_realize;
	widget_class->unrealize           = nmt_newt_component_unrealize;
	widget_class->get_components      = nmt_newt_component_get_components;
	widget_class->find_component      = nmt_newt_component_find_component;
	widget_class->size_request        = nmt_newt_component_size_request;
	widget_class->size_allocate       = nmt_newt_component_size_allocate;
	widget_class->get_focus_component = nmt_newt_component_get_focus_component;

	/* properties */

	/**
	 * NmtNewtComponent:component:
	 *
	 * The component's #newtComponent
	 */
	g_object_class_install_property (object_class, PROP_COMPONENT,
	                                 g_param_spec_pointer ("component", "", "",
	                                                       G_PARAM_READABLE |
	                                                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtComponent:sensitive:
	 *
	 * Whether the component is sensitive. Insensitive components will
	 * be skipped over in the keyboard tab chain, and may be displayed
	 * differently.
	 */
	g_object_class_install_property (object_class, PROP_SENSITIVE,
	                                 g_param_spec_boolean ("sensitive", "", "",
	                                                       TRUE,
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_STATIC_STRINGS));
}
