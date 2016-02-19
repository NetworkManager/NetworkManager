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
 * SECTION:nmt-newt-widget
 * @short_description: Base TUI Widget class
 *
 * #NmtNewtWidget is the abstract base class for nmt-newt. All widgets
 * inherit from one of its two subclasses: #NmtNewtComponent, for
 * widgets that wrap a (single) #newtComponent, and #NmtNewtContainer,
 * for widgets consisting of multiple components. See those classes
 * for more details.
 *
 * With the exception of #NmtNewtForm, all widgets start out with a
 * floating reference, which will be sunk by the container they are
 * added to. #NmtNewtForm is the "top-level" widget type, and so does
 * not have a floating reference.
 *
 * FIXME: need RTL support
 */

#include "nm-default.h"

#include "nmt-newt-widget.h"
#include "nmt-newt-form.h"

G_DEFINE_ABSTRACT_TYPE (NmtNewtWidget, nmt_newt_widget, G_TYPE_INITIALLY_UNOWNED)

#define NMT_NEWT_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_WIDGET, NmtNewtWidgetPrivate))

typedef struct {
	NmtNewtWidget *parent;
	gboolean visible, realized, valid;
	gboolean exit_on_activate;

	int pad_left, pad_top, pad_right, pad_bottom;
} NmtNewtWidgetPrivate;

enum {
	PROP_0,

	PROP_PARENT,
	PROP_VISIBLE,
	PROP_VALID,
	PROP_EXIT_ON_ACTIVATE,

	LAST_PROP
};

enum {
	NEEDS_REBUILD,
	ACTIVATED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
nmt_newt_widget_init (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	priv->visible = TRUE;
	priv->valid = TRUE;
}

static void
nmt_newt_widget_finalize (GObject *object)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (object);

	nmt_newt_widget_unrealize (NMT_NEWT_WIDGET (object));
	g_clear_object (&priv->parent);

	G_OBJECT_CLASS (nmt_newt_widget_parent_class)->finalize (object);
}

/**
 * nmt_newt_widget_realize:
 * @widget: an #NmtNewtWidget
 *
 * "Realizes" @widget. That is, creates #newtComponents corresponding
 * to @widget and its children.
 *
 * You should not need to call this yourself; an #NmtNewtForm will
 * cause its children to be realized and unrealized as needed.
 */
void
nmt_newt_widget_realize (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	if (!priv->realized) {
		NMT_NEWT_WIDGET_GET_CLASS (widget)->realize (widget);
		priv->realized = TRUE;
	}
}

/**
 * nmt_newt_widget_unrealize:
 * @widget: an #NmtNewtWidget
 *
 * "Unrealizes" @widget, destroying its #newtComponents.
 *
 * You should not need to call this yourself; an #NmtNewtForm will
 * cause its children to be realized and unrealized as needed.
 */
void
nmt_newt_widget_unrealize (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	if (priv->realized) {
		NMT_NEWT_WIDGET_GET_CLASS (widget)->unrealize (widget);
		priv->realized = FALSE;
	}
}

/**
 * nmt_newt_widget_get_realized:
 * @widget: an #NmtNewtWidget
 *
 * Checks if @widget is realized or not.
 *
 * Returns: whether @widget is realized.
 */
gboolean
nmt_newt_widget_get_realized (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	return priv->realized;
}

/**
 * nmt_newt_widget_get_components:
 * @widget: an #NmtNewtWidget
 *
 * Gets the #newtComponents that make up @widget, if @widget is
 * visible. If @widget has not yet been realized, it will be realized
 * first.
 *
 * If this function is called on a widget, then the widget will assume
 * that someone else is now responsible for destroying the components,
 * and so it will not destroy them itself when the widget is
 * destroyed. Normally, components will end up being destroyed by the
 * #NmtNewtForm they are added to.
 *
 * Returns: a %NULL-terminated array of components, in focus-chain
 *   order. You must free the array with g_free() when you are done
 *   with it.
 */
newtComponent *
nmt_newt_widget_get_components (NmtNewtWidget *widget)
{
	if (nmt_newt_widget_get_visible (widget)) {
		nmt_newt_widget_realize (widget);
		return NMT_NEWT_WIDGET_GET_CLASS (widget)->get_components (widget);
	} else
		return NULL;
}

/**
 * nmt_newt_widget_find_component:
 * @widget: an #NmtNewtWidget
 * @co: a #newtComponent
 *
 * Finds the widget inside @widget that owns @co.
 *
 * Return value: @co's owner, or %NULL if it was not found.
 */
NmtNewtWidget *
nmt_newt_widget_find_component (NmtNewtWidget *widget,
                                newtComponent  co)
{
	return NMT_NEWT_WIDGET_GET_CLASS (widget)->find_component (widget, co);
}

/**
 * nmt_newt_widget_set_padding:
 * @widget: an #NmtNewtWidget
 * @pad_left: padding on the left of @widget
 * @pad_top: padding on the top of @widget
 * @pad_right: padding on the right of @widget
 * @pad_bottom: padding on the bottom of @widget
 *
 * Sets the padding on @widget.
 */
void
nmt_newt_widget_set_padding (NmtNewtWidget *widget,
                             int            pad_left,
                             int            pad_top,
                             int            pad_right,
                             int            pad_bottom)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	priv->pad_left = pad_left;
	priv->pad_top = pad_top;
	priv->pad_right = pad_right;
	priv->pad_bottom = pad_bottom;
}

/**
 * nmt_newt_widget_size_request:
 * @widget: an #NmtNewtWidget
 * @width: (out): on output, the widget's requested width
 * @height: (out): on output, the widget's requested height
 *
 * Asks @widget for its requested size. If @widget is not visible,
 * this will return 0, 0. If @widget has not yet been realized, it
 * will be realized first.
 */
void
nmt_newt_widget_size_request (NmtNewtWidget *widget,
                              int           *width,
                              int           *height)
{
	if (nmt_newt_widget_get_visible (widget)) {
		NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

		nmt_newt_widget_realize (widget);
		NMT_NEWT_WIDGET_GET_CLASS (widget)->size_request (widget, width, height);

		*width += priv->pad_left + priv->pad_right;
		*height += priv->pad_top + priv->pad_bottom;
	} else
		*width = *height = 0;
}

/**
 * nmt_newt_widget_size_allocate:
 * @widget: an #NmtNewtWidget
 * @x: the widget's (absolute) X coordinate
 * @y: the widget's (absolute) Y coordinate
 * @width: the widget's allocated width
 * @height: the widget's allocated height
 *
 * Positions @widget at the given coordinates, with the given size. If
 * @widget is not visible, this has no effect. If @widget has not yet
 * been realized, it will be realized first.
 *
 * @x and @y are absolute coordinates (ie, relative to the screen /
 * terminal window, not relative to @widget's parent).
 *
 * In general, the results are undefined if @width or @height is less
 * than the widget's requested size. If @width or @height is larger
 * than the requested size, most #NmtNewtComponents will ignore the
 * extra space, but some components and most containers will expand to
 * fit.
 */
void
nmt_newt_widget_size_allocate (NmtNewtWidget *widget,
                               int            x,
                               int            y,
                               int            width,
                               int            height)
{
	if (nmt_newt_widget_get_visible (widget)) {
		NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

		nmt_newt_widget_realize (widget);
		x += priv->pad_left;
		y += priv->pad_top;
		width -= priv->pad_left + priv->pad_right;
		height -= priv->pad_top + priv->pad_bottom;

		NMT_NEWT_WIDGET_GET_CLASS (widget)->size_allocate (widget, x, y, width, height);
	}
}

/**
 * nmt_newt_widget_get_focus_component:
 * @widget: an #NmtNewtWidget
 *
 * Gets the #newtComponent that should be given the keyboard focus when
 * @widget is focused.
 *
 * Returns: the #newtComponent to focus, or %NULL if @widget can't
 *   take the focus.
 */
newtComponent
nmt_newt_widget_get_focus_component (NmtNewtWidget *widget)
{
	if (!NMT_NEWT_WIDGET_GET_CLASS (widget)->get_focus_component)
		return NULL;

	return NMT_NEWT_WIDGET_GET_CLASS (widget)->get_focus_component (widget);
}

static void
nmt_newt_widget_real_activated (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	if (priv->exit_on_activate)
		nmt_newt_form_quit (nmt_newt_widget_get_form (widget));
}	

/**
 * nmt_newt_widget_activated:
 * @widget: an #NmtNewtWidget
 *
 * Tells @widget that its #newtComponent has been activated (ie, the
 * user hit "Return" on it) and emits #NmtNewtWidget::activated.
 *
 * If #NmtNewtWidget:exit-on-activate is set on @widget, then this
 * will call nmt_newt_form_quit() on the widget's form.
 */
void
nmt_newt_widget_activated (NmtNewtWidget *widget)
{
	g_signal_emit (widget, signals[ACTIVATED], 0);
}

/**
 * nmt_newt_widget_get_exit_on_activate:
 * @widget: an #NmtNewtWidget
 *
 * Gets @widget's #NmtNewtWidget:exit-on-activate flag, qv.
 *
 * Returns: @widget's #NmtNewtWidget:exit-on-activate flag
 */
gboolean
nmt_newt_widget_get_exit_on_activate (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	return priv->exit_on_activate;
}

/**
 * nmt_newt_widget_set_exit_on_activate:
 * @widget: an #NmtNewtWidget
 * @exit_on_activate: whether @widget should exit on activate.
 *
 * Sets @widget's #NmtNewtWidget:exit-on-activate flag, qv.
 */
void
nmt_newt_widget_set_exit_on_activate (NmtNewtWidget *widget,
                                      gboolean       exit_on_activate)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	exit_on_activate = !!exit_on_activate;
	if (priv->exit_on_activate != exit_on_activate) {
		priv->exit_on_activate = exit_on_activate;
		g_object_notify (G_OBJECT (widget), "exit-on-activate");
	}
} 

/**
 * nmt_newt_widget_get_visible:
 * @widget: an #NmtNewtWidget
 *
 * Gets @widget's #NmtNewtWidget:visible flag, qv.
 *
 * Returns: @widget's #NmtNewtWidget:visible flag
 */
gboolean
nmt_newt_widget_get_visible (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	return priv->visible;
}

/**
 * nmt_newt_widget_set_visible:
 * @widget: an #NmtNewtWidget
 * @visible: whether @widget should be visible
 *
 * Sets @widget's #NmtNewtWidget:visible flag, qv.
 */
void
nmt_newt_widget_set_visible (NmtNewtWidget *widget,
                             gboolean       visible)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	visible = !!visible;
	if (priv->visible != visible) {
		priv->visible = visible;
		g_object_notify (G_OBJECT (widget), "visible");
		nmt_newt_widget_needs_rebuild (widget);
	}
}

/**
 * nmt_newt_widget_set_parent:
 * @widget: an #NmtNewtWidget
 * @parent: @widget's parent
 *
 * Sets @widget's parent to @parent. This is used internally by
 * #NmtNewtContainer implementations; you must use an appropriate
 * container-specific method to actually add a widget to a container.
 */
void
nmt_newt_widget_set_parent (NmtNewtWidget *widget,
                            NmtNewtWidget *parent)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	g_clear_object (&priv->parent);
	priv->parent = parent ? g_object_ref (parent) : NULL;
	g_object_notify (G_OBJECT (widget), "parent");
}

/**
 * nmt_newt_widget_get_parent:
 * @widget: an #NmtNewtWidget
 *
 * Gets @widget's parent
 *
 * Returns: @widget's parent
 */
NmtNewtWidget *
nmt_newt_widget_get_parent (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	return priv->parent;
}

/**
 * nmt_newt_widget_get_form:
 * @widget: an #NmtNewtWidget
 *
 * Gets @widget's top-level form.
 *
 * Returns: @widget's #NmtNewtForm
 */
NmtNewtForm *
nmt_newt_widget_get_form (NmtNewtWidget *widget)
{
	while (widget) {
		if (NMT_IS_NEWT_FORM (widget))
			return NMT_NEWT_FORM (widget);
		widget = nmt_newt_widget_get_parent (widget);
	}

	return NULL;
}

/**
 * nmt_newt_widget_get_valid:
 * @widget: an #NmtNewtWidget
 *
 * Gets @widget's #NmtNewtWidget:valid flag, indicating whether its
 * content is valid.
 *
 * Returns: @widget's #NmtNewtWidget:valid flag
 */
gboolean
nmt_newt_widget_get_valid (NmtNewtWidget *widget)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	return priv->valid;
}

/**
 * nmt_newt_widget_set_valid:
 * @widget: an #NmtNewtWidget
 * @valid: whether @widget is valid
 *
 * Sets @widget's #NmtNewtWidget:valid flag, indicating whether its
 * content is valid.
 *
 * This method should be considered "protected"; if you change it, the
 * widget implementation will likely just change it back at some
 * point.
 */
void
nmt_newt_widget_set_valid (NmtNewtWidget *widget,
                           gboolean       valid)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (widget);

	valid = !!valid;
	if (priv->valid == valid)
		return;

	priv->valid = valid;
	g_object_notify (G_OBJECT (widget), "valid");
}

/**
 * nmt_newt_widget_needs_rebuilds:
 * @widget: an #NmtNewtWidget
 *
 * Marks @widget as needing to be "rebuilt" (ie, re-realized). This is
 * called automatically in some cases (such as when adding a widget to
 * or removing it from a container). #NmtNewtComponent implementations
 * should also call this if they need to make some change that can
 * only be done by destroying their current #newtComponent and
 * creating a new one.
 */
void
nmt_newt_widget_needs_rebuild (NmtNewtWidget *widget)
{
	g_signal_emit (widget, signals[NEEDS_REBUILD], 0);
}

static void
nmt_newt_widget_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	NmtNewtWidget *widget = NMT_NEWT_WIDGET (object);

	switch (prop_id) {
	case PROP_PARENT:
		nmt_newt_widget_set_parent (widget, g_value_get_object (value));
		break;
	case PROP_VISIBLE:
		nmt_newt_widget_set_visible (widget, g_value_get_boolean (value));
		break;
	case PROP_EXIT_ON_ACTIVATE:
		nmt_newt_widget_set_exit_on_activate (widget, g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_widget_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
	NmtNewtWidgetPrivate *priv = NMT_NEWT_WIDGET_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_object (value, priv->parent);
		break;
	case PROP_VISIBLE:
		g_value_set_boolean (value, priv->visible);
		break;
	case PROP_VALID:
		g_value_set_boolean (value, priv->valid);
		break;
	case PROP_EXIT_ON_ACTIVATE:
		g_value_set_boolean (value, priv->exit_on_activate);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_widget_class_init (NmtNewtWidgetClass *widget_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (widget_class);

	g_type_class_add_private (widget_class, sizeof (NmtNewtWidgetPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_widget_set_property;
	object_class->get_property = nmt_newt_widget_get_property;
	object_class->finalize     = nmt_newt_widget_finalize;

	widget_class->activated = nmt_newt_widget_real_activated;

	/* signals */

	/**
	 * NmtNewtWidget::needs-rebuild:
	 * @widget: the #NmtNewtWidget
	 *
	 * Emitted when nmt_newt_widget_need_rebuild() is called on @widget
	 * or any of its children. This signal propagates up the container
	 * hierarchy, eventually reaching the top-level #NmtNewtForm.
	 */
	signals[NEEDS_REBUILD] =
		g_signal_new ("needs-rebuild",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtNewtWidgetClass, needs_rebuild),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	/**
	 * NmtNewtWidget::activated:
	 * @widget: the #NmtNewtWidget
	 *
	 * Emitted when the widget's #newtComponent is activated.
	 */
	signals[ACTIVATED] =
		g_signal_new ("activated",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtNewtWidgetClass, activated),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	/* properties */

	/**
	 * NmtNewtWidget:parent:
	 *
	 * The widget's parent widget, or %NULL if it has no parent.
	 */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_object ("parent", "", "",
		                      NMT_TYPE_NEWT_WIDGET,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtWidget:visible:
	 *
	 * Whether the widget is visible. Invisible widgets do not get
	 * realized or sized.
	 */
	g_object_class_install_property
		(object_class, PROP_VISIBLE,
		 g_param_spec_boolean ("visible", "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtWidget:valid:
	 *
	 * Whether the widget's content is considered valid. Components
	 * determine their own validity. A container, by default, is
	 * considered valid if all of its children are valid.
	 */
	g_object_class_install_property
		(object_class, PROP_VALID,
		 g_param_spec_boolean ("valid", "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtWidget:exit-on-activate:
	 *
	 * If %TRUE, the widget will call nmt_newt_form_quit() on its form
	 * when it is activated.
	 */
	g_object_class_install_property
		(object_class, PROP_EXIT_ON_ACTIVATE,
		 g_param_spec_boolean ("exit-on-activate", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
}
