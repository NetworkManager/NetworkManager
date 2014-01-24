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
 * SECTION:nmt-widget-list
 * @short_description: A list of widgets, with Add and Remove buttons
 *
 * #NmtWidgetList presents a homogeneous list of widgets, with "Remove"
 * buttons next to each one, and an "Add" button at the button to add
 * new ones.
 *
 * It is the base class for #NmtAddressList, and is used internally by
 * #NmtRouteTable.
 *
 * FIXME: The way this works is sort of weird.
 */

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus-glib.h>
#include <glib/gi18n-lib.h>

#include "nmt-widget-list.h"
#include "nmt-newt.h"

G_DEFINE_TYPE (NmtWidgetList, nmt_widget_list, NMT_TYPE_NEWT_GRID)

#define NMT_WIDGET_LIST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_WIDGET_LIST, NmtWidgetListPrivate))

typedef struct {
	int length;

	NmtWidgetListCallback create_callback;
	gpointer user_data;
	GDestroyNotify destroy_notify;

	NmtNewtWidget *empty_widget;

	GPtrArray *widgets;
	GPtrArray *remove_buttons;

	NmtNewtWidget *add_button;
	GBinding *add_sensitivity;
} NmtWidgetListPrivate;

enum {
	PROP_0,
	PROP_CREATE_CALLBACK,
	PROP_USER_DATA,
	PROP_DESTROY_NOTIFY,
	PROP_EMPTY_WIDGET,
	PROP_LENGTH,

	LAST_PROP
};

enum {
	ADD_CLICKED,
	REMOVE_CLICKED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void add_clicked    (NmtNewtButton *button, gpointer user_data);
static void remove_clicked (NmtNewtButton *button, gpointer user_data);

/**
 * NmtWidgetListCallback:
 * @list: the #NmtWidgetList
 * @n: the number of the widget being added
 * @user_data: the callback's user data
 *
 * Called by #NmtWidgetList to ask for a new widget to be created.
 *
 * Note that the widget is not created to go with any particular
 * value, but rather is created to be at a certain spot in the list.
 * When an element is deleted from the list, it is actually always
 * the last widget in the list that is removed, but it is assumed
 * that the widget list is bound to some array-valued property, and
 * so when an element is deleted from that array, the widgets will
 * all update themselves automatically when the array changes.
 *
 * Returns: a new widget for the list
 */

/**
 * nmt_widget_list_new:
 * @create_callback: callback to create new widgets
 * @user_data: user data for @create_callback
 * @destroy_notify: #GDestroyNotify for @user_data
 * @empty_widget: (allow-none): a widget to display when there are
 *   no "real" widgets in the list.
 *
 * Creates a new #NmtWidgetList.
 *
 * Returns: a new #NmtWidgetList.
 */
NmtNewtWidget *
nmt_widget_list_new (NmtWidgetListCallback  create_callback,
                     gpointer               user_data,
                     GDestroyNotify         destroy_notify,
                     NmtNewtWidget         *empty_widget)
{
	return g_object_new (NMT_TYPE_WIDGET_LIST,
	                     "create-callback", create_callback,
	                     "user-data", user_data,
	                     "destroy-notify", destroy_notify,
	                     "empty-widget", empty_widget,
	                     NULL);
}

static void
nmt_widget_list_init (NmtWidgetList *list)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (list);

	priv->widgets = g_ptr_array_new ();
	priv->remove_buttons = g_ptr_array_new ();

	priv->add_button = nmt_newt_button_new (_("Add..."));
	g_signal_connect (priv->add_button, "clicked",
	                  G_CALLBACK (add_clicked), list);
	nmt_newt_grid_add (NMT_NEWT_GRID (list), priv->add_button, 0, 0);
}

static void
nmt_widget_list_constructed (GObject *object)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (object);

	if (priv->length == 0 && priv->empty_widget) {
		nmt_newt_widget_set_visible (priv->empty_widget, TRUE);
		nmt_newt_grid_move (NMT_NEWT_GRID (object), priv->add_button, 0, 1);
	}

	G_OBJECT_CLASS (nmt_widget_list_parent_class)->constructed (object);
}

static void
nmt_widget_list_finalize (GObject *object)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (object);

	g_ptr_array_unref (priv->widgets);
	g_ptr_array_unref (priv->remove_buttons);

	if (priv->user_data && priv->destroy_notify)
		priv->destroy_notify (priv->user_data);

	g_clear_object (&priv->empty_widget);

	G_OBJECT_CLASS (nmt_widget_list_parent_class)->finalize (object);
}

static void
ensure_widgets (NmtWidgetList *list)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (list);
	NmtNewtWidget *widget, *button, *focus;
	gboolean was_empty;
	NmtNewtForm *form;
	int i;

	was_empty = priv->widgets->len == 0;

	if (priv->length < priv->widgets->len) {
		/* remove excess widgets */
		for (i = priv->length; i < priv->widgets->len; i++) {
			nmt_newt_container_remove (NMT_NEWT_CONTAINER (list), priv->widgets->pdata[i]);
			nmt_newt_container_remove (NMT_NEWT_CONTAINER (list), priv->remove_buttons->pdata[i]);
		}
		g_ptr_array_set_size (priv->widgets, priv->length);
		g_ptr_array_set_size (priv->remove_buttons, priv->length);

	} else if (priv->length > priv->widgets->len) {
		/* add new widgets */
		for (i = priv->widgets->len; i < priv->length; i++) {
			widget = NMT_WIDGET_LIST_GET_CLASS (list)->create_widget (list, i);

			nmt_newt_grid_add (NMT_NEWT_GRID (list), widget, 0, i);
			g_ptr_array_add (priv->widgets, widget);

			button = nmt_newt_button_new (_("Remove"));
			g_signal_connect (button, "clicked",
			                  G_CALLBACK (remove_clicked), list);

			nmt_newt_grid_add (NMT_NEWT_GRID (list), button, 1, i);
			nmt_newt_widget_set_padding (button, 1, 0, 0, 0);
			g_ptr_array_add (priv->remove_buttons, button);
		}

	} else
		return;

	if (priv->widgets->len == 0 && priv->empty_widget) {
		nmt_newt_widget_set_visible (priv->empty_widget, TRUE);
		nmt_newt_grid_move (NMT_NEWT_GRID (list), priv->add_button, 0, 1);
	} else {
		if (was_empty && priv->empty_widget)
			nmt_newt_widget_set_visible (priv->empty_widget, FALSE);
		nmt_newt_grid_move (NMT_NEWT_GRID (list), priv->add_button, 0, priv->length);
	}

	form = nmt_newt_widget_get_form (NMT_NEWT_WIDGET (list));
	if (form) {
		if (priv->widgets->len) {
			if (was_empty)
				focus = priv->widgets->pdata[0];
			else
				focus = priv->widgets->pdata[priv->widgets->len - 1];
		} else
			focus = priv->add_button;
		nmt_newt_form_set_focus (form, focus);
	}

	g_clear_object (&priv->add_sensitivity);
	if (priv->widgets->len) {
		widget = priv->widgets->pdata[priv->widgets->len - 1];
		priv->add_sensitivity = g_object_bind_property (widget, "valid",
		                                                priv->add_button, "sensitive",
		                                                G_BINDING_SYNC_CREATE);
		g_object_add_weak_pointer (G_OBJECT (priv->add_sensitivity),
		                           (gpointer *)&priv->add_sensitivity);
	}
}

static void
add_clicked (NmtNewtButton *button, gpointer list)
{
	g_signal_emit (G_OBJECT (list), signals[ADD_CLICKED], 0, NULL);
}

static void
remove_clicked (NmtNewtButton *button, gpointer list)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (list);
	int i;

	for (i = 0; i < priv->remove_buttons->len; i++) {
		if (priv->remove_buttons->pdata[i] == (gpointer)button)
			break;
	}
	g_return_if_fail (i < priv->remove_buttons->len);

	g_signal_emit (G_OBJECT (list), signals[REMOVE_CLICKED], 0, i, NULL);
}

static NmtNewtWidget *
nmt_widget_list_real_create_widget (NmtWidgetList *list,
                                    int            n)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (list);

	g_return_val_if_fail (priv->create_callback != NULL, NULL);

	return priv->create_callback (list, n, priv->user_data);
}

/**
 * nmt_widget_list_get_length:
 * @list: the #NmtNewtWidgetList
 *
 * Gets the number of widgets in the list.
 *
 * Returns: the number of widgets in the list.
 */
int
nmt_widget_list_get_length (NmtWidgetList *list)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (list);

	return priv->length;
}

/**
 * nmt_widget_list_set_length:
 * @list: the #NmtNewtWidgetList
 * @length: the new length
 *
 * Changes the number of widgets in the list. Widgets will be added or
 * deleted as necessary.
 */
void
nmt_widget_list_set_length (NmtWidgetList *list,
                            int            length)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (list);

	if (priv->length != length) {
		priv->length = length;
		g_object_notify (G_OBJECT (list), "length");
	}

	ensure_widgets (list);
}

static void
nmt_widget_list_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CREATE_CALLBACK:
		priv->create_callback = g_value_get_pointer (value);
		break;
	case PROP_USER_DATA:
		priv->user_data = g_value_get_pointer (value);
		break;
	case PROP_DESTROY_NOTIFY:
		priv->destroy_notify = g_value_get_pointer (value);
		break;
	case PROP_LENGTH:
		priv->length = g_value_get_int (value);
		ensure_widgets (NMT_WIDGET_LIST (object));
		break;
	case PROP_EMPTY_WIDGET:
		priv->empty_widget = g_value_get_object (value);
		if (priv->empty_widget) {
			g_object_ref_sink (priv->empty_widget);
			nmt_newt_grid_add (NMT_NEWT_GRID (object), priv->empty_widget, 0, 0);
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_widget_list_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
	NmtWidgetListPrivate *priv = NMT_WIDGET_LIST_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CREATE_CALLBACK:
		g_value_set_pointer (value, priv->create_callback);
		break;
	case PROP_USER_DATA:
		g_value_set_pointer (value, priv->user_data);
		break;
	case PROP_DESTROY_NOTIFY:
		g_value_set_pointer (value, priv->destroy_notify);
		break;
	case PROP_LENGTH:
		g_value_set_int (value, priv->length);
		break;
	case PROP_EMPTY_WIDGET:
		g_value_set_object (value, priv->empty_widget);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_widget_list_class_init (NmtWidgetListClass *list_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (list_class);

	g_type_class_add_private (list_class, sizeof (NmtWidgetListPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_widget_list_constructed;
	object_class->set_property = nmt_widget_list_set_property;
	object_class->get_property = nmt_widget_list_get_property;
	object_class->finalize     = nmt_widget_list_finalize;

	list_class->create_widget = nmt_widget_list_real_create_widget;

	/* signals */

	/**
	 * NmtNewtWidget::add-clicked:
	 * @list: the #NmtNewtWidgetList
	 *
	 * Emitted when the user clicks the "Add" button. The caller can
	 * decide whether or not to add a new widget, and call
	 * nmt_widget_list_set_length() with the new length if so.
	 *
	 * FIXME: the "Add" button should be insensitive if it's
	 * not going to work.
	 */
	signals[ADD_CLICKED] =
		g_signal_new ("add-clicked",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtWidgetListClass, add_clicked),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);
	/**
	 * NmtNewtWidget::remove-clicked:
	 * @list: the #NmtNewtWidgetList
	 * @n: the widget being removed
	 *
	 * Emitted when the user clicks one of the "Remove" buttons. The
	 * caller can decide whether or not to remove the widget, and
	 * call nmt_widget_list_set_length() with the new length if so.
	 *
	 * FIXME: the "Remove" button should be insensitive if it's not
	 * going to work.
	 */
	signals[REMOVE_CLICKED] =
		g_signal_new ("remove-clicked",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtWidgetListClass, remove_clicked),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_INT);

	/* properties */

	/**
	 * NmtWidgetList:create-callback:
	 *
	 * Callback called to create a new widget.
	 */
	g_object_class_install_property (object_class, PROP_CREATE_CALLBACK,
	                                 g_param_spec_pointer ("create-callback", "", "",
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtWidgetList:user-data:
	 *
	 * User data for #NmtWidgetList:create-callback
	 */
	g_object_class_install_property (object_class, PROP_USER_DATA,
	                                 g_param_spec_pointer ("user-data", "", "",
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtWidgetList:destroy-notify:
	 *
	 * #GDestroyNotify for #NmtWidgetList:user-data
	 */
	g_object_class_install_property (object_class, PROP_DESTROY_NOTIFY,
	                                 g_param_spec_pointer ("destroy-notify", "", "",
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtWidgetList:length:
	 *
	 * The length of the widget list; changing this value will add or
	 * remove widgets from the list.
	 */
	g_object_class_install_property (object_class, PROP_LENGTH,
	                                 g_param_spec_int ("length", "", "",
	                                                   0, G_MAXINT, 0,
	                                                   G_PARAM_READWRITE |
	                                                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtWidgetList:empty-widget:
	 *
	 * If non-%NULL, this widget will be displayed when there are
	 * no "real" widgets in the list.
	 */
	g_object_class_install_property (object_class, PROP_EMPTY_WIDGET,
	                                 g_param_spec_object ("empty-widget", "", "",
	                                                      NMT_TYPE_NEWT_WIDGET,
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_CONSTRUCT_ONLY |
	                                                      G_PARAM_STATIC_STRINGS));
}
