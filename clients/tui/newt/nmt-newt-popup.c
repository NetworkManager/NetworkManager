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
 * SECTION:nmt-newt-popup
 * @short_description: Pop-up menus
 *
 * #NmtNewtPopup implements a pop-up menu. When inactive, they appear
 * the same as #NmtNewtButtons, displaying the label from the
 * #NmtNewtPopup:active entry. When activated, they pop up a temporary
 * #NmtNewtForm containing an #NmtNewtListbox to select from.
 */

#include "nm-default.h"

#include "nmt-newt-popup.h"
#include "nmt-newt-form.h"
#include "nmt-newt-hacks.h"
#include "nmt-newt-listbox.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtPopup, nmt_newt_popup, NMT_TYPE_NEWT_BUTTON)

#define NMT_NEWT_POPUP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_POPUP, NmtNewtPopupPrivate))

typedef struct {
	GArray *entries;
	int active;
} NmtNewtPopupPrivate;

enum {
	PROP_0,
	PROP_ACTIVE,
	PROP_ACTIVE_ID,

	LAST_PROP
};

/**
 * NmtNewtPopupEntry:
 * @label: the user-visible label for the entry
 * @id: the internal ID of the entry
 *
 * A single entry in a pop-up menu.
 */

/**
 * nmt_newt_popup_new:
 * @entries: an array of #NmtNewtPopupEntry, terminated by an
 *   entry with a %NULL label
 *
 * Creates a new #NmtNewtPopup with the given entries.
 *
 * Returns: a new #NmtNewtPopup
 */
NmtNewtWidget *
nmt_newt_popup_new (NmtNewtPopupEntry *entries)
{
	NmtNewtWidget *widget;
	NmtNewtPopupPrivate *priv;
	int i;

	widget = g_object_new (NMT_TYPE_NEWT_POPUP, NULL);
	priv = NMT_NEWT_POPUP_GET_PRIVATE (widget);

	for (i = 0; entries[i].label; i++) {
		NmtNewtPopupEntry entry;

		entry.label = nmt_newt_locale_from_utf8 (_(entries[i].label));
		entry.id = g_strdup (entries[i].id);
		g_array_append_val (priv->entries, entry);
	}

	return widget;
}

static void
popup_entry_clear_func (NmtNewtPopupEntry *entry)
{
	g_free (entry->label);
	g_free (entry->id);
}

static void
nmt_newt_popup_init (NmtNewtPopup *popup)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (popup);

	priv->entries = g_array_sized_new (FALSE, FALSE, sizeof (NmtNewtPopupEntry), 10);
	g_array_set_clear_func (priv->entries, (GDestroyNotify) popup_entry_clear_func);
}

static void
nmt_newt_popup_finalize (GObject *object)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (object);

	g_array_unref (priv->entries);

	G_OBJECT_CLASS (nmt_newt_popup_parent_class)->finalize (object);
}

static newtComponent
nmt_newt_popup_build_component (NmtNewtComponent *component,
                                gboolean          sensitive)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (component);
	NmtNewtPopupEntry *entries = (NmtNewtPopupEntry *)priv->entries->data;

	nmt_newt_button_set_label (NMT_NEWT_BUTTON (component),
	                           entries[priv->active].label);
	return NMT_NEWT_COMPONENT_CLASS (nmt_newt_popup_parent_class)->
		build_component (component, sensitive);
}

static void
nmt_newt_popup_activated (NmtNewtWidget *widget)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (widget);
	NmtNewtPopupEntry *entries = (NmtNewtPopupEntry *)priv->entries->data;
	NmtNewtForm *form;
	NmtNewtWidget *listbox, *ret;
	int button_x, button_y;
	int window_x, window_y;
	int list_w, list_h;
	int i, active;

	listbox = nmt_newt_listbox_new (priv->entries->len, 0);
	nmt_newt_widget_set_exit_on_activate (listbox, TRUE);
	for (i = 0; i < priv->entries->len; i++)
		nmt_newt_listbox_append (NMT_NEWT_LISTBOX (listbox), entries[i].label, NULL);
	nmt_newt_listbox_set_active (NMT_NEWT_LISTBOX (listbox), priv->active);
	nmt_newt_widget_set_padding (listbox, 1, 0, 1, 0);

	nmt_newt_widget_size_request (listbox, &list_w, &list_h);

	g_object_get (nmt_newt_widget_get_form (widget),
	              "x", &window_x,
	              "y", &window_y,
	              NULL);
	newtComponentGetPosition (nmt_newt_component_get_component (NMT_NEWT_COMPONENT (widget)),
	                          &button_x, &button_y);
	/* (window_x + button_x) is the screen X coordinate of the newtComponent. A
	 * newtButton labelled "Foo" is rendered as " <Foo>" (with a preceding
	 * space), so the "F" is at (window_x + button_x + 2). We've added 1 column
	 * of padding to the left of the listbox, so we need to position the popup
	 * at (window_x + button_x + 1) in order for its text to be aligned with the
	 * button's text. (The x and y coordinates given to NmtNewtForm are the
	 * coordinates of the top left of the window content, ignoring the border
	 * graphics.)
	 */
	window_x += button_x + 1;
	window_y += button_y - priv->active;

	form = g_object_new (NMT_TYPE_NEWT_FORM,
	                     "x", window_x,
	                     "y", window_y,
	                     "width", list_w,
	                     "height", list_h,
	                     "padding", 0,
	                     "escape-exits", TRUE,
	                     NULL);
	nmt_newt_form_set_content (form, listbox);

	ret = nmt_newt_form_run_sync (form);
	if (ret == listbox)
		active = nmt_newt_listbox_get_active (NMT_NEWT_LISTBOX (listbox));
	else
		active = priv->active;

	g_object_unref (form);

	if (active != priv->active) {
		priv->active = active;
		g_object_notify (G_OBJECT (widget), "active");
		g_object_notify (G_OBJECT (widget), "active-id");
		nmt_newt_widget_needs_rebuild (widget);
	}

	NMT_NEWT_WIDGET_CLASS (nmt_newt_popup_parent_class)->activated (widget);
}

/**
 * nmt_newt_popup_get_active:
 * @popup: a #NmtNewtPopup
 *
 * Gets the index of the active entry in @popup.
 *
 * Returns: the index of the active entry in @popup.
 */
int
nmt_newt_popup_get_active (NmtNewtPopup *popup)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (popup);

	return priv->active;
}

/**
 * nmt_newt_popup_set_active:
 * @popup: a #NmtNewtPopup
 * @active: the index of the new active entry
 *
 * Sets the active entry in @popup.
 */
void
nmt_newt_popup_set_active (NmtNewtPopup *popup,
                           int           active)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (popup);

	active = CLAMP (active, 0, priv->entries->len - 1);

	if (active != priv->active) {
		priv->active = active;
		g_object_notify (G_OBJECT (popup), "active");
		g_object_notify (G_OBJECT (popup), "active-id");
	}
}

/**
 * nmt_newt_popup_get_active_id:
 * @popup: a #NmtNewtPopup
 *
 * Gets the textual ID of the active entry in @popup.
 *
 * Returns: the ID of the active entry in @popup.
 */
const char *
nmt_newt_popup_get_active_id (NmtNewtPopup *popup)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (popup);
	NmtNewtPopupEntry *entries = (NmtNewtPopupEntry *)priv->entries->data;

	return entries[priv->active].id;
}

/**
 * nmt_newt_popup_set_active_id:
 * @popup: a #NmtNewtPopup
 * @active_id: the ID of the new active entry
 *
 * Sets the active entry in @popup.
 */
void
nmt_newt_popup_set_active_id (NmtNewtPopup *popup,
                              const char   *active_id)
{
	NmtNewtPopupPrivate *priv = NMT_NEWT_POPUP_GET_PRIVATE (popup);
	NmtNewtPopupEntry *entries = (NmtNewtPopupEntry *)priv->entries->data;
	int i;

	for (i = 0; i < priv->entries->len; i++) {
		if (!g_strcmp0 (active_id, entries[i].id)) {
			nmt_newt_popup_set_active (popup, i);
			return;
		}
	}
}

static void
nmt_newt_popup_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
	NmtNewtPopup *popup = NMT_NEWT_POPUP (object);

	switch (prop_id) {
	case PROP_ACTIVE:
		nmt_newt_popup_set_active (popup, g_value_get_uint (value));
		break;
	case PROP_ACTIVE_ID:
		nmt_newt_popup_set_active_id (popup, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_popup_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
	NmtNewtPopup *popup = NMT_NEWT_POPUP (object);

	switch (prop_id) {
	case PROP_ACTIVE:
		g_value_set_uint (value, nmt_newt_popup_get_active (popup));
		break;
	case PROP_ACTIVE_ID:
		g_value_set_string (value, nmt_newt_popup_get_active_id (popup));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_popup_class_init (NmtNewtPopupClass *popup_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (popup_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (popup_class);
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (popup_class);

	g_type_class_add_private (popup_class, sizeof (NmtNewtPopupPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_popup_set_property;
	object_class->get_property = nmt_newt_popup_get_property;
	object_class->finalize     = nmt_newt_popup_finalize;

	widget_class->activated = nmt_newt_popup_activated;

	component_class->build_component = nmt_newt_popup_build_component;

	/**
	 * NmtNewtPopup:active:
	 *
	 * The index of the currently-active entry.
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE,
		 g_param_spec_uint ("active", "", "",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtPopup:active-id:
	 *
	 * The textual ID of the currently-active entry.
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE_ID,
		 g_param_spec_string ("active-id", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
}
