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
 * SECTION:nmt-newt-listbox
 * @short_description: Single-choice listboxes
 *
 * #NmtNewtListbox implements a single-choice listbox.
 *
 * A listbox has some number of rows, each associated with an
 * arbitrary pointer value. The pointer values do not need to be
 * unique, but some APIs will not be usable if they aren't. You
 * can also cause rows with %NULL keys to be treated specially.
 *
 * The listbox will emit #NmtNewtWidget::activate when the user
 * presses Return on a selection.
 */

#include "nm-default.h"

#include "nmt-newt-listbox.h"
#include "nmt-newt-form.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtListbox, nmt_newt_listbox, NMT_TYPE_NEWT_COMPONENT)

#define NMT_NEWT_LISTBOX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_LISTBOX, NmtNewtListboxPrivate))

typedef struct {
	int height, alloc_height, width;
	gboolean fixed_height;
	NmtNewtListboxFlags flags;

	GPtrArray *entries;
	GPtrArray *keys;

	int active;
	gpointer active_key;
	gboolean skip_null_keys;

} NmtNewtListboxPrivate;

enum {
	PROP_0,
	PROP_HEIGHT,
	PROP_FLAGS,
	PROP_ACTIVE,
	PROP_ACTIVE_KEY,
	PROP_SKIP_NULL_KEYS,

	LAST_PROP
};

/**
 * NmtNewtListboxFlags:
 * @NMT_NEWT_LISTBOX_SCROLL: the listbox should have a scroll bar.
 * @NMT_NEWT_LISTBOX_BORDER: the listbox should have a border around it.
 *
 * Flags describing an #NmtNewtListbox
 */

/**
 * nmt_newt_listbox_new:
 * @height: the height of the listbox, or -1 for no fixed height
 * @flags: the listbox flags
 *
 * Creates a new #NmtNewtListbox
 *
 * Returns: a new #NmtNewtListbox
 */
NmtNewtWidget *
nmt_newt_listbox_new (int                 height,
                      NmtNewtListboxFlags flags)
{
	return g_object_new (NMT_TYPE_NEWT_LISTBOX,
	                     "height", height,
	                     "flags", flags,
	                     NULL);
}

/**
 * nmt_newt_listbox_append:
 * @listbox: an #NmtNewtListbox
 * @entry: the text for the new row
 * @key: (allow-none): the key associated with @entry
 *
 * Adds a row to @listbox.
 */
void
nmt_newt_listbox_append (NmtNewtListbox *listbox,
                         const char     *entry,
                         gpointer        key)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	g_ptr_array_add (priv->entries, nmt_newt_locale_from_utf8 (entry));
	g_ptr_array_add (priv->keys, key);
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (listbox));
}

/**
 * nmt_newt_listbox_clear:
 * @listbox: an #NmtNewtListbox
 *
 * Clears the contents of @listbox.
 */
void
nmt_newt_listbox_clear (NmtNewtListbox *listbox)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	g_ptr_array_set_size (priv->entries, 0);
	g_ptr_array_set_size (priv->keys, 0);

	priv->active = -1;
	priv->active_key = NULL;

	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (listbox));
}

/**
 * nmt_newt_listbox_set_active:
 * @listbox: an #NmtNewtListbox
 * @active: the row to make active
 *
 * Sets @active to be the currently-selected row in @listbox,
 * scrolling it into view if needed.
 */
void
nmt_newt_listbox_set_active (NmtNewtListbox *listbox,
                             int             active)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	if (active == priv->active)
		return;

	g_return_if_fail (active >= 0 && active < priv->entries->len);
	g_return_if_fail (!priv->skip_null_keys || priv->keys->pdata[active]);

	priv->active = active;
	priv->active_key = priv->keys->pdata[active];

	g_object_notify (G_OBJECT (listbox), "active");
	g_object_notify (G_OBJECT (listbox), "active-key");
}

/**
 * nmt_newt_listbox_set_active_key:
 * @listbox: an #NmtNewtListbox
 * @active_key: the key for the row to make active
 *
 * Selects the (first) row in @listbox with @active_key as its key,
 * scrolling it into view if needed.
 */
void
nmt_newt_listbox_set_active_key (NmtNewtListbox *listbox,
                                 gpointer        active_key)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);
	int i;

	if (active_key == priv->active_key)
		return;

	g_return_if_fail (!priv->skip_null_keys || active_key);

	for (i = 0; i < priv->keys->len; i++) {
		if (priv->keys->pdata[i] == active_key) {
			priv->active = i;
			priv->active_key = active_key;

			g_object_notify (G_OBJECT (listbox), "active");
			g_object_notify (G_OBJECT (listbox), "active-key");
			return;
		}
	}
}

/**
 * nmt_newt_listbox_get_active:
 * @listbox: an #NmtNewtListbox
 *
 * Gets the currently-selected row in @listbox.
 *
 * Returns: the currently-selected row in @listbox.
 */
int
nmt_newt_listbox_get_active (NmtNewtListbox *listbox)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	return priv->active;
}

/**
 * nmt_newt_listbox_get_active_key:
 * @listbox: an #NmtNewtListbox
 *
 * Gets the key of the currently-selected row in @listbox.
 *
 * Returns: the key of the currently-selected row in @listbox.
 */
gpointer
nmt_newt_listbox_get_active_key (NmtNewtListbox *listbox)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	return priv->active_key;
}

/**
 * nmt_newt_listbox_set_height:
 * @listbox: an #NmtNewtListbox
 * @height: the new height, or -1 for no fixed height
 *
 * Updates @listbox's height.
 */
void
nmt_newt_listbox_set_height (NmtNewtListbox *listbox,
                             int             height)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	priv->height = height;
	priv->fixed_height = priv->height != 0;
	g_object_notify (G_OBJECT (listbox), "height");
}

static void
nmt_newt_listbox_init (NmtNewtListbox *listbox)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	priv->entries = g_ptr_array_new_with_free_func (g_free);
	priv->keys = g_ptr_array_new ();

	priv->active = -1;
}

static void
nmt_newt_listbox_finalize (GObject *object)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (object);

	g_ptr_array_unref (priv->entries);
	g_ptr_array_unref (priv->keys);

	G_OBJECT_CLASS (nmt_newt_listbox_parent_class)->finalize (object);
}

static void
nmt_newt_listbox_size_request (NmtNewtWidget *widget,
                               int           *width,
                               int           *height)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (widget);

	NMT_NEWT_WIDGET_CLASS (nmt_newt_listbox_parent_class)->
		size_request (widget, width, height);

	priv->alloc_height = -1;
	if (!priv->fixed_height)
		*height = 1;
	priv->width = *width;
}

static void
nmt_newt_listbox_size_allocate (NmtNewtWidget *widget,
                                int            x,
                                int            y,
                                int            width,
                                int            height)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (widget);

	if (width > priv->width) {
		newtListboxSetWidth (nmt_newt_component_get_component (NMT_NEWT_COMPONENT (widget)),
		                     width);
	}

	NMT_NEWT_WIDGET_CLASS (nmt_newt_listbox_parent_class)->
		size_allocate (widget, x, y, width, height);

	priv->alloc_height = height;

	if (!priv->fixed_height && height != priv->height) {
		priv->height = height;
		nmt_newt_widget_needs_rebuild (widget);
	}
}

static void
update_active_internal (NmtNewtListbox *listbox,
                        int             new_active)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);

	if (priv->active == new_active)
		return;
	if (new_active >= priv->keys->len)
		return;

	if (priv->skip_null_keys && !priv->keys->pdata[new_active]) {
		if (new_active > priv->active) {
			while (   new_active < priv->entries->len
			       && !priv->keys->pdata[new_active])
				new_active++;
		} else {
			while (   new_active >= 0
			       && !priv->keys->pdata[new_active])
				new_active--;
		}

		if (   new_active < 0
		    || new_active >= priv->entries->len
		    || !priv->keys->pdata[new_active]) {
			g_assert (priv->active >= 0 && priv->active < priv->entries->len);
			return;
		}
	}

	nmt_newt_listbox_set_active (listbox, new_active);
}

static void
selection_changed_callback (newtComponent  co,
                            void          *user_data)
{
	NmtNewtListbox *listbox = user_data;
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (listbox);
	int new_active;

	new_active = GPOINTER_TO_UINT (newtListboxGetCurrent (co));
	update_active_internal (listbox, new_active);

	if (priv->active != new_active)
		newtListboxSetCurrent (co, priv->active);
}

static guint
convert_flags (NmtNewtListboxFlags flags)
{
	guint newt_flags = NEWT_FLAG_RETURNEXIT;

	if (flags & NMT_NEWT_LISTBOX_SCROLL)
		newt_flags |= NEWT_FLAG_SCROLL;
	if (flags & NMT_NEWT_LISTBOX_BORDER)
		newt_flags |= NEWT_FLAG_BORDER;

	return newt_flags;
}

static newtComponent
nmt_newt_listbox_build_component (NmtNewtComponent *component,
                                  gboolean          sensitive)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (component);
	newtComponent co;
	int i, active;

	if (priv->active == -1)
		update_active_internal (NMT_NEWT_LISTBOX (component), 0);
	active = priv->active;

	co = newtListbox (-1, -1, priv->height, convert_flags (priv->flags));
	newtComponentAddCallback (co, selection_changed_callback, component);

	for (i = 0; i < priv->entries->len; i++) {
		newtListboxAppendEntry (co, priv->entries->pdata[i], GUINT_TO_POINTER (i));
		if (active == -1 && priv->keys->pdata[i] == priv->active_key)
			active = i;
	}

	if (active != -1)
		newtListboxSetCurrent (co, active);

	return co;
}

static void
nmt_newt_listbox_activated (NmtNewtWidget *widget)
{
	NmtNewtListbox *listbox = NMT_NEWT_LISTBOX (widget);
	newtComponent co = nmt_newt_component_get_component (NMT_NEWT_COMPONENT (widget));

	nmt_newt_listbox_set_active (listbox, GPOINTER_TO_UINT (newtListboxGetCurrent (co)));

	NMT_NEWT_WIDGET_CLASS (nmt_newt_listbox_parent_class)->activated (widget);
}

static void
nmt_newt_listbox_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
	NmtNewtListbox *listbox = NMT_NEWT_LISTBOX (object);
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HEIGHT:
		priv->height = g_value_get_int (value);
		priv->fixed_height = (priv->height != 0);
		break;
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		break;
	case PROP_ACTIVE:
		nmt_newt_listbox_set_active (listbox, g_value_get_int (value));
		break;
	case PROP_ACTIVE_KEY:
		nmt_newt_listbox_set_active_key (listbox, g_value_get_pointer (value));
		break;
	case PROP_SKIP_NULL_KEYS:
		priv->skip_null_keys = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_listbox_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
	NmtNewtListboxPrivate *priv = NMT_NEWT_LISTBOX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HEIGHT:
		g_value_set_int (value, priv->height);
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	case PROP_ACTIVE:
		g_value_set_int (value, priv->active);
		break;
	case PROP_ACTIVE_KEY:
		g_value_set_pointer (value, priv->active_key);
		break;
	case PROP_SKIP_NULL_KEYS:
		g_value_set_boolean (value, priv->skip_null_keys);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_listbox_class_init (NmtNewtListboxClass *listbox_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (listbox_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (listbox_class);
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (listbox_class);

	g_type_class_add_private (listbox_class, sizeof (NmtNewtListboxPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_listbox_set_property;
	object_class->get_property = nmt_newt_listbox_get_property;
	object_class->finalize     = nmt_newt_listbox_finalize;

	widget_class->size_request  = nmt_newt_listbox_size_request;
	widget_class->size_allocate = nmt_newt_listbox_size_allocate;
	widget_class->activated     = nmt_newt_listbox_activated;

	component_class->build_component = nmt_newt_listbox_build_component;

	/* properties */

	/**
	 * NmtNewtListbox:height:
	 *
	 * The listbox's height, or -1 if it has no fixed height.
	 */
	g_object_class_install_property
		(object_class, PROP_HEIGHT,
		 g_param_spec_int ("height", "", "",
		                   -1, 255, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtListbox:flags:
	 *
	 * The listbox's #NmtNewtListboxFlags.
	 */
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint ("flags", "", "",
		                    0, 0xFFFF, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtListbox:active:
	 *
	 * The currently-selected row.
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE,
		 g_param_spec_int ("active", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtListbox:active-key:
	 *
	 * The key of the currently-selected row.
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE_KEY,
		 g_param_spec_pointer ("active-key", "", "",
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtListbox:skip-null-keys:
	 *
	 * If %TRUE, rows with %NULL key values will be skipped over when
	 * navigating the list with the arrow keys.
	 */
	g_object_class_install_property
		(object_class, PROP_SKIP_NULL_KEYS,
		 g_param_spec_boolean ("skip-null-keys", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
}
