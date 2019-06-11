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
 * SECTION:nmt-newt-entry
 * @short_description: Text entries
 *
 * #NmtNewtEntry implements entry widgets, with optional filtering and
 * validation.
 *
 * See also #NmtNewtEntryNumeric, for numeric-only entries.
 */

#include "nm-default.h"

#include "nmt-newt-entry.h"
#include "nmt-newt-form.h"
#include "nmt-newt-hacks.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtEntry, nmt_newt_entry, NMT_TYPE_NEWT_COMPONENT)

#define NMT_NEWT_ENTRY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_ENTRY, NmtNewtEntryPrivate))

typedef struct {
	int width;
	NmtNewtEntryFlags flags;
	char *text;
	int last_cursor_pos;
	guint idle_update;

	NmtNewtEntryFilter filter;
	gpointer filter_data;

	NmtNewtEntryValidator validator;
	gpointer validator_data;
} NmtNewtEntryPrivate;

enum {
	PROP_0,
	PROP_TEXT,
	PROP_WIDTH,
	PROP_FLAGS,
	PROP_PASSWORD,

	LAST_PROP
};

/**
 * NmtNewtEntryFlags:
 * @NMT_NEWT_ENTRY_NOSCROLL: the entry content should not scroll left
 *   and right
 * @NMT_NEWT_ENTRY_PASSWORD: the entry should show '*'s instead of its
 *   actual contents
 * @NMT_NEWT_ENTRY_NONEMPTY: the entry should be considered not
 *   #NmtNewtWidget:valid if it is empty.
 *
 * Flags describing an #NmtNewtEntry
 */

/**
 * nmt_newt_entry_new:
 * @width: the width in characters for the entry
 * @flags: flags describing the entry
 *
 * Creates a new #NmtNewtEntry.
 *
 * Returns: a new #NmtNewtEntry
 */
NmtNewtWidget *
nmt_newt_entry_new (int               width,
                    NmtNewtEntryFlags flags)
{
	return g_object_new (NMT_TYPE_NEWT_ENTRY,
	                     "width", width,
	                     "flags", flags,
	                     NULL);
}

/**
 * NmtNewtEntryFilter:
 * @entry: the #NmtNewtEntry
 * @text: the current contents of @entry
 * @ch: the character just typed
 * @position: the position of the cursor in @entry
 * @user_data: the data passed to nmt_newt_entry_set_filter()
 *
 * Callback function used to filter the contents of an entry.
 *
 * Returns: %TRUE if @ch should be accepted, %FALSE if not
 */

/**
 * nmt_newt_entry_set_filter:
 * @entry: an #NmtNewtEntry
 * @filter: the function to use to filter the entry
 * @user_data: data for @filter
 *
 * Sets a #NmtNewtEntryFilter on @entry, to allow filtering out
 * certain characters from the entry.
 *
 * Note that @filter will only be called for printable characters (eg,
 * not for cursor-control characters or the like), and that it will
 * only be called for user input, not, eg, for
 * nmt_newt_entry_set_text().
 */
void
nmt_newt_entry_set_filter (NmtNewtEntry       *entry,
                           NmtNewtEntryFilter  filter,
                           gpointer            user_data)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	priv->filter = filter;
	priv->filter_data = user_data;
}

static void
nmt_newt_entry_check_valid (NmtNewtEntry *entry)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);
	gboolean valid;

	if (   (priv->flags & NMT_NEWT_ENTRY_NONEMPTY)
	    && *priv->text == '\0')
		valid = FALSE;
	else if (priv->validator)
		valid = !!priv->validator (entry, priv->text, priv->validator_data);
	else
		valid = TRUE;

	nmt_newt_widget_set_valid (NMT_NEWT_WIDGET (entry), valid);
}

/**
 * NmtNewtEntryValidator:
 * @entry: the #NmtNewtEntry
 * @text: the current contents of @entry
 * @user_data: the data passed to nmt_newt_entry_set_validator()
 *
 * Callback function used to validate the contents of an entry.
 *
 * Returns: whether the entry is #NmtNewtWidget:valid
 */

/**
 * nmt_newt_entry_set_validator:
 * @entry: an #NmtNewtEntry
 * @validator: the function to use to validate the entry
 * @user_data: data for @validator
 *
 * Sets a #NmtNewtEntryValidator on @entry, to allow validation of
 * the entry contents. If @validator returns %FALSE, then the entry
 * will not be considered #NmtNewtWidget:valid.
 */
void
nmt_newt_entry_set_validator (NmtNewtEntry          *entry,
                              NmtNewtEntryValidator  validator,
                              gpointer               user_data)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	priv->validator = validator;
	priv->validator_data = user_data;

	nmt_newt_entry_check_valid (entry);
}

static void
nmt_newt_entry_set_text_internal (NmtNewtEntry  *entry,
                                  const char    *text,
                                  newtComponent  co)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	if (!text)
		text = "";

	if (!strcmp (priv->text, text))
		return;

	g_free (priv->text);
	priv->text = g_strdup (text);

	if (co) {
		char *text_lc;

		text_lc = priv->text ? nmt_newt_locale_from_utf8 (priv->text) : NULL;
		newtEntrySet (co, text_lc, TRUE);
		g_free (text_lc);
		priv->last_cursor_pos = -1;
	}

	g_object_freeze_notify (G_OBJECT (entry));
	nmt_newt_entry_check_valid (entry);
	g_object_notify (G_OBJECT (entry), "text");
	g_object_thaw_notify (G_OBJECT (entry));
}

/**
 * nmt_newt_entry_set_text:
 * @entry: an #NmtNewtEntry
 * @text: the new text
 *
 * Updates @entry's text. Note that this skips the entry's
 * #NmtNewtEntryFilter, but will cause its #NmtNewtEntryValidator to
 * be re-run.
 */
void
nmt_newt_entry_set_text (NmtNewtEntry *entry,
                         const char   *text)
{
	newtComponent co;

	co = nmt_newt_component_get_component (NMT_NEWT_COMPONENT (entry));
	nmt_newt_entry_set_text_internal (entry, text, co);
}

/**
 * nmt_newt_entry_get_text:
 * @entry: an #NmtNewtEntry
 *
 * Gets @entry's text
 *
 * Returns: @entry's text
 */
const char *
nmt_newt_entry_get_text (NmtNewtEntry *entry)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	return priv->text;
}

/**
 * nmt_newt_entry_set_width:
 * @entry: an #NmtNewtEntpry
 * @widget: the new width
 *
 * Updates @entry's width
 */
void
nmt_newt_entry_set_width (NmtNewtEntry *entry,
                          int           width)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	if (priv->width == width)
		return;

	priv->width = width;
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (entry));

	g_object_notify (G_OBJECT (entry), "width");
}

/**
 * nmt_newt_entry_get_width:
 * @entry: an #NmtNewtEntry
 *
 * Gets @entry's width
 *
 * Returns: @entry's width
 */
int
nmt_newt_entry_get_width (NmtNewtEntry *entry)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	return priv->width;
}

static void
nmt_newt_entry_init (NmtNewtEntry *entry)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	priv->text = g_strdup ("");
	priv->last_cursor_pos = -1;
}

static void
nmt_newt_entry_constructed (GObject *object)
{
	nmt_newt_entry_check_valid (NMT_NEWT_ENTRY (object));

	G_OBJECT_CLASS (nmt_newt_entry_parent_class)->constructed (object);
}

static void
nmt_newt_entry_finalize (GObject *object)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (object);

	g_free (priv->text);
	if (priv->idle_update)
		g_source_remove (priv->idle_update);

	G_OBJECT_CLASS (nmt_newt_entry_parent_class)->finalize (object);
}

static gboolean
idle_update_entry (gpointer entry)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);
	newtComponent co = nmt_newt_component_get_component (entry);
	char *text;

	priv->idle_update = 0;
	if (!co)
		return FALSE;

	priv->last_cursor_pos = newtEntryGetCursorPosition (co);

	text = nmt_newt_locale_to_utf8 (newtEntryGetValue (co));
	nmt_newt_entry_set_text_internal (entry, text, NULL);
	g_free (text);

	return FALSE;
}

static int
entry_filter (newtComponent  entry,
              void          *self,
              int            ch,
              int            cursor)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (self);

	if (g_ascii_isprint (ch)) {
		if (priv->filter) {
			char *text = nmt_newt_locale_to_utf8 (newtEntryGetValue (entry));

			if (!priv->filter (self, text, ch, cursor, priv->filter_data)) {
				g_free (text);
				return 0;
			}
			g_free (text);
		}
	}

	if (!priv->idle_update)
		priv->idle_update = g_idle_add (idle_update_entry, self);
	return ch;
}

static guint
convert_flags (NmtNewtEntryFlags flags)
{
	guint newt_flags = NEWT_FLAG_RETURNEXIT;

	if (!(flags & NMT_NEWT_ENTRY_NOSCROLL))
		newt_flags |= NEWT_FLAG_SCROLL;
	if (flags & NMT_NEWT_ENTRY_PASSWORD)
		newt_flags |= NEWT_FLAG_PASSWORD;

	return newt_flags;
}

static newtComponent
nmt_newt_entry_build_component (NmtNewtComponent *component,
                                gboolean          sensitive)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (component);
	newtComponent co;
	char *text_lc;
	int flags;

	flags = convert_flags (priv->flags);
	if (!sensitive)
		flags |= NEWT_FLAG_DISABLED;

	text_lc = priv->text ? nmt_newt_locale_from_utf8 (priv->text) : NULL;
	co = newtEntry (-1, -1, text_lc, priv->width, NULL, flags);
	g_free (text_lc);

	if (priv->last_cursor_pos != -1)
		newtEntrySetCursorPosition (co, priv->last_cursor_pos);

	newtEntrySetFilter (co, entry_filter, component);
	return co;
}

static void
nmt_newt_entry_activated (NmtNewtWidget *widget)
{
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (widget);

	if (priv->idle_update) {
		g_source_remove (priv->idle_update);
		idle_update_entry (widget);
	}

	NMT_NEWT_WIDGET_CLASS (nmt_newt_entry_parent_class)->activated (widget);
}

static void
nmt_newt_entry_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
	NmtNewtEntry *entry = NMT_NEWT_ENTRY (object);
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	switch (prop_id) {
	case PROP_TEXT:
		nmt_newt_entry_set_text (entry, g_value_get_string (value));
		break;
	case PROP_WIDTH:
		nmt_newt_entry_set_width (entry, g_value_get_int (value));
		break;
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (entry));
		break;
	case PROP_PASSWORD:
		if (g_value_get_boolean (value))
			priv->flags |= NMT_NEWT_ENTRY_PASSWORD;
		else
			priv->flags &= ~NMT_NEWT_ENTRY_PASSWORD;
		nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (entry));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_entry_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
	NmtNewtEntry *entry = NMT_NEWT_ENTRY (object);
	NmtNewtEntryPrivate *priv = NMT_NEWT_ENTRY_GET_PRIVATE (entry);

	switch (prop_id) {
	case PROP_TEXT:
		g_value_set_string (value, nmt_newt_entry_get_text (entry));
		break;
	case PROP_WIDTH:
		g_value_set_int (value, priv->width);
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	case PROP_PASSWORD:
		g_value_set_boolean (value, (priv->flags & NMT_NEWT_ENTRY_PASSWORD) != 0);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_entry_class_init (NmtNewtEntryClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (entry_class);
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtNewtEntryPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_newt_entry_constructed;
	object_class->set_property = nmt_newt_entry_set_property;
	object_class->get_property = nmt_newt_entry_get_property;
	object_class->finalize     = nmt_newt_entry_finalize;

	widget_class->activated = nmt_newt_entry_activated;

	component_class->build_component    = nmt_newt_entry_build_component;

	/**
	 * NmtNewtEntry:text
	 *
	 * The entry's text
	 */
	g_object_class_install_property
		(object_class, PROP_TEXT,
		 g_param_spec_string ("text", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtEntry:width
	 *
	 * The entry's width in characters
	 */
	g_object_class_install_property
		(object_class, PROP_WIDTH,
		 g_param_spec_int ("width", "", "",
		                   -1, 80, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtEntry:flags
	 *
	 * The entry's #NmtNewtEntryFlags
	 */
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint ("flags", "", "",
		                    0, 0xFFFF, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtEntry:password
	 *
	 * %TRUE if #NmtNewtEntry:flags contains %NMT_NEWT_ENTRY_PASSWORD,
	 * %FALSE if not.
	 */
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_boolean ("password", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
}
