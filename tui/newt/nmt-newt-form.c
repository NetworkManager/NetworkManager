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
 * SECTION:nmt-newt-form
 * @short_description: The top-level NmtNewt widget
 *
 * #NmtNewtForm is the top-level widget that contains and presents a
 * "form" (aka dialog) to the user.
 */

#include "config.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <glib/gi18n-lib.h>

#include "nmt-newt-form.h"
#include "nmt-newt-button.h"
#include "nmt-newt-grid.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtForm, nmt_newt_form, NMT_TYPE_NEWT_CONTAINER)

#define NMT_NEWT_FORM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_FORM, NmtNewtFormPrivate))

typedef struct {
	newtComponent form;
	NmtNewtWidget *content;

	guint x, y, width, height;
	guint padding;
	gboolean fixed_x, fixed_y;
	gboolean fixed_width, fixed_height;
	char *title_lc;

	gboolean dirty, escape_exits;
	NmtNewtWidget *focus;
#ifdef HAVE_NEWTFORMGETSCROLLPOSITION
	int scroll_position = 0;
#endif
} NmtNewtFormPrivate;

enum {
	PROP_0,
	PROP_TITLE,
	PROP_FULLSCREEN,
	PROP_FULLSCREEN_VERTICAL,
	PROP_FULLSCREEN_HORIZONTAL,
	PROP_X,
	PROP_Y,
	PROP_WIDTH,
	PROP_HEIGHT,
	PROP_PADDING,
	PROP_ESCAPE_EXITS,

	LAST_PROP
};

enum {
	QUIT,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void nmt_newt_form_redraw (NmtNewtForm *form);

/**
 * nmt_newt_form_new:
 * @title: (allow-none): the form title
 *
 * Creates a new form, which will be shown centered on the screen.
 * Compare nmt_newt_form_new_fullscreen(). You can also position a
 * form manually by setting its #NmtNewtForm:x and #NmtNewtForm:y
 * properties at construct time, and/or by setting
 * #NmtNewtForm:fullscreen, #NmtNewtform:fullscreen-horizontal, or
 * #NmtNewtForm:fullscreen-vertical.
 *
 * If @title is NULL, the form will have no title.
 *
 * Returns: a new #NmtNewtForm
 */
NmtNewtForm *
nmt_newt_form_new (const char *title)
{
	return g_object_new (NMT_TYPE_NEWT_FORM,
	                     "title", title,
	                     NULL);
}

/**
 * nmt_newt_form_new_fullscreen:
 * @title: (allow-none): the form title
 *
 * Creates a new fullscreen form. Compare nmt_newt_form_new().
 *
 * If @title is NULL, the form will have no title.
 *
 * Returns: a new #NmtNewtForm
 */
NmtNewtForm *
nmt_newt_form_new_fullscreen (const char *title)
{
	return g_object_new (NMT_TYPE_NEWT_FORM,
	                     "title", title,
	                     "fullscreen", TRUE,
	                     NULL);
}

static void
nmt_newt_form_init (NmtNewtForm *form)
{
	g_object_ref_sink (form);
}

static void
nmt_newt_form_finalize (GObject *object)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (object);

	g_free (priv->title_lc);
	g_clear_object (&priv->focus);

	G_OBJECT_CLASS (nmt_newt_form_parent_class)->finalize (object);
}

static void
nmt_newt_form_needs_rebuild (NmtNewtWidget *widget)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (widget);

	if (!priv->dirty) {
		priv->dirty = TRUE;
		nmt_newt_form_redraw (NMT_NEWT_FORM (widget));
	}
}

static void
nmt_newt_form_remove (NmtNewtContainer *container,
                      NmtNewtWidget    *widget)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (container);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_newt_form_parent_class);

	g_return_if_fail (widget == priv->content);

	parent_class->remove (container, widget);
	priv->content = NULL;
}

/**
 * nmt_newt_form_set_content:
 * @form: the #NmtNewtForm
 * @content: the form's content
 *
 * Sets @form's content to be @content.
 */
void
nmt_newt_form_set_content (NmtNewtForm      *form,
                           NmtNewtWidget    *content)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (form);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_newt_form_parent_class);

	if (priv->content)
		nmt_newt_form_remove (NMT_NEWT_CONTAINER (form), priv->content);

	priv->content = content;

	if (priv->content)
		parent_class->add (NMT_NEWT_CONTAINER (form), content);
}

static void
nmt_newt_form_build (NmtNewtForm *form)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (form);
	int screen_height, screen_width, form_height, form_width;
	newtComponent *cos;
	int i;

	priv->dirty = FALSE;
	nmt_newt_widget_realize (NMT_NEWT_WIDGET (form));

	nmt_newt_widget_size_request (priv->content, &form_width, &form_height);
	newtGetScreenSize (&screen_width, &screen_height);

	if (!priv->fixed_width)
		priv->width = MIN (form_width + 2 * priv->padding, screen_width - 2);
	if (!priv->fixed_height)
		priv->height = MIN (form_height + 2 * priv->padding, screen_height - 2);

	if (!priv->fixed_x)
		priv->x = (screen_width - form_width) / 2;
	if (!priv->fixed_y)
		priv->y = (screen_height - form_height) / 2;

	nmt_newt_widget_size_allocate (priv->content,
	                               priv->padding,
	                               priv->padding,
	                               priv->width - 2 * priv->padding,
	                               priv->height - 2 * priv->padding);

	if (priv->height - 2 * priv->padding < form_height) {
		newtComponent scroll_bar =
			newtVerticalScrollbar (priv->width - 1, 0, priv->height,
			                       NEWT_COLORSET_WINDOW,
			                       NEWT_COLORSET_ACTCHECKBOX);

		priv->form = newtForm (scroll_bar, NULL, NEWT_FLAG_NOF12);
		newtFormAddComponent (priv->form, scroll_bar);
		newtFormSetHeight (priv->form, priv->height - 2);
	} else
		priv->form = newtForm (NULL, NULL, NEWT_FLAG_NOF12);

	if (priv->escape_exits)
		newtFormAddHotKey (priv->form, NEWT_KEY_ESCAPE);

	cos = nmt_newt_widget_get_components (priv->content);
	for (i = 0; cos[i]; i++)
		newtFormAddComponent (priv->form, cos[i]);
	g_free (cos);

	if (priv->focus) {
		newtComponent fco;

		fco = nmt_newt_widget_get_focus_component (priv->focus);
		if (fco)
			newtFormSetCurrent (priv->form, fco);
	}
#ifdef HAVE_NEWTFORMGETSCROLLPOSITION
	if (priv->scroll_position)
		newtFormSetScrollPosition (priv->form, priv->scroll_position);
#endif

	newtOpenWindow (priv->x, priv->y, priv->width, priv->height, priv->title_lc);
}

static void
nmt_newt_form_destroy (NmtNewtForm *form)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (form);

#ifdef HAVE_NEWTFORMGETSCROLLPOSITION
	priv->scroll_position = newtFormGetScrollPosition (priv->form);
#endif

	newtFormDestroy (priv->form);
	priv->form = NULL;
	newtPopWindowNoRefresh ();

	nmt_newt_widget_unrealize (NMT_NEWT_WIDGET (form));
}

/* A "normal" newt program would call newtFormRun() to run newt's main loop
 * and process events. But we want to let GLib's main loop control the program
 * (eg, so libnm-glib can process D-Bus notifications). So we call this function
 * to run a single iteration of newt's main loop (or rather, to run newt's
 * main loop for 1ms) whenever there are events for newt to process (redrawing
 * or keypresses).
 */
static void
nmt_newt_form_iterate (NmtNewtForm *form)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (form);
	NmtNewtWidget *focus;
	struct newtExitStruct es;

	if (priv->dirty) {
		nmt_newt_form_destroy (form);
		nmt_newt_form_build (form);
	}

	newtFormSetTimer (priv->form, 1);
	newtFormRun (priv->form, &es);

	if (   es.reason == NEWT_EXIT_HOTKEY
	    || es.reason == NEWT_EXIT_ERROR) {
		/* The user hit Esc or there was an error. */
		g_clear_object (&priv->focus);
		nmt_newt_form_quit (form);
		return;
	}

	if (es.reason == NEWT_EXIT_COMPONENT) {
		/* The user hit Return/Space on a component; update the form focus
		 * to point that that component, and activate it.
		 */
		focus = nmt_newt_widget_find_component (priv->content, es.u.co);
		if (focus) {
			nmt_newt_form_set_focus (form, focus);
			nmt_newt_widget_activated (focus);
		}
	} else {
		/* The 1ms timer ran out. Update focus but don't do anything else. */
		focus = nmt_newt_widget_find_component (priv->content,
		                                        newtFormGetCurrent (priv->form));
		if (focus)
			nmt_newt_form_set_focus (form, focus);
	}
}

/* @form_stack keeps track of all currently-displayed forms, from top to bottom.
 * @keypress_source is the global stdin-monitoring GSource. When it triggers,
 * nmt_newt_form_keypress_callback() iterates the top-most form, so it can
 * process the keypress.
 */
static GSList *form_stack;
static GSource *keypress_source;

static gboolean
nmt_newt_form_keypress_callback (int          fd,
                                 GIOCondition condition,
                                 gpointer     user_data)
{
	g_return_val_if_fail (form_stack != NULL, FALSE);

	nmt_newt_form_iterate (form_stack->data);
	return TRUE;
}

static gboolean
nmt_newt_form_timeout_callback (gpointer user_data)
{
	if (form_stack)
		nmt_newt_form_iterate (form_stack->data);
	return FALSE;
}

static void
nmt_newt_form_redraw (NmtNewtForm *form)
{
	g_timeout_add (0, nmt_newt_form_timeout_callback, NULL);
}

static void
nmt_newt_form_real_show (NmtNewtForm *form)
{
	if (!keypress_source) {
		GIOChannel *io;

		io = g_io_channel_unix_new (STDIN_FILENO);
		keypress_source = g_io_create_watch (io, G_IO_IN);
		g_source_set_can_recurse (keypress_source, TRUE);
		g_source_set_callback (keypress_source,
		                       (GSourceFunc) nmt_newt_form_keypress_callback,
		                       NULL, NULL);
		g_source_attach (keypress_source, NULL);
		g_io_channel_unref (io);
	}

	nmt_newt_form_build (form);
	form_stack = g_slist_prepend (form_stack, g_object_ref (form));
	nmt_newt_form_redraw (form);
}

/**
 * nmt_newt_form_show:
 * @form: an #NmtNewtForm
 *
 * Displays @form and begins running it asynchronously in the default
 * #GMainContext. If another form is currently running, it will remain
 * visible in the background, but will not be able to receive keyboard
 * input until @form exits.
 *
 * Call nmt_newt_form_quit() to quit the form.
 */
void
nmt_newt_form_show (NmtNewtForm *form)
{
	NMT_NEWT_FORM_GET_CLASS (form)->show (form);
}

/**
 * nmt_newt_form_run_sync:
 * @form: an #NmtNewtForm
 *
 * Displays @form as with nmt_newt_form_show(), but then iterates the
 * #GMainContext internally until @form exits.
 *
 * Returns: the widget whose activation caused @form to exit, or
 *   %NULL if it was not caused by a widget. FIXME: this exit value is
 *   sort of weird and may not be 100% accurate anyway.
 */
NmtNewtWidget *
nmt_newt_form_run_sync (NmtNewtForm *form)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (form);

	nmt_newt_form_show (form);
	while (priv->form)
		g_main_context_iteration (NULL, TRUE);

	return priv->focus;
}

/**
 * nmt_newt_form_quit:
 * @form: an #NmtNewtForm
 *
 * Causes @form to exit.
 */
void
nmt_newt_form_quit (NmtNewtForm *form)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (form);

	g_return_if_fail (priv->form != NULL);

	nmt_newt_form_destroy (form);

	form_stack = g_slist_remove (form_stack, form);

	if (form_stack)
		nmt_newt_form_iterate (form_stack->data);
	else if (keypress_source) {
		g_source_destroy (keypress_source);
		g_clear_pointer (&keypress_source, g_source_unref);
	}

	g_signal_emit (form, signals[QUIT], 0);
	g_object_unref (form);
}

/**
 * nmt_newt_form_set_focus:
 * @form: an #NmtNewtForm
 * @widget: the widget to focus
 *
 * Focuses @widget in @form.
 */
void
nmt_newt_form_set_focus (NmtNewtForm   *form,
                         NmtNewtWidget *widget)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (form);

	g_return_if_fail (priv->form != NULL);

	if (priv->focus == widget)
		return;

	if (priv->focus)
		g_object_unref (priv->focus);
	priv->focus = widget;
	if (priv->focus)
		g_object_ref (priv->focus);
}

static void
nmt_newt_form_set_property (GObject      *object,
                            guint         prop_id,
                            const GValue *value,
                            GParamSpec   *pspec)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (object);
	int screen_width, screen_height;

	switch (prop_id) {
	case PROP_TITLE:
		if (g_value_get_string (value)) {
			priv->title_lc = nmt_newt_locale_from_utf8 (g_value_get_string (value));
		} else
			priv->title_lc = NULL;
		break;
	case PROP_FULLSCREEN:
		if (g_value_get_boolean (value)) {
			newtGetScreenSize (&screen_width, &screen_height);
			priv->x = priv->y = 2;
			priv->fixed_x = priv->fixed_y = TRUE;
			priv->width = screen_width - 4;
			priv->height = screen_height - 4;
			priv->fixed_width = priv->fixed_height = TRUE;
		}
		break;
	case PROP_FULLSCREEN_VERTICAL:
		if (g_value_get_boolean (value)) {
			newtGetScreenSize (&screen_width, &screen_height);
			priv->y = 2;
			priv->fixed_y = TRUE;
			priv->height = screen_height - 4;
			priv->fixed_height = TRUE;
		}
		break;
	case PROP_FULLSCREEN_HORIZONTAL:
		if (g_value_get_boolean (value)) {
			newtGetScreenSize (&screen_width, &screen_height);
			priv->x = 2;
			priv->fixed_x = TRUE;
			priv->width = screen_width - 4;
			priv->fixed_width = TRUE;
		}
		break;
	case PROP_X:
		if (g_value_get_uint (value)) {
			priv->x = g_value_get_uint (value);
			priv->fixed_x = TRUE;
		}
		break;
	case PROP_Y:
		if (g_value_get_uint (value)) {
			priv->y = g_value_get_uint (value);
			priv->fixed_y = TRUE;
		}
		break;
	case PROP_WIDTH:
		if (g_value_get_uint (value)) {
			priv->width = g_value_get_uint (value);
			priv->fixed_width = TRUE;
		}
		break;
	case PROP_HEIGHT:
		if (g_value_get_uint (value)) {
			priv->height = g_value_get_uint (value);
			priv->fixed_height = TRUE;
		}
		break;
	case PROP_PADDING:
		priv->padding = g_value_get_uint (value);
		break;
	case PROP_ESCAPE_EXITS:
		priv->escape_exits = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_form_get_property (GObject    *object,
                            guint       prop_id,
                            GValue     *value,
                            GParamSpec *pspec)
{
	NmtNewtFormPrivate *priv = NMT_NEWT_FORM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_TITLE:
		if (priv->title_lc) {
			g_value_take_string (value, nmt_newt_locale_to_utf8 (priv->title_lc));
		} else
			g_value_set_string (value, NULL);
		break;
	case PROP_X:
		g_value_set_uint (value, priv->x);
		break;
	case PROP_Y:
		g_value_set_uint (value, priv->y);
		break;
	case PROP_WIDTH:
		g_value_set_uint (value, priv->width);
		break;
	case PROP_HEIGHT:
		g_value_set_uint (value, priv->height);
		break;
	case PROP_PADDING:
		g_value_set_uint (value, priv->padding);
		break;
	case PROP_ESCAPE_EXITS:
		g_value_set_boolean (value, priv->escape_exits);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_form_class_init (NmtNewtFormClass *form_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (form_class);
	NmtNewtContainerClass *container_class = NMT_NEWT_CONTAINER_CLASS (form_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (form_class);

	g_type_class_add_private (form_class, sizeof (NmtNewtFormPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_form_set_property;
	object_class->get_property = nmt_newt_form_get_property;
	object_class->finalize     = nmt_newt_form_finalize;

	widget_class->needs_rebuild = nmt_newt_form_needs_rebuild;

	container_class->remove = nmt_newt_form_remove;

	form_class->show = nmt_newt_form_real_show;

	/* signals */

	/**
	 * NmtNewtForm::quit:
	 * @form: the #NmtNewtForm
	 *
	 * Emitted when the form quits.
	 */
	signals[QUIT] =
		g_signal_new ("quit",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NmtNewtFormClass, quit),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	/**
	 * NmtNewtForm:title:
	 *
	 * The form's title. If non-%NULL, this will be displayed above
	 * the form in its border.
	 */
	g_object_class_install_property (object_class, PROP_TITLE,
	                                 g_param_spec_string ("title", "", "",
	                                                      NULL,
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_STATIC_STRINGS |
	                                                      G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:fullscreen:
	 *
	 * If %TRUE, the form will fill the entire "screen" (ie, terminal
	 * window).
	 */
	g_object_class_install_property (object_class, PROP_FULLSCREEN,
	                                 g_param_spec_boolean ("fullscreen", "", "",
	                                                       FALSE,
	                                                       G_PARAM_WRITABLE |
	                                                       G_PARAM_STATIC_STRINGS |
	                                                       G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:fullscreen-vertical:
	 *
	 * If %TRUE, the form will fill the entire "screen" (ie, terminal
	 * window) vertically, but not necessarily horizontally.
	 */
	g_object_class_install_property (object_class, PROP_FULLSCREEN_VERTICAL,
	                                 g_param_spec_boolean ("fullscreen-vertical", "", "",
	                                                       FALSE,
	                                                       G_PARAM_WRITABLE |
	                                                       G_PARAM_STATIC_STRINGS |
	                                                       G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:fullscreen-horizontal:
	 *
	 * If %TRUE, the form will fill the entire "screen" (ie, terminal
	 * window) horizontally, but not necessarily vertically.
	 */
	g_object_class_install_property (object_class, PROP_FULLSCREEN_HORIZONTAL,
	                                 g_param_spec_boolean ("fullscreen-horizontal", "", "",
	                                                       FALSE,
	                                                       G_PARAM_WRITABLE |
	                                                       G_PARAM_STATIC_STRINGS |
	                                                       G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:x:
	 *
	 * The form's x coordinate. By default, the form will be centered
	 * on the screen.
	 */
	g_object_class_install_property (object_class, PROP_X,
	                                 g_param_spec_uint ("x", "", "",
	                                                    0, G_MAXUINT, 0,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_STATIC_STRINGS |
	                                                    G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:y:
	 *
	 * The form's y coordinate. By default, the form will be centered
	 * on the screen.
	 */
	g_object_class_install_property (object_class, PROP_Y,
	                                 g_param_spec_uint ("y", "", "",
	                                                    0, G_MAXUINT, 0,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_STATIC_STRINGS |
	                                                    G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:width:
	 *
	 * The form's width. By default, this will be determined by the
	 * width of the form's content.
	 */
	g_object_class_install_property (object_class, PROP_WIDTH,
	                                 g_param_spec_uint ("width", "", "",
	                                                    0, G_MAXUINT, 0,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_STATIC_STRINGS |
	                                                    G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:height:
	 *
	 * The form's height. By default, this will be determined by the
	 * height of the form's content.
	 */
	g_object_class_install_property (object_class, PROP_HEIGHT,
	                                 g_param_spec_uint ("height", "", "",
	                                                    0, G_MAXUINT, 0,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_STATIC_STRINGS |
	                                                    G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:padding:
	 *
	 * The padding between the form's content and its border.
	 */
	g_object_class_install_property (object_class, PROP_PADDING,
	                                 g_param_spec_uint ("padding", "", "",
	                                                    0, G_MAXUINT, 1,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_STATIC_STRINGS |
	                                                    G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NmtNewtForm:escape-exits:
	 *
	 * If %TRUE, then hitting the Escape key will cause the form to
	 * exit.
	 */
	g_object_class_install_property (object_class, PROP_ESCAPE_EXITS,
	                                 g_param_spec_boolean ("escape-exits", "", "",
	                                                       FALSE,
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_STATIC_STRINGS |
	                                                       G_PARAM_CONSTRUCT_ONLY));
}
