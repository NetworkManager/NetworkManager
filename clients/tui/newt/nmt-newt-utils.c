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
 * SECTION:nmt-newt-utils
 * @short_description: Utility functions
 */

#include "nm-default.h"

#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>

#include "nmt-newt-utils.h"

static void
nmt_newt_dialog_g_log_handler (const char     *log_domain,
                               GLogLevelFlags  log_level,
                               const char     *message,
                               gpointer        user_data)
{
	const char *level_name;
	char *full_message;
	int screen_width, screen_height;
	newtComponent text, ok, form;
	newtGrid grid;

	g_assert (!(log_level & G_LOG_FLAG_RECURSION));

	if (log_level & G_LOG_LEVEL_DEBUG)
		return;

	switch (log_level & G_LOG_LEVEL_MASK) {
	case G_LOG_LEVEL_ERROR:
		level_name = "ERROR";
		break;
	case G_LOG_LEVEL_CRITICAL:
		level_name = "CRITICAL";
		break;
	case G_LOG_LEVEL_WARNING:
		level_name = "WARNING";
		break;
	case G_LOG_LEVEL_MESSAGE:
		level_name = "Message";
		break;
	default:
		level_name = NULL;
	}

	full_message = g_strdup_printf ("%s%s%s%s%s",
	                                log_domain ? log_domain : "",
	                                log_domain && level_name ? " " : "",
	                                level_name ? level_name : "",
	                                log_domain || level_name ? ": " : "",
	                                message);

	/* newtWinMessage() wraps the window too narrowly by default, so
	 * we don't want to use that. But we intentionally avoid using any
	 * NmtNewt classes, to avoid possible error recursion.
	 */

	newtGetScreenSize (&screen_width, &screen_height);
	text = newtTextboxReflowed (-1, -1, full_message, MAX (70, screen_width - 10), 0, 0, 0);
	g_free (full_message);

	ok = newtButton (-1, -1, "OK");

	grid = newtCreateGrid (1, 2);
	newtGridSetField (grid, 0, 0, NEWT_GRID_COMPONENT, text, 0, 0, 0, 0, 0, 0);
	newtGridSetField (grid, 0, 1, NEWT_GRID_COMPONENT, ok, 0, 1, 0, 0,
	                  NEWT_ANCHOR_RIGHT, 0);

	newtGridWrappedWindow (grid, (char *) (level_name ? level_name : ""));
	newtGridFree (grid, TRUE);

	form = newtForm (NULL, NULL, 0);
	newtFormAddComponents (form, text, ok, NULL);
	newtRunForm (form);
	newtFormDestroy (form);
	newtPopWindow ();
}

static void
nmt_newt_basic_g_log_handler (const char     *log_domain,
                              GLogLevelFlags  log_level,
                              const char     *message,
                              gpointer        user_data)
{
	newtSuspend ();
	g_log_default_handler (log_domain, log_level, message, NULL);
	newtResume ();
}

static void
nmt_newt_suspend_callback (gpointer user_data)
{
	newtSuspend ();
	kill (getpid (), SIGTSTP);
	newtResume ();
}

/**
 * nmt_newt_init:
 *
 * Wrapper for newtInit() that also does some nmt-newt-internal setup.
 * This should be called once, before any other nmt-newt functions.
 */
void
nmt_newt_init (void)
{
	newtInit ();
	newtCls ();

	newtSetColor (NEWT_COLORSET_CHECKBOX, "black", "lightgray");
	newtSetColor (NMT_NEWT_COLORSET_BAD_LABEL, "red", "lightgray");
	newtSetColor (NMT_NEWT_COLORSET_PLAIN_LABEL, "black", "lightgray");
	newtSetColor (NMT_NEWT_COLORSET_DISABLED_BUTTON, "blue", "lightgray");
	newtSetColor (NMT_NEWT_COLORSET_TEXTBOX_WITH_BACKGROUND, "black", "white");

	if (g_getenv ("NMTUI_DEBUG"))
		g_log_set_default_handler (nmt_newt_dialog_g_log_handler, NULL);
	else
		g_log_set_default_handler (nmt_newt_basic_g_log_handler, NULL);

	newtSetSuspendCallback (nmt_newt_suspend_callback, NULL);
}

/**
 * nmt_newt_finished:
 *
 * Wrapper for newtFinished(). Should be called at the end of the program.
 */
void
nmt_newt_finished (void)
{
	newtFinished ();
	g_log_set_default_handler (g_log_default_handler, NULL);
}

/**
 * nmt_newt_message_dialog:
 * @message: a printf()-style message format
 * @...: arguments
 *
 * Displays the given message in a dialog box with a single "OK"
 * button, and returns after the user clicks "OK".
 */
void
nmt_newt_message_dialog  (const char *message,
                          ...)
{
	va_list ap;
	char *msg, *msg_lc, *ok_lc;

	va_start (ap, message);
	msg = g_strdup_vprintf (message, ap);
	va_end (ap);

	msg_lc = nmt_newt_locale_from_utf8 (msg);
	ok_lc = nmt_newt_locale_from_utf8 (_("OK"));
	newtWinMessage (NULL, ok_lc, "%s", msg_lc);

	g_free (ok_lc);
	g_free (msg_lc);
	g_free (msg);
}

/**
 * nmt_newt_choice_dialog:
 * @button1: the label for the first button
 * @button2: the label for the second button
 * @message: a printf()-style message format
 * @...: arguments
 *
 * Displays the given message in a dialog box with two buttons with
 * the indicated labels, and waits for the user to click one.
 *
 * Returns: which button was clicked: 0 for @button1 or 1 for @button2
 */
int
nmt_newt_choice_dialog (const char *button1,
                        const char *button2,
                        const char *message,
                        ...)
{
	va_list ap;
	char *msg, *msg_lc, *button1_lc, *button2_lc;
	int choice;

	va_start (ap, message);
	msg = g_strdup_vprintf (message, ap);
	va_end (ap);

	msg_lc = nmt_newt_locale_from_utf8 (msg);
	button1_lc = nmt_newt_locale_from_utf8 (button1);
	button2_lc = nmt_newt_locale_from_utf8 (button2);
	choice = newtWinChoice (NULL, button1_lc, button2_lc, "%s", msg_lc);

	g_free (button1_lc);
	g_free (button2_lc);
	g_free (msg_lc);
	g_free (msg);

	return choice;
}

/**
 * nmt_newt_locale_to_utf8:
 * @str_lc: a string in the user's locale encoding
 *
 * Convenience wrapper around g_locale_to_utf8().
 *
 * Note that libnewt works in terms of the user's locale character
 * set, NOT UTF-8, so all strings received from libnewt must be
 * converted back to UTF-8 before being returned to the caller or used
 * in other APIs.
 *
 * Returns: @str_lc, converted to UTF-8.
 */
char *
nmt_newt_locale_to_utf8 (const char *str_lc)
{
	char *str_utf8;

	str_utf8 = g_locale_to_utf8 (str_lc, -1, NULL, NULL, NULL);
	if (!str_utf8)
		str_utf8 = g_strdup ("");
	return str_utf8;
}

/**
 * nmt_newt_locale_from_utf8:
 * @str_utf8: a UTF-8 string
 *
 * Convenience wrapper around g_locale_from_utf8().
 *
 * Note that libnewt works in terms of the user's locale character
 * set, NOT UTF-8, so all strings from nmt-newt must be converted to
 * locale encoding before being passed to libnewt.
 *
 * Returns: @str_utf8, converted to the user's locale encoding.
 */
char *
nmt_newt_locale_from_utf8 (const char *str_utf8)
{
	char *str_lc;

	str_lc = g_locale_from_utf8 (str_utf8, -1, NULL, NULL, NULL);
	if (!str_lc)
		str_lc = g_strdup ("");
	return str_lc;
}

/**
 * nmt_newt_text_width
 * @str: a UTF-8 string
 *
 * Computes the width (in terminal columns) of @str.
 *
 * Returns: the width of @str
 */
int
nmt_newt_text_width (const char *str)
{
	int width;
	gunichar ch;

	for (width = 0; *str; str = g_utf8_next_char (str)) {
		ch = g_utf8_get_char (str);

		/* Based on _vte_iso2022_unichar_width */
		if (G_LIKELY (ch < 0x80))
			width += 1;
		else if (G_UNLIKELY (g_unichar_iszerowidth (ch)))
			width += 0;
		else if (G_UNLIKELY (g_unichar_iswide (ch)))
			width += 2;
		else
			width += 1;
	}

	return width;
}

/**
 * nmt_newt_edit_string:
 * @data: data to edit
 *
 * libnewt does not have a multi-line editable text component, so
 * nmt-newt provides this function instead, which will open the user's
 * editor to edit a file containing the given @data (ensuring that the
 * current screen state is saved before starting the editor and
 * restored after it returns).
 *
 * Returns: the edited data, or %NULL if an error occurred.
 */
char *
nmt_newt_edit_string (const char *data)
{
	gssize len, nwrote;
	char *filename, *argv[3];
	GError *error = NULL;
	int fd, status;
	char *new_data = NULL;

	fd = g_file_open_tmp ("XXXXXX.json", &filename, &error);
	if (fd == -1) {
		nmt_newt_message_dialog (_("Could not create temporary file: %s"), error->message);
		g_error_free (error);
		return NULL;
	}

	len = data ? strlen (data) : 0;
	while (len) {
		do
			nwrote = write (fd, data, len);
		while (nwrote == -1 && errno == EINTR);

		len -= nwrote;
		data += nwrote;
	}
	close (fd);

	argv[0] = (char *) g_getenv ("VISUAL");
	if (!argv[0])
		argv[0] = (char *) g_getenv ("EDITOR");
	if (!argv[0])
		argv[0] = (char *) "vi";
	argv[1] = filename;
	argv[2] = NULL;

	newtSuspend ();
	g_spawn_sync (NULL, argv, NULL,
	              G_SPAWN_SEARCH_PATH | G_SPAWN_CHILD_INHERITS_STDIN,
	              NULL, NULL, NULL, NULL,
	              &status, &error);
	newtResume ();

	if (error) {
		nmt_newt_message_dialog (_("Could not create temporary file: %s"), error->message);
		g_error_free (error);
		goto done;
	}

#if GLIB_CHECK_VERSION (2, 34, 0)
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	if (!g_spawn_check_exit_status (status, &error)) {
		nmt_newt_message_dialog (_("Editor failed: %s"), error->message);
		g_error_free (error);
		goto done;
	}
	G_GNUC_END_IGNORE_DEPRECATIONS
#else
	if (WIFEXITED (status)) {
		if (WEXITSTATUS (status) != 0)
			nmt_newt_message_dialog (_("Editor failed with status %d"), WEXITSTATUS (status));
	} else if (WIFSIGNALED (status))
		nmt_newt_message_dialog (_("Editor failed with signal %d"), WTERMSIG (status));
#endif

	if (!g_file_get_contents (filename, &new_data, NULL, &error)) {
		nmt_newt_message_dialog (_("Could not re-read file: %s"), error->message);
		g_error_free (error);
		goto done;
	}

 done:
	unlink (filename);
	g_free (filename);

	return new_data;
}	

