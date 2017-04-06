/* nmcli - command-line tool to control NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2010 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nm-client-utils.h"
#include "nm-meta-setting-access.h"

#include "common.h"
#include "settings.h"

#define ML_HEADER_WIDTH 79
#define ML_VALUE_INDENT 40

/*****************************************************************************/

static const char *
_meta_type_nmc_generic_info_get_name (const NMMetaAbstractInfo *abstract_info)
{
	return ((const NmcMetaGenericInfo *) abstract_info)->name;
}

static const NMMetaAbstractInfo *const*
_meta_type_nmc_generic_info_get_nested (const NMMetaAbstractInfo *abstract_info,
                                        guint *out_len,
                                        gpointer *out_to_free)
{
	const NmcMetaGenericInfo *info;
	guint n;

	info = (const NmcMetaGenericInfo *) abstract_info;

	if (out_len) {
		n = 0;
		if (info->nested) {
			for (; info->nested[n]; n++) {
			}
		}
		*out_len = n;
	}
	*out_to_free = NULL;
	return (const NMMetaAbstractInfo *const*) info->nested;
}

static gconstpointer
_meta_type_nmc_generic_info_get_fcn (const NMMetaEnvironment *environment,
                                     gpointer environment_user_data,
                                     const NMMetaAbstractInfo *abstract_info,
                                     gpointer target,
                                     NMMetaAccessorGetType get_type,
                                     NMMetaAccessorGetFlags get_flags,
                                     gpointer *out_to_free)
{
	const NmcMetaGenericInfo *info = (const NmcMetaGenericInfo *) abstract_info;

	nm_assert (!out_to_free || !*out_to_free);

	if (!info->get_fcn)
		g_return_val_if_reached (NULL);
	if (!NM_IN_SET (get_type,
	                NM_META_ACCESSOR_GET_TYPE_PARSABLE,
	                NM_META_ACCESSOR_GET_TYPE_PRETTY,
	                NM_META_ACCESSOR_GET_TYPE_TERMFORMAT))
		g_return_val_if_reached (NULL);

	/* omitting the out_to_free value is only allowed for TERMFORMAT. */
	nm_assert (out_to_free || NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_TERMFORMAT));

	return info->get_fcn (environment, environment_user_data,
	                      info, target,
	                      get_type, get_flags,
	                      out_to_free);
}

const NMMetaType nmc_meta_type_generic_info = {
	.type_name =         "nmc-generic-info",
	.get_name =          _meta_type_nmc_generic_info_get_name,
	.get_nested =        _meta_type_nmc_generic_info_get_nested,
	.get_fcn =           _meta_type_nmc_generic_info_get_fcn,
};

/*****************************************************************************/

static gboolean
use_colors (NmcColorOption color_option)
{
	if (color_option == NMC_USE_COLOR_AUTO) {
		static NmcColorOption cached = NMC_USE_COLOR_AUTO;

		if (G_UNLIKELY (cached == NMC_USE_COLOR_AUTO)) {
			if (   g_strcmp0 (g_getenv ("TERM"), "dumb") == 0
				|| !isatty (fileno (stdout)))
				cached = NMC_USE_COLOR_NO;
			else
				cached = NMC_USE_COLOR_YES;
		}
		return cached == NMC_USE_COLOR_YES;
	}

	return color_option == NMC_USE_COLOR_YES;
}

static const char *
colorize_string (NmcColorOption color_option,
                 NMMetaTermColor color,
                 NMMetaTermFormat color_fmt,
                 const char *str,
                 char **out_to_free)
{
	const char *out = str;

	if (   use_colors (color_option)
	    && (color != NM_META_TERM_COLOR_NORMAL || color_fmt != NM_META_TERM_FORMAT_NORMAL)) {
		*out_to_free = nmc_colorize (color_option, color, color_fmt, "%s", str);
		out = *out_to_free;
	}

	return out;
}

/*****************************************************************************/

static gboolean
parse_global_arg (NmCli *nmc, const char *arg)
{
	if (nmc_arg_is_option (arg, "ask"))
		nmc->ask = TRUE;
	else if (nmc_arg_is_option (arg, "show-secrets"))
		nmc->nmc_config_mutable.show_secrets = TRUE;
	else
		return FALSE;

	return TRUE;
}
/**
 * next_arg:
 * @nmc: NmCli data
 * @*argc: pointer to left number of arguments to parse
 * @***argv: pointer to const char *array of arguments still to parse
 * @...: a %NULL terminated list of cmd options to match (e.g., "--active")
 *
 * Takes care of autocompleting options when needed and performs
 * match against passed options while moving forward the pointer
 * to the remaining arguments.
 *
 * Returns: the number of the matched option  if a match is found against
 * one of the custom options passed; 0 if no custom option matched and still
 * some args need to be processed or autocompletion has been performed;
 * -1 otherwise (no more args).
 */
int
next_arg (NmCli *nmc, int *argc, char ***argv, ...)
{
	va_list args;
	const char *cmd_option;

	g_assert (*argc >= 0);

	do {
		int cmd_option_pos = 1;

		if (*argc > 0) {
			(*argc)--;
			(*argv)++;
		}
		if (*argc == 0)
			return -1;


		va_start (args, argv);

		if (nmc && nmc->complete && *argc == 1) {
			while ((cmd_option = va_arg (args, const char *)))
				nmc_complete_strings (**argv, cmd_option, NULL);

			if (***argv == '-')
				nmc_complete_strings (**argv, "--ask", "--show-secrets", NULL);

			va_end (args);
			return 0;
		}

		/* Check command dependent options first */
		while ((cmd_option = va_arg (args, const char *))) {
			/* strip heading "--" form cmd_option */
			if (nmc_arg_is_option (**argv, cmd_option + 2)) {
				va_end (args);
				return cmd_option_pos;
			}
			cmd_option_pos++;
		}

		va_end (args);

	} while (nmc && parse_global_arg (nmc, **argv));

	return 0;
}

gboolean
nmc_arg_is_help (const char *arg)
{
	if (!arg)
		return FALSE;
	if (   matches (arg, "help")
	    || (g_str_has_prefix (arg, "-")  && matches (arg + 1, "help"))
	    || (g_str_has_prefix (arg, "--") && matches (arg + 2, "help"))) {
		return TRUE;
	}
	return FALSE;
}

gboolean
nmc_arg_is_option (const char *str, const char *opt_name)
{
	const char *p;

	if (!str || !*str)
		return FALSE;

	if (str[0] != '-')
		return FALSE;

	p = (str[1] == '-') ? str + 2 : str + 1;

	return (*p ? matches (p, opt_name) : FALSE);
}

/*
 * Helper function to parse command-line arguments.
 * arg_arr: description of arguments to look for
 * last:    whether these are last expected arguments
 * argc:    command-line argument array size
 * argv:    command-line argument array
 * error:   error set on a failure (when FALSE is returned)
 * Returns: TRUE on success, FALSE on an error and sets 'error'
 */
gboolean
nmc_parse_args (nmc_arg_t *arg_arr, gboolean last, int *argc, char ***argv, GError **error)
{
	nmc_arg_t *p;
	gboolean found;
	gboolean have_mandatory;

	g_return_val_if_fail (arg_arr != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	while (*argc > 0) {
		found = FALSE;

		for (p = arg_arr; p->name; p++) {
			if (strcmp (**argv, p->name) == 0) {

				if (p->found) {
					/* Don't allow repeated arguments, because the argument of the same
					 * name could be used later on the line for another purpose. Assume
					 * that's the case and return.
					 */
					return TRUE;
				}

				if (p->has_value) {
					(*argc)--;
					(*argv)++;
					if (!*argc) {
						g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
						             _("Error: value for '%s' argument is required."), *(*argv-1));
						return FALSE;
					}
					*(p->value) = **argv;
				}
				p->found = TRUE;
				found = TRUE;
				break;
			}
		}

		if (!found) {
			have_mandatory = TRUE;
			for (p = arg_arr; p->name; p++) {
				if (p->mandatory && !p->found) {
					have_mandatory = FALSE;
					break;
				}
			}

			if (have_mandatory && !last)
				return TRUE;

			if (p->name)
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: Argument '%s' was expected, but '%s' provided."), p->name, **argv);
			else
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: Unexpected argument '%s'"), **argv);
			return FALSE;
		}

		next_arg (NULL, argc, argv, NULL);
	}

	return TRUE;
}

/*
 *  Convert SSID to a hex string representation.
 *  Caller has to free the returned string using g_free()
 */
char *
ssid_to_hex (const char *str, gsize len)
{
	GString *printable;
	char *printable_str;
	int i;

	if (str == NULL || len == 0)
		return NULL;

	printable = g_string_new (NULL);
	for (i = 0; i < len; i++) {
		g_string_append_printf (printable, "%02X", (unsigned char) str[i]);
	}
	printable_str = g_string_free (printable, FALSE);
	return printable_str;
}

/*
 * Erase terminal line using ANSI escape sequences.
 * It prints <ESC>[2K sequence to erase the line and then \r to return back
 * to the beginning of the line.
 *
 * http://www.termsys.demon.co.uk/vtansi.htm
 */
void
nmc_terminal_erase_line (void)
{
	/* We intentionally use printf(), not g_print() here, to ensure that
	 * GLib doesn't mistakenly try to convert the string.
	 */
	printf ("\33[2K\r");
	fflush (stdout);
}

/*
 * Print animated progress for an operation.
 * Repeated calls of the function will show rotating slash in terminal followed
 * by the string passed in 'str' argument.
 */
void
nmc_terminal_show_progress (const char *str)
{
	static int idx = 0;
	const char slashes[4] = {'|', '/', '-', '\\'};

	nmc_terminal_erase_line ();
	g_print ("%c %s", slashes[idx++], str ? str : "");
	fflush (stdout);
	if (idx == 4)
		idx = 0;
}

const char *
nmc_term_color_sequence (NMMetaTermColor color)
{
	switch (color) {
        case NM_META_TERM_COLOR_BLACK:
		return "\33[30m";
		break;
        case NM_META_TERM_COLOR_RED:
		return "\33[31m";
		break;
        case NM_META_TERM_COLOR_GREEN:
		return "\33[32m";
		break;
        case NM_META_TERM_COLOR_YELLOW:
		return "\33[33m";
		break;
        case NM_META_TERM_COLOR_BLUE:
		return "\33[34m";
		break;
        case NM_META_TERM_COLOR_MAGENTA:
		return "\33[35m";
		break;
        case NM_META_TERM_COLOR_CYAN:
		return "\33[36m";
		break;
        case NM_META_TERM_COLOR_WHITE:
		return "\33[37m";
		break;
	default:
		return "";
		break;
	}
}

/* Parses @str for color as string or number */
NMMetaTermColor
nmc_term_color_parse_string (const char *str, GError **error)
{
	unsigned long color_int;
	static const char *colors[] = { "normal", "black", "red", "green", "yellow",
	                                "blue", "magenta", "cyan", "white", NULL };

	if (nmc_string_to_uint (str, TRUE, 0, 8, &color_int)) {
		return (NMMetaTermColor) color_int;
	} else {
		const char *color, **p;
		int i;

		color = nmc_string_is_valid (str, colors, error);
		for (p = colors, i = 0; *p != NULL; p++, i++) {
			if (*p == color)
				return (NMMetaTermColor) i;
		}
		return -1;
	}
}

const char *
nmc_term_format_sequence (NMMetaTermFormat format)
{
	switch (format) {
        case NM_META_TERM_FORMAT_BOLD:
		return "\33[1m";
		break;
        case NM_META_TERM_FORMAT_DIM:
		return "\33[2m";
		break;
        case NM_META_TERM_FORMAT_UNDERLINE:
		return "\33[4m";
		break;
        case NM_META_TERM_FORMAT_BLINK:
		return "\33[5m";
		break;
        case NM_META_TERM_FORMAT_REVERSE:
		return "\33[7m";
		break;
        case NM_META_TERM_FORMAT_HIDDEN:
		return "\33[8m";
		break;
	default:
		return "";
		break;
	}
}

char *
nmc_colorize (NmcColorOption color_option, NMMetaTermColor color, NMMetaTermFormat format, const char *fmt, ...)
{
	va_list args;
	char *str, *colored;
	const char *ansi_color, *color_end, *ansi_fmt, *format_end;
	static const char *end_seq = "\33[0m";

	va_start (args, fmt);
	str = g_strdup_vprintf (fmt, args);
	va_end (args);

	if (!use_colors (color_option))
		return str;

	ansi_color = nmc_term_color_sequence (color);
	ansi_fmt = nmc_term_format_sequence (format);
	color_end = *ansi_color ? end_seq : "";
	format_end = *ansi_fmt ? end_seq : "";

	colored = g_strdup_printf ("%s%s%s%s%s", ansi_fmt, ansi_color, str, color_end, format_end);
	g_free (str);
	return colored;
}

/*
 * Count characters belonging to terminal color escape sequences.
 * @start points to beginning of the string, @end points to the end,
 * or NULL if the string is nul-terminated.
 */
static int
nmc_count_color_escape_chars (const char *start, const char *end)
{
	int num = 0;
	gboolean inside = FALSE;

	if (end == NULL)
		end = start + strlen (start);

	while (start < end) {
		if (*start == '\33' && *(start+1) == '[')
			inside = TRUE;
		if (inside)
			num++;
		if (*start == 'm') 
			inside = FALSE;
		start++;
	}
	return num;
}

/* Filter out possible ANSI color escape sequences */
/* It directly modifies the passed string @str. */
void
nmc_filter_out_colors_inplace (char *str)
{
	const char *p1;
	char *p2;
	gboolean copy_char = TRUE;

	if (!str)
		return;

	p1 = p2 = str;
	while (*p1) {
		if (*p1 == '\33' && *(p1+1) == '[')
			copy_char = FALSE;
		if (copy_char)
			*p2++ = *p1;
		if (!copy_char && *p1 == 'm')
			copy_char = TRUE;
		p1++;
	}
	*p2 = '\0';
}

/* Filter out possible ANSI color escape sequences */
char *
nmc_filter_out_colors (const char *str)
{
	char *filtered;

	if (!str)
		return NULL;

	filtered = g_strdup (str);
	nmc_filter_out_colors_inplace (filtered);
	return filtered;
}

/*
 * Ask user for input and return the string.
 * The caller is responsible for freeing the returned string.
 */
char *
nmc_get_user_input (const char *ask_str)
{
	char *line = NULL;
	size_t line_ln = 0;
	ssize_t num;

	g_print ("%s", ask_str);
	num = getline (&line, &line_ln, stdin);

	/* Remove newline from the string */
	if (num < 1 || (num == 1 && line[0] == '\n')) {
		g_free (line);
		line = NULL;
	} else {
		if (line[num-1] == '\n')
			line[num-1] = '\0';
	}

	return line;
}

/*
 * Split string in 'line' according to 'delim' to (argument) array.
 */
int
nmc_string_to_arg_array (const char *line, const char *delim, gboolean unquote,
                         char ***argv, int *argc)
{
	char **arr;

	arr = nmc_strsplit_set (line ? line : "", delim ? delim : " \t", 0);

	if (unquote) {
		int i = 0;
		char *s;
		size_t l;
		const char *quotes = "\"'";

		while (arr && arr[i]) {
			s = arr[i];
			l = strlen (s);
			if (l >= 2) {
				if (strchr (quotes, s[0]) && s[l-1] == s[0]) {
					memmove (s, s+1, l-2);
					s[l-2] = '\0';
				}
			}
			i++;
		}
	}

	*argv = arr;
	*argc = g_strv_length (arr);

	return 0;
}

/*
 * Convert string array (char **) to description string in the form of:
 * "[string1, string2, ]"
 *
 * Returns: a newly allocated string. Caller must free it with g_free().
 */
char *
nmc_util_strv_for_display (const char *const*strv, gboolean brackets)
{
	GString *result;
	guint i = 0;

	result = g_string_sized_new (150);
	if (brackets)
		g_string_append_c (result, '[');
	while (strv && strv[i]) {
		if (result->len > 1)
			g_string_append (result, ", ");
		g_string_append (result, strv[i]);
		i++;
	}
	if (brackets)
		g_string_append_c (result, ']');

	return g_string_free (result, FALSE);
}

/*
 * Find out how many columns an UTF-8 string occupies on the screen.
 */
int
nmc_string_screen_width (const char *start, const char *end)
{
	int width = 0;
	const char *p = start;

	if (end == NULL)
		end = start + strlen (start);

	while (p < end) {
		width += g_unichar_iswide (g_utf8_get_char (p)) ? 2 : g_unichar_iszerowidth (g_utf8_get_char (p)) ? 0 : 1;
		p = g_utf8_next_char (p);
	}

	/* Subtract color escape sequences as they don't occupy space. */
	return width - nmc_count_color_escape_chars (start, NULL);
}

void
set_val_str (NmcOutputField fields_array[], guint32 idx, char *value)
{
	fields_array[idx].value = value;
	fields_array[idx].value_is_array = FALSE;
	fields_array[idx].free_value = TRUE;
}

void
set_val_strc (NmcOutputField fields_array[], guint32 idx, const char *value)
{
	fields_array[idx].value = (char *) value;
	fields_array[idx].value_is_array = FALSE;
	fields_array[idx].free_value = FALSE;
}

void
set_val_arr (NmcOutputField fields_array[], guint32 idx, char **value)
{
	fields_array[idx].value = value;
	fields_array[idx].value_is_array = TRUE;
	fields_array[idx].free_value = TRUE;
}

void
set_val_arrc (NmcOutputField fields_array[], guint32 idx, const char **value)
{
	fields_array[idx].value = (char **) value;
	fields_array[idx].value_is_array = TRUE;
	fields_array[idx].free_value = FALSE;
}

void
set_val_color_all (NmcOutputField fields_array[], NMMetaTermColor color)
{
	int i;

	for (i = 0; fields_array[i].info; i++) {
		fields_array[i].color = color;
	}
}

void
set_val_color_fmt_all (NmcOutputField fields_array[], NMMetaTermFormat format)
{
	int i;

	for (i = 0; fields_array[i].info; i++) {
		fields_array[i].color_fmt = format;
	}
}

/*
 * Free 'value' members in array of NmcOutputField
 */
void
nmc_free_output_field_values (NmcOutputField fields_array[])
{
	NmcOutputField *iter = fields_array;

	while (iter && iter->info) {
		if (iter->free_value) {
			if (iter->value_is_array)
				g_strfreev ((char **) iter->value);
			else
				g_free ((char *) iter->value);
			iter->value = NULL;
		}
		iter++;
	}
}

/*****************************************************************************/

typedef struct {
	guint idx;
	gsize self_offset_plus_1;
	gsize sub_offset_plus_1;
} OutputSelectionItem;

static NmcOutputSelection *
_output_selection_pack (const NMMetaAbstractInfo *const* fields_array,
                        GArray *array,
                        GString *str)
{
	NmcOutputSelection *result;
	guint i;
	guint len;

	len = array ? array->len : 0;

	/* re-organize the collected output data in one buffer that can be freed using
	 * g_free(). This makes allocation more complicated, but saves us from special
	 * handling for free. */
	result = g_malloc0 (sizeof (NmcOutputSelection) + (len * sizeof (NmcOutputSelectionItem)) + (str ? str->len : 0));
	*((guint *) &result->num) = len;
	if (len > 0) {
		char *pdata = &((char *) result)[sizeof (NmcOutputSelection) + (len * sizeof (NmcOutputSelectionItem))];

		if (str)
			memcpy (pdata, str->str, str->len);
		for (i = 0; i < len; i++) {
			const OutputSelectionItem *a = &g_array_index (array, OutputSelectionItem, i);
			NmcOutputSelectionItem *p = (NmcOutputSelectionItem *) &result->items[i];

			p->info = fields_array[a->idx];
			p->idx = a->idx;
			if (a->self_offset_plus_1 > 0)
				p->self_selection = &pdata[a->self_offset_plus_1 - 1];
			if (a->sub_offset_plus_1 > 0)
				p->sub_selection = &pdata[a->sub_offset_plus_1 - 1];
		}
	}

	return result;
}

static gboolean
_output_selection_select_one (const NMMetaAbstractInfo *const* fields_array,
                              const char *fields_prefix,
                              const char *fields_str,
                              gboolean validate_nested,
                              GArray **p_array,
                              GString **p_str,
                              GError **error)
{
	guint i, j;
	const char *i_name;
	const char *right;
	gboolean found = FALSE;
	const NMMetaAbstractInfo *fields_array_failure = NULL;
	gs_free char *fields_str_clone = NULL;

	nm_assert (fields_str);
	nm_assert (p_array);
	nm_assert (p_str);
	nm_assert (!error || !*error);

	right = strchr (fields_str, '.');
	if (right) {
		fields_str_clone = g_strdup (fields_str);
		fields_str_clone[right - fields_str] = '\0';
		i_name = fields_str_clone;
		right = &fields_str_clone[right - fields_str + 1];
	} else
		i_name = fields_str;

	if (!fields_array)
		goto not_found;

	for (i = 0; fields_array[i]; i++) {
		const NMMetaAbstractInfo *fi = fields_array[i];

		if (g_ascii_strcasecmp (i_name, nm_meta_abstract_info_get_name (fi)) != 0)
			continue;

		if (!right || !validate_nested) {
			found = TRUE;
			break;
		}

		if (fi->meta_type == &nm_meta_type_setting_info_editor) {
			const NMMetaSettingInfoEditor *fi_s = &fi->as.setting_info;

			for (j = 1; j < fi_s->properties_num; j++) {
				if (g_ascii_strcasecmp (right, fi_s->properties[j].property_name) == 0) {
					found = TRUE;
					break;
				}
			}
		} else if (fi->meta_type == &nmc_meta_type_generic_info) {
			const NmcMetaGenericInfo *fi_g = (const NmcMetaGenericInfo *) fi;

			for (j = 0; fi_g->nested && fi_g->nested[j]; j++) {
				if (g_ascii_strcasecmp (right, nm_meta_abstract_info_get_name ((const NMMetaAbstractInfo *) fi_g->nested[j])) == 0) {
					found = TRUE;
					break;
				}
			}
		}
		fields_array_failure = fields_array[i];
		break;
	}

	if (!found) {
not_found:
		if (   !right
		    && !fields_prefix
		    && (   !g_ascii_strcasecmp (i_name, "all")
		        || !g_ascii_strcasecmp (i_name, "common")))
			g_set_error (error, NMCLI_ERROR, 0, _("field '%s' has to be alone"), i_name);
		else {
			gs_free char *allowed_fields = NULL;

			if (fields_array_failure) {
				gs_free char *p = NULL;

				if (fields_prefix) {
					p = g_strdup_printf ("%s.%s", fields_prefix,
					                     nm_meta_abstract_info_get_name (fields_array_failure));
				}
				allowed_fields = nmc_get_allowed_fields_nested (fields_array_failure, p);
			} else
				allowed_fields = nmc_get_allowed_fields (fields_array, NULL);

			g_set_error (error, NMCLI_ERROR, 1, _("invalid field '%s%s%s%s%s'; %s%s%s"),
			             fields_prefix ?: "", fields_prefix ? "." : "",
			             i_name, right ? "." : "", right ?: "",
			             NM_PRINT_FMT_QUOTED (allowed_fields, "allowed fields: ", allowed_fields, "", "no fields"));
		}
		return FALSE;
	}

	{
		GString *str;
		OutputSelectionItem s = {
			.idx = i,
		};

		if (!*p_str)
			*p_str = g_string_sized_new (64);
		str = *p_str;

		s.self_offset_plus_1 = str->len + 1;
		if (fields_prefix) {
			g_string_append (str, fields_prefix);
			g_string_append_c (str, '.');
		}
		g_string_append_len (str, i_name, strlen (i_name) + 1);

		if (right) {
			s.sub_offset_plus_1 = str->len + 1;
			g_string_append_len (str, right, strlen (right) + 1);
		}

		if (!*p_array)
			*p_array = g_array_new (FALSE, FALSE, sizeof (OutputSelectionItem));
		g_array_append_val (*p_array, s);
	}

	return TRUE;
}

static NmcOutputSelection *
_output_selection_create_all (const NMMetaAbstractInfo *const* fields_array)
{
	gs_unref_array GArray *array = NULL;
	guint i;

	if (fields_array) {
		array = g_array_new (FALSE, FALSE, sizeof (OutputSelectionItem));
		for (i = 0; fields_array[i]; i++) {
			OutputSelectionItem s = {
				.idx = i,
			};

			g_array_append_val (array, s);
		}
	}

	return _output_selection_pack (fields_array, array, NULL);
}

static NmcOutputSelection *
_output_selection_create_one (const NMMetaAbstractInfo *const* fields_array,
                              const char *fields_prefix,
                              const char *fields_str, /* one field selector (contains not commas) and is alrady stripped of spaces. */
                              gboolean validate_nested,
                              GError **error)
{
	gs_unref_array GArray *array = NULL;
	nm_auto_free_gstring GString *str = NULL;

	g_return_val_if_fail (!error || !*error, NULL);
	nm_assert (fields_str && !strchr (fields_str, ','));

	if (!_output_selection_select_one (fields_array,
	                                   fields_prefix,
	                                   fields_str,
	                                   validate_nested,
	                                   &array,
	                                   &str,
	                                   error))
		return NULL;
	return _output_selection_pack (fields_array, array, str);

}

#define PRINT_DATA_COL_PARENT_NIL (G_MAXUINT)

typedef struct {
	const NmcOutputSelectionItem *selection_item;
	guint parent_idx;
	guint self_idx;
	bool is_leaf;
} PrintDataCol;

static gboolean
_output_selection_append (GArray *cols,
                          const char *fields_prefix,
                          guint parent_idx,
                          const NmcOutputSelectionItem *selection_item,
                          GPtrArray *gfree_keeper,
                          GError **error)
{
	gs_free gpointer nested_to_free = NULL;
	guint col_idx;
	guint i;
	const NMMetaAbstractInfo *const*nested;
	NmcOutputSelection *selection;
	const NmcOutputSelectionItem *si;

	col_idx = cols->len;

	{
		PrintDataCol col = {
			.selection_item = selection_item,
			.parent_idx = parent_idx,
			.self_idx = col_idx,
			.is_leaf = TRUE,
		};
		g_array_append_val (cols, col);
	}

	nested = nm_meta_abstract_info_get_nested (selection_item->info, NULL, &nested_to_free);

	if (selection_item->sub_selection) {
		if (!nested) {
			gs_free char *allowed_fields = NULL;

			if (parent_idx != PRINT_DATA_COL_PARENT_NIL) {
				si = g_array_index (cols, PrintDataCol, parent_idx).selection_item;
				allowed_fields = nmc_get_allowed_fields_nested (si->info, si->self_selection);
			}
			if (!allowed_fields) {
				g_set_error (error, NMCLI_ERROR, 1, _("invalid field '%s%s%s'; no such field"),
				             selection_item->self_selection ?: "", selection_item->self_selection ? "." : "",
				             selection_item->sub_selection);
			} else {
				g_set_error (error, NMCLI_ERROR, 1, _("invalid field '%s%s%s'; allowed fields: [%s]"),
				             selection_item->self_selection ?: "", selection_item->self_selection ? "." : "",
				             selection_item->sub_selection,
				             allowed_fields);
			}
			return FALSE;
		}

		selection = _output_selection_create_one (nested, selection_item->self_selection,
		                                          selection_item->sub_selection, FALSE, error);
		if (!selection)
			return FALSE;
		nm_assert (selection->num == 1);
	} else if (nested) {
		selection = _output_selection_create_all (nested);
		nm_assert (selection && selection->num > 0);
	} else
		selection = NULL;

	if (selection) {
		g_ptr_array_add (gfree_keeper, selection);

		for (i = 0; i < selection->num; i++) {
			si = &selection->items[i];
			if (!_output_selection_append (cols, si->self_selection, col_idx,
			                               si, gfree_keeper, error))
				return FALSE;
		}
		g_array_index (cols, PrintDataCol, col_idx).is_leaf = FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

NmcOutputSelection *
nmc_output_selection_create (const NMMetaAbstractInfo *const* fields_array,
                             const char *fields_prefix,
                             const char *fields_str, /* a comma separated list of selectors */
                             gboolean validate_nested,
                             GError **error)
{
	gs_unref_array GArray *array = NULL;
	nm_auto_free_gstring GString *str = NULL;
	gs_free char *fields_str_clone = NULL;
	char *fields_str_cur;
	char *fields_str_next;

	g_return_val_if_fail (!error || !*error, NULL);

	if (!fields_str)
		return _output_selection_create_all (fields_array);

	fields_str_clone = g_strdup (fields_str);
	for (fields_str_cur = fields_str_clone; fields_str_cur; fields_str_cur = fields_str_next) {
		fields_str_cur = nm_str_skip_leading_spaces (fields_str_cur);
		fields_str_next = strchr (fields_str_cur, ',');
		if (fields_str_next)
			*fields_str_next++ = '\0';

		g_strchomp (fields_str_cur);
		if (!fields_str_cur[0])
			continue;
		if (!_output_selection_select_one (fields_array,
		                                   fields_prefix,
		                                   fields_str_cur,
		                                   validate_nested,
		                                   &array,
		                                   &str,
		                                   error))
			return NULL;
	}

	return _output_selection_pack (fields_array, array, str);
}

/**
 * _output_selection_parse:
 * @fields: a %NULL terminated array of meta-data fields
 * @fields_str: a comma separated selector for fields. Nested fields
 *   can be specified using '.' notation.
 * @out_cols: (transfer full): the result, parsed as an GArray of PrintDataCol items.
 *   The order of the items is as specified by @fields_str. Meta data
 *   items that contain nested elements are unpacked (note the is_leaf
 *   and parent properties of PrintDataCol).
 * @out_gfree_keeper: (transfer full): an output GPtrArray that owns
 *   strings to which @out_cols points to. The lifetime of @out_cols
 *   and @out_gfree_keeper should correspond.
 * @error:
 *
 * Returns: %TRUE on success.
 */
static gboolean
_output_selection_parse (const NMMetaAbstractInfo *const*fields,
                         const char *fields_str,
                         GArray **out_cols,
                         GPtrArray **out_gfree_keeper,
                         GError **error)
{
	NmcOutputSelection *selection;
	gs_unref_ptrarray GPtrArray *gfree_keeper = NULL;
	gs_unref_array GArray *cols = NULL;
	guint i;

	selection = nmc_output_selection_create (fields, NULL, fields_str, FALSE, error);
	if (!selection)
		return FALSE;

	if (!selection->num) {
		g_set_error (error, NMCLI_ERROR, 1, _("failure to select field"));
		return FALSE;
	}

	gfree_keeper = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (gfree_keeper, selection);

	cols = g_array_new (FALSE, TRUE, sizeof (PrintDataCol));

	for (i = 0; i < selection->num; i++) {
		const NmcOutputSelectionItem *si = &selection->items[i];

		if (!_output_selection_append (cols, NULL, PRINT_DATA_COL_PARENT_NIL,
		                               si, gfree_keeper, error))
			return FALSE;
	}

	*out_cols = g_steal_pointer (&cols);
	*out_gfree_keeper = g_steal_pointer (&gfree_keeper);
	return TRUE;
}

/*****************************************************************************/

/**
 * parse_output_fields:
 * @field_str: comma-separated field names to parse
 * @fields_array: array of allowed fields
 * @parse_groups: whether the fields can contain group prefix (e.g. general.driver)
 * @group_fields: (out) (allow-none): array of field names for particular groups
 * @error: (out) (allow-none): location to store error, or %NULL
 *
 * Parses comma separated fields in @fields_str according to @fields_array.
 * When @parse_groups is %TRUE, fields can be in the form 'group.field'. Then
 * @group_fields will be filled with the required field for particular group.
 * @group_fields array corresponds to the returned array.
 * Examples:
 *   @field_str:     "type,name,uuid" | "ip4,general.device" | "ip4.address,ip6"
 *   returned array:   2    0    1    |   7         0        |     7         9
 *   @group_fields:   NULL NULL NULL  |  NULL    "device"    | "address"    NULL
 *
 * Returns: #GArray with indices representing fields in @fields_array.
 *   Caller is responsible for freeing the array.
 */
GArray *
parse_output_fields (const char *fields_str,
                     const NMMetaAbstractInfo *const*fields_array,
                     gboolean parse_groups,
                     GPtrArray **out_group_fields,
                     GError **error)
{
	gs_free NmcOutputSelection *selection = NULL;
	GArray *array;
	GPtrArray *group_fields = NULL;
	guint i;

	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (!out_group_fields || !*out_group_fields, NULL);

	selection = nmc_output_selection_create (fields_array, NULL, fields_str, TRUE, error);
	if (!selection)
		return NULL;

	array = g_array_sized_new (FALSE, FALSE, sizeof (int), selection->num);
	if (parse_groups && out_group_fields)
		group_fields = g_ptr_array_new_full (selection->num, g_free);

	for (i = 0; i < selection->num; i++) {
		int idx = selection->items[i].idx;

		g_array_append_val (array, idx);
		if (group_fields)
			g_ptr_array_add (group_fields, g_strdup (selection->items[i].sub_selection));
	}

	if (group_fields)
		*out_group_fields = group_fields;
	return array;
}

char *
nmc_get_allowed_fields_nested (const NMMetaAbstractInfo *abstract_info, const char *name_prefix)
{
	gs_free gpointer nested_to_free = NULL;
	guint i;
	const NMMetaAbstractInfo *const*nested;
	GString *allowed_fields;

	nested = nm_meta_abstract_info_get_nested (abstract_info, NULL, &nested_to_free);
	if (!nested)
		return NULL;

	allowed_fields = g_string_sized_new (256);

	if (!name_prefix)
		name_prefix = nm_meta_abstract_info_get_name (abstract_info);

	for (i = 0; nested[i]; i++) {
		g_string_append_printf (allowed_fields, "%s.%s,",
		                        name_prefix, nm_meta_abstract_info_get_name (nested[i]));
	}
	g_string_truncate (allowed_fields, allowed_fields->len - 1);
	return g_string_free (allowed_fields, FALSE);
}

char *
nmc_get_allowed_fields (const NMMetaAbstractInfo *const*fields_array, const char *name_prefix)
{
	GString *allowed_fields;
	guint i;

	if (!fields_array || !fields_array[0])
		return NULL;

	allowed_fields = g_string_sized_new (256);
	for (i = 0; fields_array[i]; i++) {
		if (name_prefix)
			g_string_append_printf (allowed_fields, "%s.", name_prefix);
		g_string_append_printf (allowed_fields, "%s,", nm_meta_abstract_info_get_name (fields_array[i]));
	}
	g_string_truncate (allowed_fields, allowed_fields->len - 1);
	return g_string_free (allowed_fields, FALSE);
}

NmcOutputField *
nmc_dup_fields_array (const NMMetaAbstractInfo *const*fields, NmcOfFlags flags)
{
	NmcOutputField *row;
	gsize l;

	for (l = 0; fields[l]; l++) {
	}

	row = g_new0 (NmcOutputField, l + 1);
	for (l = 0; fields[l]; l++)
		row[l].info = fields[l];
	row[0].flags = flags;
	return row;
}

void
nmc_empty_output_fields (NmcOutputData *output_data)
{
	guint i;

	/* Free values in field structure */
	for (i = 0; i < output_data->output_data->len; i++) {
		NmcOutputField *fld_arr = g_ptr_array_index (output_data->output_data, i);
		nmc_free_output_field_values (fld_arr);
	}

	/* Empty output_data array */
	if (output_data->output_data->len > 0)
		g_ptr_array_remove_range (output_data->output_data, 0, output_data->output_data->len);
}

/*****************************************************************************/

typedef struct {
	guint col_idx;
	const PrintDataCol *col;
	bool is_nested;
	const char *title;
	int width;
} PrintDataHeaderCell;

typedef struct {
	guint row_idx;
	const PrintDataHeaderCell *header_cell;
	NMMetaTermColor term_color;
	NMMetaTermFormat term_format;
	const char *text;
	bool text_to_free:1;
} PrintDataCell;

static void
_print_data_header_cell_clear (gpointer cell_p)
{
}

static void
_print_data_cell_clear_text (PrintDataCell *cell)
{
	if (cell->text_to_free) {
		g_free ((char *) cell->text);
		cell->text_to_free = FALSE;
	}
	cell->text = NULL;
}

static void
_print_data_cell_clear (gpointer cell_p)
{
	PrintDataCell *cell = cell_p;

	_print_data_cell_clear_text (cell);
}

static void
_print_fill (const NmcConfig *nmc_config,
             gpointer const *targets,
             const PrintDataCol *cols,
             guint cols_len,
             GArray **out_header_row,
             GArray **out_cells)
{
	GArray *cells;
	GArray *header_row;
	guint i_row, i_col;
	guint targets_len;
	gboolean pretty;
	NMMetaAccessorGetType text_get_type;

	pretty = (nmc_config->print_output != NMC_PRINT_TERSE);

	header_row = g_array_sized_new (FALSE, TRUE, sizeof (PrintDataHeaderCell), cols_len);
	g_array_set_clear_func (header_row, _print_data_header_cell_clear);

	for (i_col = 0; i_col < cols_len; i_col++) {
		const PrintDataCol *col;
		PrintDataHeaderCell *header_cell;
		guint col_idx;

		col = &cols[i_col];
		if (!col->is_leaf)
			continue;

		col_idx = header_row->len;
		g_array_set_size (header_row, col_idx + 1);

		header_cell = &g_array_index (header_row, PrintDataHeaderCell, col_idx);

		header_cell->col_idx = col_idx;
		header_cell->col = col;
		header_cell->is_nested = FALSE;
		header_cell->title = nm_meta_abstract_info_get_name (col->selection_item->info);
		if (pretty)
			header_cell->title = _(header_cell->title);
	}

	targets_len = NM_PTRARRAY_LEN (targets);

	cells = g_array_sized_new (FALSE, TRUE, sizeof (PrintDataCell), targets_len * header_row->len);
	g_array_set_clear_func (cells, _print_data_cell_clear);
	g_array_set_size (cells, targets_len * header_row->len);

	text_get_type = pretty
	                ? NM_META_ACCESSOR_GET_TYPE_PRETTY
	                : NM_META_ACCESSOR_GET_TYPE_PARSABLE;

	for (i_row = 0; i_row < targets_len; i_row++) {
		gpointer target = targets[i_row];
		PrintDataCell *cells_line = &g_array_index (cells, PrintDataCell, i_row * header_row->len);

		for (i_col = 0; i_col < header_row->len; i_col++) {
			char *to_free = NULL;
			PrintDataCell *cell = &cells_line[i_col];
			const PrintDataHeaderCell *header_cell;
			const NMMetaAbstractInfo *info;

			header_cell = &g_array_index (header_row, PrintDataHeaderCell, i_col);
			info = header_cell->col->selection_item->info;

			cell->row_idx = i_row;
			cell->header_cell = header_cell;
			cell->text = nm_meta_abstract_info_get (info,
			                                        NULL,
			                                        NULL,
			                                        target,
			                                        text_get_type,
			                                        NM_META_ACCESSOR_GET_FLAGS_NONE,
			                                        (gpointer *) &to_free);
			cell->text_to_free = !!to_free;

			nm_meta_termformat_unpack (nm_meta_abstract_info_get (info,
			                                                      NULL,
			                                                      NULL,
			                                                      target,
			                                                      NM_META_ACCESSOR_GET_TYPE_TERMFORMAT,
			                                                      NM_META_ACCESSOR_GET_FLAGS_NONE,
			                                                      NULL),
			                           &cell->term_color,
			                           &cell->term_format);

			if (pretty && (!cell->text || !cell->text[0])) {
				_print_data_cell_clear_text (cell);
				cell->text = "--";
			} else if (!cell->text)
				cell->text = "";
		}
	}

	for (i_col = 0; i_col < header_row->len; i_col++) {
		PrintDataHeaderCell *header_cell = &g_array_index (header_row, PrintDataHeaderCell, i_col);

		header_cell->width = nmc_string_screen_width (header_cell->title, NULL);

		for (i_row = 0; i_row < targets_len; i_row++) {
			const PrintDataCell *cell = &g_array_index (cells, PrintDataCell, i_row * cols_len + i_col);

			if (header_cell->is_nested) {
				g_assert_not_reached (/*TODO*/);
			} else {
				header_cell->width = NM_MAX (header_cell->width,
				                             nmc_string_screen_width (cell->text, NULL));
			}
		}

		header_cell->width += 1;
	}

	*out_header_row = header_row;
	*out_cells = cells;
}

static void
_print_do (const NmcConfig *nmc_config,
           const char *header_name_no_l10n,
           guint col_len,
           guint row_len,
           const PrintDataHeaderCell *header_row,
           const PrintDataCell *cells)
{
	int width1, width2;
	int table_width = 0;
	gboolean pretty = (nmc_config->print_output == NMC_PRINT_PRETTY);
	gboolean terse = (nmc_config->print_output == NMC_PRINT_TERSE);
	gboolean multiline = nmc_config->multiline_output;
	guint i_row, i_col;
	nm_auto_free_gstring GString *str = NULL;

	g_assert (col_len && row_len);

	/* Main header */
	if (pretty) {
		gs_free char *line = NULL;
		int header_width;
		const char *header_name = _(header_name_no_l10n);

		header_width = nmc_string_screen_width (header_name, NULL) + 4;

		if (multiline) {
			table_width = NM_MAX (header_width, ML_HEADER_WIDTH);
			line = g_strnfill (ML_HEADER_WIDTH, '=');
		} else { /* tabular */
			table_width = NM_MAX (table_width, header_width);
			line = g_strnfill (table_width, '=');
		}

		width1 = strlen (header_name);
		width2 = nmc_string_screen_width (header_name, NULL);
		g_print ("%s\n", line);
		g_print ("%*s\n", (table_width + width2)/2 + width1 - width2, header_name);
		g_print ("%s\n", line);
	}

	str = !multiline
	      ? g_string_sized_new (100)
	      : NULL;

	/* print the header for the tabular form */
	if (!multiline && !terse) {
		for (i_col = 0; i_col < col_len; i_col++) {
			const PrintDataHeaderCell *header_cell = &header_row[i_col];
			const char *title;

			title = header_cell->title;

			width1 = strlen (title);
			width2 = nmc_string_screen_width (title, NULL);  /* Width of the string (in screen colums) */
			g_string_append_printf (str, "%-*s", (int) (header_cell->width + width1 - width2), title);
			g_string_append_c (str, ' ');  /* Column separator */
			table_width += header_cell->width + width1 - width2 + 1;
		}

		if (str->len)
			g_string_truncate (str, str->len-1);  /* Chop off last column separator */
		g_print ("%s\n", str->str);
		g_string_truncate (str, 0);

		/* Print horizontal separator */
		if (pretty) {
			gs_free char *line = NULL;

			g_print ("%s\n", (line = g_strnfill (table_width, '-')));
		}
	}

	for (i_row = 0; i_row < row_len; i_row++) {
		const PrintDataCell *current_line = &cells[i_row * col_len];

		for (i_col = 0; i_col < col_len; i_col++) {
			const PrintDataCell *cell = &current_line[i_col];
			gs_free char *text_to_free = NULL;
			const char *text;

			if (cell->header_cell->is_nested) {
				g_assert_not_reached (/*TODO*/);
			} else {
				text = colorize_string (nmc_config->use_colors,
				                        cell->term_color, cell->term_format,
				                        cell->text, &text_to_free);
			}

			if (multiline) {
				gs_free char *prefix = NULL;

				prefix = g_strdup_printf ("%s:", cell->header_cell->title);
				width1 = strlen (prefix);
				width2 = nmc_string_screen_width (prefix, NULL);
				g_print ("%-*s%s\n", (int) (terse ? 0 : ML_VALUE_INDENT+width1-width2), prefix, text);
			} else {
				nm_assert (str);
				if (terse) {
					if (nmc_config->escape_values) {
						const char *p = text;
						while (*p) {
							if (*p == ':' || *p == '\\')
								g_string_append_c (str, '\\');  /* Escaping by '\' */
							g_string_append_c (str, *p);
							p++;
						}
					}
					else
						g_string_append_printf (str, "%s", text);
					g_string_append_c (str, ':');  /* Column separator */
				} else {
					const PrintDataHeaderCell *header_cell = &header_row[i_col];

					width1 = strlen (text);
					width2 = nmc_string_screen_width (text, NULL);  /* Width of the string (in screen colums) */
					g_string_append_printf (str, "%-*s", (int) (header_cell->width + width1 - width2), text);
					g_string_append_c (str, ' ');  /* Column separator */
					table_width += header_cell->width + width1 - width2 + 1;
				}
			}
		}

		if (!multiline) {
			if (str->len)
				g_string_truncate (str, str->len-1);  /* Chop off last column separator */
			g_print ("%s\n", str->str);

			g_string_truncate (str, 0);
		}

		if (   pretty
		    && (   i_row < row_len - 1
		        || multiline)) {
			gs_free char *line = NULL;

			g_print ("%s\n", (line = g_strnfill (ML_HEADER_WIDTH, '-')));
		}
	}
}

gboolean
nmc_print (const NmcConfig *nmc_config,
           gpointer const *targets,
           const char *header_name_no_l10n,
           const NMMetaAbstractInfo *const*fields,
           const char *fields_str,
           GError **error)
{
	gs_unref_ptrarray GPtrArray *gfree_keeper = NULL;
	gs_unref_array GArray *cols = NULL;
	gs_unref_array GArray *header_row = NULL;
	gs_unref_array GArray *cells = NULL;

	if (!_output_selection_parse (fields, fields_str,
	                              &cols, &gfree_keeper,
	                              error))
		return FALSE;

	_print_fill (nmc_config,
	             targets,
	             &g_array_index (cols, PrintDataCol, 0),
	             cols->len,
	             &header_row,
	             &cells);

	_print_do (nmc_config,
	           header_name_no_l10n,
	           header_row->len,
	           cells->len / header_row->len,
	           &g_array_index (header_row, PrintDataHeaderCell, 0),
	           &g_array_index (cells, PrintDataCell, 0));

	return TRUE;
}

/*****************************************************************************/

static const char *
get_value_to_print (NmcColorOption color_option,
                    const NmcOutputField *field,
                    gboolean field_name,
                    const char *not_set_str,
                    char **out_to_free)
{
	gboolean is_array = field->value_is_array;
	const char *value;
	const char *out;
	gs_free char *free_value = NULL;

	nm_assert (out_to_free && !*out_to_free);

	if (field_name)
		value = _(nm_meta_abstract_info_get_name (field->info));
	else {
		value = field->value
		            ? (is_array
		                  ? (free_value = g_strjoinv (" | ", (char **) field->value))
		                  : (*((const char *) field->value))
		                        ? field->value
		                        : not_set_str)
		            : not_set_str;
	}

	/* colorize the value */
	out = colorize_string (color_option, field->color, field->color_fmt, value, out_to_free);

	if (out && out == free_value) {
		nm_assert (!*out_to_free);
		*out_to_free = g_steal_pointer (&free_value);
	}

	return out;
}

/*
 * Print both headers or values of 'field_values' array.
 * Entries to print and their order are specified via indices in
 * 'nmc->indices' array.
 * Various flags influencing the output of fields are set up in the first item
 * of 'field_values' array.
 */
void
print_required_fields (const NmcConfig *nmc_config,
                       NmcOfFlags of_flags,
                       const GArray *indices,
                       const char *header_name,
                       int indent,
                       const NmcOutputField *field_values)
{
	nm_auto_free_gstring GString *str = NULL;
	int width1, width2;
	int table_width = 0;
	const char *not_set_str;
	int i;
	gboolean terse = (nmc_config->print_output == NMC_PRINT_TERSE);
	gboolean pretty = (nmc_config->print_output == NMC_PRINT_PRETTY);
	gboolean main_header_add = of_flags & NMC_OF_FLAG_MAIN_HEADER_ADD;
	gboolean main_header_only = of_flags & NMC_OF_FLAG_MAIN_HEADER_ONLY;
	gboolean field_names = of_flags & NMC_OF_FLAG_FIELD_NAMES;
	gboolean section_prefix = of_flags & NMC_OF_FLAG_SECTION_PREFIX;

	/* --- Main header --- */
	if ((main_header_add || main_header_only) && pretty) {
		gs_free char *line = NULL;
		int header_width;

		header_width = nmc_string_screen_width (header_name, NULL) + 4;

		if (nmc_config->multiline_output) {
			table_width = NM_MAX (header_width, ML_HEADER_WIDTH);
			line = g_strnfill (ML_HEADER_WIDTH, '=');
		} else { /* tabular */
			table_width = NM_MAX (table_width, header_width);
			line = g_strnfill (table_width, '=');
		}

		width1 = strlen (header_name);
		width2 = nmc_string_screen_width (header_name, NULL);
		g_print ("%s\n", line);
		g_print ("%*s\n", (table_width + width2)/2 + width1 - width2, header_name);
		g_print ("%s\n", line);
	}

	if (main_header_only)
		return;

	/* No field headers are printed in terse mode nor for multiline output */
	if ((terse || nmc_config->multiline_output) && field_names)
		return;

	/* Don't replace empty strings in terse mode */
	not_set_str = terse ? "" : "--";

	if (nmc_config->multiline_output) {
		for (i = 0; i < indices->len; i++) {
			int idx = g_array_index (indices, int, i);
			gboolean is_array = field_values[idx].value_is_array;

			/* section prefix can't be an array */
			g_assert (!is_array || !section_prefix || idx != 0);

			if (section_prefix && idx == 0)  /* The first field is section prefix */
				continue;

			if (is_array) {
				gs_free char *val_to_free = NULL;
				const char **p, *val, *print_val;
				int j;

				/* value is a null-terminated string array */

				for (p = (const char **) field_values[idx].value, j = 1; p && *p; p++, j++) {
					gs_free char *tmp = NULL;

					val = *p ?: not_set_str;
					print_val = colorize_string (nmc_config->use_colors, field_values[idx].color, field_values[idx].color_fmt,
					                             val, &val_to_free);
					tmp = g_strdup_printf ("%s%s%s[%d]:",
					                       section_prefix ? (const char*) field_values[0].value : "",
					                       section_prefix ? "." : "",
					                       _(nm_meta_abstract_info_get_name (field_values[idx].info)),
					                       j);
					width1 = strlen (tmp);
					width2 = nmc_string_screen_width (tmp, NULL);
					g_print ("%-*s%s\n", (int) (terse ? 0 : ML_VALUE_INDENT+width1-width2), tmp, print_val);
				}
			} else {
				gs_free char *val_to_free = NULL;
				gs_free char *tmp = NULL;
				const char *hdr_name = (const char*) field_values[0].value;
				const char *val = (const char*) field_values[idx].value;
				const char *print_val;

				/* value is a string */

				val = val && *val ? val : not_set_str;
				print_val = colorize_string (nmc_config->use_colors, field_values[idx].color, field_values[idx].color_fmt,
				                             val, &val_to_free);
				tmp = g_strdup_printf ("%s%s%s:",
				                       section_prefix ? hdr_name : "",
				                       section_prefix ? "." : "",
				                       _(nm_meta_abstract_info_get_name (field_values[idx].info)));
				width1 = strlen (tmp);
				width2 = nmc_string_screen_width (tmp, NULL);
				g_print ("%-*s%s\n", (int) (terse ? 0 : ML_VALUE_INDENT+width1-width2), tmp, print_val);
			}
		}
		if (pretty) {
			gs_free char *line = NULL;

			g_print ("%s\n", (line = g_strnfill (ML_HEADER_WIDTH, '-')));
		}

		return;
	}

	/* --- Tabular mode: each line = one object --- */

	str = g_string_new (NULL);

	for (i = 0; i < indices->len; i++) {
		gs_free char *val_to_free = NULL;
		int idx;
		const char *value;

		idx = g_array_index (indices, int, i);

		value = get_value_to_print (nmc_config->use_colors, (NmcOutputField *) field_values+idx, field_names,
		                            not_set_str, &val_to_free);

		if (terse) {
			if (nmc_config->escape_values) {
				const char *p = value;
				while (*p) {
					if (*p == ':' || *p == '\\')
						g_string_append_c (str, '\\');  /* Escaping by '\' */
					g_string_append_c (str, *p);
					p++;
				}
			}
			else
				g_string_append_printf (str, "%s", value);
			g_string_append_c (str, ':');  /* Column separator */
		} else {
			width1 = strlen (value);
			width2 = nmc_string_screen_width (value, NULL);  /* Width of the string (in screen colums) */
			g_string_append_printf (str, "%-*s", field_values[idx].width + width1 - width2, strlen (value) > 0 ? value : not_set_str);
			g_string_append_c (str, ' ');  /* Column separator */
			table_width += field_values[idx].width + width1 - width2 + 1;
		}
	}

	/* Print actual values */
	if (str->len > 0) {
		g_string_truncate (str, str->len-1);  /* Chop off last column separator */
		if (indent > 0) {
			gs_free char *indent_str = NULL;

			g_string_prepend (str, (indent_str = g_strnfill (indent, ' ')));
		}

		g_print ("%s\n", str->str);

		/* Print horizontal separator */
		if (field_names && pretty) {
			gs_free char *line = NULL;

			g_print ("%s\n", (line = g_strnfill (table_width, '-')));
		}
	}
}

void
print_data_prepare_width (GPtrArray *output_data)
{
	int i, j;
	size_t len;
	NmcOutputField *row;
	int num_fields = 0;

	if (!output_data || output_data->len < 1)
		return;

	/* How many fields? */
	row = g_ptr_array_index (output_data, 0);
	while (row->info) {
		num_fields++;
		row++;
	}

	/* Find out maximal string lengths */
	for (i = 0; i < num_fields; i++) {
		size_t max_width = 0;
		for (j = 0; j < output_data->len; j++) {
			gboolean field_names;
			gs_free char * val_to_free = NULL;
			const char *value;

			row = g_ptr_array_index (output_data, j);
			field_names = row[0].flags & NMC_OF_FLAG_FIELD_NAMES;
			value = get_value_to_print (NMC_USE_COLOR_NO, row+i, field_names, "--", &val_to_free);
			len = nmc_string_screen_width (value, NULL);
			max_width = len > max_width ? len : max_width;
		}
		for (j = 0; j < output_data->len; j++) {
			row = g_ptr_array_index (output_data, j);
			row[i].width = max_width + 1;
		}
	}
}

void
print_data (const NmcConfig *nmc_config,
            const GArray *indices,
            const char *header_name,
            int indent,
            const NmcOutputData *out)
{
	guint i;

	for (i = 0; i < out->output_data->len; i++) {
		const NmcOutputField *field_values = g_ptr_array_index (out->output_data, i);

		print_required_fields (nmc_config, field_values[0].flags,
		                       indices, header_name,
		                       indent, field_values);
	}
}

