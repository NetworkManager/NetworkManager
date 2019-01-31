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
 * Copyright 2010 Lennart Poettering
 * Copyright 2010 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/auxv.h>
#include <sys/prctl.h>

#include "nm-client-utils.h"
#include "nm-meta-setting-access.h"

#include "common.h"
#include "nmcli.h"
#include "settings.h"

#define ML_HEADER_WIDTH 79
#define ML_VALUE_INDENT 40

/*****************************************************************************/

static const char *
_meta_type_nmc_generic_info_get_name (const NMMetaAbstractInfo *abstract_info, gboolean for_header)
{
	const NmcMetaGenericInfo *info = (const NmcMetaGenericInfo *) abstract_info;

	if (for_header)
		return info->name_header ?: info->name;
	return info->name;
}

static const NMMetaAbstractInfo *const*
_meta_type_nmc_generic_info_get_nested (const NMMetaAbstractInfo *abstract_info,
                                        guint *out_len,
                                        gpointer *out_to_free)
{
	const NmcMetaGenericInfo *info;

	info = (const NmcMetaGenericInfo *) abstract_info;

	NM_SET_OUT (out_len, NM_PTRARRAY_LEN (info->nested));
	return (const NMMetaAbstractInfo *const*) info->nested;
}

static gconstpointer
_meta_type_nmc_generic_info_get_fcn (const NMMetaAbstractInfo *abstract_info,
                                     const NMMetaEnvironment *environment,
                                     gpointer environment_user_data,
                                     gpointer target,
                                     gpointer target_data,
                                     NMMetaAccessorGetType get_type,
                                     NMMetaAccessorGetFlags get_flags,
                                     NMMetaAccessorGetOutFlags *out_flags,
                                     gboolean *out_is_default,
                                     gpointer *out_to_free)
{
	const NmcMetaGenericInfo *info = (const NmcMetaGenericInfo *) abstract_info;

	nm_assert (!out_to_free || !*out_to_free);
	nm_assert (out_flags && !*out_flags);

	if (!NM_IN_SET (get_type,
	                NM_META_ACCESSOR_GET_TYPE_PARSABLE,
	                NM_META_ACCESSOR_GET_TYPE_PRETTY,
	                NM_META_ACCESSOR_GET_TYPE_COLOR))
		g_return_val_if_reached (NULL);

	/* omitting the out_to_free value is only allowed for COLOR. */
	nm_assert (out_to_free || NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_COLOR));

	if (info->get_fcn) {
		return info->get_fcn (environment,
		                      environment_user_data,
		                      info,
		                      target,
		                      target_data,
		                      get_type,
		                      get_flags,
		                      out_flags,
		                      out_is_default,
		                      out_to_free);
	}

	if (info->nested) {
		NMC_HANDLE_COLOR (NM_META_COLOR_NONE);
		return info->name;
	}

	g_return_val_if_reached (NULL);
}

const NMMetaType nmc_meta_type_generic_info = {
	.type_name =         "nmc-generic-info",
	.get_name =          _meta_type_nmc_generic_info_get_name,
	.get_nested =        _meta_type_nmc_generic_info_get_nested,
	.get_fcn =           _meta_type_nmc_generic_info_get_fcn,
};

/*****************************************************************************/

static const char *
colorize_string (const NmcConfig *nmc_config,
                 NMMetaColor color,
                 const char *str,
                 char **out_to_free)
{
	const char *out = str;

	if (nmc_config && nmc_config->use_colors) {
		*out_to_free = nmc_colorize (nmc_config, color, "%s", str);
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
			if (cmd_option[0] == '-' && cmd_option[1] == '-') {
				/* Match as an option (leading "--" stripped) */
				if (nmc_arg_is_option (**argv, cmd_option + 2)) {
					va_end (args);
					return cmd_option_pos;
				}
			} else {
				/* Match literally. */
				if (strcmp (**argv, cmd_option) == 0) {
					va_end (args);
					return cmd_option_pos;
				}
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
	g_print ("%c %s", slashes[idx++], str ?: "");
	fflush (stdout);
	if (idx == 4)
		idx = 0;
}

char *
nmc_colorize (const NmcConfig *nmc_config, NMMetaColor color, const char *fmt, ...)
{
	va_list args;
	char *str, *colored;
	const char *ansi_seq = NULL;

	va_start (args, fmt);
	str = g_strdup_vprintf (fmt, args);
	va_end (args);

	if (nmc_config->use_colors)
		ansi_seq =  nmc_config->palette[color];

	if (ansi_seq == NULL)
		return str;

	colored = g_strdup_printf ("\33[%sm%s\33[0m", ansi_seq, str);
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
	gs_free const char **arr0 = NULL;
	char **arr;

	arr0 = nm_utils_strsplit_set (line ?: "", delim ?: " \t", FALSE);
	if (!arr0)
		arr = g_new0 (char *, 1);
	else
		arr = g_strdupv ((char **) arr0);

	if (unquote) {
		int i = 0;
		char *s;
		size_t l;
		const char *quotes = "\"'";

		while (arr[i]) {
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
set_val_color_all (NmcOutputField fields_array[], NMMetaColor color)
{
	int i;

	for (i = 0; fields_array[i].info; i++) {
		fields_array[i].color = color;
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

#define PRINT_DATA_COL_PARENT_NIL (G_MAXUINT)

typedef struct _PrintDataCol {
	union {
		const struct _PrintDataCol *parent_col;

		/* while constructing the list of columns in _output_selection_append(), we keep track
		 * of the parent by index. The reason is, that at that point our columns are still
		 * tracked in a GArray which is growing (hence, the pointers are changing).
		 * Later, _output_selection_complete() converts the index into the actual pointer.
		 */
		guint _parent_idx;
	};
	const NMMetaSelectionItem *selection_item;
	guint self_idx;
	bool is_leaf;
} PrintDataCol;

static gboolean
_output_selection_append (GArray *cols,
                          guint parent_idx,
                          const NMMetaSelectionItem *selection_item,
                          GPtrArray *gfree_keeper,
                          GError **error)
{
	gs_free gpointer nested_to_free = NULL;
	guint col_idx;
	guint i;
	const NMMetaAbstractInfo *const*nested;
	NMMetaSelectionResultList *selection;
	const NMMetaSelectionItem *si;

	col_idx = cols->len;

	{
		PrintDataCol col = {
			.selection_item = selection_item,
			._parent_idx = parent_idx,
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
				allowed_fields = nm_meta_abstract_info_get_nested_names_str (si->info, si->self_selection);
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

		selection = nm_meta_selection_create_parse_one (nested, selection_item->self_selection,
		                                                selection_item->sub_selection, FALSE, error);
		if (!selection)
			return FALSE;
		nm_assert (selection->num == 1);
	} else if (nested) {
		selection = nm_meta_selection_create_all (nested);
		nm_assert (selection && selection->num > 0);
	} else
		selection = NULL;

	if (selection) {
		g_ptr_array_add (gfree_keeper, selection);

		for (i = 0; i < selection->num; i++) {
			si = &selection->items[i];
			if (!_output_selection_append (cols,
			                               col_idx,
			                               si,
			                               gfree_keeper,
			                               error))
				return FALSE;
		}

		if (!NM_IN_SET(selection_item->info->meta_type,
		               &nm_meta_type_setting_info_editor,
		               &nmc_meta_type_generic_info))
			g_array_index (cols, PrintDataCol, col_idx).is_leaf = FALSE;
	}

	return TRUE;
}

static void
_output_selection_complete (GArray *cols)
{
	guint i;

	nm_assert (cols);
	nm_assert (g_array_get_element_size (cols) == sizeof (PrintDataCol));

	for (i = 0; i < cols->len; i++) {
		PrintDataCol *col = &g_array_index (cols, PrintDataCol, i);

		if (col->_parent_idx == PRINT_DATA_COL_PARENT_NIL)
			col->parent_col = NULL;
		else {
			nm_assert (col->_parent_idx < i);
			col->parent_col = &g_array_index (cols, PrintDataCol, col->_parent_idx);
		}
	}
}

/*****************************************************************************/

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
	NMMetaSelectionResultList *selection;
	gs_unref_ptrarray GPtrArray *gfree_keeper = NULL;
	gs_unref_array GArray *cols = NULL;
	guint i;

	selection = nm_meta_selection_create_parse_list (fields, fields_str, FALSE, error);
	if (!selection)
		return FALSE;

	if (!selection->num) {
		g_set_error (error, NMCLI_ERROR, 1, _("failure to select field"));
		g_free (selection);
		return FALSE;
	}

	gfree_keeper = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (gfree_keeper, selection);

	cols = g_array_new (FALSE, TRUE, sizeof (PrintDataCol));

	for (i = 0; i < selection->num; i++) {
		const NMMetaSelectionItem *si = &selection->items[i];

		if (!_output_selection_append (cols, PRINT_DATA_COL_PARENT_NIL,
		                               si, gfree_keeper, error))
			return FALSE;
	}

	_output_selection_complete (cols);

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
	gs_free NMMetaSelectionResultList *selection = NULL;
	GArray *array;
	GPtrArray *group_fields = NULL;
	guint i;

	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (!out_group_fields || !*out_group_fields, NULL);

	selection = nm_meta_selection_create_parse_list (fields_array, fields_str, TRUE, error);
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

	g_ptr_array_unref (output_data->output_data);
}

/*****************************************************************************/

typedef struct {
	guint col_idx;
	const PrintDataCol *col;
	const char *title;
	bool title_to_free:1;

	/* whether the column should be printed. If not %TRUE,
	 * the column will be skipped. */
	bool to_print:1;

	int width;
} PrintDataHeaderCell;

typedef enum {
	PRINT_DATA_CELL_FORMAT_TYPE_PLAIN = 0,
	PRINT_DATA_CELL_FORMAT_TYPE_STRV,
} PrintDataCellFormatType;

typedef struct {
	guint row_idx;
	const PrintDataHeaderCell *header_cell;
	NMMetaColor color;
	union {
		const char *plain;
		const char *const*strv;
	} text;
	PrintDataCellFormatType text_format:3;
	bool text_to_free:1;
} PrintDataCell;

static void
_print_data_header_cell_clear (gpointer cell_p)
{
	PrintDataHeaderCell *cell = cell_p;

	if (cell->title_to_free) {
		g_free ((char *) cell->title);
		cell->title_to_free = FALSE;
	}
	cell->title = NULL;
}

static void
_print_data_cell_clear_text (PrintDataCell *cell)
{
	switch (cell->text_format) {
	case PRINT_DATA_CELL_FORMAT_TYPE_PLAIN:
		if (cell->text_to_free)
			g_free ((char *) cell->text.plain);
		cell->text.plain = NULL;
		break;
	case PRINT_DATA_CELL_FORMAT_TYPE_STRV:
		if (cell->text_to_free)
			g_strfreev ((char **) cell->text.strv);
		cell->text.strv = NULL;
		break;
	};
	cell->text_format = PRINT_DATA_CELL_FORMAT_TYPE_PLAIN;
	cell->text_to_free = FALSE;
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
             gpointer targets_data,
             const PrintDataCol *cols,
             guint cols_len,
             GArray **out_header_row,
             GArray **out_cells)
{
	GArray *cells;
	GArray *header_row;
	guint i_row, i_col;
	guint targets_len;
	NMMetaAccessorGetType text_get_type;
	NMMetaAccessorGetFlags text_get_flags;


	header_row = g_array_sized_new (FALSE, TRUE, sizeof (PrintDataHeaderCell), cols_len);
	g_array_set_clear_func (header_row, _print_data_header_cell_clear);

	for (i_col = 0; i_col < cols_len; i_col++) {
		const PrintDataCol *col;
		PrintDataHeaderCell *header_cell;
		guint col_idx;
		const NMMetaAbstractInfo *info;

		col = &cols[i_col];
		if (!col->is_leaf)
			continue;

		info = col->selection_item->info;

		col_idx = header_row->len;
		g_array_set_size (header_row, col_idx + 1);

		header_cell = &g_array_index (header_row, PrintDataHeaderCell, col_idx);

		header_cell->col_idx = col_idx;
		header_cell->col = col;

		/* by default, the entire column is skipped. That is the case,
		 * unless we have a cell (below) which opts-in to be printed. */
		header_cell->to_print = FALSE;

		header_cell->title = nm_meta_abstract_info_get_name (info, TRUE);
		if (   nmc_config->multiline_output
		    && col->parent_col
		    && NM_IN_SET (info->meta_type,
		                  &nm_meta_type_property_info,
		                  &nmc_meta_type_generic_info)) {
			header_cell->title = g_strdup_printf ("%s.%s",
			                                      nm_meta_abstract_info_get_name (col->parent_col->selection_item->info, FALSE),
			                                      header_cell->title);
			header_cell->title_to_free = TRUE;
		}
	}

	targets_len = NM_PTRARRAY_LEN (targets);

	cells = g_array_sized_new (FALSE, TRUE, sizeof (PrintDataCell), targets_len * header_row->len);
	g_array_set_clear_func (cells, _print_data_cell_clear);
	g_array_set_size (cells, targets_len * header_row->len);

	text_get_type = nmc_print_output_to_accessor_get_type (nmc_config->print_output);
	text_get_flags = NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV;
	if (nmc_config->show_secrets)
		text_get_flags |= NM_META_ACCESSOR_GET_FLAGS_SHOW_SECRETS;

	for (i_row = 0; i_row < targets_len; i_row++) {
		gpointer target = targets[i_row];
		PrintDataCell *cells_line = &g_array_index (cells, PrintDataCell, i_row * header_row->len);

		for (i_col = 0; i_col < header_row->len; i_col++) {
			char *to_free = NULL;
			PrintDataCell *cell = &cells_line[i_col];
			PrintDataHeaderCell *header_cell;
			const NMMetaAbstractInfo *info;
			NMMetaAccessorGetOutFlags text_out_flags, color_out_flags;
			gconstpointer value;
			gboolean is_default;

			header_cell = &g_array_index (header_row, PrintDataHeaderCell, i_col);
			info = header_cell->col->selection_item->info;

			cell->row_idx = i_row;
			cell->header_cell = header_cell;

			value = nm_meta_abstract_info_get (info,
			                                   nmc_meta_environment,
			                                   nmc_meta_environment_arg,
			                                   target,
			                                   targets_data,
			                                   text_get_type,
			                                   text_get_flags,
			                                   &text_out_flags,
			                                   &is_default,
			                                   (gpointer *) &to_free);

			nm_assert (!to_free || value == to_free);

			if (   is_default
			    && (   nmc_config->overview
			        || NM_FLAGS_HAS (text_out_flags, NM_META_ACCESSOR_GET_OUT_FLAGS_HIDE))) {
				/* don't mark the entry for display. This is to shorten the output in case
				 * the property is the default value. But we only do that, if the user
				 * opts in to this behavior (-overview), or of the property marks itself
				 * eligible to be hidden.
				 *
				 * In general, only new API shall mark itself eligible to be hidden.
				 * Long established properties cannot, because it would be a change
				 * in behavior. */
			} else
				header_cell->to_print = TRUE;

			if (NM_FLAGS_HAS (text_out_flags, NM_META_ACCESSOR_GET_OUT_FLAGS_STRV)) {
				if (nmc_config->multiline_output) {
					cell->text_format = PRINT_DATA_CELL_FORMAT_TYPE_STRV;
					cell->text.strv = value;
					cell->text_to_free = !!to_free;
				} else {
					if (value && ((const char *const*) value)[0]) {
						cell->text.plain = g_strjoinv (" | ", (char **) value);
						cell->text_to_free = TRUE;
					}
					if (to_free)
						g_strfreev ((char **) to_free);
				}
			} else {
				cell->text.plain = value;
				cell->text_to_free = !!to_free;
			}

			cell->color = GPOINTER_TO_INT (nm_meta_abstract_info_get (info,
			                                                          nmc_meta_environment,
			                                                          nmc_meta_environment_arg,
			                                                          target,
			                                                          targets_data,
			                                                          NM_META_ACCESSOR_GET_TYPE_COLOR,
			                                                          NM_META_ACCESSOR_GET_FLAGS_NONE,
			                                                          &color_out_flags,
			                                                          NULL,
			                                                          NULL));

			if (cell->text_format == PRINT_DATA_CELL_FORMAT_TYPE_PLAIN) {
				if (   NM_IN_SET (nmc_config->print_output, NMC_PRINT_NORMAL, NMC_PRINT_PRETTY)
				    && (   !cell->text.plain
				        || !cell->text.plain[0])) {
					_print_data_cell_clear_text (cell);
					cell->text.plain = "--";
				} else if (!cell->text.plain)
					cell->text.plain = "";
				nm_assert (cell->text_format == PRINT_DATA_CELL_FORMAT_TYPE_PLAIN);
			}
		}
	}

	for (i_col = 0; i_col < header_row->len; i_col++) {
		PrintDataHeaderCell *header_cell = &g_array_index (header_row, PrintDataHeaderCell, i_col);

		header_cell->width = nmc_string_screen_width (header_cell->title, NULL);

		for (i_row = 0; i_row < targets_len; i_row++) {
			const PrintDataCell *cell = &g_array_index (cells, PrintDataCell, i_row * cols_len + i_col);
			const char *const*i_strv;

			switch (cell->text_format) {
			case PRINT_DATA_CELL_FORMAT_TYPE_PLAIN:
				header_cell->width = NM_MAX (header_cell->width,
				                             nmc_string_screen_width (cell->text.plain, NULL));
				break;
			case PRINT_DATA_CELL_FORMAT_TYPE_STRV:
				i_strv = cell->text.strv;
				if (i_strv) {
					for (; *i_strv; i_strv++) {
						header_cell->width = NM_MAX (header_cell->width,
						                             nmc_string_screen_width (*i_strv, NULL));
					}
				}
				break;
			}
		}

		header_cell->width += 1;
	}

	*out_header_row = header_row;
	*out_cells = cells;
}

static gboolean
_print_skip_column (const NmcConfig *nmc_config,
                    const PrintDataHeaderCell *header_cell)
{
	const NMMetaSelectionItem *selection_item;
	const NMMetaAbstractInfo *info;

	selection_item = header_cell->col->selection_item;
	info = selection_item->info;

	if (!header_cell->to_print)
		return TRUE;

	if (nmc_config->multiline_output) {
		if (info->meta_type == &nm_meta_type_setting_info_editor) {
			/* we skip the "name" entry for the setting in multiline output. */
			return TRUE;
		}
		if (   info->meta_type == &nmc_meta_type_generic_info
		    && ((const NmcMetaGenericInfo *) info)->nested) {
			/* skip the "name" entry for parent generic-infos */
			return TRUE;
		}
	} else {
		if (   NM_IN_SET (info->meta_type,
		                  &nm_meta_type_setting_info_editor,
		                  &nmc_meta_type_generic_info)
		    && selection_item->sub_selection) {
			/* in tabular form, we skip the "name" entry for sections that have sub-selections.
			 * That is, for "ipv4.may-fail", but not for "ipv4". */
			return TRUE;
		}
	}
	return FALSE;
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
	guint i_row, i_col;
	nm_auto_free_gstring GString *str = NULL;

	g_assert (col_len);

	/* Main header */
	if (   nmc_config->print_output == NMC_PRINT_PRETTY
	    && header_name_no_l10n) {
		gs_free char *line = NULL;
		int header_width;
		const char *header_name = _(header_name_no_l10n);

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

	str = !nmc_config->multiline_output
	      ? g_string_sized_new (100)
	      : NULL;

	/* print the header for the tabular form */
	if (   NM_IN_SET (nmc_config->print_output, NMC_PRINT_NORMAL, NMC_PRINT_PRETTY)
	    && !nmc_config->multiline_output) {
		for (i_col = 0; i_col < col_len; i_col++) {
			const PrintDataHeaderCell *header_cell = &header_row[i_col];
			const char *title;

			if (_print_skip_column (nmc_config, header_cell))
				continue;

			title = header_cell->title;

			width1 = strlen (title);
			width2 = nmc_string_screen_width (title, NULL);  /* Width of the string (in screen columns) */
			g_string_append_printf (str, "%-*s", (int) (header_cell->width + width1 - width2), title);
			g_string_append_c (str, ' ');  /* Column separator */
			table_width += header_cell->width + width1 - width2 + 1;
		}

		if (str->len)
			g_string_truncate (str, str->len-1);  /* Chop off last column separator */
		g_print ("%s\n", str->str);
		g_string_truncate (str, 0);

		/* Print horizontal separator */
		if (nmc_config->print_output == NMC_PRINT_PRETTY) {
			gs_free char *line = NULL;

			g_print ("%s\n", (line = g_strnfill (table_width, '-')));
		}
	}

	for (i_row = 0; i_row < row_len; i_row++) {
		const PrintDataCell *current_line = &cells[i_row * col_len];

		for (i_col = 0; i_col < col_len; i_col++) {
			const PrintDataCell *cell = &current_line[i_col];
			const char *const*lines = NULL;
			guint i_lines, lines_len;

			if (_print_skip_column (nmc_config, cell->header_cell))
				continue;

			lines_len = 0;
			switch (cell->text_format) {
			case PRINT_DATA_CELL_FORMAT_TYPE_PLAIN:
				lines = &cell->text.plain;
				lines_len = 1;
				break;
			case PRINT_DATA_CELL_FORMAT_TYPE_STRV:
				nm_assert (nmc_config->multiline_output);
				lines = cell->text.strv;
				lines_len = NM_PTRARRAY_LEN (lines);
				break;
			}

			for (i_lines = 0; i_lines < lines_len; i_lines++) {
				gs_free char *text_to_free = NULL;
				const char *text;

				text = colorize_string (nmc_config, cell->color, lines[i_lines], &text_to_free);
				if (nmc_config->multiline_output) {
					gs_free char *prefix = NULL;

					if (cell->text_format == PRINT_DATA_CELL_FORMAT_TYPE_STRV)
						prefix = g_strdup_printf ("%s[%u]:", cell->header_cell->title, i_lines + 1);
					else
						prefix = g_strdup_printf ("%s:", cell->header_cell->title);
					width1 = strlen (prefix);
					width2 = nmc_string_screen_width (prefix, NULL);
					g_print ("%-*s%s\n",
					         (int) (  nmc_config->print_output == NMC_PRINT_TERSE
					               ? 0
					               : ML_VALUE_INDENT+width1-width2),
					         prefix,
					         text);
				} else {
					nm_assert (str);
					if (nmc_config->print_output == NMC_PRINT_TERSE) {
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
						width2 = nmc_string_screen_width (text, NULL);  /* Width of the string (in screen columns) */
						g_string_append_printf (str, "%-*s", (int) (header_cell->width + width1 - width2), text);
						g_string_append_c (str, ' ');  /* Column separator */
						table_width += header_cell->width + width1 - width2 + 1;
					}
				}
			}
		}

		if (!nmc_config->multiline_output) {
			if (str->len)
				g_string_truncate (str, str->len-1);  /* Chop off last column separator */
			g_print ("%s\n", str->str);

			g_string_truncate (str, 0);
		}

		if (   nmc_config->print_output == NMC_PRINT_PRETTY
		    && nmc_config->multiline_output) {
			gs_free char *line = NULL;

			g_print ("%s\n", (line = g_strnfill (ML_HEADER_WIDTH, '-')));
		}
	}
}

gboolean
nmc_print (const NmcConfig *nmc_config,
           gpointer const *targets,
           gpointer targets_data,
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
	             targets_data,
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

static void
pager_fallback (void)
{
	char buf[64];
	int rb;
	int errsv;

	do {
		rb = read (STDIN_FILENO, buf, sizeof (buf));
		if (rb == -1) {
			errsv = errno;
			if (errsv == EINTR)
				continue;
			g_printerr (_("Error reading nmcli output: %s\n"), nm_strerror_native (errsv));
			_exit(EXIT_FAILURE);
		}
		if (write (STDOUT_FILENO, buf, rb) == -1) {
			errsv = errno;
			g_printerr (_("Error writing nmcli output: %s\n"), nm_strerror_native (errsv));
			_exit(EXIT_FAILURE);
		}
	} while (rb > 0);

	_exit(EXIT_SUCCESS);
}

pid_t
nmc_terminal_spawn_pager (const NmcConfig *nmc_config)
{
	const char *pager = getenv ("PAGER");
	pid_t pager_pid;
	pid_t parent_pid;
	int fd[2];
	int errsv;

	if (   nmc_config->in_editor
	    || nmc_config->print_output == NMC_PRINT_TERSE
	    || !nmc_config->use_colors
	    || g_strcmp0 (pager, "") == 0
	    || getauxval (AT_SECURE))
		return 0;

	if (pipe (fd) == -1) {
		errsv = errno;
		g_printerr (_("Failed to create pager pipe: %s\n"), nm_strerror_native (errsv));
		return 0;
	}

	parent_pid = getpid ();

	pager_pid = fork ();
	if (pager_pid == -1) {
		errsv = errno;
		g_printerr (_("Failed to fork pager: %s\n"), nm_strerror_native (errsv));
		nm_close (fd[0]);
		nm_close (fd[1]);
		return 0;
	}

	/* In the child start the pager */
	if (pager_pid == 0) {
		dup2 (fd[0], STDIN_FILENO);
		nm_close (fd[0]);
		nm_close (fd[1]);

		setenv ("LESS", "FRSXMK", 1);
		setenv ("LESSCHARSET", "utf-8", 1);

		/* Make sure the pager goes away when the parent dies */
		if (prctl (PR_SET_PDEATHSIG, SIGTERM) < 0)
			_exit (EXIT_FAILURE);

		/* Check whether our parent died before we were able
		 * to set the death signal */
		if (getppid () != parent_pid)
			_exit (EXIT_SUCCESS);

		if (pager) {
			execlp (pager, pager, NULL);
			execl ("/bin/sh", "sh", "-c", pager, NULL);
		}

		/* Debian's alternatives command for pagers is
		 * called 'pager'. Note that we do not call
		 * sensible-pagers here, since that is just a
		 * shell script that implements a logic that
		 * is similar to this one anyway, but is
		 * Debian-specific. */
		execlp ("pager", "pager", NULL);

		execlp ("less", "less", NULL);
		execlp ("more", "more", NULL);

		pager_fallback ();
		/* not reached */
	}

	/* Return in the parent */
	if (dup2 (fd[1], STDOUT_FILENO) < 0) {
		errsv = errno;
		g_printerr (_("Failed to duplicate pager pipe: %s\n"), nm_strerror_native (errsv));
	}
	if (dup2 (fd[1], STDERR_FILENO) < 0) {
		errsv = errno;
		g_printerr (_("Failed to duplicate pager pipe: %s\n"), nm_strerror_native (errsv));
	}

	nm_close (fd[0]);
	nm_close (fd[1]);
	return pager_pid;
}

/*****************************************************************************/

static const char *
get_value_to_print (const NmcConfig *nmc_config,
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
		value = nm_meta_abstract_info_get_name (field->info, FALSE);
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
	out = colorize_string (nmc_config, field->color, value, out_to_free);

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
	gboolean main_header_add = of_flags & NMC_OF_FLAG_MAIN_HEADER_ADD;
	gboolean main_header_only = of_flags & NMC_OF_FLAG_MAIN_HEADER_ONLY;
	gboolean field_names = of_flags & NMC_OF_FLAG_FIELD_NAMES;
	gboolean section_prefix = of_flags & NMC_OF_FLAG_SECTION_PREFIX;

	nm_cli_spawn_pager (&nm_cli);

	/* --- Main header --- */
	if (   nmc_config->print_output == NMC_PRINT_PRETTY
	    && (   main_header_add
	        || main_header_only)) {
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
	if (   (   nmc_config->print_output == NMC_PRINT_TERSE
	        || nmc_config->multiline_output)
	    && field_names)
		return;

	/* Don't replace empty strings in terse mode */
	not_set_str = nmc_config->print_output == NMC_PRINT_TERSE ? "" : "--";

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
					print_val = colorize_string (nmc_config, field_values[idx].color,
					                             val, &val_to_free);
					tmp = g_strdup_printf ("%s%s%s[%d]:",
					                       section_prefix ? (const char*) field_values[0].value : "",
					                       section_prefix ? "." : "",
					                       nm_meta_abstract_info_get_name (field_values[idx].info, FALSE),
					                       j);
					width1 = strlen (tmp);
					width2 = nmc_string_screen_width (tmp, NULL);
					g_print ("%-*s%s\n",
					         (int) (nmc_config->print_output == NMC_PRINT_TERSE
					                ? 0
					                : ML_VALUE_INDENT + width1 - width2),
					         tmp,
					         print_val);
				}
			} else {
				gs_free char *val_to_free = NULL;
				gs_free char *tmp = NULL;
				const char *hdr_name = (const char*) field_values[0].value;
				const char *val = (const char*) field_values[idx].value;
				const char *print_val;

				/* value is a string */

				val = val && *val ? val : not_set_str;
				print_val = colorize_string (nmc_config, field_values[idx].color,
				                             val, &val_to_free);
				tmp = g_strdup_printf ("%s%s%s:",
				                       section_prefix ? hdr_name : "",
				                       section_prefix ? "." : "",
				                       nm_meta_abstract_info_get_name (field_values[idx].info, FALSE));
				width1 = strlen (tmp);
				width2 = nmc_string_screen_width (tmp, NULL);
				g_print ("%-*s%s\n",
				         (int) (  nmc_config->print_output == NMC_PRINT_TERSE
				                ? 0
				                : ML_VALUE_INDENT + width1 - width2),
				         tmp,
				         print_val);
			}
		}
		if (nmc_config->print_output == NMC_PRINT_PRETTY) {
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

		value = get_value_to_print (nmc_config, (NmcOutputField *) field_values+idx, field_names,
		                            not_set_str, &val_to_free);

		if (nmc_config->print_output == NMC_PRINT_TERSE) {
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
			width2 = nmc_string_screen_width (value, NULL);  /* Width of the string (in screen columns) */
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
		if (   nmc_config->print_output == NMC_PRINT_PRETTY
		    && field_names) {
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
			value = get_value_to_print (NULL, row+i, field_names, "--", &val_to_free);
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

