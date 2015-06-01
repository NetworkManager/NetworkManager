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
 * (C) Copyright 2010 - 2014 Red Hat, Inc.
 */

/* Generated configuration file */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gi18n.h>

#include "utils.h"

int
matches (const char *cmd, const char *pattern)
{
	size_t len = strlen (cmd);
	if (!len || len > strlen (pattern))
		return -1;
	return memcmp (pattern, cmd, len);
}

int
next_arg (int *argc, char ***argv)
{
	int arg_num = *argc;

	if (arg_num > 0) {
		(*argc)--;
		(*argv)++;
	}
	if (arg_num <= 1)
		return -1;

	return 0;
}

gboolean
nmc_arg_is_help (const char *arg)
{
	if (!arg)
		return FALSE;
	if (   matches (arg, "help") == 0
	    || (g_str_has_prefix (arg, "-")  && matches (arg+1, "help") == 0)
	    || (g_str_has_prefix (arg, "--") && matches (arg+2, "help") == 0)) {
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

	return (*p ? (matches (p, opt_name) == 0) : FALSE);
}


/*
 * Helper function to parse command-line arguments.
 * arg_arr: description of arguments to look for
 * last:    whether these are last expected arguments
 * argc:    command-line argument array
 * argv:    command-line argument array size
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
					if (next_arg (argc, argv) != 0) {
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

		next_arg (argc, argv);
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
 * Converts IPv4 address from guint32 in network-byte order to text representation.
 * Returns: text form of the IP or NULL (then error is set)
 */
char *
nmc_ip4_address_as_string (guint32 ip, GError **error)
{
	guint32 tmp_addr;
	char buf[INET_ADDRSTRLEN];

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	memset (&buf, '\0', sizeof (buf));
	tmp_addr = ip;

	if (inet_ntop (AF_INET, &tmp_addr, buf, INET_ADDRSTRLEN)) {
		return g_strdup (buf);
	} else {
		g_set_error (error, NMCLI_ERROR, 0, _("Error converting IP4 address '0x%X' to text form"),
		             ntohl (tmp_addr));
		return NULL;
	}
}

/*
 * Converts IPv6 address in in6_addr structure to text representation.
 * Returns: text form of the IP or NULL (then error is set)
 */
char *
nmc_ip6_address_as_string (const struct in6_addr *ip, GError **error)
{
	char buf[INET6_ADDRSTRLEN];

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	memset (&buf, '\0', sizeof (buf));

	if (inet_ntop (AF_INET6, ip, buf, INET6_ADDRSTRLEN)) {
		return g_strdup (buf);
	} else {
		if (error) {
			int j;
			GString *ip6_str = g_string_new (NULL);
			g_string_append_printf (ip6_str, "%02X", ip->s6_addr[0]);
			for (j = 1; j < 16; j++)
				g_string_append_printf (ip6_str, " %02X", ip->s6_addr[j]);
			g_set_error (error, NMCLI_ERROR, 0, _("Error converting IP6 address '%s' to text form"),
			             ip6_str->str);
			g_string_free (ip6_str, TRUE);
		}
		return NULL;
	}
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
nmc_term_color_sequence (NmcTermColor color)
{
	switch (color) {
        case NMC_TERM_COLOR_BLACK:
		return "\33[30m";
		break;
        case NMC_TERM_COLOR_RED:
		return "\33[31m";
		break;
        case NMC_TERM_COLOR_GREEN:
		return "\33[32m";
		break;
        case NMC_TERM_COLOR_YELLOW:
		return "\33[33m";
		break;
        case NMC_TERM_COLOR_BLUE:
		return "\33[34m";
		break;
        case NMC_TERM_COLOR_MAGENTA:
		return "\33[35m";
		break;
        case NMC_TERM_COLOR_CYAN:
		return "\33[36m";
		break;
        case NMC_TERM_COLOR_WHITE:
		return "\33[37m";
		break;
	default:
		return "";
		break;
	}
}

char *
nmc_colorize (NmcTermColor color, const char *fmt, ...)
{
	va_list args;
	char *str, *colored;
	const char *ansi_color, *color_end;

	va_start (args, fmt);
	str = g_strdup_vprintf (fmt, args);
	va_end (args);

	ansi_color = nmc_term_color_sequence (color);
	if (*ansi_color)
		color_end = "\33[0m";
	else
		color_end = "";

	colored = g_strdup_printf ("%s%s%s", ansi_color, str, color_end);
	g_free (str);
	return colored;
}

/*
 * Convert string to signed integer.
 * If required, the resulting number is checked to be in the <min,max> range.
 */
gboolean
nmc_string_to_int_base (const char *str,
                        int base,
                        gboolean range_check,
                        long int min,
                        long int max,
                        long int *value)
{
	char *end;
	long int tmp;

	errno = 0;
	tmp = strtol (str, &end, base);
	if (errno || *end != '\0' || (range_check && (tmp < min || tmp > max))) {
		return FALSE;
	}
	*value = tmp;
	return TRUE;
}

/*
 * Convert string to unsigned integer.
 * If required, the resulting number is checked to be in the <min,max> range.
 */
gboolean
nmc_string_to_uint_base (const char *str,
                         int base,
                         gboolean range_check,
                         unsigned long int min,
                         unsigned long int max,
                         unsigned long int *value)
{
	char *end;
	unsigned long int tmp;

	errno = 0;
	tmp = strtoul (str, &end, base);
	if (errno || *end != '\0' || (range_check && (tmp < min || tmp > max))) {
		return FALSE;
	}
	*value = tmp;
	return TRUE;
}

gboolean
nmc_string_to_int (const char *str,
                   gboolean range_check,
                   long int min,
                   long int max,
                   long int *value)
{
	return nmc_string_to_int_base (str, 10, range_check, min, max, value);
}

gboolean
nmc_string_to_uint (const char *str,
                    gboolean range_check,
                    unsigned long int min,
                    unsigned long int max,
                    unsigned long int *value)
{
	return nmc_string_to_uint_base (str, 10, range_check, min, max, value);
}

gboolean
nmc_string_to_bool (const char *str, gboolean *val_bool, GError **error)
{
	const char *s_true[] = { "true", "yes", "on", NULL };
	const char *s_false[] = { "false", "no", "off", NULL };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (g_strcmp0 (str, "o") == 0) {
		g_set_error (error, 1, 0,
		             _("'%s' is ambiguous (on x off)"), str);
		return FALSE;
	}

	if (nmc_string_is_valid (str, s_true, NULL))
		*val_bool = TRUE;
	else if (nmc_string_is_valid (str, s_false, NULL))
		*val_bool = FALSE;
	else {
		g_set_error (error, 1, 0,
		             _("'%s' is not valid; use [%s] or [%s]"),
		             str, "true, yes, on", "false, no, off");
		return FALSE;
	}
	return TRUE;
}

gboolean
nmc_string_to_tristate (const char *str, NMCTriStateValue *val, GError **error)
{
	const char *s_true[] = { "true", "yes", "on", NULL };
	const char *s_false[] = { "false", "no", "off", NULL };
	const char *s_unknown[] = { "unknown", NULL };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (g_strcmp0 (str, "o") == 0) {
		g_set_error (error, 1, 0,
		             _("'%s' is ambiguous (on x off)"), str);
		return FALSE;
	}

	if (nmc_string_is_valid (str, s_true, NULL))
		*val = NMC_TRI_STATE_YES;
	else if (nmc_string_is_valid (str, s_false, NULL))
		*val = NMC_TRI_STATE_NO;
	else if (nmc_string_is_valid (str, s_unknown, NULL))
		*val = NMC_TRI_STATE_UNKNOWN;
	else {
		g_set_error (error, 1, 0,
		             _("'%s' is not valid; use [%s], [%s] or [%s]"),
		             str, "true, yes, on", "false, no, off", "unknown");
		return FALSE;
	}
	return TRUE;
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
 * Check whether 'input' is contained in 'allowed' array. It performs case
 * insensitive comparison and supports shortcut strings if they are unique.
 * Returns: a pointer to found string in allowed array on success or NULL.
 * On failure: error->code : 0 - string not found; 1 - string is ambiguous
 */
const char *
nmc_string_is_valid (const char *input, const char **allowed, GError **error)
{
	const char **p;
	size_t input_ln, p_len;
	gboolean prev_match = FALSE;
	const char *ret = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	if (!input || !*input)
		goto finish;

	input_ln = strlen (input);
	for (p = allowed; p && *p; p++) {
		p_len = strlen (*p);
		if (g_ascii_strncasecmp (input, *p, input_ln) == 0) {
			if (input_ln == p_len) {
				ret = *p;
				break;
			}
			if (!prev_match)
				ret = *p;
			else {
				g_set_error (error, 1, 1, _("'%s' is ambiguous (%s x %s)"),
				             input, ret, *p);
				return NULL;
			}
			prev_match = TRUE;
		}
	}

finish:
	if (ret == NULL) {
		char *valid_vals = g_strjoinv (", ", (char **) allowed);
		if (!input || !*input)
			g_set_error (error, 1, 0, _("missing name, try one of [%s]"), valid_vals);
		else
			g_set_error (error, 1, 0, _("'%s' not among [%s]"), input, valid_vals);

		g_free (valid_vals);
	}
	return ret;
}

/*
 * Convert string array (char **) to GSList.
 *
 * Returns: pointer to newly created GSList. Caller should free it.
 */
GSList *
nmc_util_strv_to_slist (char **strv)
{
	GSList *list = NULL;
	guint i = 0;

	while (strv && strv[i])
		list = g_slist_prepend (list, g_strdup (strv[i++]));

	return g_slist_reverse (list);
}

/*
 * Convert string array (char **) to description string in the form of:
 * "[string1, string2, ]"
 *
 * Returns: a newly allocated string. Caller must free it with g_free().
 */
char *
nmc_util_strv_for_display (const char **strv, gboolean brackets)
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
 * Wrapper function for g_strsplit_set() that removes empty strings
 * from the vector as they are not useful in most cases.
 */
char **
nmc_strsplit_set (const char *str, const char *delimiter, int max_tokens)
{
	char **result;
	uint i;
	uint j;

	result = g_strsplit_set (str, delimiter, max_tokens);

	/* remove empty strings */
	for (i = 0; result && result[i]; i++) {
		if (*(result[i]) == '\0') {
			g_free (result[i]);
			for (j = i; result[j]; j++)
				result[j] = result[j + 1];
			i--;
		}
	}
	return result;
}

/*
 * Find out how many columns an UTF-8 string occupies on the screen
 */
int
nmc_string_screen_width (const char *start, const char *end)
{
	int width = 0;

	if (end == NULL)
		end = start + strlen (start);

	while (start < end) {
		width += g_unichar_iswide (g_utf8_get_char (start)) ? 2 : g_unichar_iszerowidth (g_utf8_get_char (start)) ? 0 : 1;
		start = g_utf8_next_char (start);
	}
	return width;
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

/*
 * Free 'value' members in array of NmcOutputField
 */
void
nmc_free_output_field_values (NmcOutputField fields_array[])
{
	NmcOutputField *iter = fields_array;

	while (iter && iter->name) {
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
                     const NmcOutputField fields_array[],
                     gboolean parse_groups,
                     GPtrArray **group_fields,
                     GError **error)
{
	char **fields, **iter;
	GArray *array;
	int i, j;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (group_fields == NULL || *group_fields == NULL, NULL);

	array = g_array_new (FALSE, FALSE, sizeof (int));
	if (parse_groups && group_fields)
		*group_fields = g_ptr_array_new_full (20, (GDestroyNotify) g_free);

	/* Split supplied fields string */
	fields = g_strsplit_set (fields_str, ",", -1);
	for (iter = fields; iter && *iter; iter++) {
		int idx = -1;

		g_strstrip (*iter);
		if (parse_groups) {
			/* e.g. "general.device,general.driver,ip4,ip6" */
			gboolean found = FALSE;
			char *left = *iter;
			char *right = strchr (*iter, '.');

			if (right)
				*right++ = '\0';

			for (i = 0; fields_array[i].name; i++) {
				if (strcasecmp (left, fields_array[i].name) == 0) {
					NmcOutputField *valid_names = fields_array[i].group;
					idx = i;
					if (!right && !valid_names) {
						found = TRUE;
						break;
					}
					for (j = 0; valid_names && valid_names[j].name; j++) {
						if (!right || strcasecmp (right, valid_names[j].name) == 0) {
							found = TRUE;
							break;
						}
					}
					if (found)
						break;
				}
			}
			if (found) {
				/* Add index to array, and field name (or NULL) to group_fields array */
				g_array_append_val (array, idx);
				if (group_fields && *group_fields)
					g_ptr_array_add (*group_fields, g_strdup (right));
			}
			if (right)
				*(right-1) = '.';  /* Restore the original string */
		} else {
			/* e.g. "general,ip4,ip6" */
			for (i = 0; fields_array[i].name; i++) {
				if (strcasecmp (*iter, fields_array[i].name) == 0) {
					g_array_append_val (array, i);
					break;
				}
			}
		}

		/* Field was not found - error case */
		if (fields_array[i].name == NULL) {
			/* Set GError */
			if (!strcasecmp (*iter, "all") || !strcasecmp (*iter, "common"))
				g_set_error (error, NMCLI_ERROR, 0, _("field '%s' has to be alone"), *iter);
			else {
				char *allowed_fields = nmc_get_allowed_fields (fields_array, idx);
				g_set_error (error, NMCLI_ERROR, 1, _("invalid field '%s'; allowed fields: %s"),
				             *iter, allowed_fields);
				g_free (allowed_fields);
			}

			/* Free arrays on error */
			g_array_free (array, TRUE);
			array = NULL;
			if (group_fields && *group_fields) {
				g_ptr_array_free (*group_fields, TRUE);
				*group_fields = NULL;
			}
			goto done;
		}
	}
done:
	if (fields)
		g_strfreev (fields);
	return array;
}

/**
* nmc_get_allowed_fields:
* @fields_array: array of fields
* @group_idx: index to the array (for second-level array in 'group' member),
*   or -1
*
* Returns: string of allowed fields names.
*   Caller is responsible for freeing the array.
*/
char *
nmc_get_allowed_fields (const NmcOutputField fields_array[], int group_idx)
{
	GString *allowed_fields = g_string_sized_new (256);
	int i;

	if (group_idx != -1 && fields_array[group_idx].group) {
		NmcOutputField *second_level = fields_array[group_idx].group;
		for (i = 0; second_level[i].name; i++)
			g_string_append_printf (allowed_fields, "%s.%s,",
			                        fields_array[group_idx].name, second_level[i].name);
	} else {
		for (i = 0; fields_array[i].name; i++)
			g_string_append_printf (allowed_fields, "%s,", fields_array[i].name);
	}
	g_string_truncate (allowed_fields, allowed_fields->len - 1);

	return g_string_free (allowed_fields, FALSE);
}

gboolean
nmc_terse_option_check (NMCPrintOutput print_output, const char *fields, GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (print_output == NMC_PRINT_TERSE) {
		if (!fields) {
			g_set_error_literal (error, NMCLI_ERROR, 0, _("Option '--terse' requires specifying '--fields'"));
			return FALSE;
		} else if (   !strcasecmp (fields, "all")
		           || !strcasecmp (fields, "common")) {
			g_set_error (error, NMCLI_ERROR, 0, _("Option '--terse' requires specific '--fields' option values , not '%s'"), fields);
			return FALSE;
		}
	}
	return TRUE;
}

NmcOutputField *
nmc_dup_fields_array (NmcOutputField fields[], size_t size, guint32 flags)
{
	NmcOutputField *row;

	row = g_malloc0 (size);
	memcpy (row, fields, size);
	row[0].flags = flags;

	return row;
}

void
nmc_empty_output_fields (NmCli *nmc)
{
	guint i;

	/* Free values in field structure */
	for (i = 0; i < nmc->output_data->len; i++) {
		NmcOutputField *fld_arr = g_ptr_array_index (nmc->output_data, i);
		nmc_free_output_field_values (fld_arr);
	}

	/* Empty output_data array */
	if (nmc->output_data->len > 0)
		g_ptr_array_remove_range (nmc->output_data, 0, nmc->output_data->len);

	if (nmc->print_fields.indices) {
		g_array_free (nmc->print_fields.indices, TRUE);
		nmc->print_fields.indices = NULL;
	}
}

static char *
get_value_to_print (NmcOutputField *fields,
                    gboolean field_name,
                    const char *not_set_str,
                    gboolean *dealloc)
{
	gboolean is_array = fields->value_is_array;
	char *value;

	if (field_name)
		value = _(fields->name_l10n);
	else
		value = fields->value ?
		          (is_array ? g_strjoinv (" | ", (char **) fields->value) :
		                      (char *) fields->value) :
		          (char *) not_set_str;
	*dealloc = fields->value && is_array && !field_name;
	return value;
}

/*
 * Print both headers or values of 'field_values' array.
 * Entries to print and their order are specified via indices in
 * 'nmc->print_fields.indices' array.
 * Various flags influencing the output of fields are set up in the first item
 * of 'field_values' array.
 */
void
print_required_fields (NmCli *nmc, const NmcOutputField field_values[])
{
	GString *str;
	int width1, width2;
	int table_width = 0;
	char *line = NULL;
	char *indent_str;
	const char *not_set_str = "--";
	int i;
	const NmcPrintFields fields = nmc->print_fields;
	gboolean multiline = nmc->multiline_output;
	gboolean terse = (nmc->print_output == NMC_PRINT_TERSE);
	gboolean pretty = (nmc->print_output == NMC_PRINT_PRETTY);
	gboolean escape = nmc->escape_values;
	gboolean main_header_add = field_values[0].flags & NMC_OF_FLAG_MAIN_HEADER_ADD;
	gboolean main_header_only = field_values[0].flags & NMC_OF_FLAG_MAIN_HEADER_ONLY;
	gboolean field_names = field_values[0].flags & NMC_OF_FLAG_FIELD_NAMES;
	gboolean section_prefix = field_values[0].flags & NMC_OF_FLAG_SECTION_PREFIX;
	gboolean main_header = main_header_add || main_header_only;

	/* No headers are printed in terse mode:
	 * - neither main header nor field (column) names
	 */
	if ((main_header_only || field_names) && terse)
		return;

	if (multiline) {
	/* --- Multiline mode --- */
		enum { ML_HEADER_WIDTH = 79 };
		enum { ML_VALUE_INDENT = 40 };
		if (main_header && pretty) {
			/* Print the main header */
			int header_width = nmc_string_screen_width (fields.header_name, NULL) + 4;
			table_width = header_width < ML_HEADER_WIDTH ? ML_HEADER_WIDTH : header_width;

			line = g_strnfill (ML_HEADER_WIDTH, '=');
			width1 = strlen (fields.header_name);
			width2 = nmc_string_screen_width (fields.header_name, NULL);
			g_print ("%s\n", line);
			g_print ("%*s\n", (table_width + width2)/2 + width1 - width2, fields.header_name);
			g_print ("%s\n", line);
			g_free (line);
		}

		/* Print values */
		if (!main_header_only && !field_names) {
			for (i = 0; i < fields.indices->len; i++) {
				char *tmp;
				int idx = g_array_index (fields.indices, int, i);
				gboolean is_array = field_values[idx].value_is_array;

				/* section prefix can't be an array */
				g_assert (!is_array || !section_prefix || idx != 0);

				if (section_prefix && idx == 0)  /* The first field is section prefix */
					continue;

				if (is_array) {
					/* value is a null-terminated string array */
					const char **p;
					int j;

					for (p = (const char **) field_values[idx].value, j = 1; p && *p; p++, j++) {
						tmp = g_strdup_printf ("%s%s%s[%d]:",
						                       section_prefix ? (const char*) field_values[0].value : "",
						                       section_prefix ? "." : "",
						                       _(field_values[idx].name_l10n),
						                       j);
						width1 = strlen (tmp);
						width2 = nmc_string_screen_width (tmp, NULL);
						g_print ("%-*s%s\n", terse ? 0 : ML_VALUE_INDENT+width1-width2, tmp,
						         *p ? *p : not_set_str);
						g_free (tmp);
					}
				} else {
					/* value is a string */
					const char *hdr_name = (const char*) field_values[0].value;
					const char *val = (const char*) field_values[idx].value;

					tmp = g_strdup_printf ("%s%s%s:",
					                       section_prefix ? hdr_name : "",
					                       section_prefix ? "." : "",
					                       _(field_values[idx].name_l10n));
					width1 = strlen (tmp);
					width2 = nmc_string_screen_width (tmp, NULL);
					g_print ("%-*s%s\n", terse ? 0 : ML_VALUE_INDENT+width1-width2, tmp,
					         val ? val : not_set_str);
					g_free (tmp);
				}
			}
			if (pretty) {
				line = g_strnfill (ML_HEADER_WIDTH, '-');
				g_print ("%s\n", line);
				g_free (line);
			}
		}
		return;
	}

	/* --- Tabular mode: each line = one object --- */
	str = g_string_new (NULL);

	for (i = 0; i < fields.indices->len; i++) {
		int idx = g_array_index (fields.indices, int, i);
		gboolean dealloc;
		char *value = get_value_to_print ((NmcOutputField *) field_values+idx, field_names, not_set_str, &dealloc);

		if (terse) {
			if (escape) {
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
			g_string_append_printf (str, "%-*s", field_values[idx].width + width1 - width2, strlen (value) > 0 ? value : "--");
			g_string_append_c (str, ' ');  /* Column separator */
			table_width += field_values[idx].width + width1 - width2 + 1;
		}

		if (dealloc)
			g_free (value);
	}

	/* Print the main table header */
	if (main_header && pretty) {
		int header_width = nmc_string_screen_width (fields.header_name, NULL) + 4;
		table_width = table_width < header_width ? header_width : table_width;

		line = g_strnfill (table_width, '=');
		width1 = strlen (fields.header_name);
		width2 = nmc_string_screen_width (fields.header_name, NULL);
		g_print ("%s\n", line);
		g_print ("%*s\n", (table_width + width2)/2 + width1 - width2, fields.header_name);
		g_print ("%s\n", line);
		g_free (line);
	}

	/* Print actual values */
	if (!main_header_only && str->len > 0) {
		g_string_truncate (str, str->len-1);  /* Chop off last column separator */
		if (fields.indent > 0) {
			indent_str = g_strnfill (fields.indent, ' ');
			g_string_prepend (str, indent_str);
			g_free (indent_str);
		}
		g_print ("%s\n", str->str);
	}

	/* Print horizontal separator */
	if (!main_header_only && field_names && pretty) {
		if (str->len > 0) {
			line = g_strnfill (table_width, '-');
			g_print ("%s\n", line);
			g_free (line);
		}
	}

	g_string_free (str, TRUE);
}

/*
 * Print nmc->output_data
 *
 * It first finds out maximal string length in columns and fill the value to
 * 'width' member of NmcOutputField, so that columns in tabular output are
 * properly aligned. Then each object (row in tabular) is printed using
 * print_required_fields() function.
 */
void
print_data (NmCli *nmc)
{
	int i, j;
	size_t len;
	NmcOutputField *row;
	int num_fields = 0;

	if (!nmc->output_data || nmc->output_data->len < 1)
		return;

	/* How many fields? */
	row = g_ptr_array_index (nmc->output_data, 0);
	while (row->name) {
		num_fields++;
		row++;
	}

	/* Find out maximal string lengths */
	for (i = 0; i < num_fields; i++) {
		size_t max_width = 0;
		for (j = 0; j < nmc->output_data->len; j++) {
			gboolean field_names, dealloc;
			char *value;
			row = g_ptr_array_index (nmc->output_data, j);
			field_names = row[0].flags & NMC_OF_FLAG_FIELD_NAMES;
			value = get_value_to_print (row+i, field_names, "--", &dealloc);
			len = nmc_string_screen_width (value, NULL);
			max_width = len > max_width ? len : max_width;
			if (dealloc)
				g_free (value);
		}
		for (j = 0; j < nmc->output_data->len; j++) {
			row = g_ptr_array_index (nmc->output_data, j);
			row[i].width = max_width + 1;
		}
	}

	/* Now we can print the data. */
	for (i = 0; i < nmc->output_data->len; i++) {
		row = g_ptr_array_index (nmc->output_data, i);
		print_required_fields (nmc, row);
	}
}

/*
* Compare versions of nmcli and NM daemon.
* Return: TRUE  - the versions match (when only major and minor match, print a warning)
*         FALSE - versions mismatch
*/
gboolean
nmc_versions_match (NmCli *nmc)
{
	const char *nm_ver = NULL;
	const char *dot;
	gboolean match = FALSE;

	g_return_val_if_fail (nmc != NULL, FALSE);

	/* --nocheck option - don't compare the versions */
	if (nmc->nocheck_ver)
		return TRUE;

	nmc->get_client (nmc);
	nm_ver = nm_client_get_version (nmc->client);
	if (nm_ver) {
		if (!strcmp (nm_ver, VERSION))
			match = TRUE;
		else {
			dot = strchr (nm_ver, '.');
			if (dot) {
				dot = strchr (dot + 1, '.');
				if (dot && !strncmp (nm_ver, VERSION, dot-nm_ver)) {
					g_printerr (_("Warning: nmcli (%s) and NetworkManager (%s) versions don't match. Use --nocheck to suppress the warning.\n"),
					            VERSION, nm_ver);
					match = TRUE;
				}
			}
		}
	}

	if (!match) {
		g_string_printf (nmc->return_text, _("Error: nmcli (%s) and NetworkManager (%s) versions don't match. Force execution using --nocheck, but the results are unpredictable."),
		                 VERSION, nm_ver ? nm_ver : _("unknown"));
		nmc->return_value = NMC_RESULT_ERROR_VERSIONS_MISMATCH;
	}

	return match;
}

