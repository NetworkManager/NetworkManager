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
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-client-utils.h"

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
		             /* Translators: the first %s is the partial value entered by
		              * the user, the second %s a list of compatible values.
		              */
		             _("'%s' is ambiguous (%s)"), str, "on x off");
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
		             /* Translators: the first %s is the partial value entered by
		              * the user, the second %s a list of compatible values.
		              */
		             _("'%s' is ambiguous (%s)"), str, "on x off");
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

gboolean
matches (const char *cmd, const char *pattern)
{
	size_t len = strlen (cmd);
	if (!len || len > strlen (pattern))
		return FALSE;
	return memcmp (pattern, cmd, len) == 0;
}

