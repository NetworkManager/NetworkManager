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

#ifndef NMC_UTILS_H
#define NMC_UTILS_H

#include "nmcli.h"

/* === Types === */

typedef struct {
	const char *name;
	gboolean has_value;
	const char **value;
	gboolean mandatory;
	gboolean found;
} nmc_arg_t;

/* === Functions === */
int next_arg (NmCli *nmc, int *argc, char ***argv, ...);
gboolean nmc_arg_is_help (const char *arg);
gboolean nmc_arg_is_option (const char *arg, const char *opt_name);
gboolean nmc_parse_args (nmc_arg_t *arg_arr, gboolean last, int *argc, char ***argv, GError **error);
char *ssid_to_hex (const char *str, gsize len);
void nmc_terminal_erase_line (void);
void nmc_terminal_show_progress (const char *str);
const char *nmc_term_color_sequence (NmcTermColor color);
const char *nmc_term_format_sequence (NmcTermFormat format);
NmcTermColor nmc_term_color_parse_string (const char *str, GError **error);
char *nmc_colorize (NmcColorOption color_option, NmcTermColor color, NmcTermFormat format, const char * fmt, ...)  _nm_printf (4, 5);
void nmc_filter_out_colors_inplace (char *str);
char *nmc_filter_out_colors (const char *str);
char *nmc_get_user_input (const char *ask_str);
int nmc_string_to_arg_array (const char *line, const char *delim, gboolean unquote,
                             char ***argv, int *argc);
const char *nmc_string_is_valid (const char *input, const char **allowed, GError **error);
char * nmc_util_strv_for_display (const char *const*strv, gboolean brackets);
char **nmc_strsplit_set (const char *str, const char *delimiter, int max_tokens);
int nmc_string_screen_width (const char *start, const char *end);
void set_val_str  (NmcOutputField fields_array[], guint32 index, char *value);
void set_val_strc (NmcOutputField fields_array[], guint32 index, const char *value);
void set_val_arr  (NmcOutputField fields_array[], guint32 index, char **value);
void set_val_arrc (NmcOutputField fields_array[], guint32 index, const char **value);
void set_val_color_all (NmcOutputField fields_array[], NmcTermColor color);
void set_val_color_fmt_all (NmcOutputField fields_array[], NmcTermFormat format);
void nmc_free_output_field_values (NmcOutputField fields_array[]);
GArray *parse_output_fields (const char *fields_str,
                             const NmcOutputField fields_array[],
                             gboolean parse_groups,
                             GPtrArray **group_fields,
                             GError **error);
char *nmc_get_allowed_fields (const NmcOutputField fields_array[], int group_idx);
NmcOutputField *nmc_dup_fields_array (NmcOutputField fields[], size_t size, guint32 flags);
void nmc_empty_output_fields (NmcOutputData *output_data);
void print_required_fields (const NmcConfig *nmc_config,
                            NmcOfFlags of_flags,
                            const GArray *indices,
                            const char *header_name,
                            int indent,
                            const NmcOutputField *field_values);
void print_data_prepare_width (GPtrArray *output_data);
void print_data (const NmcConfig *nmc_config, const NmcOutputData *out);

#endif /* NMC_UTILS_H */
