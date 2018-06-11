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
 * Copyright 2010 - 2018 Red Hat, Inc.
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
void nmc_terminal_spawn_pager (const NmcConfig *nmc_config);
char *nmc_colorize (const NmcConfig *nmc_config, NMMetaColor color, const char * fmt, ...)  _nm_printf (3, 4);
void nmc_filter_out_colors_inplace (char *str);
char *nmc_filter_out_colors (const char *str);
char *nmc_get_user_input (const char *ask_str);
int nmc_string_to_arg_array (const char *line, const char *delim, gboolean unquote,
                             char ***argv, int *argc);
const char *nmc_string_is_valid (const char *input, const char **allowed, GError **error);
char * nmc_util_strv_for_display (const char *const*strv, gboolean brackets);
int nmc_string_screen_width (const char *start, const char *end);
void set_val_str  (NmcOutputField fields_array[], guint32 index, char *value);
void set_val_strc (NmcOutputField fields_array[], guint32 index, const char *value);
void set_val_arr  (NmcOutputField fields_array[], guint32 index, char **value);
void set_val_arrc (NmcOutputField fields_array[], guint32 index, const char **value);
void set_val_color_all (NmcOutputField fields_array[], NMMetaColor color);
void nmc_free_output_field_values (NmcOutputField fields_array[]);

GArray *parse_output_fields (const char *fields_str,
                             const NMMetaAbstractInfo *const* fields_array,
                             gboolean parse_groups,
                             GPtrArray **group_fields,
                             GError **error);
NmcOutputField *nmc_dup_fields_array (const NMMetaAbstractInfo *const*fields, NmcOfFlags flags);
void nmc_empty_output_fields (NmcOutputData *output_data);
void print_required_fields (const NmcConfig *nmc_config,
                            NmcOfFlags of_flags,
                            const GArray *indices,
                            const char *header_name,
                            int indent,
                            const NmcOutputField *field_values);
void print_data_prepare_width (GPtrArray *output_data);
void print_data (const NmcConfig *nmc_config,
                 const GArray *indices,
                 const char *header_name,
                 int indent,
                 const NmcOutputData *out);

/*****************************************************************************/

extern const NMMetaEnvironment *const nmc_meta_environment;
extern NmCli *const nmc_meta_environment_arg;

typedef enum {

	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_RUNNING = 0,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_VERSION,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_STATE,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_STARTUP,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_CONNECTIVITY,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_NETWORKING,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIFI_HW,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIFI,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WWAN_HW,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WWAN,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIMAX_HW,
	NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIMAX,
	_NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_NUM,

	NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_PERMISSION = 0,
	NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_VALUE,
	_NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_NUM,

	NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_LEVEL = 0,
	NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_DOMAINS,
	_NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_NUM,

	NMC_GENERIC_INFO_TYPE_IP4_CONFIG_ADDRESS = 0,
	NMC_GENERIC_INFO_TYPE_IP4_CONFIG_GATEWAY,
	NMC_GENERIC_INFO_TYPE_IP4_CONFIG_ROUTE,
	NMC_GENERIC_INFO_TYPE_IP4_CONFIG_DNS,
	NMC_GENERIC_INFO_TYPE_IP4_CONFIG_DOMAIN,
	NMC_GENERIC_INFO_TYPE_IP4_CONFIG_WINS,
	_NMC_GENERIC_INFO_TYPE_IP4_CONFIG_NUM,

	NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ADDRESS = 0,
	NMC_GENERIC_INFO_TYPE_IP6_CONFIG_GATEWAY,
	NMC_GENERIC_INFO_TYPE_IP6_CONFIG_ROUTE,
	NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DNS,
	NMC_GENERIC_INFO_TYPE_IP6_CONFIG_DOMAIN,
	_NMC_GENERIC_INFO_TYPE_IP6_CONFIG_NUM,

	NMC_GENERIC_INFO_TYPE_CON_SHOW_NAME = 0,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_UUID,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_TYPE,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_TIMESTAMP,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_TIMESTAMP_REAL,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_AUTOCONNECT,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_AUTOCONNECT_PRIORITY,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_READONLY,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_DBUS_PATH,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_ACTIVE,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_DEVICE,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_STATE,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_ACTIVE_PATH,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_SLAVE,
	NMC_GENERIC_INFO_TYPE_CON_SHOW_FILENAME,
	_NMC_GENERIC_INFO_TYPE_CON_SHOW_NUM,

	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_NAME = 0,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_UUID,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEVICES,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_STATE,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEFAULT,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEFAULT6,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_SPEC_OBJECT,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_VPN,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DBUS_PATH,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_CON_PATH,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_ZONE,
	NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_MASTER_PATH,
	_NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_NUM,

} NmcGenericInfoType;

#define NMC_HANDLE_COLOR(color) \
	G_STMT_START { \
		if (get_type == NM_META_ACCESSOR_GET_TYPE_COLOR) \
			return GINT_TO_POINTER (color); \
	} G_STMT_END

struct _NmcMetaGenericInfo {
	union {
		NMObjBaseInst parent;
		const NMMetaType *meta_type;
	};
	NmcGenericInfoType info_type;
	const char *name;
	const char *name_header;
	const NmcMetaGenericInfo *const*nested;

#define NMC_META_GENERIC_INFO_GET_FCN_ARGS \
	const NMMetaEnvironment *environment, \
	gpointer environment_user_data, \
	const NmcMetaGenericInfo *info, \
	gpointer target, \
	NMMetaAccessorGetType get_type, \
	NMMetaAccessorGetFlags get_flags, \
	NMMetaAccessorGetOutFlags *out_flags, \
	gboolean *out_is_default, \
	gpointer *out_to_free

	gconstpointer (*get_fcn) (NMC_META_GENERIC_INFO_GET_FCN_ARGS);
};

#define NMC_META_GENERIC(n, ...) \
	(&((NmcMetaGenericInfo) { \
		.meta_type =                        &nmc_meta_type_generic_info, \
		.name =                             n, \
		__VA_ARGS__ \
	}))

#define NMC_META_GENERIC_WITH_NESTED(n, nest, ...) \
	NMC_META_GENERIC (n, .nested = (nest), __VA_ARGS__)

#define NMC_META_GENERIC_GROUP(_group_name, _nested, _name_header) \
	((const NMMetaAbstractInfo *const*) ((const NmcMetaGenericInfo *const[]) { \
		NMC_META_GENERIC_WITH_NESTED (_group_name,_nested, .name_header = _name_header), \
		NULL, \
	}))

static inline const char *
nmc_meta_generic_get_str_i18n (const char *s, NMMetaAccessorGetType get_type)
{
	if (!NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_PRETTY,
	                          NM_META_ACCESSOR_GET_TYPE_PARSABLE))
		g_return_val_if_reached (NULL);

	if (!s)
		return NULL;
	if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return gettext (s);
	return s;
}

static inline const char *
nmc_meta_generic_get_bool (gboolean val, NMMetaAccessorGetType get_type)
{
	return nmc_meta_generic_get_str_i18n (val ? N_("yes") : N_("no"), get_type);
}

static inline char *
nmc_meta_generic_get_enum_with_detail (gint64 enum_val, const char *str_val, NMMetaAccessorGetType get_type)
{
	if (!NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_PRETTY,
	                          NM_META_ACCESSOR_GET_TYPE_PARSABLE))
		g_return_val_if_reached (NULL);

	if (!str_val) {
		/* Pass %NULL for only printing the numeric value. */
		return g_strdup_printf ("%lld", (long long) enum_val);
	}

	/* note that this function will always print "$NUM ($NICK)", also in PARSABLE
	 * mode. That might not be desired, but it's done for certain properties to preserve
	 * previous behavior. */
	if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return g_strdup_printf (_("%lld (%s)"), (long long) enum_val, gettext (str_val));
	return g_strdup_printf ("%lld (%s)", (long long) enum_val, str_val);
}

/*****************************************************************************/

gboolean nmc_print (const NmcConfig *nmc_config,
                    gpointer const *targets,
                    const char *header_name_no_l10n,
                    const NMMetaAbstractInfo *const*fields,
                    const char *fields_str,
                    GError **error);

/*****************************************************************************/

#endif /* NMC_UTILS_H */
