/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-core-aux.h"

#include "nm-libnm-core-intern/nm-libnm-core-utils.h"

/*****************************************************************************/

typedef enum {
	KEY_TYPE_STRING,
	KEY_TYPE_INT,
	KEY_TYPE_BOOL,
} KeyType;

typedef struct {
	const char *str_val;
	union {
		int vint;
		bool vbool;
	} typ_val;
} ParseData;

typedef struct {
	const char *name;
	NMTeamLinkWatcherType watcher_type;
	KeyType key_type;
	union {
		int         (*fint)    (const NMTeamLinkWatcher *watcher);
		gboolean    (*fbool)   (const NMTeamLinkWatcher *watcher);
		const char *(*fstring) (const NMTeamLinkWatcher *watcher);
	} get_fcn;
	union {
		int vint;
		bool vbool;
	} def_val;
} TeamLinkWatcherKeyInfo;

static gboolean
_team_link_watcher_validate_active (const NMTeamLinkWatcher *watcher)
{
	return NM_FLAGS_HAS (nm_team_link_watcher_get_flags (watcher), NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE);
}

static gboolean
_team_link_watcher_validate_inactive (const NMTeamLinkWatcher *watcher)
{
	return NM_FLAGS_HAS (nm_team_link_watcher_get_flags (watcher), NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE);
}

static gboolean
_team_link_watcher_send_always (const NMTeamLinkWatcher *watcher)
{
	return NM_FLAGS_HAS (nm_team_link_watcher_get_flags (watcher), NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS);
}

static const TeamLinkWatcherKeyInfo _team_link_watcher_key_infos[_NM_TEAM_LINK_WATCHER_KEY_NUM] = {

#define _KEY_INFO(key_id, _name, _watcher_type, _key_type, ...) \
	[key_id] = { .name = ""_name"", .watcher_type = (_watcher_type), .key_type = _key_type, ##__VA_ARGS__ }

	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_NAME,              "name",              NM_TEAM_LINK_WATCHER_TYPE_ETHTOOL | NM_TEAM_LINK_WATCHER_TYPE_NSNAPING | NM_TEAM_LINK_WATCHER_TYPE_ARPING, KEY_TYPE_STRING, .get_fcn.fstring = nm_team_link_watcher_get_name,        ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_DELAY_UP,          "delay-up",          NM_TEAM_LINK_WATCHER_TYPE_ETHTOOL,                                                                         KEY_TYPE_INT,    .get_fcn.fint    = nm_team_link_watcher_get_delay_up,    ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_DELAY_DOWN,        "delay-down",        NM_TEAM_LINK_WATCHER_TYPE_ETHTOOL,                                                                         KEY_TYPE_INT,    .get_fcn.fint    = nm_team_link_watcher_get_delay_down,  ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_INIT_WAIT,         "init-wait",         NM_TEAM_LINK_WATCHER_TYPE_NSNAPING | NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                     KEY_TYPE_INT,    .get_fcn.fint    = nm_team_link_watcher_get_init_wait,   ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_INTERVAL,          "interval",          NM_TEAM_LINK_WATCHER_TYPE_NSNAPING | NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                     KEY_TYPE_INT,    .get_fcn.fint    = nm_team_link_watcher_get_interval,    ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_MISSED_MAX,        "missed-max",        NM_TEAM_LINK_WATCHER_TYPE_NSNAPING | NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                     KEY_TYPE_INT,    .get_fcn.fint    = nm_team_link_watcher_get_missed_max,  .def_val.vint = 3, ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_TARGET_HOST,       "target-host",       NM_TEAM_LINK_WATCHER_TYPE_NSNAPING | NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                     KEY_TYPE_STRING, .get_fcn.fstring = nm_team_link_watcher_get_target_host, ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_VLANID,            "vlanid",            NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                                                          KEY_TYPE_INT,    .get_fcn.fint    = nm_team_link_watcher_get_vlanid,      .def_val.vint = -1, ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_SOURCE_HOST,       "source-host",       NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                                                          KEY_TYPE_STRING, .get_fcn.fstring = nm_team_link_watcher_get_source_host, ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_VALIDATE_ACTIVE,   "validate-active",   NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                                                          KEY_TYPE_BOOL,   .get_fcn.fbool   = _team_link_watcher_validate_active,   ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_VALIDATE_INACTIVE, "validate-inactive", NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                                                          KEY_TYPE_BOOL,   .get_fcn.fbool   = _team_link_watcher_validate_inactive, ),
	_KEY_INFO (NM_TEAM_LINK_WATCHER_KEY_SEND_ALWAYS,       "send-always",       NM_TEAM_LINK_WATCHER_TYPE_ARPING,                                                                          KEY_TYPE_BOOL,   .get_fcn.fbool   = _team_link_watcher_send_always,       ),

};

static NMTeamLinkWatcherType
_team_link_watcher_get_watcher_type_from_name (const char *name)
{
	if (name) {
		if (nm_streq (name, NM_TEAM_LINK_WATCHER_ETHTOOL))
			return NM_TEAM_LINK_WATCHER_TYPE_ETHTOOL;
		if (nm_streq (name, NM_TEAM_LINK_WATCHER_NSNA_PING))
			return NM_TEAM_LINK_WATCHER_TYPE_NSNAPING;
		if (nm_streq (name, NM_TEAM_LINK_WATCHER_ARP_PING))
			return NM_TEAM_LINK_WATCHER_TYPE_ARPING;
	}
	return NM_TEAM_LINK_WATCHER_TYPE_NONE;
}

static const char *
_parse_data_get_str (const ParseData parse_data[static _NM_TEAM_LINK_WATCHER_KEY_NUM],
                     NMTeamLinkWatcherKeyId key_id)
{
	nm_assert (_NM_INT_NOT_NEGATIVE (key_id) && key_id < _NM_TEAM_LINK_WATCHER_KEY_NUM);
	nm_assert (_team_link_watcher_key_infos[key_id].key_type == KEY_TYPE_STRING);

	return parse_data[key_id].str_val;
}

static int
_parse_data_get_int (const ParseData parse_data[static _NM_TEAM_LINK_WATCHER_KEY_NUM],
                     NMTeamLinkWatcherKeyId key_id)
{
	nm_assert (_NM_INT_NOT_NEGATIVE (key_id) && key_id < _NM_TEAM_LINK_WATCHER_KEY_NUM);
	nm_assert (_team_link_watcher_key_infos[key_id].key_type == KEY_TYPE_INT);

	if (parse_data[key_id].str_val)
		return parse_data[key_id].typ_val.vint;
	return _team_link_watcher_key_infos[key_id].def_val.vint;
}

static int
_parse_data_get_bool (const ParseData parse_data[static _NM_TEAM_LINK_WATCHER_KEY_NUM],
                      NMTeamLinkWatcherKeyId key_id)
{
	nm_assert (_NM_INT_NOT_NEGATIVE (key_id) && key_id < _NM_TEAM_LINK_WATCHER_KEY_NUM);
	nm_assert (_team_link_watcher_key_infos[key_id].key_type == KEY_TYPE_BOOL);

	if (parse_data[key_id].str_val)
		return parse_data[key_id].typ_val.vbool;
	return _team_link_watcher_key_infos[key_id].def_val.vbool;
}

char *
nm_utils_team_link_watcher_to_string (const NMTeamLinkWatcher *watcher)
{
	nm_auto_free_gstring GString *str = NULL;
	const char *name;
	NMTeamLinkWatcherType watcher_type;
	NMTeamLinkWatcherKeyId key_id;

	if (!watcher)
		return NULL;

	str = g_string_new (NULL);

	name = nm_team_link_watcher_get_name (watcher);
	g_string_append_printf (str, "name=%s", name ?: "");

	watcher_type = _team_link_watcher_get_watcher_type_from_name (name);

	for (key_id = 0; key_id < _NM_TEAM_LINK_WATCHER_KEY_NUM; key_id++) {
		const TeamLinkWatcherKeyInfo *info = &_team_link_watcher_key_infos[key_id];
		const char *vstr;
		int vint;
		bool vbool;

		nm_assert (info->name && info->name && NM_STRCHAR_ALL (info->name, ch,((ch >= 'a' && ch <= 'z') || NM_IN_SET (ch, '-'))));
		nm_assert (NM_IN_SET (info->key_type, KEY_TYPE_STRING,
		                                      KEY_TYPE_INT,
		                                      KEY_TYPE_BOOL));

		if (key_id == NM_TEAM_LINK_WATCHER_KEY_NAME)
			continue;

		if (!NM_FLAGS_ALL (info->watcher_type, watcher_type))
			continue;

		switch (info->key_type) {
		case KEY_TYPE_STRING:
			vstr = info->get_fcn.fstring (watcher);
			if (vstr) {
				g_string_append_printf (nm_gstring_add_space_delimiter (str),
				                        "%s=%s", info->name, vstr);
			}
			break;
		case KEY_TYPE_INT:
			vint = info->get_fcn.fint (watcher);
			if (vint != info->def_val.vint) {
				g_string_append_printf (nm_gstring_add_space_delimiter (str),
				                        "%s=%d", info->name, vint);
			}
			break;
		case KEY_TYPE_BOOL:
			vbool = info->get_fcn.fbool (watcher);
			if (vbool != info->def_val.vbool) {
				g_string_append_printf (nm_gstring_add_space_delimiter (str),
				                        "%s=%s", info->name, vbool ? "true" : "false");
			}
			break;
		}
	}

	return g_string_free (g_steal_pointer (&str), FALSE);
}

NMTeamLinkWatcher *
nm_utils_team_link_watcher_from_string (const char *str,
                                        GError **error)
{
	gs_free const char **tokens = NULL;
	ParseData parse_data[_NM_TEAM_LINK_WATCHER_KEY_NUM] = { };
	NMTeamLinkWatcherType watcher_type;
	NMTeamLinkWatcherKeyId key_id;
	gsize i_token;
	NMTeamLinkWatcher *watcher;
	int errsv;

	g_return_val_if_fail (str, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	tokens = nm_utils_escaped_tokens_split (str, NM_ASCII_SPACES);
	if (!tokens) {
		g_set_error (error, 1, 0, "'%s' is not valid", str);
		return NULL;
	}

	for (i_token = 0; tokens[i_token]; i_token++) {
		const TeamLinkWatcherKeyInfo *info;
		const char *key = tokens[i_token];
		const char *val;

		val = strchr (key, '=');
		if (!val) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    _("'%s' is not valid: properties should be specified as 'key=value'"),
			                    key);
			return NULL;
		}
		((char *) val)[0] = '\0';
		val++;

		for (key_id = 0; key_id < _NM_TEAM_LINK_WATCHER_KEY_NUM; key_id++) {
			info = &_team_link_watcher_key_infos[key_id];
			if (nm_streq (key, info->name))
				break;
		}

		if (key_id == _NM_TEAM_LINK_WATCHER_KEY_NUM) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    _("'%s' is not a valid key"), key);
			return NULL;
		}

		if (parse_data[key_id].str_val) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    _("duplicate key '%s'"), key);
			return NULL;
		}

		parse_data[key_id].str_val = val;

		if (info->key_type == KEY_TYPE_INT) {
			gint64 v64;

			v64 = _nm_utils_ascii_str_to_int64 (val, 10, G_MININT, G_MAXINT, G_MAXINT64);
			if (   v64 == G_MAXINT64
			    && ((errsv = errno) != 0)) {
				if (errsv == ERANGE) {
					nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
					                    _("number for '%s' is out of range"), key);
				} else {
					nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
					                    _("value for '%s' must be a number"), key);
				}
				return NULL;
			}
			parse_data[key_id].typ_val.vint = v64;
		} else if (info->key_type == KEY_TYPE_BOOL) {
			int vbool;

			vbool = _nm_utils_ascii_str_to_bool (val, -1);
			if (vbool == -1) {
				nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
				                    _("value for '%s' must be a boolean"), key);
				return NULL;
			}
			parse_data[key_id].typ_val.vbool = vbool;
		}
	}

	if (!parse_data[NM_TEAM_LINK_WATCHER_KEY_NAME].str_val) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    _("missing 'name' attribute"));
		return NULL;
	}

	watcher_type = _team_link_watcher_get_watcher_type_from_name (parse_data[NM_TEAM_LINK_WATCHER_KEY_NAME].str_val);
	if (watcher_type == NM_TEAM_LINK_WATCHER_TYPE_NONE) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    _("invalid 'name' \"%s\""),
		                    parse_data[NM_TEAM_LINK_WATCHER_KEY_NAME].str_val);
		return NULL;
	}

	for (key_id = 0; key_id < _NM_TEAM_LINK_WATCHER_KEY_NUM; key_id++) {
		const TeamLinkWatcherKeyInfo *info = &_team_link_watcher_key_infos[key_id];

		if (!parse_data[key_id].str_val)
			continue;
		if (!NM_FLAGS_ALL (info->watcher_type, watcher_type)) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    _("attribute '%s' is invalid for \"%s\""),
			                    info->name,
			                    parse_data[NM_TEAM_LINK_WATCHER_KEY_NAME].str_val);
			return NULL;
		}
	}

	switch (watcher_type) {
	case NM_TEAM_LINK_WATCHER_TYPE_ETHTOOL:
		watcher = nm_team_link_watcher_new_ethtool (_parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_DELAY_UP),
		                                            _parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_DELAY_DOWN),
		                                            error);
		break;
	case NM_TEAM_LINK_WATCHER_TYPE_NSNAPING:
		watcher = nm_team_link_watcher_new_nsna_ping (_parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_INIT_WAIT),
		                                              _parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_INTERVAL),
		                                              _parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_MISSED_MAX),
		                                              _parse_data_get_str (parse_data, NM_TEAM_LINK_WATCHER_KEY_TARGET_HOST),
		                                              error);
		break;
	default:
		nm_assert (watcher_type == NM_TEAM_LINK_WATCHER_TYPE_ARPING);
		watcher = nm_team_link_watcher_new_arp_ping2 (_parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_INIT_WAIT),
		                                              _parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_INTERVAL),
		                                              _parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_MISSED_MAX),
		                                              _parse_data_get_int (parse_data, NM_TEAM_LINK_WATCHER_KEY_VLANID),
		                                              _parse_data_get_str (parse_data, NM_TEAM_LINK_WATCHER_KEY_TARGET_HOST),
		                                              _parse_data_get_str (parse_data, NM_TEAM_LINK_WATCHER_KEY_SOURCE_HOST),
		                                              (  NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE
		                                               | (_parse_data_get_bool (parse_data, NM_TEAM_LINK_WATCHER_KEY_VALIDATE_ACTIVE)   ? NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE   : NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE)
		                                               | (_parse_data_get_bool (parse_data, NM_TEAM_LINK_WATCHER_KEY_VALIDATE_INACTIVE) ? NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE : NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE)
		                                               | (_parse_data_get_bool (parse_data, NM_TEAM_LINK_WATCHER_KEY_SEND_ALWAYS)       ? NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS       : NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE)
		                                              ),
		                                              error);
		break;
	}

#if NM_MORE_ASSERTS > 5
	if (watcher) {
		gs_free char *str2 = NULL;
		nm_auto_unref_team_link_watcher NMTeamLinkWatcher *watcher2 = NULL;
		static _nm_thread_local int recursive;

		nm_assert (!error || !*error);
		if (recursive == 0) {
			recursive = 1;
			str2 = nm_utils_team_link_watcher_to_string (watcher);
			nm_assert (str2);
			watcher2 = nm_utils_team_link_watcher_from_string (str2, NULL);
			nm_assert (watcher2);
			nm_assert (nm_team_link_watcher_equal (watcher, watcher2));
			nm_assert (nm_team_link_watcher_equal (watcher2, watcher));
			nm_assert (recursive == 1);
			recursive = 0;
		}
	} else
		nm_assert (!error || *error);
#endif

	return watcher;
}
