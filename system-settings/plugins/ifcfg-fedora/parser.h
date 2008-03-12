/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#ifndef _PARSER_H_
#define _PARSER_H_

#include <glib.h>
#include <nm-connection.h>
#include <nm-setting-ip4-config.h>

#define IFCFG_TAG "ifcfg-"
#define KEYS_TAG "keys-"
#define BAK_TAG ".bak"
#define TILDE_TAG "~"
#define ORIG_TAG ".orig"
#define REJ_TAG ".rej"

typedef struct {
	char *ifcfg_path;
	gboolean ignored;
	gboolean exported;

	GHashTable *secrets;
} ConnectionData;

NMConnection * parser_parse_file (const char *file, GError **error);

void connection_update_from_resolv_conf (char **lines, NMSettingIP4Config *s_ip4);

ConnectionData *connection_data_get (NMConnection *connection);
ConnectionData *connection_data_add (NMConnection *connection, const char *ifcfg_path);
void connection_data_copy_secrets (ConnectionData *from, ConnectionData *to);

#endif /* _PARSER_H_ */
