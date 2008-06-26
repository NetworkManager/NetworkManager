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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#ifndef _PARSER_H_
#define _PARSER_H_

#include <glib.h>
#include <NetworkManager.h>
#include <nm-connection.h>

#define IFCFG_TAG "ifcfg-"
#define BAK_TAG ".bak"

NMConnection *parse_ifcfg (const char *iface, NMDeviceType type);
gboolean parser_ignore_device (const char *iface);

guint32        parser_parse_routes (const char *filename);

#endif /* _PARSER_H_ */
