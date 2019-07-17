/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
 * (C) Copyright 2008 Canonical Ltd.
 */

#ifndef __NMS_IFUPDOWN_PARSER_H__
#define __NMS_IFUPDOWN_PARSER_H__

#include "nm-connection.h"
#include "nms-ifupdown-interface-parser.h"

NMConnection *ifupdown_new_connection_from_if_block (if_block *block,
                                                     gboolean autoconnect,
                                                     GError **error);

#endif /* __NMS_IFUPDOWN_PARSER_H__ */
