// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
