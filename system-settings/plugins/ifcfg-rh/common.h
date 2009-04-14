/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 - 2009 Red Hat, Inc.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <glib.h>

#define IFCFG_TAG "ifcfg-"
#define KEYS_TAG "keys-"
#define BAK_TAG ".bak"
#define TILDE_TAG "~"
#define ORIG_TAG ".orig"
#define REJ_TAG ".rej"

#define IFCFG_DIR SYSCONFDIR"/sysconfig/network-scripts"

#define IFCFG_PLUGIN_NAME "ifcfg-rh"
#define IFCFG_PLUGIN_INFO "(c) 2007 - 2008 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list."

#define TYPE_ETHERNET "Ethernet"
#define TYPE_WIRELESS "Wireless"

#define TAG_CA_CERT_PATH  "ca-cert-path"
#define TAG_CA_CERT_HASH  "ca-cert-hash"

#define TAG_CLIENT_CERT_PATH  "client-cert-path"
#define TAG_CLIENT_CERT_HASH  "client-cert-hash"

#define TAG_PRIVATE_KEY_PATH  "private-key-path"
#define TAG_PRIVATE_KEY_HASH  "private-key-hash"

#define TAG_PHASE2_CA_CERT_PATH  "phase2-ca-cert-path"
#define TAG_PHASE2_CA_CERT_HASH  "phase2-ca-cert-hash"

#define TAG_PHASE2_CLIENT_CERT_PATH  "phase2-client-cert-path"
#define TAG_PHASE2_CLIENT_CERT_HASH  "phase2-client-cert-hash"

#define TAG_PHASE2_PRIVATE_KEY_PATH  "phase2-private-key-path"
#define TAG_PHASE2_PRIVATE_KEY_HASH  "phase2-private-key-hash"

GQuark ifcfg_plugin_error_quark (void);


#endif  /* __COMMON_H__ */

