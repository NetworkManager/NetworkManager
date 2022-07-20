/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2013 - 2015 Red Hat, Inc.
 */

#ifndef __NM_WIREGUARD_IMPORT_H__
#define __NM_WIREGUARD_IMPORT_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

NM_AVAILABLE_IN_1_40
NMConnection *nm_conn_wireguard_import(const char *filename, GError **error);

G_END_DECLS

#endif /* __NM_WIREGUARD_IMPORT_H__ */
