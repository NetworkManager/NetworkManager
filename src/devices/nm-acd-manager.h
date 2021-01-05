/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 - 2018 Red Hat, Inc.
 */

#ifndef __NM_ACD_MANAGER__
#define __NM_ACD_MANAGER__

#include <netinet/in.h>

typedef struct _NMAcdManager NMAcdManager;

typedef struct {
    void (*probe_terminated_callback)(NMAcdManager *self, gpointer user_data);
    GDestroyNotify user_data_destroy;
} NMAcdCallbacks;

NMAcdManager *nm_acd_manager_new(int                   ifindex,
                                 const guint8 *        hwaddr,
                                 guint                 hwaddr_len,
                                 const NMAcdCallbacks *callbacks,
                                 gpointer              user_data);

void nm_acd_manager_free(NMAcdManager *self);

gboolean nm_acd_manager_add_address(NMAcdManager *self, in_addr_t address);
int      nm_acd_manager_start_probe(NMAcdManager *self, guint timeout);
gboolean nm_acd_manager_check_address(NMAcdManager *self, in_addr_t address);
int      nm_acd_manager_announce_addresses(NMAcdManager *self);

NM_AUTO_DEFINE_FCN0(NMAcdManager *, _nm_auto_free_acdmgr, nm_acd_manager_free);
#define nm_auto_free_acdmgr nm_auto(_nm_auto_free_acdmgr)

#endif /* __NM_ACD_MANAGER__ */
