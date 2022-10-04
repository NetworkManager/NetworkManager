/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_BOND_MANAGER_H__
#define __NM_BOND_MANAGER_H__

typedef struct _NMBondManager NMBondManager;

struct _NMPlatform;

typedef enum {
    NM_BOND_MANAGER_EVENT_TYPE_STATE,
} NMBondManagerEventType;

typedef void (*NMBondManagerCallback)(NMBondManager         *self,
                                      NMBondManagerEventType event_type,
                                      gpointer               user_data);

NMBondManager *nm_bond_manager_new(struct _NMPlatform   *platform,
                                   int                   ifindex,
                                   const char           *connection_uuid,
                                   NMBondManagerCallback callback,
                                   gpointer              user_data);

void nm_bond_manager_reapply(NMBondManager *self);

void nm_bond_manager_destroy(NMBondManager *self);

int          nm_bond_manager_get_ifindex(NMBondManager *self);
const char  *nm_bond_manager_get_connection_uuid(NMBondManager *self);
NMOptionBool nm_bond_manager_get_state(NMBondManager *self);

#endif /* __NM_BOND_MANAGER_H__ */
