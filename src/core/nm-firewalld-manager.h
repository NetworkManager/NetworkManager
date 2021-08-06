/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NM_FIREWALLD_MANAGER_H__
#define __NM_FIREWALLD_MANAGER_H__

#define NM_TYPE_FIREWALLD_MANAGER (nm_firewalld_manager_get_type())
#define NM_FIREWALLD_MANAGER(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_FIREWALLD_MANAGER, NMFirewalldManager))
#define NM_FIREWALLD_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_FIREWALLD_MANAGER, NMFirewalldManagerClass))
#define NM_IS_FIREWALLD_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_FIREWALLD_MANAGER))
#define NM_IS_FIREWALLD_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_FIREWALLD_MANAGER))
#define NM_FIREWALLD_MANAGER_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_FIREWALLD_MANAGER, NMFirewalldManagerClass))

#define NM_FIREWALLD_MANAGER_STATE_CHANGED "state-changed"

typedef enum {
    NM_FIREWALLD_MANAGER_STATE_CHANGED_TYPE_INITIALIZED,
    NM_FIREWALLD_MANAGER_STATE_CHANGED_TYPE_NAME_OWNER_CHANGED,
    NM_FIREWALLD_MANAGER_STATE_CHANGED_TYPE_RELOADED,
} NMFirewalldManagerStateChangedType;

typedef struct _NMFirewalldManagerCallId NMFirewalldManagerCallId;

typedef struct _NMFirewalldManager      NMFirewalldManager;
typedef struct _NMFirewalldManagerClass NMFirewalldManagerClass;

GType nm_firewalld_manager_get_type(void);

NMFirewalldManager *nm_firewalld_manager_get(void);

gboolean nm_firewalld_manager_get_running(NMFirewalldManager *self);

typedef void (*NMFirewalldManagerAddRemoveCallback)(NMFirewalldManager *      self,
                                                    NMFirewalldManagerCallId *call_id,
                                                    GError *                  error,
                                                    gpointer                  user_data);

NMFirewalldManagerCallId *
nm_firewalld_manager_add_or_change_zone(NMFirewalldManager *                mgr,
                                        const char *                        iface,
                                        const char *                        zone,
                                        gboolean                            add,
                                        NMFirewalldManagerAddRemoveCallback callback,
                                        gpointer                            user_data);
NMFirewalldManagerCallId *
nm_firewalld_manager_remove_from_zone(NMFirewalldManager *                mgr,
                                      const char *                        iface,
                                      const char *                        zone,
                                      NMFirewalldManagerAddRemoveCallback callback,
                                      gpointer                            user_data);

void nm_firewalld_manager_cancel_call(NMFirewalldManagerCallId *call_id);

#endif /* __NM_FIREWALLD_MANAGER_H__ */
