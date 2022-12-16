/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Atul Anand <atulhjp@gmail.com>.
 * Copyright (C) 2016 - 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_PACRUNNER_MANAGER_H__
#define __NETWORKMANAGER_PACRUNNER_MANAGER_H__

#define NM_TYPE_PACRUNNER_MANAGER (nm_pacrunner_manager_get_type())
#define NM_PACRUNNER_MANAGER(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_PACRUNNER_MANAGER, NMPacrunnerManager))
#define NM_PACRUNNER_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_PACRUNNER_MANAGER, NMPacrunnerManagerClass))
#define NM_IS_PACRUNNER_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_PACRUNNER_MANAGER))
#define NM_IS_PACRUNNER_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_PACRUNNER_MANAGER))
#define NM_PACRUNNER_MANAGER_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_PACRUNNER_MANAGER, NMPacrunnerManagerClass))

typedef struct _NMPacrunnerManagerClass NMPacrunnerManagerClass;

typedef struct _NMPacrunnerConfId NMPacrunnerConfId;

GType nm_pacrunner_manager_get_type(void);

NMPacrunnerManager *nm_pacrunner_manager_get(void);

NMPacrunnerConfId *
nm_pacrunner_manager_add(NMPacrunnerManager *self, const char *iface, const NML3ConfigData *l3cd);

void nm_pacrunner_manager_remove(NMPacrunnerConfId *conf_id);

gboolean nm_pacrunner_manager_remove_clear(NMPacrunnerConfId **p_conf_id);

#endif /* __NETWORKMANAGER_PACRUNNER_MANAGER_H__ */
