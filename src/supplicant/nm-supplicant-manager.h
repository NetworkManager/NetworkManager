// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_MANAGER_H__
#define __NETWORKMANAGER_SUPPLICANT_MANAGER_H__

#include "nm-supplicant-types.h"
#include "devices/nm-device.h"

#define NM_TYPE_SUPPLICANT_MANAGER              (nm_supplicant_manager_get_type ())
#define NM_SUPPLICANT_MANAGER(obj)              (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManager))
#define NM_SUPPLICANT_MANAGER_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManagerClass))
#define NM_IS_SUPPLICANT_MANAGER(obj)           (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_MANAGER))
#define NM_IS_SUPPLICANT_MANAGER_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_MANAGER))
#define NM_SUPPLICANT_MANAGER_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManagerClass))

typedef struct _NMSupplicantManagerClass NMSupplicantManagerClass;

GType nm_supplicant_manager_get_type (void);

NMSupplicantManager *nm_supplicant_manager_get (void);

void nm_supplicant_manager_set_wfd_ies (NMSupplicantManager *self,
                                        GBytes *wfd_ies);

NMSupplicantInterface *nm_supplicant_manager_create_interface (NMSupplicantManager *mgr,
                                                               const char *ifname,
                                                               NMSupplicantDriver driver);
NMSupplicantInterface *nm_supplicant_manager_create_interface_from_path (NMSupplicantManager *self,
                                                                         const char *object_path);

#endif /* __NETWORKMANAGER_SUPPLICANT_MANAGER_H__ */
