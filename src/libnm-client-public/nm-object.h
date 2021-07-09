/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#ifndef __NM_OBJECT_H__
#define __NM_OBJECT_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-types.h"

G_BEGIN_DECLS

#define NM_TYPE_OBJECT            (nm_object_get_type())
#define NM_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_OBJECT, NMObject))
#define NM_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_OBJECT, NMObjectClass))
#define NM_IS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_OBJECT))
#define NM_IS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_OBJECT))
#define NM_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_OBJECT, NMObjectClass))

#define NM_OBJECT_PATH   "path"
#define NM_OBJECT_CLIENT "client"

/**
 * NMObject:
 */
typedef struct _NMObjectClass NMObjectClass;

GType nm_object_get_type(void);

const char *nm_object_get_path(NMObject *object);

NM_AVAILABLE_IN_1_24
NMClient *nm_object_get_client(NMObject *object);

G_END_DECLS

#endif /* __NM_OBJECT_H__ */
