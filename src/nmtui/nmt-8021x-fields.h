/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */

#ifndef NMT_8021X_FIELDS_H
#define NMT_8021X_FIELDS_H

#include "libnmt-newt/nmt-newt.h"

#define NMT_TYPE_8021X_FIELDS (nmt_8021x_fields_get_type())
#define NMT_8021X_FIELDS(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_8021X_FIELDS, Nmt8021xFields))
#define NMT_8021X_FIELDS_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_8021X_FIELDS, Nmt8021xFieldsClass))
#define NMT_IS_8021X_FIELDS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_8021X_FIELDS))
#define NMT_IS_8021X_FIELDS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_8021X_FIELDS))
#define NMT_8021X_FIELDS_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_8021X_FIELDS, Nmt8021xFieldsClass))

typedef struct _Nmt8021xFields Nmt8021xFields;

typedef struct _Nmt8021xFieldsClass Nmt8021xFieldsClass;

GType nmt_8021x_fields_get_type(void);

NmtNewtWidget *nmt_8021x_fields_new(NMSetting8021x *setting, gboolean is_wired);

#endif /* NMT_8021X_FIELDS_H */
