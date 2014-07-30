/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_PASSWORD_FIELDS_H
#define NMT_PASSWORD_FIELDS_H

#include "nmt-newt.h"

G_BEGIN_DECLS

#define NMT_TYPE_PASSWORD_FIELDS            (nmt_password_fields_get_type ())
#define NMT_PASSWORD_FIELDS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PASSWORD_FIELDS, NmtPasswordFields))
#define NMT_PASSWORD_FIELDS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PASSWORD_FIELDS, NmtPasswordFieldsClass))
#define NMT_IS_PASSWORD_FIELDS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PASSWORD_FIELDS))
#define NMT_IS_PASSWORD_FIELDS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PASSWORD_FIELDS))
#define NMT_PASSWORD_FIELDS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PASSWORD_FIELDS, NmtPasswordFieldsClass))

typedef struct {
	NmtNewtGrid parent;

} NmtPasswordFields;

typedef struct {
	NmtNewtGridClass parent;

} NmtPasswordFieldsClass;

GType nmt_password_fields_get_type (void);

typedef enum {
	NMT_PASSWORD_FIELDS_ALWAYS_ASK    = (1 << 0),
	NMT_PASSWORD_FIELDS_SHOW_PASSWORD = (1 << 1),
} NmtPasswordFieldsExtras;

NmtNewtWidget *nmt_password_fields_new (int                     width,
                                        NmtPasswordFieldsExtras extras);

G_END_DECLS

#endif /* NMT_PASSWORD_FIELDS_H */
