/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef NM_POLICY_H
#define NM_POLICY_H

#include "nm-manager.h"
#include "nm-settings.h"

#define NM_TYPE_POLICY            (nm_policy_get_type ())
#define NM_POLICY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_POLICY, NMPolicy))
#define NM_POLICY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_POLICY, NMPolicyClass))
#define NM_IS_POLICY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_POLICY))
#define NM_IS_POLICY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_POLICY))
#define NM_POLICY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_POLICY, NMPolicyClass))

typedef struct {
	GObject parent;
} NMPolicy;

typedef struct {
	GObjectClass parent;

} NMPolicyClass;

GType nm_policy_get_type (void);

NMPolicy *nm_policy_new (NMManager *manager, NMSettings *settings);

#endif /* NM_POLICY_H */
