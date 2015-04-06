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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_TEAM_FACTORY_H__
#define __NETWORKMANAGER_TEAM_FACTORY_H__

#include "nm-glib.h"

#define NM_TYPE_TEAM_FACTORY (nm_team_factory_get_type ())
#define NM_TEAM_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_TEAM_FACTORY, NMTeamFactory))

typedef struct {
	GObject parent;
} NMTeamFactory;

typedef struct {
	GObjectClass parent;
} NMTeamFactoryClass;

#endif /* __NETWORKMANAGER_TEAM_FACTORY_H__ */
