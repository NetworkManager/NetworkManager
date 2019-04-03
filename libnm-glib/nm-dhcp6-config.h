/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2008 - 2010 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#ifndef NM_DHCP6_CONFIG_H
#define NM_DHCP6_CONFIG_H

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_DHCP6_CONFIG            (nm_dhcp6_config_get_type ())
#define NM_DHCP6_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP6_CONFIG, NMDHCP6Config))
#define NM_DHCP6_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP6_CONFIG, NMDHCP6ConfigClass))
#define NM_IS_DHCP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP6_CONFIG))
#define NM_IS_DHCP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP6_CONFIG))

typedef struct {
	NMObject parent;
} NMDHCP6Config;

typedef struct {
	NMObjectClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDHCP6ConfigClass;

#define NM_DHCP6_CONFIG_OPTIONS "options"

GType nm_dhcp6_config_get_type (void);

GObject *nm_dhcp6_config_new (DBusGConnection *connection, const char *object_path);

GHashTable * nm_dhcp6_config_get_options (NMDHCP6Config *config);

const char * nm_dhcp6_config_get_one_option (NMDHCP6Config *config, const char *option);

G_END_DECLS

#endif /* NM_DHCP6_CONFIG_H */
