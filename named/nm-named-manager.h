/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2004 Red Hat, Inc.
 *
 * Written by Colin Walters <walters@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __NM_NAMED_MANAGER_H__
#define __NM_NAMED_MANAGER_H__

#include "config.h"
#include <glib-object.h>

typedef enum
{
	NM_NAMED_MANAGER_ERROR_SYSTEM,
	NM_NAMED_MANAGER_ERROR_INVALID_NAMESERVER,
	NM_NAMED_MANAGER_ERROR_INVALID_HOST,
	NM_NAMED_MANAGER_ERROR_INVALID_ID
} NMNamedManagerError;

#define NM_NAMED_MANAGER_ERROR nm_named_manager_error_quark ()
GQuark nm_named_manager_error_quark (void);

G_BEGIN_DECLS

#define NM_TYPE_NAMED_MANAGER (nm_named_manager_get_type ())
#define NM_NAMED_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_NAMED_MANAGER, NMNamedManager))
#define NM_NAMED_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_NAMED_MANAGER, NMNamedManagerClass))
#define NM_IS_NAMED_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_NAMED_MANAGER))
#define NM_IS_NAMED_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_NAMED_MANAGER))
#define NM_NAMED_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_NAMED_MANAGER, NMNamedManagerClass)) 

typedef struct NMNamedManagerPrivate NMNamedManagerPrivate;

typedef struct
{
	GObject parent;

	NMNamedManagerPrivate *priv;
} NMNamedManager;

typedef struct
{
	GObjectClass parent;

} NMNamedManagerClass;

GType nm_named_manager_get_type (void);

NMNamedManager * nm_named_manager_new (void);

gboolean nm_named_manager_start (NMNamedManager *mgr, GError **error);

guint nm_named_manager_add_domain_search (NMNamedManager *mgr,
					  const char *domain,
					  GError **error);
guint nm_named_manager_add_nameserver_ipv4 (NMNamedManager *mgr,
					    const char *server,
					    GError **error);
guint nm_named_manager_add_domain_nameserver_ipv4 (NMNamedManager *mgr,
						   const char *domain,
						   const char *server,
						   GError **error);

gboolean nm_named_manager_remove_domain_search (NMNamedManager *mgr,
						guint id,
						GError **error);
gboolean nm_named_manager_remove_nameserver_ipv4 (NMNamedManager *mgr,
						  guint id,
						  GError **error);
gboolean nm_named_manager_remove_domain_nameserver_ipv4 (NMNamedManager *mgr,
							 guint id,
							 GError **error);

G_END_DECLS

#endif /* __NM_NAMED_MANAGER_H__ */
