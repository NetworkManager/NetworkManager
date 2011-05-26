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
 * Author: Pantelis Koukousoulas <pktoss@gmail.com>
 */

#ifndef NM_BR2684_MANAGER_H
#define NM_BR2864_MANAGER_H

#include <glib.h>
#include <glib-object.h>

#include "nm-activation-request.h"
#include "nm-connection.h"
#include "nm-ip4-config.h"

#define NM_TYPE_BR2684_MANAGER            (nm_br2684_manager_get_type ())
#define NM_BR2684_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BR2684_MANAGER, NMBr2684Manager))
#define NM_BR2684_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_BR2684_MANAGER, NMBr2684ManagerClass))
#define NM_IS_BR2684_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BR2684_MANAGER))
#define NM_IS_BR2684_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_BR2684_MANAGER))
#define NM_BR2684_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_BR2684_MANAGER, NMBr2684ManagerClass))

typedef struct {
	GObject parent;
} NMBr2684Manager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*state_changed) (NMBr2684Manager *manager, guint state);
} NMBr2684ManagerClass;

GType nm_br2684_manager_get_type (void);

NMBr2684Manager *nm_br2684_manager_new (void);

gboolean nm_br2684_manager_start (NMBr2684Manager *manager,
                                  NMActRequest *req,
                                  guint32 timeout_secs,
                                  GError **err);


#define NM_BR2684_MANAGER_ERROR nm_br2684_manager_error_quark()
#define NM_TYPE_BR2684_MANAGER_ERROR (nm_br2684_manager_error_get_type ())

GQuark nm_br2684_manager_error_quark (void);

#endif /* NM_BR2684_MANAGER_H */
