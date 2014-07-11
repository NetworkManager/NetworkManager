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

#ifndef NM_CONFIG_DATA_H
#define NM_CONFIG_DATA_H

#include <glib.h>
#include <glib-object.h>

#include "nm-types.h"

G_BEGIN_DECLS

#define NM_TYPE_CONFIG_DATA            (nm_config_data_get_type ())
#define NM_CONFIG_DATA(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONFIG_DATA, NMConfigData))
#define NM_CONFIG_DATA_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_CONFIG_DATA, NMConfigDataClass))
#define NM_IS_CONFIG_DATA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONFIG_DATA))
#define NM_IS_CONFIG_DATA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_CONFIG_DATA))
#define NM_CONFIG_DATA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_CONFIG_DATA, NMConfigDataClass))


#define NM_CONFIG_DATA_CONNECTIVITY_URI      "connectivity-uri"
#define NM_CONFIG_DATA_CONNECTIVITY_INTERVAL "connectivity-interval"
#define NM_CONFIG_DATA_CONNECTIVITY_RESPONSE "connectivity-response"

struct _NMConfigData {
	GObject parent;
};

typedef struct {
	GObjectClass parent;
} NMConfigDataClass;

GType nm_config_data_get_type (void);

const char *nm_config_data_get_connectivity_uri (const NMConfigData *config_data);
const guint nm_config_data_get_connectivity_interval (const NMConfigData *config_data);
const char *nm_config_data_get_connectivity_response (const NMConfigData *config_data);

#include "nm-config.h"

/* private function: internal use only */
void _nm_config_data_set_config (NMConfigData *config_data, NMConfig *config);

G_END_DECLS

#endif /* NM_CONFIG_DATA_H */

