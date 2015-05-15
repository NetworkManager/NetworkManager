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


#define NM_CONFIG_DATA_CONFIG_MAIN_FILE      "config-main-file"
#define NM_CONFIG_DATA_CONFIG_DESCRIPTION    "config-description"
#define NM_CONFIG_DATA_KEYFILE               "keyfile"
#define NM_CONFIG_DATA_CONNECTIVITY_URI      "connectivity-uri"
#define NM_CONFIG_DATA_CONNECTIVITY_INTERVAL "connectivity-interval"
#define NM_CONFIG_DATA_CONNECTIVITY_RESPONSE "connectivity-response"
#define NM_CONFIG_DATA_NO_AUTO_DEFAULT       "no-auto-default"
#define NM_CONFIG_DATA_DNS_MODE              "dns"

typedef enum { /*< flags >*/
	NM_CONFIG_CHANGE_NONE                      = 0,
	NM_CONFIG_CHANGE_CONFIG_FILES              = (1L << 0),
	NM_CONFIG_CHANGE_VALUES                    = (1L << 1),
	NM_CONFIG_CHANGE_CONNECTIVITY              = (1L << 2),
	NM_CONFIG_CHANGE_NO_AUTO_DEFAULT           = (1L << 3),
	NM_CONFIG_CHANGE_DNS_MODE                  = (1L << 4),
	NM_CONFIG_CHANGE_RC_MANAGER                = (1L << 5),

	_NM_CONFIG_CHANGE_LAST,
	NM_CONFIG_CHANGE_ALL                       = ((_NM_CONFIG_CHANGE_LAST - 1) << 1) - 1,
} NMConfigChangeFlags;

struct _NMConfigData {
	GObject parent;
};

typedef struct {
	GObjectClass parent;
} NMConfigDataClass;

GType nm_config_data_get_type (void);

NMConfigData *nm_config_data_new (const char *config_main_file,
                                  const char *config_description,
                                  const char *const*no_auto_default,
                                  GKeyFile *keyfile);
NMConfigData *nm_config_data_new_update_no_auto_default (const NMConfigData *base, const char *const*no_auto_default);

NMConfigChangeFlags nm_config_data_diff (NMConfigData *old_data, NMConfigData *new_data);

const char *nm_config_data_get_config_main_file (const NMConfigData *config_data);
const char *nm_config_data_get_config_description (const NMConfigData *config_data);

char *nm_config_data_get_value (const NMConfigData *config_data, const char *group, const char *key, GError **error);

const char *nm_config_data_get_connectivity_uri (const NMConfigData *config_data);
const guint nm_config_data_get_connectivity_interval (const NMConfigData *config_data);
const char *nm_config_data_get_connectivity_response (const NMConfigData *config_data);

const char *const*nm_config_data_get_no_auto_default (const NMConfigData *config_data);
const GSList *    nm_config_data_get_no_auto_default_list (const NMConfigData *config_data);

const char *nm_config_data_get_dns_mode (const NMConfigData *self);
const char *nm_config_data_get_rc_manager (const NMConfigData *self);

gboolean nm_config_data_get_ignore_carrier (const NMConfigData *self, NMDevice *device);
gboolean nm_config_data_get_assume_ipv6ll_only (const NMConfigData *self, NMDevice *device);

char *nm_config_data_get_connection_default (const NMConfigData *self,
                                             const char *property,
                                             NMDevice *device);

G_END_DECLS

#endif /* NM_CONFIG_DATA_H */

