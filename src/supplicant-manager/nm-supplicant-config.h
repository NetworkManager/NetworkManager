/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2006 Red Hat, Inc.
 */

#ifndef NM_SUPPLICANT_CONFIG_H
#define NM_SUPPLICANT_CONFIG_H

#include <glib-object.h>
#include <nm-setting-wireless.h>
#include "nm-supplicant-types.h"

G_BEGIN_DECLS

#define NM_TYPE_SUPPLICANT_CONFIG            (nm_supplicant_config_get_type ())
#define NM_SUPPLICANT_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfig))
#define NM_SUPPLICANT_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfigClass))
#define NM_IS_SUPPLICANT_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_CONFIG))
#define NM_IS_SUPPLICANT_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_CONFIG))
#define NM_SUPPLICANT_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_CONFIG, NMSupplicantConfigClass))

struct _NMSupplicantConfig
{
	GObject parent;
};

typedef struct
{
	GObjectClass parent;
} NMSupplicantConfigClass;


GType nm_supplicant_config_get_type (void);

NMSupplicantConfig * nm_supplicant_config_new (void);

guint32 nm_supplicant_config_get_ap_scan (NMSupplicantConfig * self);

void nm_supplicant_config_set_ap_scan (NMSupplicantConfig * self,
                                       guint32 ap_scan);

gboolean nm_supplicant_config_add_option (NMSupplicantConfig *self,
                                          const char * key,
                                          const char * value,
                                          gint32 len,
                                          gboolean secret);

GHashTable *nm_supplicant_config_get_hash (NMSupplicantConfig * self);

GHashTable *nm_supplicant_config_get_blobs (NMSupplicantConfig * self);

gboolean nm_supplicant_config_add_setting_wireless (NMSupplicantConfig * self,
                                                    NMSettingWireless * setting,
                                                    gboolean is_broadcast);

gboolean nm_supplicant_config_add_setting_wireless_security (NMSupplicantConfig * self,
                                                             NMSettingWirelessSecurity * setting,
                                                             const char *connection_uid);

G_END_DECLS

#endif	/* NM_SUPPLICANT_CONFIG_H */
