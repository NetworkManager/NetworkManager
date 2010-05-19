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
 * Copyright (C) 2009 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_MODEM_H
#define NM_MODEM_H

#include <dbus/dbus-glib.h>
#include <glib-object.h>
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_MODEM			(nm_modem_get_type ())
#define NM_MODEM(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM, NMModem))
#define NM_MODEM_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),	NM_TYPE_MODEM, NMModemClass))
#define NM_IS_MODEM(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM))
#define NM_IS_MODEM_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),	NM_TYPE_MODEM))
#define NM_MODEM_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),	NM_TYPE_MODEM, NMModemClass))

#define NM_MODEM_PATH      "path"
#define NM_MODEM_DEVICE    "device"
#define NM_MODEM_IFACE     "iface"
#define NM_MODEM_IP_METHOD "ip-method"
#define NM_MODEM_ENABLED   "enabled"

#define NM_MODEM_PPP_STATS         "ppp-stats"
#define NM_MODEM_PPP_FAILED        "ppp-failed"
#define NM_MODEM_PREPARE_RESULT    "prepare-result"
#define NM_MODEM_IP4_CONFIG_RESULT "ip4-config-result"
#define NM_MODEM_NEED_AUTH         "need-auth"

typedef struct {
	GObject parent;
} NMModem;

typedef struct {
	GObjectClass parent;

	gboolean (*get_user_pass)                  (NMModem *modem,
	                                            NMConnection *connection,
	                                            const char **user,
	                                            const char **pass);

	const char * (*get_setting_name)           (NMModem *modem);

	gboolean (*check_connection_compatible)    (NMModem *modem,
	                                            NMConnection *connection,
	                                            GError **error);

	NMConnection * (*get_best_auto_connection) (NMModem *modem,
	                                            GSList *connections,
	                                            char **specific_object);

	NMActStageReturn (*act_stage1_prepare)     (NMModem *modem,
	                                            NMActRequest *req,
	                                            GPtrArray **out_hints,
	                                            const char **out_setting_name,
	                                            NMDeviceStateReason *reason);

	void (*deactivate_quickly)                 (NMModem *self, NMDevice *device);

	/* Signals */
	void (*ppp_stats)  (NMModem *self, guint32 in_bytes, guint32 out_bytes);
	void (*ppp_failed) (NMModem *self, NMDeviceStateReason reason);

	void (*prepare_result)    (NMModem *self, gboolean success, NMDeviceStateReason reason);
	void (*ip4_config_result) (NMModem *self, const char *iface, NMIP4Config *config, GError *error);

	void (*need_auth)  (NMModem *self,
	                    const char *setting_name,
	                    gboolean retry,
	                    RequestSecretsCaller caller,
	                    const char *hint1,
	                    const char *hint2);
} NMModemClass;

GType nm_modem_get_type (void);

/* Protected */

NMPPPManager *nm_modem_get_ppp_manager (NMModem *modem);
DBusGProxy *  nm_modem_get_proxy       (NMModem *modem, const char *interface);
const char *  nm_modem_get_iface       (NMModem *modem);
const char *  nm_modem_get_path        (NMModem *modem);

NMConnection *nm_modem_get_best_auto_connection (NMModem *self,
                                                 GSList *connections,
                                                 char **specific_object);

gboolean nm_modem_check_connection_compatible (NMModem *self,
                                               NMConnection *connection,
                                               GError **error);

NMActStageReturn nm_modem_act_stage1_prepare (NMModem *modem,
                                              NMActRequest *req,
                                              NMDeviceStateReason *reason);

NMActStageReturn nm_modem_act_stage2_config (NMModem *modem,
                                             NMActRequest *req,
                                             NMDeviceStateReason *reason);

NMActStageReturn nm_modem_stage3_ip4_config_start (NMModem *modem,
                                                   NMDevice *device,
                                                   NMDeviceClass *device_class,
                                                   NMDeviceStateReason *reason);

NMActStageReturn nm_modem_stage4_get_ip4_config (NMModem *modem,
                                                 NMDevice *device,
                                                 NMDeviceClass *device_class,
                                                 NMIP4Config **config,
                                                 NMDeviceStateReason *reason);

void nm_modem_deactivate_quickly (NMModem *modem, NMDevice *device);

void nm_modem_device_state_changed (NMModem *modem,
                                    NMDeviceState new_state,
                                    NMDeviceState old_state,
                                    NMDeviceStateReason reason);

gboolean nm_modem_hw_is_up (NMModem *modem, NMDevice *device);

gboolean nm_modem_hw_bring_up (NMModem *modem, NMDevice *device, gboolean *no_firmware);

gboolean nm_modem_connection_secrets_updated (NMModem *modem,
                                              NMActRequest *req,
                                              NMConnection *connection,
                                              GSList *updated_settings,
                                              RequestSecretsCaller caller);

const DBusGObjectInfo *nm_modem_get_serial_dbus_info (void);

gboolean      nm_modem_get_mm_enabled (NMModem *self);

void          nm_modem_set_mm_enabled (NMModem *self, gboolean enabled);

G_END_DECLS

#endif /* NM_MODEM_H */
