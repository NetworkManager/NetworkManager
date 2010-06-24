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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_DEVICE_H
#define NM_DEVICE_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include <netinet/in.h>

#include "NetworkManager.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-connection.h"

typedef enum NMActStageReturn
{
	NM_ACT_STAGE_RETURN_FAILURE = 0,
	NM_ACT_STAGE_RETURN_SUCCESS,
	NM_ACT_STAGE_RETURN_POSTPONE,
	NM_ACT_STAGE_RETURN_STOP         /* This activation chain is done */
} NMActStageReturn;


G_BEGIN_DECLS

#define NM_TYPE_DEVICE			(nm_device_get_type ())
#define NM_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE, NMDeviceClass))

typedef struct {
	GObject parent;
} NMDevice;

typedef struct {
	GObjectClass parent;

	/* Hardware state, ie IFF_UP */
	gboolean        (*hw_is_up)      (NMDevice *self);
	gboolean        (*hw_bring_up)   (NMDevice *self, gboolean *no_firmware);
	void            (*hw_take_down)  (NMDevice *self);

	/* Additional stuff required to operate the device, like a 
	 * connection to the supplicant, Bluez, etc
	 */
	gboolean        (*is_up)         (NMDevice *self);
	gboolean        (*bring_up)      (NMDevice *self);
	void            (*take_down)     (NMDevice *self);

	void        (* update_hw_address) (NMDevice *self);
	void        (* update_permanent_hw_address) (NMDevice *self);

	guint32		(* get_type_capabilities)	(NMDevice *self);
	guint32		(* get_generic_capabilities)	(NMDevice *self);

	gboolean	(* is_available) (NMDevice *self);

	NMConnection * (* get_best_auto_connection) (NMDevice *self,
	                                             GSList *connections,
	                                             char **specific_object);

	void        (* connection_secrets_updated) (NMDevice *self,
	                                            NMConnection *connection,
	                                            GSList *updated_settings,
	                                            RequestSecretsCaller caller);

	gboolean    (* check_connection_compatible) (NMDevice *self,
	                                             NMConnection *connection,
	                                             GError **error);

	NMActStageReturn	(* act_stage1_prepare)	(NMDevice *self,
	                                             NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage2_config)	(NMDevice *self,
	                                             NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage3_ip4_config_start) (NMDevice *self,
														 NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage3_ip6_config_start) (NMDevice *self,
														 NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage4_get_ip4_config)	(NMDevice *self,
														 NMIP4Config **config,
	                                                     NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage4_get_ip6_config)	(NMDevice *self,
														 NMIP6Config **config,
	                                                     NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage4_ip4_config_timeout)	(NMDevice *self,
	                                                         NMIP4Config **config,
	                                                         NMDeviceStateReason *reason);
	NMActStageReturn	(* act_stage4_ip6_config_timeout)	(NMDevice *self,
	                                                         NMIP6Config **config,
	                                                         NMDeviceStateReason *reason);
	void			(* deactivate)			(NMDevice *self);
	void			(* deactivate_quickly)	(NMDevice *self);

	gboolean		(* can_interrupt_activation)		(NMDevice *self);

	gboolean        (* spec_match_list)     (NMDevice *self, const GSList *specs);

	NMConnection *  (* connection_match_config) (NMDevice *self, const GSList *connections);
} NMDeviceClass;


GType nm_device_get_type (void);

const char *    nm_device_get_path (NMDevice *dev);
void            nm_device_set_path (NMDevice *dev, const char *path);

const char *	nm_device_get_udi		(NMDevice *dev);
const char *	nm_device_get_iface		(NMDevice *dev);
int             nm_device_get_ifindex	(NMDevice *dev);
const char *	nm_device_get_ip_iface	(NMDevice *dev);
int             nm_device_get_ip_ifindex(NMDevice *dev);
const char *	nm_device_get_driver	(NMDevice *dev);
const char *	nm_device_get_type_desc (NMDevice *dev);

NMDeviceType	nm_device_get_device_type	(NMDevice *dev);
guint32		nm_device_get_capabilities	(NMDevice *dev);
guint32		nm_device_get_type_capabilities	(NMDevice *dev);

int			nm_device_get_priority (NMDevice *dev);

guint32			nm_device_get_ip4_address	(NMDevice *dev);
void				nm_device_update_ip4_address	(NMDevice *dev);

NMDHCP4Config * nm_device_get_dhcp4_config (NMDevice *dev);
NMDHCP6Config * nm_device_get_dhcp6_config (NMDevice *dev);

NMIP4Config *	nm_device_get_ip4_config	(NMDevice *dev);
NMIP6Config *	nm_device_get_ip6_config	(NMDevice *dev);

void *		nm_device_get_system_config_data	(NMDevice *dev);

NMActRequest *	nm_device_get_act_request	(NMDevice *dev);

gboolean		nm_device_is_available (NMDevice *dev);

NMConnection * nm_device_get_best_auto_connection (NMDevice *dev,
                                                   GSList *connections,
                                                   char **specific_object);

void			nm_device_activate_schedule_stage1_device_prepare		(NMDevice *device);
void			nm_device_activate_schedule_stage2_device_config		(NMDevice *device);
void			nm_device_activate_schedule_stage4_ip4_config_get		(NMDevice *device);
void			nm_device_activate_schedule_stage4_ip4_config_timeout	(NMDevice *device);
void			nm_device_activate_schedule_stage4_ip6_config_get		(NMDevice *device);
void			nm_device_activate_schedule_stage4_ip6_config_timeout	(NMDevice *device);
gboolean		nm_device_deactivate_quickly	(NMDevice *dev);
gboolean		nm_device_is_activating		(NMDevice *dev);
gboolean		nm_device_can_interrupt_activation		(NMDevice *self);
gboolean		nm_device_autoconnect_allowed	(NMDevice *self);

NMDeviceState nm_device_get_state (NMDevice *device);

gboolean nm_device_get_managed (NMDevice *device);
void nm_device_set_managed (NMDevice *device,
                            gboolean managed,
                            NMDeviceStateReason reason);

void nm_device_set_dhcp_timeout (NMDevice *device, guint32 timeout);
void nm_device_set_dhcp_anycast_address (NMDevice *device, guint8 *addr);

void nm_device_clear_autoconnect_inhibit (NMDevice *device);

G_END_DECLS

#endif	/* NM_DEVICE_H */
