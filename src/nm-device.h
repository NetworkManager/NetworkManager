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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef NM_DEVICE_H
#define NM_DEVICE_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "NetworkManager.h"
#include "nm-ip4-config.h"

#if 0
#define IOCTL_DEBUG
#endif

typedef enum NMWirelessScanInterval
{
	NM_WIRELESS_SCAN_INTERVAL_INIT = 0,
	NM_WIRELESS_SCAN_INTERVAL_ACTIVE,
	NM_WIRELESS_SCAN_INTERVAL_INACTIVE
} NMWirelessScanInterval;

typedef enum NMActStageReturn
{
	NM_ACT_STAGE_RETURN_FAILURE = 0,
	NM_ACT_STAGE_RETURN_SUCCESS,
	NM_ACT_STAGE_RETURN_POSTPONE
} NMActStageReturn;


G_BEGIN_DECLS

#define NM_TYPE_DEVICE			(nm_device_get_type ())
#define NM_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE, NMDeviceClass))

typedef struct _NMDevice NMDevice;
typedef struct _NMDeviceClass NMDeviceClass;
typedef struct _NMDevicePrivate NMDevicePrivate;

struct _NMDevice
{
	GObject parent;

	/*< private >*/
	NMDevicePrivate *priv;
};

struct NMData;
struct NMActRequest;

struct _NMDeviceClass
{
	GObjectClass parent;

	gboolean		(* is_test_device)	(NMDevice *self);

	const char *	(* has_active_link)	(NMDevice *self);
	void			(* set_active_link)	(NMDevice *self, gboolean active);
	void			(* update_link)	(NMDevice *self);

	void			(* bring_up)		(NMDevice *self);
	void			(* bring_down)		(NMDevice *self);

	guint32		(* get_type_capabilities)	(NMDevice *self);
	guint32		(* get_generic_capabilities)	(NMDevice *self);

	void			(* init)				(NMDevice *self);
	void			(* start)				(NMDevice *self);
	NMActStageReturn	(* act_stage1_prepare)	(NMDevice *self, struct NMActRequest *req);
	NMActStageReturn	(* act_stage2_config)	(NMDevice *self, struct NMActRequest *req);
	NMActStageReturn	(* act_stage3_ip_config_start)(NMDevice *self,
											 struct NMActRequest *req);
	NMActStageReturn	(* act_stage4_get_ip4_config)	(NMDevice *self,
											 struct NMActRequest *req,
											 NMIP4Config **config);
	NMActStageReturn	(* act_stage4_ip_config_timeout)	(NMDevice *self,
												 struct NMActRequest *req,
												 NMIP4Config **config);
	void			(* deactivate)			(NMDevice *self);
	void			(* deactivate_quickly)	(NMDevice *self);

	void			(* activation_failure_handler)	(NMDevice *self,
											 struct NMActRequest *req);
	void			(* activation_success_handler)	(NMDevice *self,
											 struct NMActRequest *req);
	void			(* activation_cancel_handler)		(NMDevice *self,
											 struct NMActRequest *req);

	gboolean		(* can_interrupt_activation)		(NMDevice *self);
};


GType nm_device_get_type (void);

NMDevice *	nm_device_new (const char *iface, 
						const char *udi,
						gboolean test_dev,
						NMDeviceType test_dev_type,
						struct NMData *app_data);

void		nm_device_stop (NMDevice *self);

const char *	nm_device_get_udi		(NMDevice *dev);

const char *	nm_device_get_iface		(NMDevice *dev);

const char *	nm_device_get_driver	(NMDevice *dev);

NMDeviceType	nm_device_get_device_type	(NMDevice *dev);
guint32		nm_device_get_capabilities	(NMDevice *dev);
guint32		nm_device_get_type_capabilities	(NMDevice *dev);

struct NMData *	nm_device_get_app_data	(NMDevice *dev);

gboolean		nm_device_get_removed	(NMDevice *dev);
void			nm_device_set_removed	(NMDevice *dev,
								 const gboolean removed);

gboolean		nm_device_has_active_link	(NMDevice *dev);
void			nm_device_set_active_link	(NMDevice *dev,
									 const gboolean active);

guint32			nm_device_get_ip4_address	(NMDevice *dev);
void				nm_device_update_ip4_address	(NMDevice *dev);
struct in6_addr *	nm_device_get_ip6_address	(NMDevice *dev);

gboolean		nm_device_get_use_dhcp	(NMDevice *dev);
void			nm_device_set_use_dhcp	(NMDevice *dev,
								 gboolean use_dhcp);

NMIP4Config *	nm_device_get_ip4_config	(NMDevice *dev);
void			nm_device_set_ip4_config	(NMDevice *dev,
								 NMIP4Config *config);

void			nm_device_bring_up		(NMDevice *dev);
gboolean		nm_device_bring_up_wait	(NMDevice *self,
								 gboolean cancelable);
void			nm_device_bring_down	(NMDevice *dev);
gboolean		nm_device_bring_down_wait (NMDevice *self,
								  gboolean cancelable);
gboolean		nm_device_is_up		(NMDevice *dev);

void *		nm_device_get_system_config_data	(NMDevice *dev);

struct NMActRequest *	nm_device_get_act_request	(NMDevice *dev);

void		nm_device_get_hw_address (NMDevice *dev, struct ether_addr *addr);
void		nm_device_update_hw_address (NMDevice *dev);

/* Utility routines */
NMDevice *	nm_get_device_by_udi	(struct NMData *data,
								 const char *udi);
NMDevice *	nm_get_device_by_iface	(struct NMData *data,
								 const char *iface);
NMDevice *	nm_get_device_by_iface_locked	(struct NMData *data,
								 const char *iface);

gboolean		nm_device_is_test_device	(NMDevice *dev);

gboolean		nm_device_activation_start	(struct NMActRequest *req);
void			nm_device_activate_schedule_stage1_device_prepare		(struct NMActRequest *req);
void			nm_device_activate_schedule_stage2_device_config		(struct NMActRequest *req);
void			nm_device_activate_schedule_stage4_ip_config_get		(struct NMActRequest *req);
void			nm_device_activate_schedule_stage4_ip_config_timeout	(struct NMActRequest *req);
void			nm_device_deactivate		(NMDevice *dev);
gboolean		nm_device_deactivate_quickly	(NMDevice *dev);
gboolean		nm_device_is_activating		(NMDevice *dev);
void			nm_device_activation_cancel	(NMDevice *dev);
gboolean		nm_device_activation_should_cancel (NMDevice *self);

void			nm_device_activation_failure_handler	(NMDevice *dev,
											 struct NMActRequest *req);
void			nm_device_activation_success_handler	(NMDevice *dev,
											 struct NMActRequest *req);

gboolean		nm_device_can_interrupt_activation		(NMDevice *self);

G_END_DECLS

#endif	/* NM_DEVICE_H */
