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

#include "NetworkManager.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"
#include "nm-connection.h"

#if 0
# define IOCTL_DEBUG 1
#endif

#ifdef IOCTL_DEBUG
# define nm_ioctl_info(fmt, args...)				\
  G_STMT_START {								\
      g_message ("<information>\t" fmt "\n", ##args);	\
  } G_STMT_END
#else
# define nm_ioctl_info(fmt, args...) do { } while(0)
#endif

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

struct _NMDeviceClass
{
	GObjectClass parent;

	void			(* update_link)	(NMDevice *self);

	gboolean		(* is_up)			(NMDevice *self);
	gboolean		(* bring_up)		(NMDevice *self);
	void			(* bring_down)		(NMDevice *self);

	void        (* set_hw_address) (NMDevice *self);

	guint32		(* get_type_capabilities)	(NMDevice *self);
	guint32		(* get_generic_capabilities)	(NMDevice *self);

	NMConnection * (* get_best_connection) (NMDevice *self,
	                                        char **specific_object);

	void        (* connection_secrets_updated) (NMDevice *self,
	                                            NMConnection *connection,
	                                            const char *setting_name);

	gboolean    (* check_connection) (NMDevice *self, NMConnection *connection);

	NMActStageReturn	(* act_stage1_prepare)	(NMDevice *self);
	NMActStageReturn	(* act_stage2_config)	(NMDevice *self);
	NMActStageReturn	(* act_stage3_ip_config_start) (NMDevice *self);
	NMActStageReturn	(* act_stage4_get_ip4_config)	(NMDevice *self,
														 NMIP4Config **config);
	NMActStageReturn	(* act_stage4_ip_config_timeout)	(NMDevice *self,
												 NMIP4Config **config);
	void			(* deactivate)			(NMDevice *self);
	void			(* deactivate_quickly)	(NMDevice *self);

	void			(* activation_cancel_handler)		(NMDevice *self);

	gboolean		(* can_interrupt_activation)		(NMDevice *self);
};


GType nm_device_get_type (void);

const char *	nm_device_get_dbus_path	(NMDevice *dev);
const char *	nm_device_get_udi		(NMDevice *dev);
guint32			nm_device_get_index		(NMDevice *dev);
const char *	nm_device_get_iface		(NMDevice *dev);
const char *	nm_device_get_driver	(NMDevice *dev);

NMDeviceType	nm_device_get_device_type	(NMDevice *dev);
guint32		nm_device_get_capabilities	(NMDevice *dev);
guint32		nm_device_get_type_capabilities	(NMDevice *dev);

gboolean		nm_device_has_active_link	(NMDevice *dev);
guint32			nm_device_get_ip4_address	(NMDevice *dev);
void				nm_device_update_ip4_address	(NMDevice *dev);
struct in6_addr *	nm_device_get_ip6_address	(NMDevice *dev);

gboolean		nm_device_get_use_dhcp	(NMDevice *dev);
void			nm_device_set_use_dhcp	(NMDevice *dev,
								 gboolean use_dhcp);

NMIP4Config *	nm_device_get_ip4_config	(NMDevice *dev);
void			nm_device_set_ip4_config	(NMDevice *dev,
								 NMIP4Config *config);

gboolean		nm_device_is_up	(NMDevice *dev);
gboolean		nm_device_bring_up (NMDevice *dev, gboolean wait);
void			nm_device_bring_down (NMDevice *dev, gboolean wait);


void *		nm_device_get_system_config_data	(NMDevice *dev);

NMActRequest *	nm_device_get_act_request	(NMDevice *dev);

NMConnection * nm_device_get_best_connection (NMDevice *dev,
                                              char **specific_object);

void			nm_device_activate_schedule_stage1_device_prepare		(NMDevice *device);
void			nm_device_activate_schedule_stage2_device_config		(NMDevice *device);
void			nm_device_activate_schedule_stage4_ip_config_get		(NMDevice *device);
void			nm_device_activate_schedule_stage4_ip_config_timeout	(NMDevice *device);
gboolean		nm_device_deactivate_quickly	(NMDevice *dev);
gboolean		nm_device_is_activating		(NMDevice *dev);
void			nm_device_activation_cancel	(NMDevice *dev);

gboolean		nm_device_can_interrupt_activation		(NMDevice *self);

NMDeviceState nm_device_get_state (NMDevice *device);

G_END_DECLS

#endif	/* NM_DEVICE_H */
