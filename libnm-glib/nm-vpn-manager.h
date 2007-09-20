/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_VPN_MANAGER_H
#define NM_VPN_MANAGER_H 1

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include "nm-object.h"
#include "nm-device.h"
#include "nm-connection.h"
#include "nm-vpn-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_VPN_MANAGER            (nm_vpn_manager_get_type ())
#define NM_VPN_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_MANAGER, NMVPNManager))
#define NM_VPN_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_MANAGER, NMVPNManagerClass))
#define NM_IS_VPN_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_MANAGER))
#define NM_IS_VPN_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPN_MANAGER))
#define NM_VPN_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_MANAGER, NMVPNManagerClass))

typedef struct {
	NMObject parent;
} NMVPNManager;

typedef struct {
	NMObjectClass parent;
} NMVPNManagerClass;

GType nm_vpn_manager_get_type (void);


NMVPNManager    *nm_vpn_manager_new     (void);
NMVPNConnection *nm_vpn_manager_connect (NMVPNManager *manager,
								 const char   *connection_type,
								 const char   *connection_path,
								 NMDevice     *device);

GSList *nm_vpn_manager_get_connections  (NMVPNManager *manager);

G_END_DECLS

#endif /* NM_MANAGER_H */
