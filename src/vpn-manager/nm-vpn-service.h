/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_VPN_SERVICE_H
#define NM_VPN_SERVICE_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include "nm-device.h"
#include "nm-vpn-connection.h"
#include "nm-activation-request.h"

#define NM_TYPE_VPN_SERVICE            (nm_vpn_service_get_type ())
#define NM_VPN_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_SERVICE, NMVPNService))
#define NM_VPN_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_SERVICE, NMVPNServiceClass))
#define NM_IS_VPN_SERVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_SERVICE))
#define NM_IS_VPN_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPN_SERVICE))
#define NM_VPN_SERVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_SERVICE, NMVPNServiceClass))

typedef struct {
	GObject parent;
} NMVPNService;

typedef struct {
	GObjectClass parent;
} NMVPNServiceClass;

GType nm_vpn_service_get_type (void);

NMVPNService * nm_vpn_service_new (const char *service_name);

const char * nm_vpn_service_get_name (NMVPNService *service);

NMVPNConnection * nm_vpn_service_activate (NMVPNService *service,
                                           NMConnection *connection,
                                           NMActRequest *act_request,
                                           NMDevice *device,
                                           GError **error);

GSList * nm_vpn_service_get_active_connections (NMVPNService *service);

#endif  /* NM_VPN_VPN_SERVICE_H */
