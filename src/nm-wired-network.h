/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_WIRED_NETWORK_H
#define NM_WIRED_NETWORK_H 1

#include <glib/gtypes.h>
#include <glib-object.h>
#include "nm-ap-security.h"

#define NM_TYPE_WIRED_NETWORK            (nm_wired_network_get_type ())
#define NM_WIRED_NETWORK(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIRED_NETWORK, NMWiredNetwork))
#define NM_WIRED_NETWORK_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIRED_NETWORK, NMWiredNetworkClass))
#define NM_IS_WIRED_NETWORK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIRED_NETWORK))
#define NM_IS_WIRED_NETWORK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_WIRED_NETWORK))
#define NM_WIRED_NETWORK_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIRED_NETWORK, NMWiredNetworkClass))

typedef struct {
	GObject parent;
} NMWiredNetwork;

typedef struct {
	GObjectClass parent;
} NMWiredNetworkClass;

GType nm_wired_network_get_type (void);

NMWiredNetwork *nm_wired_network_new            (const char     *network_id,
									    NMAPSecurity   *security);

const char     *nm_wired_network_get_network_id (NMWiredNetwork *net);
NMAPSecurity   *nm_wired_network_get_security   (NMWiredNetwork *net);
void            nm_wired_network_set_security   (NMWiredNetwork *net,
									    NMAPSecurity   *security);

#endif /* NM_WIRED_NETWORK_H */
