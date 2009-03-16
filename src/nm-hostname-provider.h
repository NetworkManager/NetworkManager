/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_HOSTNAME_PROVIDER_H
#define NM_HOSTNAME_PROVIDER_H

#include <glib-object.h>

#define NM_TYPE_HOSTNAME_PROVIDER (nm_hostname_provider_get_type ())
#define NM_HOSTNAME_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HOSTNAME_PROVIDER, NMHostnameProvider))
#define NM_IS_HOSTNAME_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HOSTNAME_PROVIDER))
#define NM_HOSTNAME_PROVIDER_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_HOSTNAME_PROVIDER, NMHostnameProvider))

typedef struct _NMHostnameProvider NMHostnameProvider;

struct _NMHostnameProvider {
	GTypeInterface g_iface;

	/* Methods */
	const char *(*get_hostname) (NMHostnameProvider *self);
};

GType nm_hostname_provider_get_type (void);

const char *nm_hostname_provider_get_hostname (NMHostnameProvider *self);

#endif /* NM_HOSTNAME_PROVIDER_H */
