/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include "nm-hostname-provider.h"

const char *
nm_hostname_provider_get_hostname (NMHostnameProvider *self)
{
	g_return_val_if_fail (NM_IS_HOSTNAME_PROVIDER (self), NULL);

	return NM_HOSTNAME_PROVIDER_GET_INTERFACE (self)->get_hostname (self);
}

GType
nm_hostname_provider_get_type (void)
{
    static GType type = 0;

    if (!G_UNLIKELY (type)) {
        const GTypeInfo type_info = {
            sizeof (NMHostnameProvider), /* class_size */
            NULL,   /* base_init */
            NULL,       /* base_finalize */
            NULL,
            NULL,       /* class_finalize */
            NULL,       /* class_data */
            0,
            0,              /* n_preallocs */
            NULL
        };

        type = g_type_register_static (G_TYPE_INTERFACE, "NMHostnameProvider", &type_info, 0);
        g_type_interface_add_prerequisite (type, G_TYPE_OBJECT);
    }

    return type;
}
