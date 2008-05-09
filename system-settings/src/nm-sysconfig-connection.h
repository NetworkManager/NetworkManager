/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SYSCONFIG_CONNECTION_H
#define NM_SYSCONFIG_CONNECTION_H

#include <nm-settings.h>

G_BEGIN_DECLS

#define NM_TYPE_SYSCONFIG_CONNECTION            (nm_sysconfig_connection_get_type ())
#define NM_SYSCONFIG_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSCONFIG_CONNECTION, NMSysconfigConnection))
#define NM_SYSCONFIG_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SYSCONFIG_CONNECTION, NMSysconfigConnectionClass))
#define NM_IS_SYSCONFIG_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSCONFIG_CONNECTION))
#define NM_IS_SYSCONFIG_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SYSCONFIG_CONNECTION))
#define NM_SYSCONFIG_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SYSCONFIG_CONNECTION, NMSysconfigConnectionClass))

typedef struct {
	NMExportedConnection parent;
} NMSysconfigConnection;

typedef struct {
	NMExportedConnectionClass parent;
} NMSysconfigConnectionClass;

GType nm_sysconfig_connection_get_type (void);

G_END_DECLS

#endif /* NM_SYSCONFIG_CONNECTION_H */
