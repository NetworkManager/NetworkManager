/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_KEYFILE_CONNECTION_H
#define NM_KEYFILE_CONNECTION_H

#include <nm-settings.h>

G_BEGIN_DECLS

#define NM_TYPE_KEYFILE_CONNECTION            (nm_keyfile_connection_get_type ())
#define NM_KEYFILE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnection))
#define NM_KEYFILE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionClass))
#define NM_IS_KEYFILE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_KEYFILE_CONNECTION))
#define NM_IS_KEYFILE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_KEYFILE_CONNECTION))
#define NM_KEYFILE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionClass))

#define NM_KEYFILE_CONNECTION_FILENAME  "filename"

typedef struct {
	NMExportedConnection parent;
} NMKeyfileConnection;

typedef struct {
	NMExportedConnectionClass parent;
} NMKeyfileConnectionClass;

GType nm_keyfile_connection_get_type (void);

NMKeyfileConnection *nm_keyfile_connection_new (const char *filename);

const char *nm_keyfile_connection_get_filename (NMKeyfileConnection *self);

G_END_DECLS

#endif /* NM_KEYFILE_CONNECTION_H */
