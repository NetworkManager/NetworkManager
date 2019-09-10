// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * (C) Copyright 2007 - 2011, 2017 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

#ifndef __NM_HOSTNAME_MANAGER_H__
#define __NM_HOSTNAME_MANAGER_H__

#define NM_TYPE_HOSTNAME_MANAGER            (nm_hostname_manager_get_type ())
#define NM_HOSTNAME_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HOSTNAME_MANAGER, NMHostnameManager))
#define NM_HOSTNAME_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_HOSTNAME_MANAGER, NMHostnameManagerClass))
#define NM_IS_HOSTNAME_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HOSTNAME_MANAGER))
#define NM_IS_HOSTNAME_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_HOSTNAME_MANAGER))
#define NM_HOSTNAME_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_HOSTNAME_MANAGER, NMHostnameManagerClass))

#define NM_HOSTNAME_MANAGER_HOSTNAME "hostname"

typedef struct _NMHostnameManager      NMHostnameManager;
typedef struct _NMHostnameManagerClass NMHostnameManagerClass;

typedef void (*NMHostnameManagerSetHostnameCb) (const char *name, gboolean result, gpointer user_data);

GType nm_hostname_manager_get_type (void);

NMHostnameManager *nm_hostname_manager_get (void);

const char *nm_hostname_manager_get_hostname (NMHostnameManager *self);

char *nm_hostname_manager_read_hostname (NMHostnameManager *self);

gboolean nm_hostname_manager_write_hostname (NMHostnameManager *self, const char *hostname);

void nm_hostname_manager_set_transient_hostname (NMHostnameManager *self,
                                                 const char *hostname,
                                                 NMHostnameManagerSetHostnameCb cb,
                                                 gpointer user_data);

gboolean nm_hostname_manager_get_transient_hostname (NMHostnameManager *self,
                                                     char **hostname);

gboolean nm_hostname_manager_validate_hostname (const char *hostname);

#endif  /* __NM_HOSTNAME_MANAGER_H__ */
