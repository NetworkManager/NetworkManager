/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef __NMP_NETNS_UTILS_H__
#define __NMP_NETNS_UTILS_H__

#include "nmp-base.h"

/*****************************************************************************/

#define NMP_TYPE_NETNS            (nmp_netns_get_type())
#define NMP_NETNS(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), NMP_TYPE_NETNS, NMPNetns))
#define NMP_NETNS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NMP_TYPE_NETNS, NMPNetnsClass))
#define NMP_IS_NETNS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMP_TYPE_NETNS))
#define NMP_IS_NETNS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMP_TYPE_NETNS))
#define NMP_NETNS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NMP_TYPE_NETNS, NMPNetnsClass))

#define NMP_NETNS_FD_NET "fd-net"
#define NMP_NETNS_FD_MNT "fd-mnt"

typedef struct _NMPNetns      NMPNetns;
typedef struct _NMPNetnsClass NMPNetnsClass;

GType nmp_netns_get_type(void);

NMPNetns *nmp_netns_new(void);

gboolean nmp_netns_push(NMPNetns *self);
gboolean nmp_netns_push_type(NMPNetns *self, int ns_types);
gboolean nmp_netns_pop(NMPNetns *self);

NMPNetns *nmp_netns_get_current(void);
NMPNetns *nmp_netns_get_initial(void);
gboolean  nmp_netns_is_initial(void);

int nmp_netns_get_fd_net(NMPNetns *self);
int nmp_netns_get_fd_mnt(NMPNetns *self);

static inline void
_nm_auto_pop_netns(NMPNetns **p)
{
    if (*p) {
        int errsv = errno;

        nmp_netns_pop(*p);
        errno = errsv;
    }
}
#define nm_auto_pop_netns nm_auto(_nm_auto_pop_netns)

gboolean nmp_netns_bind_to_path(NMPNetns *self, const char *filename, int *out_fd);
gboolean nmp_netns_bind_to_path_destroy(NMPNetns *self, const char *filename);

#endif /* __NMP_NETNS_UTILS_H__ */
