// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_L3CFG_H__
#define __NM_L3CFG_H__

#include "platform/nmp-object.h"

#define NM_TYPE_L3CFG            (nm_l3cfg_get_type ())
#define NM_L3CFG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_L3CFG, NML3Cfg))
#define NM_L3CFG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_L3CFG, NML3CfgClass))
#define NM_IS_L3CFG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_L3CFG))
#define NM_IS_L3CFG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_L3CFG))
#define NM_L3CFG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_L3CFG, NML3CfgClass))

#define NM_L3CFG_NETNS   "netns"
#define NM_L3CFG_IFINDEX "ifindex"

struct _NML3CfgPrivate;

struct _NML3Cfg {
	GObject parent;
	struct {
		NMNetns *netns;
		NMPlatform *platform;
		int ifindex;
		const NMPObject *pllink;
		struct _NML3CfgPrivate *p;
	} priv;
};

typedef struct _NML3CfgClass NML3CfgClass;

GType nm_l3cfg_get_type (void);

NML3Cfg *nm_l3cfg_new (NMNetns *netns, int ifindex);

/*****************************************************************************/

void _nm_l3cfg_notify_platform_change_on_idle (NML3Cfg *self, guint32 obj_type_flags);

/*****************************************************************************/

static inline int
nm_l3cfg_get_ifindex (const NML3Cfg *self)
{
	nm_assert (NM_IS_L3CFG (self));

	return self->priv.ifindex;
}

static inline const char *
nm_l3cfg_get_ifname (const NML3Cfg *self)
{
	nm_assert (NM_IS_L3CFG (self));

	return nmp_object_link_get_ifname (self->priv.pllink);
}

static inline NMNetns *
nm_l3cfg_get_netns (const NML3Cfg *self)
{
	nm_assert (NM_IS_L3CFG (self));

	return self->priv.netns;
}

static inline NMPlatform *
nm_l3cfg_get_platform (const NML3Cfg *self)
{
	nm_assert (NM_IS_L3CFG (self));

	return self->priv.platform;
}

#endif /* __NM_L3CFG_H__ */
