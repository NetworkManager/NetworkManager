// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#ifndef __NM_RFKILL_MANAGER_H__
#define __NM_RFKILL_MANAGER_H__

typedef enum { /*< skip >*/
	RFKILL_UNBLOCKED = 0,
	RFKILL_SOFT_BLOCKED = 1,
	RFKILL_HARD_BLOCKED = 2
} RfKillState;

typedef enum { /*< skip >*/
	RFKILL_TYPE_WLAN = 0,
	RFKILL_TYPE_WWAN = 1,

	/* UNKNOWN and MAX should always be 1 more than
	 * the last rfkill type since RFKILL_TYPE_MAX is
	 * used as an array size.
	 */
	RFKILL_TYPE_UNKNOWN, /* KEEP LAST */
	RFKILL_TYPE_MAX = RFKILL_TYPE_UNKNOWN
} RfKillType;

#define NM_TYPE_RFKILL_MANAGER            (nm_rfkill_manager_get_type ())
#define NM_RFKILL_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_RFKILL_MANAGER, NMRfkillManager))
#define NM_RFKILL_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_RFKILL_MANAGER, NMRfkillManagerClass))
#define NM_IS_RFKILL_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_RFKILL_MANAGER))
#define NM_IS_RFKILL_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_RFKILL_MANAGER))
#define NM_RFKILL_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_RFKILL_MANAGER, NMRfkillManagerClass))

#define NM_RFKILL_MANAGER_SIGNAL_RFKILL_CHANGED "rfkill-changed"

typedef struct _NMRfkillManagerClass NMRfkillManagerClass;

GType nm_rfkill_manager_get_type (void);

NMRfkillManager *nm_rfkill_manager_new (void);

RfKillState nm_rfkill_manager_get_rfkill_state (NMRfkillManager *manager, RfKillType rtype);

#endif  /* __NM_RFKILL_MANAGER_H__ */
