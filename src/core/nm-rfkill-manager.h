/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#ifndef __NM_RFKILL_MANAGER_H__
#define __NM_RFKILL_MANAGER_H__

typedef enum {
    NM_RFKILL_STATE_UNAVAILABLE  = 0,
    NM_RFKILL_STATE_UNBLOCKED    = 1,
    NM_RFKILL_STATE_SOFT_BLOCKED = 2,
    NM_RFKILL_STATE_HARD_BLOCKED = 3,
    /* NM_RFKILL_STATE_HARD_BLOCKED_OS_NOT_OWNER means that the CSME firmware
     * is currently controlling the device. This feature is implmented on Intel
     * wifi devices only.
     * The NetworkManager can get ownership on the device, but it requires to
     * first ask ownership through the iwlmei kernel module.
     */
    NM_RFKILL_STATE_HARD_BLOCKED_OS_NOT_OWNER = 4,
} NMRfkillState;

typedef enum {
    NM_RFKILL_TYPE_WLAN = 0,
    NM_RFKILL_TYPE_WWAN = 1,

    /* UNKNOWN and MAX should always be 1 more than
     * the last rfkill type since NM_RFKILL_TYPE_MAX is
     * used as an array size.
     */
    NM_RFKILL_TYPE_UNKNOWN, /* KEEP LAST */
    NM_RFKILL_TYPE_MAX = NM_RFKILL_TYPE_UNKNOWN,
} NMRfkillType;

const char *nm_rfkill_type_to_string(NMRfkillType rtype);

#define NM_TYPE_RFKILL_MANAGER (nm_rfkill_manager_get_type())
#define NM_RFKILL_MANAGER(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_RFKILL_MANAGER, NMRfkillManager))
#define NM_RFKILL_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_RFKILL_MANAGER, NMRfkillManagerClass))
#define NM_IS_RFKILL_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_RFKILL_MANAGER))
#define NM_IS_RFKILL_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_RFKILL_MANAGER))
#define NM_RFKILL_MANAGER_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_RFKILL_MANAGER, NMRfkillManagerClass))

#define NM_RFKILL_MANAGER_SIGNAL_RFKILL_CHANGED "rfkill-changed"

typedef struct _NMRfkillManagerClass NMRfkillManagerClass;

GType nm_rfkill_manager_get_type(void);

NMRfkillManager *nm_rfkill_manager_new(void);

NMRfkillState nm_rfkill_manager_get_rfkill_state(NMRfkillManager *manager, NMRfkillType rtype);

NMRadioFlags nm_rfkill_type_to_radio_available_flag(NMRfkillType type);

#endif /* __NM_RFKILL_MANAGER_H__ */
