/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_LIBNM_H__
#define __NM_DEFAULT_LIBNM_H__

/*****************************************************************************/

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#undef NETWORKMANAGER_COMPILATION
#define NETWORKMANAGER_COMPILATION NM_NETWORKMANAGER_COMPILATION_LIBNM

/*****************************************************************************/

#include "nm-version.h"
#include "nm-dbus-interface.h"
#include "nm-dhcp-config.h"
#include "nm-ip-config.h"
#include "nm-connection.h"
#include "nm-remote-connection.h"
#include "nm-active-connection.h"
#include "nm-device.h"
#include "nm-checkpoint.h"
#include "nm-client.h"
#include "nm-vpn-connection.h"
#include "nm-libnm-utils.h"
#include "nm-errors.h"

/*****************************************************************************/

#endif /* __NM_DEFAULT_LIBNM_H__ */
