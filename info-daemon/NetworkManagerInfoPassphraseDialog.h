/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_INFO_PASSPHRASE_DIALOG_H
#define NETWORK_MANAGER_INFO_PASSPHRASE_DIALOG_H

#include "NetworkManagerInfo.h"

int		nmi_passphrase_dialog_init	(NMIAppInfo *info);

void		nmi_passphrase_dialog_show	(const char *device, const char *network, NMIAppInfo *info);

void		nmi_passphrase_dialog_cancel	(NMIAppInfo *info);

#endif
