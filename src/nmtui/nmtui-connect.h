/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMTUI_CONNECT_H
#define NMTUI_CONNECT_H

#define RESCAN_TIMEOUT_MS 10000

NmtNewtForm *nmtui_connect(gboolean is_top, int argc, char **argv);

#endif /* NMTUI_CONNECT_H */
