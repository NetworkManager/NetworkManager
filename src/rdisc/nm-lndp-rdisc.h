/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-lndp-rdisc.h - Implementation of router discovery using libndp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NM_LNDP_RDISC_H
#define NM_LNDP_RDISC_H

#include "nm-rdisc.h"

#define NM_TYPE_LNDP_RDISC            (nm_lndp_rdisc_get_type ())
#define NM_LNDP_RDISC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_LNDP_RDISC, NMLNDPRDisc))
#define NM_LNDP_RDISC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_LNDP_RDISC, NMLNDPRDiscClass))
#define NM_IS_LNDP_RDISC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_LNDP_RDISC))
#define NM_IS_LNDP_RDISC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_LNDP_RDISC))
#define NM_LNDP_RDISC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_LNDP_RDISC, NMLNDPRDiscClass))

/******************************************************************/

typedef struct {
	NMRDisc parent;
} NMLNDPRDisc;

typedef struct {
	NMRDiscClass parent;
} NMLNDPRDiscClass;

/******************************************************************/

GType nm_lndp_rdisc_get_type (void);

NMRDisc *nm_lndp_rdisc_new (int ifindex, const char *ifname);

#endif /* NM_LNDP_RDISC_H */
