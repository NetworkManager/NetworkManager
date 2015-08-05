/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_PARAM_SPEC_SPECIALIZED_H
#define NM_PARAM_SPEC_SPECIALIZED_H

#include "nm-default.h"

typedef struct _NMParamSpecSpecialized NMParamSpecSpecialized;

#define NM_TYPE_PARAM_SPEC_SPECIALIZED (_nm_param_spec_specialized_get_type ())

#define NM_IS_PARAM_SPEC_SPECIALIZED(pspec) (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), NM_TYPE_PARAM_SPEC_SPECIALIZED))
#define NM_PARAM_SPEC_SPECIALIZED(pspec)    (G_TYPE_CHECK_INSTANCE_CAST ((pspec), NM_TYPE_PARAM_SPEC_SPECIALIZED, NMParamSpecSpecialized))

GType _nm_param_spec_specialized_get_type (void);

GParamSpec *_nm_param_spec_specialized (const char *name,
                                        const char *nick,
                                        const char *blurb,
                                        GType specialized_type,
                                        GParamFlags flags);

#endif /* NM_PARAM_SPEC_SPECIALIZED_H */
