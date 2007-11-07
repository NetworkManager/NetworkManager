/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_PARAM_SPEC_SPECIALIZED_H
#define NM_PARAM_SPEC_SPECIALIZED_H

#include <glib-object.h>

typedef struct _NMParamSpecSpecialized NMParamSpecSpecialized;

#define NM_TYPE_PARAM_SPEC_SPECIALIZED (nm_param_spec_specialized_get_type ())

#define NM_IS_PARAM_SPEC_SPECIALIZED(pspec) (G_TYPE_CHECK_INSTANCE_TYPE ((pspec), NM_TYPE_PARAM_SPEC_SPECIALIZED))
#define NM_PARAM_SPEC_SPECIALIZED(pspec)    (G_TYPE_CHECK_INSTANCE_CAST ((pspec), NM_TYPE_PARAM_SPEC_SPECIALIZED, NMParamSpecSpecialized))

GType nm_param_spec_specialized_get_type (void);

GParamSpec *nm_param_spec_specialized (const char *name,
							    const char *nick,
							    const char *blurb,
							    GType specialized_type,
							    GParamFlags flags);

#endif /* NM_PARAM_SPEC_SPECIALIZED_H */
