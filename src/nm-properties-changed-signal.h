/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef _NM_PROPERTIES_CHANGED_SIGNAL_H_
#define _NM_PROPERTIES_CHANGED_SIGNAL_H_

#include <glib-object.h>

#define NM_PROPERTY_PARAM_NO_EXPORT    (1 << (0 + G_PARAM_USER_SHIFT))

guint nm_properties_changed_signal_new (GObjectClass *object_class,
								guint class_offset);

#endif /* _NM_PROPERTIES_CHANGED_SIGNAL_H_ */
