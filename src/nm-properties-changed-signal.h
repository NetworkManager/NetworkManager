/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef _NM_PROPERTIES_CHANGED_SIGNAL_H_
#define _NM_PROPERTIES_CHANGED_SIGNAL_H_

#include <glib-object.h>

guint nm_properties_changed_signal_new (GObjectClass *object_class,
								guint class_offset);

#endif /* _NM_PROPERTIES_CHANGED_SIGNAL_H_ */
