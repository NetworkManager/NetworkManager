/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_JANSSON_H__
#define __NM_JANSSON_H__

/* you need to include at least "config.h" first, possibly "nm-default.h". */

#if WITH_JANSSON

    #include <jansson.h>

    /* Added in Jansson v2.8 */
    #ifndef json_object_foreach_safe
        #define json_object_foreach_safe(object, n, key, value)                         \
            for (key = json_object_iter_key(json_object_iter(object)),                  \
                n    = json_object_iter_next(object, json_object_key_to_iter(key));     \
                 key && (value = json_object_iter_value(json_object_key_to_iter(key))); \
                 key = json_object_iter_key(n),                                         \
                n    = json_object_iter_next(object, json_object_key_to_iter(key)))
    #endif

NM_AUTO_DEFINE_FCN0(json_t *, _nm_auto_decref_json, json_decref);
    #define nm_auto_decref_json nm_auto(_nm_auto_decref_json)

#endif /* WITH_JANSON */

#endif /* __NM_JANSSON_H__ */
