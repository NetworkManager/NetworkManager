/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_KEYFILE_H__
#define __NM_KEYFILE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-core-types.h"

G_BEGIN_DECLS

/**
 * NMKeyfileHandlerFlags:
 * @NM_KEYFILE_HANDLER_FLAGS_NONE: no flags set.
 *
 * Flags for customizing nm_keyfile_read() and nm_keyfile_write().
 *
 * Currently no flags are implemented.
 *
 * Since: 1.30
 */
typedef enum { /*< flags >*/
               NM_KEYFILE_HANDLER_FLAGS_NONE = 0,
} NMKeyfileHandlerFlags;

/**
 * NMKeyfileHandlerType:
 * @NM_KEYFILE_HANDLER_TYPE_WARN: a warning.
 * @NM_KEYFILE_HANDLER_TYPE_WRITE_CERT: for handling certificates while writing
 *   a connection to keyfile.
 *
 * The type of the callback for %NMKeyfileReadHandler and %NMKeyfileWriteHandler.
 * Depending on the type, you can interpret %NMKeyfileHandlerData.
 *
 * Since: 1.30
 */
typedef enum {
    NM_KEYFILE_HANDLER_TYPE_WARN       = 1,
    NM_KEYFILE_HANDLER_TYPE_WRITE_CERT = 2,
} NMKeyfileHandlerType;

/**
 * NMKeyfileHandlerData:
 *
 * Opaque type with parameters for the callback. The actual content
 * depends on the %NMKeyfileHandlerType.
 *
 * Since: 1.30
 */
typedef struct _NMKeyfileHandlerData NMKeyfileHandlerData;

/**
 * NMKeyfileReadHandler:
 * @keyfile: the #GKeyFile that is currently read
 * @connection: the #NMConnection that is being constructed.
 * @handler_type: the %NMKeyfileHandlerType that indicates which type
 *   the request is.
 * @handler_data: the #NMKeyfileHandlerData. What you can do with it
 *   depends on the @handler_type.
 * @user_data: the user-data argument to nm_keyfile_read().
 *
 * Hook to nm_keyfile_read().
 *
 * The callee may abort the reading by setting an error via nm_keyfile_handler_data_fail_with_error().
 *
 * Returns: the callee should return TRUE, if the event was handled and/or recognized.
 *   Otherwise, a default action will be performed that depends on the @type.
 *   For %NM_KEYFILE_HANDLER_TYPE_WARN type, the default action is doing nothing.
 *
 * Since: 1.30
 */
typedef gboolean (*NMKeyfileReadHandler)(GKeyFile             *keyfile,
                                         NMConnection         *connection,
                                         NMKeyfileHandlerType  handler_type,
                                         NMKeyfileHandlerData *handler_data,
                                         void                 *user_data);

NM_AVAILABLE_IN_1_30
NMConnection *nm_keyfile_read(GKeyFile             *keyfile,
                              const char           *base_dir,
                              NMKeyfileHandlerFlags handler_flags,
                              NMKeyfileReadHandler  handler,
                              void                 *user_data,
                              GError              **error);

/**
 * NMKeyfileWriteHandler:
 * @connection: the #NMConnection that is currently written.
 * @keyfile: the #GKeyFile that is currently constructed.
 * @handler_type: the %NMKeyfileHandlerType that indicates which type
 *   the request is.
 * @handler_data: the #NMKeyfileHandlerData. What you can do with it
 *   depends on the @handler_type.
 * @user_data: the user-data argument to nm_keyfile_read().
 *
 * This is a hook to tweak the serialization.
 *
 * Handler for certain properties or events that are not entirely contained
 * within the keyfile or that might be serialized differently. The @type and
 * @handler_data arguments tell which kind of argument we have at hand.
 *
 * Currently only the type %NM_KEYFILE_HANDLER_TYPE_WRITE_CERT is supported.
 *
 * The callee may call nm_keyfile_handler_data_fail_with_error() to abort
 * the writing with error.
 *
 * Returns: the callee should return %TRUE if the event was handled. If the
 *   event was unhandled, a default action will be performed that depends on
 *   the @handler_type.
 *
 * Since: 1.30
 */
typedef gboolean (*NMKeyfileWriteHandler)(NMConnection         *connection,
                                          GKeyFile             *keyfile,
                                          NMKeyfileHandlerType  handler_type,
                                          NMKeyfileHandlerData *handler_data,
                                          void                 *user_data);

NM_AVAILABLE_IN_1_30
GKeyFile *nm_keyfile_write(NMConnection         *connection,
                           NMKeyfileHandlerFlags handler_flags,
                           NMKeyfileWriteHandler handler,
                           void                 *user_data,
                           GError              **error);

/*****************************************************************************/

NM_AVAILABLE_IN_1_30
void nm_keyfile_handler_data_fail_with_error(NMKeyfileHandlerData *handler_data, GError *src);

NM_AVAILABLE_IN_1_30
void nm_keyfile_handler_data_get_context(const NMKeyfileHandlerData *handler_data,
                                         const char                **out_kf_group_name,
                                         const char                **out_kf_key_name,
                                         NMSetting                 **out_cur_setting,
                                         const char                **out_cur_property_name);

/**
 * NMKeyfileWarnSeverity:
 * @NM_KEYFILE_WARN_SEVERITY_DEBUG: debug message
 * @NM_KEYFILE_WARN_SEVERITY_INFO: info message
 * @NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE: info message about a missing file
 * @NM_KEYFILE_WARN_SEVERITY_WARN: a warning message
 *
 * The severity level of %NM_KEYFILE_HANDLER_TYPE_WARN events.
 *
 * Since: 1.30
 */
typedef enum {
    NM_KEYFILE_WARN_SEVERITY_DEBUG             = 1000,
    NM_KEYFILE_WARN_SEVERITY_INFO              = 2000,
    NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE = 2901,
    NM_KEYFILE_WARN_SEVERITY_WARN              = 3000,
} NMKeyfileWarnSeverity;

NM_AVAILABLE_IN_1_30
void nm_keyfile_handler_data_warn_get(const NMKeyfileHandlerData *handler_data,
                                      const char                **out_message,
                                      NMKeyfileWarnSeverity      *out_severity);

G_END_DECLS

#endif /* __NM_KEYFILE_H__ */
