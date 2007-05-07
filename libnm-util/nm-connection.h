#ifndef NM_CONNECTION_H
#define NM_CONNECTION_H

#include <glib.h>
#include "nm-setting.h"

typedef struct {
	GHashTable *settings;
} NMConnection;

NMConnection *nm_connection_new           (void);
NMConnection *nm_connection_new_from_hash (GHashTable *hash);
void          nm_connection_add_setting   (NMConnection *connection,
										   NMSetting    *setting);

NMSetting    *nm_connection_get_setting   (NMConnection *connection,
										   const char   *setting_name);

GHashTable   *nm_connection_to_hash       (NMConnection *connection);
void          nm_connection_destroy       (NMConnection *connection);


void nm_setting_parser_register   (const char *name,
								   NMSettingCreateFn creator);

void nm_setting_parser_unregister (const char *name);

#endif /* NM_CONNECTION_H */
