#ifndef _NETWORK_MANAGER_DIALUP_H
#define _NETWORK_MANAGER_DIALUP_H

typedef struct NMDialUpConfig
{
	char *name;	/* user-readable name, unique */
	void *data;	/* backend internal data */
} NMDialUpConfig;

#endif	/* _NETWORK_MANAGER_DIALUP_H */
