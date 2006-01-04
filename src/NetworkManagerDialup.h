#ifndef _NETWORK_MANAGER_DIALUP_H
#define _NETWORK_MANAGER_DIALUP_H

#define NM_DIALUP_TYPE_MODEM	1
#define NM_DIALUP_TYPE_ISDN	2

typedef struct NMDialUpConfig
{
	char			*name;	/* user-readable name, unique */
	void			*data;	/* backend internal data */
	unsigned int	type;	/* type: modem or ISDN, currently */
} NMDialUpConfig;

#endif	/* _NETWORK_MANAGER_DIALUP_H */
