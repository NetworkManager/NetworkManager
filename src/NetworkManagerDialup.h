#ifndef _NETWORK_MANAGER_DIALUP_H
#define _NETWORK_MANAGER_DIALUP_H

#define NM_DIALUP_TYPE_MODEM	1
#define NM_DIALUP_TYPE_ISDN	2
#define NM_DIALUP_TYPE_DSL	3

typedef struct NMDialUpConfig
{
	char			*name;	/* user-readable name, unique */
	void			*data;	/* backend internal data */
	unsigned int	type;	/* type: modem, ISDN or DSL, currently */
} NMDialUpConfig;

#endif	/* _NETWORK_MANAGER_DIALUP_H */
