/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 *
 * dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include "pathnames.h"
#include "client.h"
#include "arp.h"

extern	int			SetDHCPDefaultRoutes;
extern	int			DebugFlag;
extern	int			SetDomainName;
extern	int			SetHostName;
extern	int			ReplResolvConf;
extern	int			ReplNISConf;
extern	int			ReplNTPConf;

int	resolv_renamed = 0;
int	yp_renamed = 0;
int	ntp_renamed = 0;  

/* Note: Legths initialised to negative to allow us to distinguish between "empty" and "not set" */
char InitialHostName[HOSTNAME_MAX_LEN];
int InitialHostName_len=-1;
char InitialDomainName[HOSTNAME_MAX_LEN];
int InitialDomainName_len=-1;

/*****************************************************************************/
char *cleanmetas(char *cstr) /* this is to clean single quotes out of DHCP strings */
{
	register char *c=cstr;
	do
		if ( *c == 39 )
			*c = ' ';
	while ( *c++ );
	return cstr;
}
/*****************************************************************************/
unsigned long getgenmask(unsigned long ip_in)	/* this is to guess genmask form network address */
{
	unsigned long	t,p=ntohl(ip_in);

	if ( IN_CLASSA(p) )
		t= ~IN_CLASSA_NET;
	else
	{
		if ( IN_CLASSB(p) )
			t= ~IN_CLASSB_NET;
		else
		{
			if ( IN_CLASSC(p) )
				t= ~IN_CLASSC_NET;
			else
				t=0;
		}
	}
	while ( t & p )
		t >>= 1;

	return htonl(~t);
}

/*****************************************************************************/
int setResolvConf(dhcp_interface *iface)
{
	FILE *f;

	resolv_renamed = 1 + rename (RESOLV_CONF, ""RESOLV_CONF".sv");
	f = fopen(RESOLV_CONF,"w");
	if ( f )
	{
		int i;
	#if 0
		if ( iface->dchp_options.len[nisDomainName] )
			fprintf(f,"domain %s\n",(char *)iface->dhcp_options.val[nisDomainName]);
		else
			if ( iface->dhcp_options.len[domainName] )
				fprintf(f,"domain %s\n",(char *)iface->dhcp_options.val[domainName]);
	#endif

		for (i = 0; i < iface->dhcp_options.len[dns]; i += 4)
		{
			fprintf(f,"nameserver %u.%u.%u.%u\n",
				((unsigned char *)iface->dhcp_options.val[dns])[i],
				((unsigned char *)iface->dhcp_options.val[dns])[i+1],
				((unsigned char *)iface->dhcp_options.val[dns])[i+2],
				((unsigned char *)iface->dhcp_options.val[dns])[i+3]);
		}

	#if 0
		if ( iface->dhcp_options.len[nisDomainName] + iface->dhcp_options.len[domainName] )
		{
			fprintf (f,"search");
			if ( iface->dhcp_options.len[nisDomainName] )
				fprintf (f," %s",(char *)iface->dhcp_options.val[nisDomainName]);
			if ( iface->dhcp_options.len[domainName] )
				fprintf (f," %s",(char *)iface->dhcp_options.val[domainName]);
			fprintf (f,"\n");
		}
	#else
		if ( iface->dhcp_options.len[domainName] )
			fprintf(f,"search %s\n",(char *)iface->dhcp_options.val[domainName]);
	#endif
		fclose(f);
	}
	else
		syslog(LOG_ERR,"dhcpConfig: fopen: %m\n");

	/* moved the next section of code from before to after we've created
	 * resolv.conf. See below for explanation. <poeml@suse.de>
	 * res_init() is normally called from within the first function of the
	 * resolver which is called. Here, we want resolv.conf to be
	 * reread. Otherwise, we won't be able to find out about our hostname,
	 * because the resolver won't notice the change in resolv.conf
	 */
	(void)res_init();
	return 0;
}

/*****************************************************************************/
int setNISConf(dhcp_interface *iface)
{
	FILE *f;

	yp_renamed = 1 + rename (NIS_CONF, ""NIS_CONF".sv");
	f = fopen (NIS_CONF,"w");
	if (f)
	{
		int i;
		char *domain=NULL;

		if ( iface->dhcp_options.len[nisDomainName] )
			domain=(char *)iface->dhcp_options.val[nisDomainName];
		else
			domain=(char *)iface->dhcp_options.val[domainName];

		for ( i = 0; i < iface->dhcp_options.len[nisServers]; i += 4)
		{
			fprintf( f,"domain %s server %u.%u.%u.%u\n", (domain ? domain : "localdomain"),
				((unsigned char *)iface->dhcp_options.val[nisServers])[i],
				((unsigned char *)iface->dhcp_options.val[nisServers])[i+1],
				((unsigned char *)iface->dhcp_options.val[nisServers])[i+2],
				((unsigned char *)iface->dhcp_options.val[nisServers])[i+3]);
		}
		if ( !iface->dhcp_options.len[nisServers] )
			fprintf (f, "domain %s broadcast\n", (domain ? domain : "localdomain"));
		fclose (f);
	}
	else
		syslog (LOG_ERR, "dhcpConfig: fopen: %m\n");

	return 0;
}

/*****************************************************************************/
int setNTPConf(dhcp_interface *iface)
{
	FILE *f;

	ntp_renamed = 1 + rename (NTP_CONF,""NTP_CONF".sv");
	f = fopen(NTP_CONF,"w");
	if ( f )
	{
		int net, mask;

		memcpy (&mask, iface->dhcp_options.val[subnetMask], 4);
		net = iface->ciaddr & mask;

		/* Note: Revise drift/log file names and stratum for local clock */
		fprintf(f,"restrict default noquery notrust nomodify\n");
		fprintf(f,"restrict 127.0.0.1\n");
		fprintf(f,"restrict %u.%u.%u.%u mask %u.%u.%u.%u\n",
			((unsigned char *)&net)[0], ((unsigned char *)&net)[1],
			((unsigned char *)&net)[2], ((unsigned char *)&net)[3],
			((unsigned char *)&mask)[0], ((unsigned char *)&mask)[1],
			((unsigned char *)&mask)[2], ((unsigned char *)&mask)[3]);

		if ( iface->dhcp_options.len[ntpServers] >= 4 )
		{
			int i;
			char addr[4*3+3*1+1];

			for ( i = 0; i < iface->dhcp_options.len[ntpServers]; i += 4)
			{
				snprintf(addr,sizeof(addr),"%u.%u.%u.%u",
					((unsigned char *)iface->dhcp_options.val[ntpServers])[i],
					((unsigned char *)iface->dhcp_options.val[ntpServers])[i+1],
					((unsigned char *)iface->dhcp_options.val[ntpServers])[i+2],
					((unsigned char *)iface->dhcp_options.val[ntpServers])[i+3]);
				fprintf(f,"restrict %s\nserver %s\n",addr,addr);
			}
		}
		else
		{	/* No servers found, use local clock */
			fprintf(f, "fudge 127.127.1.0 stratum 3\n");
			fprintf(f, "server 127.127.1.0\n");
		}
		fprintf(f, "driftfile /etc/ntp.drift\n");
		fprintf(f, "logfile /var/log/ntp.log\n");
		fclose(f);
	}
	else
		syslog(LOG_ERR,"dhcpConfig: fopen: %m\n");
	return 0;
}

/*****************************************************************************/
int setHostName (dhcp_interface *iface)
{
	struct hostent *hp = NULL;
	char *dname = NULL;
	int dname_len = 0;

	if ( !iface->dhcp_options.len[hostName] )
	{
		hp = gethostbyaddr ((char *)&iface->ciaddr, sizeof(iface->ciaddr), AF_INET);
		if ( hp )
		{
			dname = hp->h_name;
			while ( *dname > 32 )
		#if 0
			if ( *dname == '.' )
				break;
			else
		#endif
				dname++;

			dname_len = dname-hp->h_name;
			iface->dhcp_options.val[hostName] = (char *)malloc(dname_len+1);
			iface->dhcp_options.len[hostName] = dname_len;
			memcpy ((char *)iface->dhcp_options.val[hostName], hp->h_name, dname_len);
			((char *)iface->dhcp_options.val[hostName])[dname_len] = 0;
			iface->dhcp_options.num++;
		}
	}
	if ( InitialHostName_len < 0 && gethostname(InitialHostName, sizeof(InitialHostName)) == 0 )
	{
		InitialHostName_len = strlen(InitialHostName);
		if ( DebugFlag )
			fprintf (stdout, "dhcpcd: orig hostname = %s\n", InitialHostName);
	}
	if ( iface->dhcp_options.len[hostName] )
	{
		sethostname (iface->dhcp_options.val[hostName], iface->dhcp_options.len[hostName]);
		if ( DebugFlag )
			fprintf(stdout,"dhcpcd: your hostname = %s\n", (char *)iface->dhcp_options.val[hostName]);
	}

	return 0;
}

/*****************************************************************************/
int setDomainName (dhcp_interface *iface)
{
	struct hostent *hp = NULL;
	char *dname = NULL;
	int dname_len = 0;

	if ( InitialDomainName_len < 0 && getdomainname(InitialDomainName,sizeof(InitialDomainName)) == 0 )
	{
		InitialDomainName_len = strlen(InitialDomainName);
		if ( DebugFlag )
			fprintf(stdout,"dhcpcd: orig domainname = %s\n",InitialDomainName);
	}
#if 0
	if ( iface->dhcp_options.len[nisDomainName] )
	{
		setdomainname (iface->dhcp_options.val[nisDomainName], iface->dhcp_options.len[nisDomainName]);
		if ( DebugFlag )
			fprintf(stdout, "dhcpcd: your domainname = %s\n", (char *)iface->dhcp_options.val[nisDomainName]);
	}
	else
	{
#endif
		if ( ! iface->dhcp_options.len[domainName] )
		{
			hp = gethostbyaddr((char *)&iface->ciaddr, sizeof(iface->ciaddr), AF_INET);
			if ( hp )
			{
				dname=hp->h_name;
				while ( *dname > 32 )
				{
					if ( *dname == '.' )
					{
						dname++;
						break;
					}
					else
						dname++;
				}

				dname_len = strlen (dname);
				if ( dname_len )
				{
					iface->dhcp_options.val[domainName]=(char *)malloc(dname_len+1);
					iface->dhcp_options.len[domainName]=dname_len;
					memcpy((char *)iface->dhcp_options.val[domainName], dname,dname_len);
					((char *)iface->dhcp_options.val[domainName])[dname_len]=0;
					iface->dhcp_options.num++;
				}
			}
		}

		if ( iface->dhcp_options.len[domainName] )
		{
			setdomainname(iface->dhcp_options.val[domainName], iface->dhcp_options.len[domainName]);
			if ( DebugFlag )
				fprintf(stdout,"dhcpcd: your domainname = %s\n", (char *)iface->dhcp_options.val[domainName]);
		}
#if 0
	}
#endif
	return 0;
}

/*****************************************************************************/
int setDefaultRoute (dhcp_interface *iface, char *route_addr)
{
	struct	rtentry		rtent;
	struct	sockaddr_in	*p;

	memset (&rtent, 0, sizeof(struct rtentry));
	p				= (struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= 0;
	p				= (struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family		= AF_INET;
	memcpy (&p->sin_addr.s_addr, route_addr, 4);
	p				= (struct sockaddr_in *)&rtent.rt_genmask;
	p->sin_family		= AF_INET;
	p->sin_addr.s_addr	= 0;
	rtent.rt_dev		= iface->iface;
	rtent.rt_metric	= 1;
	rtent.rt_window	= iface->client_options->window;
	rtent.rt_flags		= RTF_UP | RTF_GATEWAY | ( rtent.rt_window ? RTF_WINDOW : 0);

	if ( ioctl(iface->sk,SIOCADDRT,&rtent) == -1 )
	{
		if ( errno == ENETUNREACH )    /* possibly gateway is over the bridge */
		{                            /* try adding a route to gateway first */
			struct	rtentry		rtent2;
			
			memset (&rtent2, 0, sizeof(struct rtentry));
			p				= (struct sockaddr_in *)&rtent2.rt_dst;
			p->sin_family		= AF_INET;
			p				= (struct sockaddr_in *)&rtent2.rt_gateway;
			p->sin_family		= AF_INET;
			p->sin_addr.s_addr	= 0;
			memcpy (&p->sin_addr.s_addr, route_addr, 4);
			p				= (struct sockaddr_in *)&rtent2.rt_genmask;
			p->sin_family		= AF_INET;
			p->sin_addr.s_addr	= 0xffffffff;
			rtent2.rt_dev		= iface->iface;
			rtent2.rt_metric	= 0;
			rtent2.rt_flags	= RTF_UP | RTF_HOST;

			if ( ioctl (iface->sk, SIOCADDRT, &rtent2) == 0 )
			{
				if ( ioctl (iface->sk, SIOCADDRT, &rtent) == -1 )
				{
					syslog(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %m\n");
					return -1;
				}
			}
		}
		else
		{
			syslog(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %m\n");
			return -1;
		}
	}
	return 0;
}
/*****************************************************************************/
int dhcpConfig(dhcp_interface *iface)
{
	int i;
	struct ifreq ifr;
	struct rtentry	rtent;
	struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);

	/* setting IP address */
	memset (&ifr, 0, sizeof(struct ifreq));
	memcpy (ifr.ifr_name, iface->iface, strlen (iface->iface));
	p->sin_family = AF_INET;
	p->sin_addr.s_addr = iface->ciaddr;
	if ( ioctl (iface->sk, SIOCSIFADDR, &ifr) == -1 )
	{
		syslog(LOG_ERR,"dhcpConfig: ioctl SIOCSIFADDR: %m\n");
		return -1;
	}

	/* setting netmask */
	memcpy(&p->sin_addr.s_addr,iface->dhcp_options.val[subnetMask],4);
	if ( ioctl(iface->sk,SIOCSIFNETMASK,&ifr) == -1 )
	{
		p->sin_addr.s_addr = 0xffffffff; /* try 255.255.255.255 */
		if ( ioctl(iface->sk,SIOCSIFNETMASK,&ifr) == -1 )
		{
			syslog(LOG_ERR,"dhcpConfig: ioctl SIOCSIFNETMASK: %m\n");
			return -1;
		}
	}

	/* setting broadcast address */
	memcpy (&p->sin_addr.s_addr, iface->dhcp_options.val[broadcastAddr], 4);
	if ( ioctl(iface->sk,SIOCSIFBRDADDR,&ifr) == -1 )
		syslog(LOG_ERR,"dhcpConfig: ioctl SIOCSIFBRDADDR: %m\n");

	/* setting static routes */
	for ( i = 0; i < iface->dhcp_options.len[staticRoute]; i += 8)
	{
		struct sockaddr_in *dstp;
		struct sockaddr_in *gwp;
		struct sockaddr_in *mskp;

		memset (&rtent,0,sizeof(struct rtentry));
		dstp				= (struct sockaddr_in *)&rtent.rt_dst;
		dstp->sin_family	= AF_INET;
		memcpy(&dstp->sin_addr.s_addr,((char *)iface->dhcp_options.val[staticRoute])+i,4);

		gwp				= (struct sockaddr_in *)&rtent.rt_gateway;
		gwp->sin_family	= AF_INET;
		memcpy(&gwp->sin_addr.s_addr,((char *)iface->dhcp_options.val[staticRoute])+i+4,4);

		mskp				= (struct sockaddr_in *)&rtent.rt_genmask;
		mskp->sin_family	= AF_INET;
		mskp->sin_addr.s_addr = getgenmask (dstp->sin_addr.s_addr);

		rtent.rt_flags	= RTF_UP|RTF_GATEWAY;
		if ( mskp->sin_addr.s_addr == 0xffffffff )
			rtent.rt_flags |= RTF_HOST;

		rtent.rt_dev = iface->iface;
		rtent.rt_metric = 1;
		if ( ioctl(iface->sk,SIOCADDRT,&rtent) )
			syslog(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %m\n");
	}

	if ( SetDHCPDefaultRoutes )
	{
		if ( iface->dhcp_options.len[routersOnSubnet] > 3 )
			for ( i = 0; i < iface->dhcp_options.len[routersOnSubnet]; i += 4)
				setDefaultRoute (iface, iface->dhcp_options.val[routersOnSubnet]);
	}
	else if ( iface->default_router.s_addr > 0 )
		setDefaultRoute (iface, (char *)&(iface->default_router.s_addr));

	arpInform(iface);

	if ( DebugFlag )
		fprintf(stdout,"dhcpcd: your IP address = %u.%u.%u.%u\n",
				((unsigned char *)&iface->ciaddr)[0],
				((unsigned char *)&iface->ciaddr)[1],
				((unsigned char *)&iface->ciaddr)[2],
				((unsigned char *)&iface->ciaddr)[3]);

	if ( ReplResolvConf )
		setResolvConf (iface);

	if ( ReplNISConf )
		setNISConf (iface);

	if ( ReplNTPConf )
		setNTPConf (iface);

	if ( SetHostName )
		setHostName (iface);

	if ( SetDomainName )
		setDomainName (iface);
#if 0
	if ( iface->ciaddr == previous ip address )
	{
		/* execute_on_change("up"); */
	}
	else
	{
		/* IP address has changed */
		/* execute_on_change("new"); */
	}
	if ( *(unsigned int *)iface->dhcp_options.val[dhcpIPaddrLeaseTime] == 0xffffffff )
	{
		syslog(LOG_INFO,"infinite IP address lease time. Exiting\n");
		/* exit(0); */
	}
#endif
	return 0;
}
/*****************************************************************************/
