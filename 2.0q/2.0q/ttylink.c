/* Internet TTY "link" (keyboard chat) server
 * Copyright 1991 Phil Karn, KA9Q
 */
#include <time.h>
#include "global.h"
#include "mbuf.h"
#include "socket.h"
#include "telnet.h"
#include "session.h"
#include "proc.h"
#include "tty.h"
#include "mailbox.h"
#include "commands.h"

#ifdef IPV6
#include "ipv6.h"
#endif
  
#if !defined MAILBOX || defined TTYLINKSERVER || defined TTYCALL
  
extern int Attended;
static char Tnbanner[] = "Welcome to TTY-Link at %s\n";
extern char SysopBusy[];
extern int Numrows,Numcols;

/* A little wrapper for tcp connections to ttylink */
void
ttylink_tcp(int s,void *t,void *p) {
    ttylhandle(s,(void *)TELNET,p);
}

/* 30Dec2004, Replaces GOTO 'waitmsgtx' label */
static void waitmsgtx (int s)
{
   int index = 20;

	/* wait for I frame to be ACKed - K5JB/N5KNX */
	while (socklen (s,1) > 0 && index--)
		j2pause(500L);

	close_s(s);

	return;
}
  
/* This function handles all incoming "chat" sessions, be they TCP,
 * NET/ROM or AX.25
 */
void
ttylhandle(s,t,p)
int s;
void *t;
void *p;
{
    int type,index;
    struct session *sp;
    char addr[MAXSOCKSIZE];
    int len = MAXSOCKSIZE;
    struct telnet tn;
    extern char *Motd;
    time_t nowtime;

	long type_l = (long)t; /* 01Oct2009, Maiko, bridge for 64 bit warning */

#ifndef UNIX
    /* Check for enough mem for new screen - WG7J */
    if(availmem() < Memthresh+(2*Numrows*Numcols)){
        usputs(s,"System is overloaded; try again later\r\n");
		return (waitmsgtx (s));
    }
#endif
    j2getpeername(s,addr,&len);  /* we'll need this sooner or later */
    time(&nowtime);            /* current time */

    if(!Attended){
        usputs(s,SysopBusy);
#ifndef TTYLINK_NO_INTERRUPTIONS
        usprintf(Command->output,"\nWhile you were busy %s called on %s",
            psocket(addr),ctime(&nowtime));   /* adsb/n5knx */
#endif
        log(s,"TTYLINK while unattended");
		return (waitmsgtx (s));
    }

    type = (int)type_l;

    sockmode(s,SOCK_ASCII);
    sockowner(s,Curproc);   /* We own it now */
    log(s,"open %s",Sestypes[type]);
  
    /* Allocate a session descriptor */
#if defined(UNIX) || defined(TTYLINK_AUTOSWAP)
    if((sp = newsession(NULLCHAR,type,1)) == NULLSESSION){
#else
    if((sp = newsession(NULLCHAR,type,3)) == NULLSESSION){
#endif
        usputs(s,TooManySessions);
        /* Since we've added an ax.25 T2 timer, which will delay the flushing of any
           queued output, and we could lose some of this output when we close the
           user's socket [this sends an immediate disconnect and frees queued o/p]
           we'll try to force out anything queued now.  But we must be careful not
           to get stuck here forever (ie, circuit dropped out but we have infinite
           retries set). Main idea is to disconnect, but flush if we can! n5knx/k5jb
         */
		return (waitmsgtx (s));
    }
    index = (unsigned int) (sp - Sessions);
  
    /* Initialize a Telnet protocol descriptor */
    memset((char *)&tn,0,sizeof(tn));
    tn.session = sp;    /* Upward pointer */
    sp->cb.telnet = &tn;    /* Downward pointer */
    sp->s = s;
    sp->proc = Curproc;
  
#if defined(UNIX) || defined(TTYLINK_AUTOSWAP)
/* Send msg to new ttylink session's screen */
    tprintf("\007Incoming %s session %u from %s on %s",
      Sestypes[type],index,psocket(addr),ctime(&nowtime));
#else
/* Send msg to current session's screen */
    usprintf(Current->output,"\007Incoming %s session %u from %s on %s",
      Sestypes[type],index,psocket(addr),ctime(&nowtime));
    tputc('\007');   /* Cause session # to blink if StatusLines are shown */
#endif
  
    usprintf(s, Tnbanner, Hostname);
    if(Motd != NULLCHAR)
        usputs(s,Motd);
  
    tnrecv(&tn);
}
  
#endif /* !MAILBOX || TTYLINKSERVER || TTYCALL */
  
#ifdef TTYLINKSERVER
  
int
ttylstart(argc,argv,p)
int argc;
char *argv[];
void *p;
{
    int16 port;
  
#ifdef IPV6  

	int ret, doipv4, doipv6;

	doipv4 = doipv6 = 1;	/* default both ipv4 and ipv6 listeners */

	port = IPPORT_TTYLINK;

	/* 05Apr2025, Maiko (VE4KLM), should probably add ipv6 to tty service */

	if (argc > 1)
	{
		if (strstr (argv[1], "-4"))
			doipv6 = 0;

		else if (strstr (argv[1], "-6"))
			doipv4 = 0;

		/* 02Feb2024, Maiko, should have added this 'else' line */
		else port = atoi (argv[1]);

		/* this catches the port if -4 or -6 is specified */
		if (argc > 2)
			port = atoi (argv[2]);
	}

	if (!ipv6iface && doipv6)	/* don't bother if ipv6iface is disabled */
	{
		tprintf ("not running tty ipv6, since ipv6 iface is not defined\n");
		doipv6 = 0;
	}

	if (doipv6)
     ret = new_start_tcpv6 (port, "TTYLINK IPV6 Server", ttylink_tcp, 2048, 0);

	if (doipv4)
     ret = new_start_tcp (port, "TTYLINK Server", ttylink_tcp, 2048, 0);

	return ret;
#else
    if(argc < 2)
        port = IPPORT_TTYLINK;
    else
        port = atoi(argv[1]);
  
    return start_tcp(port,"TTYLINK Server",ttylink_tcp,2048);
#endif
}
  
/* Shut down Ttylink server */
int
ttyl0(argc,argv,p)
int argc;
char *argv[];
void *p;
{
    int16 port;
  
    if(argc < 2)
        port = IPPORT_TTYLINK;
    else
        port = atoi(argv[1]);
    return stop_tcp(port);
}
  
#endif /* TTYLINKSERVER */
  
