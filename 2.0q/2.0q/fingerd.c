/* Internet Finger server */
#include "global.h"
#ifdef FINGERSERVER
#include "files.h"
#include "mbuf.h"
#include "socket.h"
#include "session.h"
#include "proc.h"
#include "smtp.h"
#include "dirutil.h"
#include "commands.h"
#include "mailbox.h"

#ifdef MAILFOR
#include "mailfor.h"
#endif

#ifdef IPV6
#include "ipv6.h"	/* 05Apr2025, Maiko (VE4KLM) */
#endif

static void fingerd __ARGS((int s,void *unused,void *p));
#if defined(SAMCALLB) || defined(QRZCALLB)
extern int cb_lookup __ARGS((int, char *, FILE *));
extern char *Callserver;
#elif defined(BUCKTSR) || defined(CALLSERVER) || defined(ICALL)
extern int cb_lookup __ARGS((int, char *));
extern char *Callserver;
#endif
static int dofhelp(int argc, char *argv[], void *p);
static int dombxinfo(int argc, char *argv[], void *p);

#ifdef  APRSD
extern int doaprsstat (int argc,char *argv[],void *p);
#endif

/* Start up finger service */
int
finstart(argc,argv,p)
int argc;
char *argv[];
void *p;
{
    int16 port;

#ifdef IPV6  

	int ret, doipv4, doipv6;

	doipv4 = doipv6 = 1;	/* default both ipv4 and ipv6 listeners */

        port = IPPORT_FINGER;

	/* 05Apr2025, Maiko (VE4KLM), should add ipv6 to finger service */

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
		tprintf ("not running finger ipv6, since ipv6 iface is not defined\n");
		doipv6 = 0;
	}

	if (doipv6)
     ret = new_start_tcpv6 (port, "FINGER IPV6 Server", fingerd, 1536, 0);

	if (doipv4)
     ret = new_start_tcp (port, "FINGER Server", fingerd, 1536, 0);

	return ret;
#else

    if(argc < 2)
        port = IPPORT_FINGER;
    else
        port = atoi(argv[1]);

    return start_tcp(port,"FINGER Server",fingerd,1536);

#endif

}

int
fin0(argc,argv,p)
int argc;
char *argv[];
void *p;
{
    int16 port;

    if(argc < 2)
        port = IPPORT_FINGER;
    else
        port = atoi(argv[1]);

    return stop_tcp(port);
}

#define FLINE 128

struct finfo {
    char *name;
    int (*func) __ARGS((int argc,char *argv[],void *p));
};

struct finfo Finfo[] = {
    { "help",     dofhelp },
    { "iheard",   doipheard },
#ifdef MAILBOX
    { "mbxinfo",  dombxinfo },
#if defined(MAILCMDS) && defined(HOLD_LOCAL_MSGS)
    { "mhold",    dombholdlocal },
#endif
    { "mstat",    dombmailstats },
    { "mpast",    dombpast },
    { "users",    dombstatus },
#ifdef USERLOG
    { "usersdat", dombuserinfo },
#endif
#endif /* MAILBOX */
#ifdef ALLCMD
    { "info",     doinfo },
#endif
#ifdef AX25
    { "ax25",     doaxstat },
    { "aheard",   doaxheard },
#ifdef BPQ
    { "bpqstat",  dobpq },  /* no args => do 'bpq stat' */
#endif
#ifdef MAILFOR
    { "mailfor",  dombmailfor },
#endif // MAILFOR
#endif // AX25
#ifdef NETROM
    { "netrom",   donrstatus },
#endif
#ifndef UNIX
    { "memstat",  dostat },
#endif
    { "socket",   dosock },
    { "tcpview",  doview },
#ifdef ASY
    { "asystat",  doasystat },
#endif
#ifdef FINGER_DIVULGE_IFCONFIG
/* This gives a lot of info you might not want to be known - WG7J */
    { "ifconfig", doifconfig },
#endif
#ifdef PACKET
#ifndef IPV6
/* 13Mar2023, Maiko (VE4KLM), not using this, just want ethernet support */
    { "pkstat",  dopkstat },
#endif
#endif
#ifdef RIP
    { "rip", doripstat },
#endif
#ifdef SCC
    { "scc", dosccstat },
#endif
#ifdef  APRSD
	{ "aprsstat",	doaprsstat },
#endif
    { NULL,	NULL }
};

static void
fingerd(s,unused,p)
int s;
void *unused;
void *p;
{
    char user[80];
    int ulen,found;
    FILE *fp;
    char *file;
    struct finfo *fi;
    int outsave;
    char line[FLINE+1];

    sockmode(s,SOCK_ASCII);
    sockowner(s,Curproc);
    recvline(s,user,80);
    rip(user);
    log(s,"open Finger: %.20s",user);
    ulen = strlen(user);

#ifdef CONVERS
    if(ulen && !strcmp(user,"conf"))
        ShowConfUsers(s,0,NULL);
#ifdef LINK
    else if( ulen && !strcmp(user,"links"))
        ShowConfLinks(s,1);
#endif
    else {
#endif
        for(fi=Finfo;fi->name;fi++)
            if(!stricmp(fi->name,user))
                break;
        if(ulen && fi->name) {
            outsave = Curproc->output;
            Curproc->output = s;
            fi->func(1,NULL,NULL);
            Curproc->output = outsave;
        } else {
            if(ulen == 0){
                fp = dir(Fdir,0);
                if(fp == NULLFILE)
                    usputs(s,"No finger information available\n");
                else
                    usputs(s,"Known users on this system:\n");
            } else {
#ifdef USERLOG
                char *newargv[2];

                outsave = Curproc->output;
                Curproc->output = s;
                newargv[1] = user;
                dombuserinfo(0,newargv,NULL);
                Curproc->output = outsave;
#endif

            /* Consult local callbook, but only if we have evidence we're
             * open for busines (to avoid notfound errs if no cdrom available).
             */
#if defined(SAMCALLB) || defined(QRZCALLB)
                if(Callserver != NULLCHAR)
                    cb_lookup (s, user, (FILE *) 0);
#elif defined(BUCKTSR) || defined(CALLSERVER) || defined(ICALL)
                if(Callserver != NULLCHAR)
                    cb_lookup (s, user);
#endif

            /* Check for attempted security violation (e.g., somebody
             * might be trying to finger "../ftpusers"!)
             */
                file = pathname(Fdir,user);
                if(strncmp(file,Fdir,strlen(Fdir)) != 0){
                    fp = NULLFILE;
                    usprintf(s,"Invalid user name %s\n",user);
                } else if((fp = fopen(file,READ_TEXT)) == NULLFILE) {
                /* Now search the finger database file for this user - WG7J */
                    found = 0;
                    if((fp = fopen(Fdbase,READ_TEXT)) != NULLFILE) {
                        while(fgets(line,FLINE,fp) != NULLCHAR)
                            if(!strncmp(line,user,(unsigned)ulen)) {
                                usputs(s,line);
                                found = 1;
                                break;
                            }
                        fclose(fp);
                        fp = NULLFILE;
                    }
                    if(!found)
                        usprintf(s,"No user info for %s\n",user);
                }
                free(file);
            }
            if(fp != NULLFILE){
                sendfile(fp,s,ASCII_TYPE,0,NULL);
                fclose(fp);
            }
        }
#ifdef CONVERS
    }
#endif
    if(ulen == 0 && Listusers != NULL)
        (*Listusers)(s);
    log(s,"close Finger");
    close_s(s);
}

static int
dofhelp(argc,argv,p)
int argc;
char *argv[];
void *p;
{
    struct finfo *fi;

    j2tputs("Available finger pseudo-users:\n");
    for(fi=Finfo;fi->name;fi++, argc++) {
       j2tputs(fi->name);
       if (argc % 8) tputc(' ');
       else tputc('\n');
    }
#ifdef CONVERS
#ifdef LINK
    j2tputs("\nconf links\n");
#else
    j2tputs("\nconf\n");
#endif /* LINK */
#else
    tputc('\n');
#endif
    return(0);
}

#ifdef MAILBOX
static int
dombxinfo(int argc, char *argv[], void *p)
{
    char buf[FILE_PATH_SIZE];
    FILE *fp;

    sprintf(buf,"%s/info.hlp",Helpdir);
    if((fp = fopen(buf,READ_TEXT)) != NULLFILE) {
        sendfile(fp,Curproc->output,ASCII_TYPE,0,NULL);
        fclose(fp);
    }
    return 0;
}
#endif
#endif /* FINGERSERVER */
