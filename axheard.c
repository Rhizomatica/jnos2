/* AX25 link callsign monitoring. Also contains beginnings of
 * an automatic link quality monitoring scheme (incomplete)
 *
 * Copyright 1991 Phil Karn, KA9Q
 */
#include <ctype.h>
#include "global.h"
#include <time.h>
#ifdef AX25
#include "mbuf.h"
#include "iface.h"
#include "ax25.h"
#include "ip.h"
#include "timer.h"

#include "netrom.h"	/* 18Nov2024, Maiko, for nrhash() function prototype */
  
#define iscallsign(c) ((isupper(c)) || (isdigit(c)) || (c ==' '))
int axheard_filter_flag = AXHEARD_PASS;

/* 16Mar2024, Maiko, Add axload parameter to all 3 xx_create() functions */

/* 23Nov2024, Maiko, Adding yet another arg to prototopes for new hgroup */
 
static struct lq *al_create __ARGS((struct iface *ifp,char *addr, int, int hgroup));

/* 28Nov2024, Maiko, Adding yet another arg to prototopes for new hgroup */
static struct ld *ad_lookup __ARGS((struct iface *ifp,char *addr,int sort, int hgroup));
static struct ld *ad_create __ARGS((struct iface *ifp,char *addr, int, int hgroup));
struct lq *Lq=NULLLQ;
struct ld *Ld=NULLLD;

/*
 * 05Apr2021, Maiko (VE4KLM), interested in listing digipeated (via, not direct) calls
 * 15Apr2021, Maiko (VE4KLM), added digipeater address to lookup, we need to be able to
 * see if a callsign used multiple digipeaters ... bit of an oops ...
 */
/* 28Nov2024, Maiko, Adding yet another arg to prototopes for new hgroup */
static struct lv *av_lookup __ARGS((struct iface *ifp,char *addr, char *digiaddr, int sort, int hgroup));
static struct lv *av_create __ARGS((struct iface *ifp,char *addr, char *digiaddr, int axload, int hgroup));	/* 06Apr2021, Maiko, extra param now */
struct lv *Lv=NULLLV;

/*
 * 06Apr2021, Maiko (VE4KLM), attempts to reduce duplicate code
 *
 *  1) simplistic callsign validation
 */

static int checkcall (char *addr)
{
	register unsigned char c;

	register int i = 0;

	while(i < AXALEN-1){
		c = *(addr+i);
		c >>= 1;
		if(!iscallsign(c))
			return 0;
		i++;
	}

	return 1;
}
  
#ifdef  notdef
/* Send link quality reports to interface */
void
genrpt(ifp)
struct iface *ifp;
{
    struct mbuf *bp;
    register char *cp;
    int i;
    struct lq *lp;
    int maxentries,nentries;
  
    maxentries = (Paclen - LQHDR) / LQENTRY;
    if((bp = alloc_mbuf(Paclen)) == NULLBUF)
        return;
    cp = bp->data;
    nentries = 0;
  
    /* Build and emit header */
    cp = putlqhdr(cp,LINKVERS,Ip_addr);
  
    /* First entry is for ourselves. Since we're examining the Axsent
     * variable before we've sent this frame, add one to it so it'll
     * match the receiver's count after he gets this frame.
     */
    cp = putlqentry(cp,ifp->hwaddr,Axsent+1);
    nentries++;
  
    /* Now add entries from table */
    for(lp = lq;lp != NULLLQ;lp = lp->next){
        cp = putlqentry(cp,&lp->addr,lp->currxcnt);
        if(++nentries >= MAXENTRIES){
            /* Flush */
            bp->cnt = nentries*LQENTRY + LQHDR;
            ax_output(ifp,Ax25multi[0],ifp->hwaddr,PID_LQ,bp);
            if((bp = alloc_mbuf(Paclen)) == NULLBUF)
                return;
            cp = bp->data;
        }
    }
    if(nentries > 0){
        bp->cnt = nentries*LQENTRY + LQHDR;
        ax_output(ifp,Ax25multi[0],ifp->hwaddr,LQPID,bp);
    } else {
        free_p(bp);
    }
}
  
/* Pull the header off a link quality packet */
void
getlqhdr(hp,bpp)
struct lqhdr *hp;
struct mbuf **bpp;
{
    hp->version = pull16(bpp);
    hp->ip_addr = pull32(bpp);
}
  
/* Put a header on a link quality packet.
 * Return pointer to buffer immediately following header
 */
char *
putlqhdr(cp,version,ip_addr)
register char *cp;
int16 version;
int32 ip_addr;
{
    cp = put16(cp,version);
    return put32(cp,ip_addr);
}
  
/* Pull an entry off a link quality packet */
void
getlqentry(ep,bpp)
struct lqentry *ep;
struct mbuf **bpp;
{
    pullup(bpp,ep->addr,AXALEN);
    ep->count = pull32(bpp);
}
  
/* Put an entry on a link quality packet
 * Return pointer to buffer immediately following header
 */
char *
putlqentry(cp,addr,count)
char *cp;
char *addr;
int32 count;
{
    memcpy(cp,addr,AXALEN);
    cp += AXALEN;
    return put32(cp,count);
}
#endif
  
/* Log the source address of an incoming packet */
void
logsrc(ifp,addr)
struct iface *ifp;
char *addr;
{
    register struct lq *lp;
  
	if(axheard_filter_flag & AXHEARD_NOSRC || !(ifp->flags & LOG_AXHEARD))
		return;

	/* 06Apr2021, Maiko, new function to cut code duplication */
	if (!checkcall (addr))
		return;
 
	/* 23Nov2024, Maiko, al_lookup () and al_create() both have an extra
	 * new argument for heard group, for logsrc, set to 0 for default ifc
	 */ 
    if((lp = al_lookup(ifp,addr,1,0)) == NULLLQ)
        if((lp = al_create(ifp,addr,0,0)) == NULLLQ)
            return;
    lp->currxcnt++;
    lp->time = secclock();
}
/* Log the destination address of an incoming packet */
void
logdest(ifp,addr)
struct iface *ifp;
char *addr;
{
    register struct ld *lp;
  
	if(axheard_filter_flag & AXHEARD_NODST || !(ifp->flags & LOG_AXHEARD))
		return;

	/* 06Apr2021, Maiko, new function to cut code duplication */
	if (!checkcall (addr))
		return;
  
  /* 28Nov2024, Maiko (VE4KLM), multiple heard list support, new arg */
    if((lp = ad_lookup(ifp,addr,1,0)) == NULLLD)
        if((lp = ad_create(ifp,addr,0,0)) == NULLLD)
            return;
    lp->currxcnt++;
    lp->time = secclock();
}

/*
 * 05Apr2021, Maiko (VE4KLM), Log the source address of an digipeated incoming packet
 */
void logDigisrc (struct iface *ifp, char *addr, char *digiaddr)
{
    register struct lv *lv;

	if (axheard_filter_flag & AXHEARD_NOSRC || !(ifp->flags & LOG_AXHEARD))
		return;

	/* 06Apr2021, Maiko, new function to cut code duplication */
	if (!checkcall (addr))
		return;

	/* 06Apr2021, Maiko, should probably check the digi call as well */
	if (!checkcall (digiaddr))
		return;

    /*
     * 05Apr2021, Maiko (VE4KLM) digiaddr is not used yet, this is just playing around,
     * okay modified lv structure 06Apr2021, now using digicall so we can display it.
     *
     * 15Apr2021, Maiko (observation) - if a call exists already, and we come in via
     * another digipeater we should create another new entry, right now it doesn't,
     * it does update the count and time but from the original digipeater entry :|
     *  (meaning we need a digi parameter for av_lookup() function - done)
     *
     * Interesting this 'sort' flag, hmmm, my sort function is 'not working' ?
     *
     */

  /* 28Nov2024, Maiko (VE4KLM), multiple heard list support, new arg */

    if((lv = av_lookup(ifp,addr,digiaddr,1, 0)) == NULLLV)
        if((lv = av_create(ifp,addr, digiaddr, 0, 0)) == NULLLV)
            return;
    lv->currxcnt++;
    lv->time = secclock();
}

/* Look up an entry in the source data base */
struct lq *
al_lookup(ifp,addr,sort, hgroup)
struct iface *ifp;
char *addr;
int sort;
int hgroup;	/* 23Nov2024, Maiko, support for multiple heard lists */
{
    register struct lq *lp;
    struct lq *lplast = NULLLQ;

	/* 23Nov2024, Maiko, Doing this REALLY simplies conditional further down */
	if (!hgroup)
		hgroup = ifp->ax25->hgroup;
  
    for(lp = Lq;lp != NULLLQ;lplast = lp,lp = lp->next) {
		/* 06Nov2024, Maiko (VE4KLM), multiple heard lists now possible */
        if((lp->iface == ifp) && (lp->hgroup == hgroup /* ifp->ax25->hgroup */) && addreq(lp->addr,addr)){
            if(sort && lplast != NULLLQ){
                /* Move entry to top of list */
                lplast->next = lp->next;
                lp->next = Lq;
                Lq = lp;
            }
            return lp;
        }
    }
    return NULLLQ;
}
  
extern int Maxax25heard;
  
/* Create a new entry in the source database */
/* If there are too many entries, override the oldest one - WG7J */
static struct lq *
al_create(ifp,addr,axload, hgroup)
struct iface *ifp;
char *addr;
int axload;	/* 16Mar2024, Maiko, new argument for loading heard list */
int hgroup;	/* 23Nov2024, Maiko, support for multiple heard lists */
{
    extern int numal;        /* in ax25cmd.c - K5JB */
    register struct lq *lp;
    struct lq *lplast = NULLLQ;

	static struct lq *prevLq = NULLLQ;	/* 16Mar2024, Maiko (VE4KLM) */

	/* 23Nov2024, Maiko, Doing this REALLY simplies conditional further down */
	if (!hgroup)
		hgroup = ifp->ax25->hgroup;
  
    if(Maxax25heard && numal == Maxax25heard) {
        /* find and use last one in list */
	/* 25Apr2023, Maiko, If lp is NULL, this will blow up on the lp->next */
        for(lp = Lq;lp && (lp->next != NULLLQ);lplast = lp,lp = lp->next);
        /* delete entry from end */
        if(lplast)
            lplast->next = NULLLQ;
        else    /* Only one entry, and maxax25heard = 1 ! */
            Lq = NULLLQ;
        lp->currxcnt = 0;
    } else {    /* create a new entry */
        numal++;
        lp = (struct lq *)callocw(1,sizeof(struct lq));
    }
    memcpy(lp->addr,addr,AXALEN);
    lp->iface = ifp;

  /* 06Nov2024, Maiko (VE4KLM), set 'current heard list' group */
    lp->hgroup = hgroup; /* ifp->ax25->hgroup; */

	/*
	 * 16Mar2024, Maiko (VE4KLM), getting rid of the hsort functions,
	 * since they're not needed. Just change the way the link lists
 	 * are linked up. See my comments in aprsstat.c in the recently
	 * new aq_create() function.
	 */
	if (axload)
	{
		lp->next = NULLLQ;	/* always for load */

		if (Lq == NULL)
			Lq = prevLq = lp;

		else	/* I think this will work, had to draw it out on paper :) */
		{
			prevLq->next = lp;
			prevLq = lp;
		}
	}
	else	/* default operation is to insert at the very top of link list */
	{
    	lp->next = Lq;
    	Lq = lp;
 	}
 
    return lp;
}
  
/* Look up an entry in the destination database */
static struct ld *
ad_lookup(ifp,addr,sort, hgroup)
struct iface *ifp;
char *addr;
int sort;
int hgroup;	/* 28Nov2024, Maiko, support for multiple heard lists */
{
    register struct ld *lp;
    struct ld *lplast = NULLLD;
  
    for(lp = Ld;lp != NULLLD;lplast = lp,lp = lp->next){

	/* 28Nov2024, Maiko, Doing this REALLY simplies conditional further down */
	if (!hgroup)
		hgroup = ifp->ax25->hgroup;

		/* 06Nov2024, Maiko (VE4KLM), multiple heard lists now possible */
        if((lp->iface == ifp) && (lp->hgroup == hgroup /* ifp->ax25->hgroup */) && addreq(lp->addr,addr)){
            if(sort && lplast != NULLLD){
                /* Move entry to top of list */
                lplast->next = lp->next;
                lp->next = Ld;
                Ld = lp;
            }
            return lp;
        }
    }
    return NULLLD;
}
/* Create a new entry in the destination database */
static struct ld *
ad_create(ifp, addr, axload, hgroup)
struct iface *ifp;
char *addr;
int axload;	/* 16Mar2024, Maiko, new argument for loading heard list */
int hgroup;	/* 28Nov2024, Maiko, support for multiple heard lists */
{
    extern int numad;    /* In ax25cmd.c - K5JB */
    register struct ld *lp;
    struct ld *lplast = NULLLD;

	static struct ld *prevLd = NULLLD;	/* 16Mar2024, Maiko (VE4KLM) */

	/* 28Nov2024, Maiko, Doing this REALLY simplies conditional further down */
	if (!hgroup)
		hgroup = ifp->ax25->hgroup;
  
    if(Maxax25heard && numad == Maxax25heard) { /* find and use last one in list */
	/* 25Apr2023, Maiko, If lp is NULL, this will blow up on the lp->next */
        for(lp = Ld;lp && (lp->next != NULLLD);lplast = lp,lp = lp->next);
        /* delete entry from end */
        if(lplast)
            lplast->next = NULLLD;
        else
            Ld = NULLLD;
        lp->currxcnt = 0;
    } else {    /* create a new entry */
        numad++;
        lp = (struct ld *)callocw(1,sizeof(struct ld));
    }
    memcpy(lp->addr,addr,AXALEN);
    lp->iface = ifp;

  /* 06Nov2024, Maiko (VE4KLM), set 'current heard list' group */
    lp->hgroup = /* ifp->ax25->hgroup */ hgroup;

	/*
	 * 16Mar2024, Maiko (VE4KLM), getting rid of the hsort functions,
	 * since they're not needed. Just change the way the link lists
 	 * are linked up. See my comments in aprsstat.c in the recently
	 * new aq_create() function.
	 */
	if (axload)
	{
		lp->next = NULLLD;	/* always for load */

		if (Ld == NULL)
			Ld = prevLd = lp;

		else	/* I think this will work, had to draw it out on paper :) */
		{
			prevLd->next = lp;
			prevLd = lp;
		}
	}
	else	/* default operation is to insert at the very top of link list */
	{
    	lp->next = Ld;
    	Ld = lp;
	}
  
    return lp;
}

/*
 * 05Apr2021, Maiko (VE4KLM), Look up an entry in the digipeated source database
 * 15Apr2021, Maiko, should be using callsign / digipeater combo to do lookup !
 * 28Nov2024, Maiko, adding hgroup for multiple heard list support
 */
static struct lv * av_lookup (struct iface *ifp, char *addr, char *digiaddr, int sort, int hgroup)
{
    register struct lv *lv;
    struct lv *lvlast = NULLLV;
  
	/* 28Nov2024, Maiko, Doing this REALLY simplies conditional further down */
	if (!hgroup)
		hgroup = ifp->ax25->hgroup;

    for(lv = Lv;lv != NULLLV;lvlast = lv,lv = lv->next){
		/* 06Nov2024, Maiko (VE4KLM), multiple heard lists now possible */
        if((lv->iface == ifp) && (lv->hgroup == /* ifp->ax25->hgroup */ hgroup) && addreq(lv->addr,addr) && addreq(lv->digi,digiaddr)){
            if(sort && lvlast != NULLLV){
                /* Move entry to top of list */
                lvlast->next = lv->next;
                lv->next = Lv;
                Lv = lv;
            }
            return lv;
        }
    }
    return NULLLV;
}

/*
 * 05Apr2021, Maiko (VE4KLM), Create a new entry in digipeated source database
 * 16Mar2024, Maiko, new argument axload for loading heard list
 * 28Nov2024, Maiko, adding hgroup for multiple heard list support
 */
static struct lv * av_create (struct iface *ifp, char *addr, char *digiaddr, int axload, int hgroup)
{
	/* 25Apr2023, Maiko, Oops, we should have a separate numav for this, wonder
	 * if this is the reason why GUS is getting his crashes, so NEW 'numav' !
	 */
    extern int numav;    /* In ax25cmd.c - K5JB */
    register struct lv *lv;
    struct lv *lvlast = NULLLV;

	static struct lv *prevLv = NULLLV;	/* 16Mar2024, Maiko (VE4KLM) */

	/* 28Nov2024, Maiko, Doing this REALLY simplies conditional further down */
	if (!hgroup)
		hgroup = ifp->ax25->hgroup;
  
    if(Maxax25heard && numav == Maxax25heard) { /* find and use last one in list */
	/* 25Apr2023, Maiko, If lv is NULL, this will blow up on the lv->next */
        for(lv = Lv; lv && (lv->next != NULLLV);lvlast = lv,lv = lv->next);
        /* delete entry from end */
        if(lvlast)
            lvlast->next = NULLLV;
        else
            Lv = NULLLV;
        lv->currxcnt = 0;
    } else {    /* create a new entry */
        numav++;
        lv = (struct lv *)callocw(1,sizeof(struct lv));
    }
    memcpy(lv->addr,addr,AXALEN);
    memcpy(lv->digi,digiaddr,AXALEN);	/* 06Apr2021, Maiko */
    lv->iface = ifp;

  /* 06Nov2024, Maiko (VE4KLM), set 'current heard list' group */
    lv->hgroup = /* ifp->ax25->hgroup */ hgroup;

	/*
	 * 16Mar2024, Maiko (VE4KLM), getting rid of the hsort functions,
	 * since they're not needed. Just change the way the link lists
 	 * are linked up. See my comments in aprsstat.c in the recently
	 * new aq_create() function.
	 */
	if (axload)
	{
		lv->next = NULLLV;	/* always for load */

		if (Lv == NULL)
			Lv = prevLv = lv;

		else	/* I think this will work, had to draw it out on paper :) */
		{
			prevLv->next = lv;
			prevLv = lv;
		}
	}
	else	/* default operation is to insert at the very top of link list */
	{
    	lv->next = Lv;
    	Lv = lv;
	}
  
    return lv;
}

#ifdef	BACKUP_AXHEARD

/*
 * 21Jan2020, Maiko (VE4KLM), New functions to save and restore axheard lists
 *  (called from ax25cmd.c - but in here because I need al_create() function)
 *
 * Requested by Martijn (PD2NLX) in the Netherlands :)
 *
 * 25Jan2020, Maiko, completed save function
 *
 * 27Jan2020, Maiko, completed load function
 * 
 * 28Jan2020, Maiko, merging doax commands in ax25cmd.c, so we
 * no longer need to have full argument style function calls.
 *
int doaxhsave (int argc, char **argv, void *p)
int doaxhload (int argc, char **argv, void *p)
 *
 * 12Apr2021, Maiko (VE4KLM), besides giving the sysop an option to
 * now specify the file to save/load, I need to fix the fact loaded
 * heard list is ordered backwards, so what was the earliest heard,
 * is actually loaded as the most recent heard, time stamps actually
 * correct I think, it's more the order they appear messed up ?
 *
 * Okay, I see it now, al_create() puts new entries at the root (top)
 * of the link list, almost like if you first sorted the AxHeardFile
 * by time last heard, then run the load, would solve the problem.
 *
 * 13Apr2021, Or better, just load the file, then do a sort of some
 * type on the link list afterwards, so only oddity remaining might
 * be a 'mild' time gap between saving and loading, not sure ...
 */

static char *def_axheard_backup_file = "AxHeardFile";	/* 12Apr2021, and now providing default option */

/* 12Apr2021, Maiko (VE4KLM), sysop can now specify a filename, used to be void */
int doaxhsave (char *filename)
{
	char tmp[AXBUF];
	struct lq *lp;
	struct ld *lp2;
	struct lv *lp3;
	time_t now;
	FILE *fp;

#ifdef	APRSD	/* 29Jun2024, Maiko, some people don't want APRS stuff */
	extern int axsaveaprshrd (FILE*);	/* 23Jun2024, Maiko */	
#endif

	if (filename == NULL)
		filename = def_axheard_backup_file;

	if ((fp = fopen (filename, "w+")) == NULLFILE)
	{
		tprintf ("failed to open [%s]\n", filename);
		log (-1, "failed to open [%s]", filename);
		return 1;
	}

	/*
	 * 27Jan2020, Maiko, Forgot to save a timestamp of when this file gets
	 * created, we will need this to make sure the time stamps on a future
	 * load are 'accurate' - timestamps are based on the JNOS 'Starttime',
	 * not the epoc or whatever they call it, going back to the 1970 era.
	 *
	 * 15Apr2021, Okay, I think I need to also save the time JNOS has been
	 * running for, since the time stamps are based on since JNOS started.
	 */

	time (&now); fprintf (fp, "%ld %d\n", (long)now, secclock());
  
	for (lp = Lq; lp != NULLLQ; lp = lp->next)
	{
		/* 27Jan2025, Maiko (VE4KLM), Add hgroup hash (save heard group now) */
		fprintf (fp, "%s %s %d %d %d\n",
			lp->iface->name, pax25 (tmp, lp->addr),
				lp->time, lp->currxcnt, lp->hgroup);
	}

	/*
	 * 21May2021, Maiko (VE4KLM), added destinations and digipeated stations heard.
	 *  (it is important to put a separator between the different heard lists)
	 */

	fprintf (fp, "---\n");
	for (lp2 = Ld; lp2 != NULLLD; lp2 = lp2->next)
	{
		/* 27Jan2025, Maiko (VE4KLM), Add hgroup hash (save heard group now) */
		fprintf (fp, "%s %s %d %d %d\n",
			lp2->iface->name, pax25 (tmp, lp2->addr),
				lp2->time, lp2->currxcnt, lp2->hgroup);
	}

	fprintf (fp, "---\n");
	for (lp3 = Lv; lp3 != NULLLV; lp3 = lp3->next)
	{
	  if( lp3->iface == NULLIF )
	    continue;

		fprintf (fp, "%s %s ", lp3->iface->name, pax25 (tmp, lp3->addr));

		/* 27Jan2025, Maiko (VE4KLM), Add hgroup hash (save heard group now) */
 		fprintf (fp, "%s %d %d %d\n",
			pax25 (tmp, lp3->digi), lp3->time,
				 lp3->currxcnt, lp3->hgroup);
	}

#ifdef	APRSD	/* 29Jun2024, Maiko, some people don't want APRS stuff */
	/* 14Mar2024, Maiko (VE4KLM), Adding saving of APRS heard list */
	axsaveaprshrd (fp);
#endif

	fclose (fp);

	return 0;
}

/* 12Apr2021, Maiko (VE4KLM), sysop can now specify a filename */
int doaxhload (char *filename)
{
	char iobuffer[80];
	char ifacename[30], callsign[12];
	char thecall[AXALEN];
	int32 axetime, count;
	struct iface *ifp;
	struct lq *lp;
	long atatsave;	/* 17Apr2021, Maiko - actual time at file save */
	time_t now;
	int32 rtatsave;	/* 15Apr2021, Maiko - runtime at file save */
	FILE *fp;

	/* 21May2021, Maiko (VE4KLM), added these for remaining 2 heard lists */
	char thedigi[AXALEN], digipeater[12];
	struct ld *lp2;
	struct lv *lp3;

	/* 18Nov2024, Maiko, multiple heard list requires additional hgroup entry */
	int hgroup, retval;

#ifdef	APRSD	/* 29Jun2024, Maiko, some people don't want APRS stuff */
	extern int axloadaprshrd (FILE*, int);	/* 23Jun2024, Maiko */
#endif

	if (filename == NULL)
		filename = def_axheard_backup_file;

	if ((fp = fopen (filename, "r")) == NULLFILE)
	{
		tprintf ("failed to open [%s]\n", filename);
		log (-1, "failed to open [%s]", filename);
		return 1;
	}

	/*
	 * 27Jan2020, Maiko, Make sure to read the timestamp at the
	 * top or else we get gaps in the time stamps.
	 */
	if (fgets (iobuffer, sizeof(iobuffer) - 2, fp) == NULLCHAR)
	{
		tprintf ("failed to read timestamp from [%s]\n", filename);
		log (-1, "failed to read timestamp from [%s]", filename);
		fclose (fp);
		return 1;
	}	

	time (&now);

	/*
	 * 15Apr2021, Maiko, We need to know the 'secclock()' of JNOS when
	 * the heard list was saved, so we can compensate what is displayed
	 * for the loaded values - prior to this, values displayed were not
	 * reasonable (way out) and even negative at times - I think it is
	 * now accurate - did a few quick tests on my /tmp/tmp/rte area.
	 *
	 * 16Apr2021, Good grief, still something not right, finally though
	 * seems I am quite close, this has been tough to figure out for some
	 * odd reason, my mindset is not good with these things. Just have to
	 * figure out the sort now ...
	 *
	 * Terrible of me though - more then a year to get to fixing it ?
	 *
	 * 21Apr2021, Maiko (VE4KLM), Be carefull here, do NOT allow loading
	 * of the heard file from earlier version of JNOS - this can cause a
	 * loop and/or a crash - thanks Ron (VE3CGR) for catching this !
	 */
	if (sscanf (iobuffer, "%ld %d", &atatsave, &rtatsave) != 2)
	{
		tprintf ("unable to use older version heard file [%s]\n", filename);
		log (-1, "unable to use older version heard file [%s]", filename);
		fclose (fp);
		return 1;
	}

	while (fgets (iobuffer, sizeof(iobuffer) - 2, fp) != NULLCHAR)
	{
		/* 21May2021, Maiko, Check for separator, break out for next list */
		if (strstr (iobuffer, "---"))
			break;
	/*
	 * 18Nov2024, Maiko, multiple heard list requires tacking new
	 * hgroup to the end of the line, no longer trying to deal with
	 * the old versions of AxHeardFile, there's no point really !
	 */
		axetime = 0; count = 0; hgroup = 0;

		retval = sscanf (iobuffer, "%s %s %d %d %d", ifacename, callsign,
			&axetime, &count, &hgroup);

		if ((ifp = if_lookup (ifacename)) == NULLIF)
		{
			log (-1, "unable to lookup iface [%s]", ifacename);
			continue;
		}

		/*
		 * The heard group description to hash mapping will now be initialized
		 * elsewhere in the code, not going to try adding descriptions on the
		 * fly as in my previous attempts at coding this (from 23Nov2024) !
		 */

		if (setcall (thecall, callsign) == -1)
			log (-1, "unable to set call [%s]", callsign);

		/* if the call is already there, then don't overwrite it of course */
	/* 23Nov2024, Maiko, al_lookup () has extra new argument for heard group */ 
   		else if ((lp = al_lookup (ifp, thecall, 1, hgroup)) == NULLLQ)
		{
	/* 23Nov2024, Maiko, al_create () has extra new argument for heard group */ 
			if ((lp = al_create (ifp, thecall, 1, hgroup)) == NULLLQ)
				log (-1, "unable to create Lq entry");
			else
			{
				/* 18Nov2024, Maiko, Set the heard group if there is one */
				lp->hgroup = hgroup;

				lp->currxcnt = count;
		/*
		 * 27Jan2020, Maiko, This won't be accurate, need to find way to offset
		 * the last saved time of axheard file with 'now', so that is why I've
		 * got time_gap value (called atatsave now) added to each time read in.
		 *
		 * NOW - what will be interesting is that since JNOS logs these times
		 * based on secclock(), since JNOS started, if the corrected times are
		 * actually greater then the time JNOS has been running, we run into a
		 * problem where axheard can show negative time values, and they will
		 * actually run the wrong way each time we do a 'ax25 heard', so this
		 * requires some additional code work in ax25cmd.c, working nicely.
		 *
	 	 * 17Apr2021, Maiko (VE4KLM), probably one of the most frustrating
		 * things to deal with, I spent an entire week off and on trying to
		 * wrap my head around how to preserve last heard between save and
		 * load, I still don't quite get it, but I believe I got it now.
		 */
				lp->time = (int32)(now - atatsave) + rtatsave - axetime + secclock();

			/*
			 * this part drove me mental, doing this also screwed up the
		 	 * new sort function, so easiest way to fix is use abs() in
		 	 * the sort routine, why am I making this so difficult ?
		 	 */
				lp->time *= -1;
			}
		}
	}

	/*
	 * 21May2021, Maiko (VE4KLM), Load the Destinations Heard List
	 *
	 * NOTE : The separator --- between the different heard lists
	 *        is very important, allows us to stick to one file.
	 */

	while (fgets (iobuffer, sizeof(iobuffer) - 2, fp) != NULLCHAR)
	{
		/* Check for separator, break out for the last list */
		if (strstr (iobuffer, "---"))
			break;

		hgroup = 0;	/* 29Nov2024, oops, forgot to do this */

		/*
	 	 * 27Jan2025, Maiko, Not going to try and use heard group description
		 * anymore in the AxHeardFile, just use an integer hash value, heard
		 * group description to hash mapping will be init'd elsewhere in the
		 * code, much simpler this way.
		 */

		retval = sscanf (iobuffer, "%s %s %d %d %d", ifacename, callsign,
			&axetime, &count, &hgroup);

		if ((ifp = if_lookup (ifacename)) == NULLIF)
		{
			log (-1, "unable to lookup iface [%s]", ifacename);
			continue;
		}

		if (setcall (thecall, callsign) == -1)
			log (-1, "unable to set call [%s]", callsign);

		/* if the call is already there, then don't overwrite it of course */
		/* 28Nov2024, Maiko, note new hgroup argument passed */
   		else if ((lp2 = ad_lookup (ifp, thecall, 1, hgroup)) == NULLLD)
		{
			/* 28Nov2024, Maiko, note new hgroup argument passed */
			if ((lp2 = ad_create (ifp, thecall, 1, hgroup)) == NULLLD)
				log (-1, "unable to create Ld entry");
			else
			{
				/* 28Nov2024, Maiko, Set the heard group if there is one */
				lp2->hgroup = hgroup;

				lp2->currxcnt = count;
				lp2->time = (int32)(now - atatsave) + rtatsave - axetime + secclock();
				lp2->time *= -1;
			}
		}
	}

	/*
	 * 21May2021, Maiko (VE4KLM), Load the Digipeated Stations Heard List
	 *
	 * NOTE : The separator --- between the different heard lists
	 *        is very important, allows us to stick to one file.
 	 */

	while (fgets (iobuffer, sizeof(iobuffer) - 2, fp) != NULLCHAR)
	{
		/*
		 * 19Mar2024, Maiko, We now have to check for a separator,
		 * since I'm adding saving and loading of APRS heard list.
		 */
		if (strstr (iobuffer, "---"))
			break;

		hgroup = 0;	/* 29Nov2024, oops, forgot to do this */

		retval = sscanf (iobuffer, "%s %s %s %d %d %d",
			ifacename, callsign, digipeater, &axetime, &count, &hgroup);

		if ((ifp = if_lookup (ifacename)) == NULLIF)
		{
			log (-1, "unable to lookup iface [%s]", ifacename);
			continue;
		}

		if (setcall (thecall, callsign) == -1)
			log (-1, "unable to set call [%s]", callsign);

		else if (setcall (thedigi, digipeater) == -1)
			log (-1, "unable to set call [%s]", callsign);

		/* if the call is already there, then don't overwrite it of course */
		/* 28Nov2024, Maiko, note new hgroup argument passed */
   		else if ((lp3 = av_lookup (ifp, thecall, thedigi, 1, hgroup)) == NULLLV)
		{
			/* 28Nov2024, Maiko, note new hgroup argument passed */
			if ((lp3 = av_create (ifp, thecall, thedigi, 1, hgroup)) == NULLLV)
				log (-1, "unable to create Lv entry");
			else
			{
				/* 28Nov2024, Maiko, Set the heard group if there is one */
				lp3->hgroup = hgroup;

				lp3->currxcnt = count;
				lp3->time = (int32)(now - atatsave) + rtatsave - axetime + secclock();
				lp3->time *= -1;
			}
		}
	}

#ifdef	APRSD	/* 29Jun2024, Maiko, some people don't want APRS stuff */
	/*
	 * 22Mar2024, Maiko (VE4KLM), New load APRS heard list. The time()
	 * function is used within the APRS heard information, not secclock()
	 * as is done with the usual ax25 heard lists, so we pass a slightly
	 * different time gap to the function below, no 100%, but better.
	 */
	axloadaprshrd (fp, (int32)(now - atatsave) + secclock());
#endif

	fclose (fp);

	return 0;
}

#endif /* BACKUP_AXHEARD */

#endif /* AX25 */

