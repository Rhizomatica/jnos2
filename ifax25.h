#ifndef _IFAX25_H
#define _IFAX25_H

/* 29Sep2019, Maiko (VE4KLM), Split out of ax25.h */

#define AXALEN      7   /* Total AX.25 address length, including SSID */

/* AX.25 protocol data kept per interface */
struct ifax25 {
    int paclen;
    int lapbtimertype;
    int32 irtt;
    int version;
    int32 t2;
    int32 t3;
    int32 t4;
    int n2;
    int maxframe;
    int pthresh;
    int window;
    int32 blimit;
    int32 maxwait;   /* maximum backoff time */
    char *bctext;
    char cdigi[AXALEN];
#ifdef MAILBOX
    char bbscall[AXALEN];
#endif

	/*
	 * 06Nov2024, Maiko (VE4KLM) - new multiple heard list, this hgroup
	 * defines the 'current' group in affect, and is directly joined in
	 * with the same hgroup variable in the link list heard structure.
	 *
	 * To set the 'current heard list' for a particular port, example :
	 *
	 *   ax25 h group=XXX rp0
	 *
	 *  where XXX is a string (like 17m, 30m, 10m, vhf, whatever)
	 */

	int hgroup;
};

#endif
