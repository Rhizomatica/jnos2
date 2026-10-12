/*
 * I need a hash function to store my heard group descriptions
 *
 * The FNV-1a Hash technique by Fowler/Noll/Vo looks interesting, and simple
 *  (https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function#FNV-1_hash)
 *
 * Maiko Langelaar (VE4KLM), 27Jan2025
 */

#undef	COMMAND_LINE_UTILITY	/* #define this for linux cmd line program */

#include <stdio.h>

unsigned fnv1ahash (char *dptr)
{
	unsigned int hash32b;   /* we will use a 32 bit hash for this*/

	hash32b = 2166136261U;  /* FNV offset basis */

	// printf ("%s\n", dptr);

	while (*dptr)
	{
		hash32b = hash32b ^ *dptr;

		hash32b = hash32b * 16777619U;  /* FNV prime */

		dptr++;
	}

	return hash32b;
}

#ifdef COMMAND_LINE_UTILITY

int main (int argc, char **argv)
{
	if (argc > 1)
		printf ("%u\n", fnv1ahash (argv[1]));
	else
		printf ("use : ./fnvhash <text>\n");

	return 0;
}

#endif

