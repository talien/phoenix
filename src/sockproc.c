#include "sockproc.h"
#include <glib.h>
#include <pwd.h>

int
check_pid_exists(int pid)
{
	char buf[32];
	int res;
	snprintf(buf,sizeof(buf), "/proc/%d",pid);
	res = access(buf, F_OK);
	if (res != 0)	
	{
		return FALSE;
	}
	return TRUE;
}

void
parse_tcp_line (char *buf, char *s, char *d, unsigned int *sp,
		unsigned int *dp, unsigned int *sn)
{
    unsigned int sport = 0, dport = 0, socknum = 0;

    char prevchar = ' ';

    int field = 0, flen = 0, i;

    for (i = 0; buf[i] != '\0'; i++)
    {
/*			if (buf[i] == ' ')	printf("Tab found"); */
		if ((prevchar == ' ' && buf[i] != ' ') || (prevchar == ':'))
		{
			field++;
			flen = 0;
		}
		if ((buf[i] != ' ') && (buf[i] != ':'))
		{
			if (field == 3)
			{
			/* FIXME :  This code is platform dependent, fuck you retard, think it over */
				if (flen % 2 == 0)
					s[3 - flen / 2] = 0;
				s[3 - flen / 2] = s[3 - flen / 2] * 16 + (char) get_val_from_hex (buf[i]);
			}
			if (field == 4)
			{
				sport = sport * 16 + get_val_from_hex (buf[i]);
			}
			if (field == 5)
			{
				/* FIXME :  This code is platform dependent, fuck you retard, think it over */
				if (flen % 2 == 0)
					d[3 - flen / 2] = 0;
				d[3 - flen / 2] = d[3 - flen / 2] * 16 + (char) get_val_from_hex (buf[i]);
			}
			if (field == 6)
			{
				dport = dport * 16 + get_val_from_hex (buf[i]);
			}
			if (field == 15)
			{
				socknum = socknum * 10 + (buf[i] - 48);
			}
		}
		prevchar = buf[i];
		flen++;
	}
    *sp = sport;
    *dp = dport;
    *sn = socknum;
}

void
parse_tcp6_line (char *buf, char *s, char *d G_GNUC_UNUSED, unsigned int *sp,
		 unsigned int *dp, unsigned int *sn)
{
    unsigned int sport = 0, dport = 0, socknum = 0;

    char prevchar = ' ';

    int field = 0, flen = 0, i;

    int ipv4field = 1;

    for (i = 0; buf[i] != '\0'; i++)
    {
/*			if (buf[i] == ' ')	printf("Tab found"); */
	if ((prevchar == ' ' && buf[i] != ' ') || (prevchar == ':'))
	{
	    field++;
	    flen = 0;
	}
	if ((buf[i] != ' ') && (buf[i] != ':'))
	{
	    if (field == 3)
	    {
		/* FIXME :  This code is platform dependent, fuck you retard, think it over */
		if ((flen >= 0) && (flen <= 15) && (buf[i] != '0'))
		    ipv4field = 0;
		if ((flen >= 16) && (flen <= 19)
		    && ((buf[i] != '0') && (buf[i] != 'F')))
		    ipv4field = 0;
		if ((flen >= 20) && (flen <= 23) && (buf[i] != '0'))
		    ipv4field = 0;
		if ((flen >= 24) && (ipv4field == 1))
		{
		    if (flen % 2 == 0)
			s[3 - (flen - 24) / 2] = 0;
		    s[3 - (flen - 24) / 2] =
			s[3 - (flen - 24) / 2] * 16 +
			(char) get_val_from_hex (buf[i]);
		}
	    }
	    if (field == 4)
	    {
		sport = sport * 16 + get_val_from_hex (buf[i]);
	    }
	    if (field == 5)
	    {
		/* FIXME :  This code is platform dependent, fuck you retard, think it over */
		if ((flen >= 0) && (flen <= 15) && (buf[i] != '0'))
		    ipv4field = 0;
		if ((flen >= 16) && (flen <= 19)
		    && ((buf[i] != '0') && (buf[i] != 'F')))
		    ipv4field = 0;
		if ((flen >= 20) && (flen <= 23) && (buf[i] != '0'))
		    ipv4field = 0;
		if ((flen >= 24) && (ipv4field == 1))
		{
		    if (flen % 2 == 0)
			s[3 - (flen - 24) / 2] = 0;
		    s[3 - (flen - 24) / 2] =
			s[3 - (flen - 24) / 2] * 16 +
			(char) get_val_from_hex (buf[i]);
		}

	    }
	    if (field == 6)
	    {
		dport = dport * 16 + get_val_from_hex (buf[i]);
	    }
	    if (field == 15)
	    {
		socknum = socknum * 10 + (buf[i] - 48);
	    }
	}
	prevchar = buf[i];
	flen++;
    }
    *sp = sport;
    *dp = dport;
    *sn = socknum;
}


int
get_proc_from_conn (struct phx_conn_data *c, int direction)
{
    const char *fname = "/proc/net/tcp";

    const char *f6name = "/proc/net/tcp6";

    FILE *tcp = fopen (fname, "r");

    char buf[512];

    int lnum = 0;
    const gchar nullip[4] = { 0, 0, 0, 0 };
    if (!tcp)
    {
		perror ("Error opening file:");
		return -1;
    }
    while (fgets (buf, sizeof (buf), tcp) != NULL)
    {
		gchar s[4];

		gchar d[4];

		unsigned int sport = 0, dport = 0, socknum = 0;

		parse_tcp_line (buf, s, d, &sport, &dport, &socknum);
		lnum++;
		if (direction == OUTBOUND)
		{
			if ((dport == c->dport && sport == c->sport
			 && !strncmp (s, (gchar *) c->srcip, 4)
			 && !strncmp (d, (gchar *) c->destip, 4))
			|| (dport == c->sport && sport == c->dport
				&& !strncmp (s, (gchar *) c->destip, 4)
				&& !strncmp (d, (gchar *) c->srcip, 4)))
			{
				char fname[100];

				char procname[1024];

				int pnlen;

				c->pid = get_pid_from_sock (socknum);
				sprintf (fname, "/proc/%d/exe", c->pid);
				pnlen = readlink (fname, procname, sizeof (procname));
				procname[pnlen] = '\0';
				c->proc_name = g_string_new (procname);
				fclose(tcp);
				return pnlen + 1;
			}
		}
		else
		{
			if ((sport == c->dport) && (!strncmp (s, nullip, 4) || !strncmp ((char*)c->destip, s, 4)))
			{
				char fname[100];

				char procname[1024];

				int pnlen;

				c->pid = get_pid_from_sock (socknum);
				sprintf (fname, "/proc/%d/exe", c->pid);
				pnlen = readlink (fname, procname, sizeof (procname));
				procname[pnlen] = '\0';
				c->proc_name = g_string_new (procname);
				fclose(tcp);
				return pnlen + 1;
			}
		}
		}
    fclose (tcp);
    tcp = fopen (f6name, "r");
    lnum = 0;
    if (!tcp)
    {
		log_debug ("Error opening file: /proc/net/tcp6\n");
		return -1;
    }
    log_debug ("Searching in tcp6 connections\n");
    while (fgets (buf, sizeof (buf), tcp) != 0)
    {
		char s[4];

		char d[4];

		unsigned int sport = 0, dport = 0, socknum = 0;

		parse_tcp6_line (buf, s, d, &sport, &dport, &socknum);
		lnum++;
		if (direction == OUTBOUND)
		{
			if ((dport == c->dport && sport == c->sport
			 && !strncmp (s, (char*)c->srcip, 4) && !strncmp (d, (char*)c->destip, 4))
			|| (dport == c->sport && sport == c->dport
				&& !strncmp (s, (char*)c->destip, 4)
				&& !strncmp (d, (char*)c->srcip, 4)))
			{
				char fname[100];

				char procname[1024];

				int pnlen;

				c->pid = get_pid_from_sock (socknum);
				sprintf (fname, "/proc/%d/exe", c->pid);
				pnlen = readlink (fname, procname, sizeof (procname));
				procname[pnlen] = '\0';
				c->proc_name = g_string_new (procname);
				fclose(tcp);
				return pnlen + 1;
			}
		}
		else
		{
			if ((sport == c->dport)
			&& (!strncmp (s, nullip, 4) || !strncmp ((char*)c->destip, s, 4)))
			{
				char fname[100];

				char procname[1024];

				int pnlen;

				c->pid = get_pid_from_sock (socknum);
				sprintf (fname, "/proc/%d/exe", c->pid);
				pnlen = readlink (fname, procname, sizeof (procname));
				procname[pnlen] = '\0';
				c->proc_name = g_string_new (procname);
				fclose(tcp);
				return pnlen + 1;
			}
		}
	}
    fclose (tcp);

    return -1;
}

int
get_pid_from_sock (int socknum)
{
    DIR *proc = NULL;

    DIR *fd = NULL;

    struct dirent *procent = NULL;

    struct dirent *fdent = NULL;

    /*FIXME: I should choose the size of buffers carefully, to avoid buffer overflows */
    char buf[100];

    char buf2[100];

    char lname[100];

    size_t llen;

    int snum, result;

    int found = 0;
	int buf_len = 0;

    if ((proc = opendir ("/proc/")) == NULL)
    {
	perror ("Error opening /proc");
	exit (1);
    }
    while ((procent = readdir (proc)) && !found)
    {
	int pnum;

	if ((pnum = atoi (procent->d_name)) != 0)
	{
	    buf[0] = '\0';
	    strcat (buf, "/proc/");
	    strcat (buf, procent->d_name);
	    strcat (buf, "/fd/");
		buf_len = strlen(buf);
	    if ((fd = opendir (buf)) == NULL)
	    {
		perror
		    ("Error opening fd directory, maybe the process exited during operation");
		//closedir(proc);
		continue;
	    }
	    while ((fdent = readdir (fd)) && !found)
	    {
		//strncpy (buf2, buf, 100);
		memcpy(buf2, buf, buf_len + 1);
		strcat (buf2, fdent->d_name);
		llen = readlink (buf2, lname, sizeof (lname));
		if ((int) llen > 0)
		{
		    //printf("%d\n",llen);
		    lname[llen - 1] = '\0';
		    if (!strncmp ("socket:", lname, 7))
		    {
			snum = atoi (lname + 8);
			if (snum == socknum)
			{
			    result = atoi (procent->d_name);
			    found = 1;
			}
		    }
		}
	    }
	    closedir (fd);
	}
    }
    closedir (proc);
    return result;
}

GString *
get_user (guint32 pid)
{
    char buf[1024];

    sprintf (buf, "/proc/%d/status", pid);
    FILE *statf = fopen (buf, "r");

    if (statf == NULL)
        return NULL;
    int i = 0;

    while (i < 7)
    {
        fgets (buf, sizeof (buf), statf);
        i++;
    }
    int uid;

    sscanf (buf, "%*s %d %*d %*d %*d", &uid);
    struct passwd *pass = getpwuid (uid);

    fclose (statf);
    GString* result = g_string_new (pass->pw_name);
    return result;
}

