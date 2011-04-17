#ifndef _PHX_MISC_H
#define _PHX_MISC_H
#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>

static char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

void
log_debug (gchar * format, ...)
{
    va_list l;

    gchar msgbuf[2048];
    struct timeval tv;
    int sec, msec;
    if (!gettimeofday(&tv,NULL)) 
    {
	sec = tv.tv_sec;
	msec = tv.tv_usec;
    }
    
    va_start (l, format);
    g_vsnprintf (msgbuf, sizeof (msgbuf), format, l);
    printf ("[%d:%d] %s", sec, msec, msgbuf);
    va_end (l);

}

void
_log_trace( gchar* function, gchar* file, int line, gchar* format, ...)
{
    va_list l;
    gchar msgbuf[2048];
    struct timeval tv;
    int sec, msec;
    if (!gettimeofday(&tv,NULL)) 
    {
	sec = tv.tv_sec;
	msec = tv.tv_usec;
    }
    
    va_start (l, format);
    g_vsnprintf (msgbuf, sizeof (msgbuf), format, l);
    printf ("[%d:%d] %s:%d : %s(): %s", sec, msec, file, line, function, msgbuf);
    va_end (l);
}

void
write_ip (unsigned char *buffer)
{
    printf ("%d.", buffer[0]);
    printf ("%d.", buffer[1]);
    printf ("%d.", buffer[2]);
    printf ("%d", buffer[3]);
}

void
swrite_ip (unsigned char *buffer, char *out, int buflen)
{
    sprintf (out, "%d.%d.%d.%d", buffer[0], buffer[1], buffer[2], buffer[3]);
}

GString *
phx_write_ip (char ip[4])
{
    char ipbuf[20];

    memset ((void*)ipbuf, 0, sizeof (ipbuf));
    swrite_ip (ip, ipbuf, 0);
    return g_string_new (ipbuf);
}

int
get_val_from_hex (char hex)
{
    if (hex >= 48 && hex <= 57)
    {
	return (int) hex - 48;
    }
    if (hex >= 65 && hex <= 70)
    {
	return (int) hex - 55;
    }
    return -1;
}


void
dumphex (unsigned char *buffer, int len)
{
    int k = 0;

    printf ("0: ");
    while (k < len)
    {
	/*printf("i:%d ",i); */
	printf ("%c", hex[buffer[k] / 16]);
	printf ("%c ", hex[buffer[k] % 16]);
	/*printf("n:%d ",buf[i]); */
	k++;
	if ((k % 4) == 0)
	{
	    if (k < len)
	    {
		printf ("\n %d:", k / 4);

	    }
	    else
	    {
		printf ("\n");
	    }

	}
    }

}

void
dumpascii (unsigned char *buffer, int len)
{
    int k = 0;

    while (k < len)
    {
	printf ("%c", buffer[k]);
	k++;
    }
    printf ("\n");
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
//  printf("uid: %d\n",uid);
    struct passwd *pass = getpwuid (uid);

    close (statf);
    return g_string_new (pass->pw_name);
}

GString *
phx_dns_lookup (char ip[4])
{
    GString *destip = phx_write_ip (ip);

    struct sockaddr_in sa;	/* input */

    sa.sin_family = AF_INET;
    sa.sin_port = htons (3490);
    inet_pton (AF_INET, destip->str, &sa.sin_addr);

    char hbuf[1024];

    g_string_free (destip, TRUE);
    if (getnameinfo (&sa, sizeof (struct sockaddr), hbuf, sizeof (hbuf),
		     NULL, 0, 8))
		return NULL;
    else
		return g_string_new (hbuf);
}

int parse_network(char* str, char* nw, int* mask)
{
    int i, j, prev = 0;
	char endch = '.';
	for (j=0; j<4; j++)
	{
		if (j == 3) endch = '/';
		for (i = prev; str[i] != endch && str[i] != '\0'; i++)
		if (str[i] == '\0')
			return FALSE;
		str[i] = '\0';
		nw[j] = (char)atoi(str+prev);
		prev = i+1;
	}
	*mask = atoi(str+prev);
	return TRUE;
}	

#endif
