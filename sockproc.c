#include "sockproc.h"

void parse_tcp_line(char* buf,char *s,char *d,unsigned int *sp,unsigned int *dp, unsigned int * sn)
{
   unsigned int sport = 0, dport = 0, socknum = 0;
   char prevchar = ' ';
   int field = 0, flen = 0, i, start;
	 for(i=0;buf[i] != '\0';i++)
		{
//			if (buf[i] == ' ')	printf("Tab found");
		   	if ((prevchar == ' ' && buf[i] != ' ') || (prevchar == ':'))
			 	{
					field++;
					flen = 0;
				}
				if ( (buf[i] != ' ') && (buf[i] != ':' ) )
				{
					if (field == 3)
					{
						// FIXME :  This code is platform dependent, fuck you retard, think it over
						if (flen % 2 == 0) s[3-flen/2] = 0;
						s[3-flen/2] = s[3-flen/2]*16 + (char)get_val_from_hex(buf[i]);
					}
					if (field == 4)
					{
						sport = sport*16 + get_val_from_hex(buf[i]);
					}
					if (field == 5)
					{
						// FIXME :  This code is platform dependent, fuck you retard, think it over
						if (flen % 2 == 0) d[3-flen/2] = 0;
						d[3-flen/2] = d[3-flen/2]*16 + (char)get_val_from_hex(buf[i]);
					}
					if (field == 6)
					{
						dport = dport*16 + get_val_from_hex(buf[i]);
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
};

void parse_tcp6_line(char* buf,char *s,char *d,unsigned int *sp,unsigned int *dp, unsigned int * sn)
{
   unsigned int sport = 0, dport = 0, socknum = 0;
   char prevchar = ' ';
   int field = 0, flen = 0, i, start;
   int ipv4field = 1; 
	 for(i=0;buf[i] != '\0';i++)
		{
//			if (buf[i] == ' ')	printf("Tab found");
		   	if ((prevchar == ' ' && buf[i] != ' ') || (prevchar == ':'))
			 	{
					field++;
					flen = 0;
				}
				if ( (buf[i] != ' ') && (buf[i] != ':' ) )
				{
					if (field == 3)
					{
						// FIXME :  This code is platform dependent, fuck you retard, think it over
						if ( (flen >= 0) && (flen <= 15) && (buf[i] != '0' ) ) ipv4field = 0;
						if ( (flen >= 16) && (flen <=19) && ( (buf[i] != '0') && (buf[i] != 'F') ) ) ipv4field = 0;
						if ( (flen >= 20) && (flen <= 23) && (buf[i] != '0' ) ) ipv4field = 0;
						if ( (flen >= 24) && (ipv4field == 1) )
						{
							if (flen % 2 == 0) s[3-(flen-24)/2] = 0;
							s[3-(flen-24)/2] = s[3-(flen-24)/2]*16 + (char)get_val_from_hex(buf[i]);
						}
					}
					if (field == 4)
					{
						sport = sport*16 + get_val_from_hex(buf[i]);
					}
					if (field == 5)
					{
						// FIXME :  This code is platform dependent, fuck you retard, think it over
            if ( (flen >= 0) && (flen <= 15) && (buf[i] != '0' ) ) ipv4field = 0;
            if ( (flen >= 16) && (flen <=19) && ( (buf[i] != '0') && (buf[i] != 'F') ) ) ipv4field = 0;
            if ( (flen >= 20) && (flen <= 23) && (buf[i] != '0' ) ) ipv4field = 0;
            if ( (flen >= 24) && (ipv4field == 1) )
            {
              if (flen % 2 == 0) s[3-(flen-24)/2] = 0;
              s[3-(flen-24)/2] = s[3-(flen-24)/2]*16 + (char)get_val_from_hex(buf[i]);
            }

					}
					if (field == 6)
					{
						dport = dport*16 + get_val_from_hex(buf[i]);
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


int get_proc_from_conn(struct phx_conn_data* c,int direction)
{
	const char* fname = "/proc/net/tcp";
  const char* f6name = "/proc/net/tcp6";
	FILE *tcp = fopen(fname,"r");
	char buf[512];
	int lnum=0;
	int pid;
	const char nullip[4] = { 0,0,0,0 };
	if (!tcp)
	{
		perror("Error opening file:");
		exit(1);
	}
	while ( fgets(buf,sizeof(buf),tcp) > 0)
	{
		int i;
		int start;
		char s[4];
		char d[4];
		unsigned int sport = 0,dport = 0, socknum = 0;
		char prevchar = ' ';
		int field = 0, flen = 0;
    parse_tcp_line(buf,s,d,&sport,&dport,&socknum);
		lnum++;
		if (direction == OUTBOUND)
		{
			if ( (dport == c->dport && sport == c->sport && !strncmp(s,c->srcip,4) && !strncmp(d,c->destip,4) ) ||
				(dport == c->sport && sport == c->dport && !strncmp(s,c->destip,4) && !strncmp(d,c->srcip,4) ) )
			{
				char fname[100];
				char procname[1024];
				int pnlen;
				c->pid = get_pid_from_sock(socknum);
				sprintf(fname,"/proc/%d/exe",c->pid);
				pnlen = readlink(fname,procname,sizeof(procname));
				procname[pnlen] = '\0';
				c->proc_name = g_string_new(procname);
				return pnlen + 1;
			}
		}
		else
		{
			if ( (sport == c->dport) && ( !strncmp(s,nullip,4) || !strncmp(c->destip,s,4) ) )
			{
				char fname[100];
        char procname[1024];
        int pnlen;
        c->pid = get_pid_from_sock(socknum);
        sprintf(fname,"/proc/%d/exe",c->pid);
        pnlen = readlink(fname,procname,sizeof(procname));
        procname[pnlen] = '\0';
				c->proc_name = g_string_new(procname);
        return pnlen + 1;
			}
		}
	}
	fclose(tcp);
  tcp = fopen(f6name,"r");
  lnum = 0;
	if (!tcp)
	{
		perror("Error opening file:");
		exit(1);
	}
  printf("Searching in tcp6 connections\n");
	while ( fgets(buf,sizeof(buf),tcp) > 0)
	{
		int i;
		int start;
		char s[4];
		char d[4];
		unsigned int sport = 0,dport = 0, socknum = 0;
		char prevchar = ' ';
		int field = 0, flen = 0;
    parse_tcp6_line(buf,s,d,&sport,&dport,&socknum);
		lnum++;
		if (direction == OUTBOUND)
		{
			if ( (dport == c->dport && sport == c->sport && !strncmp(s,c->srcip,4) && !strncmp(d,c->destip,4) ) ||
				(dport == c->sport && sport == c->dport && !strncmp(s,c->destip,4) && !strncmp(d,c->srcip,4) ) )
			{
				char fname[100];
				char procname[1024];
				int pnlen;
				c->pid = get_pid_from_sock(socknum);
				sprintf(fname,"/proc/%d/exe",c->pid);
				pnlen = readlink(fname,procname,sizeof(procname));
				procname[pnlen] = '\0';
				c->proc_name = g_string_new(procname);
				return pnlen + 1;
			}
		}
		else
		{
			if ( (sport == c->dport) && ( !strncmp(s,nullip,4) || !strncmp(c->destip,s,4) ) )
			{
				char fname[100];
        char procname[1024];
        int pnlen;
        c->pid = get_pid_from_sock(socknum);
        sprintf(fname,"/proc/%d/exe",c->pid);
        pnlen = readlink(fname,procname,sizeof(procname));
        procname[pnlen] = '\0';
				c->proc_name = g_string_new(procname);
        return pnlen + 1;
			}
		}
	}
	fclose(tcp);
	
	return -1;
};

int get_pid_from_sock(int socknum)
{
	DIR *proc;
	DIR *fd;
	struct dirent *procent;
	struct dirent *fdent;
	//FIXME: I should choose the size of buffers carefully, to avoid buffer overflows
	char buf[100];
	char buf2[100];
  char lname[100];
	char sockbuf[100];
	size_t llen;
	int snum, result;
	int found = 0;
	if ((proc = opendir("/proc/")) == NULL)
	{
		perror("Error opening /proc");
		exit(1);
	}
	while ( (procent = readdir(proc)) && !found )
	{
		int pnum;
		//printf("%s\n",procent->d_name);
		if ( (pnum = atoi(procent->d_name) ) != 0)
		{
			buf[0] = '\0';
			strcat(buf,"/proc/");
			strcat(buf,procent->d_name);
			strcat(buf,"/fd/");
			//printf("%s\n",buf);
			if ((fd = opendir(buf)) == NULL)
			{
				perror("Error opening fd directory");
				closedir(proc);
				exit(1);
			}
			while ( (fdent = readdir(fd)) && !found )
			{
				strncpy(buf2,buf,100);
				strcat(buf2,fdent->d_name);
				llen = readlink(buf2,lname,sizeof(lname));
				lname[llen-1] = '\0';
				if (!strncmp("socket:",lname,7))
				{
					snum = atoi(lname+8);
					//printf("Socket number:%d\n",snum);
					if (snum == socknum)
					{
						result = atoi(procent->d_name);
						found = 1;
					}
				}
			}
			closedir(fd);
		}
	}
	closedir(proc);
	return result;
};

