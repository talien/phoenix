/*
* Copyright (c) 2008-2014 Viktor Tusa
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*
*/

#ifndef _PHX_MISC_C
#define _PHX_MISC_C
#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "config.h"
#include "misc.h"

char* rules =
  "*filter\n\
:INPUT ACCEPT [0:0]\n\
:FORWARD ACCEPT [0:0]\n\
:OUTPUT ACCEPT [0:0]\n\
:newinqueue - [0:0]\n\
:newoutqueue - [0:0]\n\
:rejectoutqueue - [0:0]\n\
:rejectinqueue - [0:0]\n\
-A INPUT -m mark --mark 0x1/0xff -j newinqueue\n\
-A INPUT -m mark --mark 0x4/0xff -j rejectinqueue\n\
-A INPUT -p tcp -m state --state NEW -j NFQUEUE --queue-num 1\n\
-A OUTPUT -m mark --mark 0x2/0xff -j newoutqueue\n\
-A OUTPUT -m mark --mark 0x3/0xff -j rejectoutqueue\n\
-A OUTPUT -p tcp -m state --state NEW -j NFQUEUE --queue-num 0\n\
-A newinqueue -j NFQUEUE --queue-num 2\n\
-A newoutqueue -j NFQUEUE --queue-num 3\n\
-A rejectoutqueue -j REJECT --reject-with icmp-port-unreachable\n\
-A rejectinqueue -j REJECT --reject-with icmp-port-unreachable\n\
COMMIT\n\
";
static char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                      };

void phx_init_log()
{
  if (global_cfg->logging_mode == PHX_CFG_LOG_SYSLOG)
    {
      openlog("phoenix", 0, LOG_DAEMON);
    }
  else if (global_cfg->logging_mode == PHX_CFG_LOG_FILE)
    {
      global_cfg->log_file_fd = open(global_cfg->log_file_name, O_APPEND | O_CREAT | O_RDWR, 0660);
    }
};

void phx_close_log()
{
  if (global_cfg->logging_mode == PHX_CFG_LOG_SYSLOG)
    {
      closelog();
    }
  else if (global_cfg->logging_mode == PHX_CFG_LOG_FILE)
    {
      close(global_cfg->log_file_fd);
    }
};

void
_log_trace( int debug, const char* function, const char* file, int line, gchar* format, ...)
{
  va_list l;
  gchar msgbuf[2048];
  gchar file_line[2500];
  struct timeval tv;
  int sec, msec;
  int size;
  if (!gettimeofday(&tv,NULL))
    {
      sec = tv.tv_sec;
      msec = tv.tv_usec;
    }

  va_start (l, format);
  g_vsnprintf (msgbuf, sizeof (msgbuf), format, l);
  switch (global_cfg->logging_mode)
    {
    case PHX_CFG_LOG_SYSLOG:
      syslog(LOG_INFO, "%s", msgbuf);
      break;
    case PHX_CFG_LOG_STDERR:
      printf ("[%d:%d] %s:%d : %s(): %s", sec, msec, file, line, function, msgbuf);
      break;
    case PHX_CFG_LOG_FILE:
      size = g_snprintf(file_line, sizeof(file_line), "[%d:%d] %s:%d : %s(): %s", sec, msec, file, line, function, msgbuf);
      write (global_cfg->log_file_fd, file_line, size);
      break;
    };
  va_end (l);
}

void
swrite_ip (char *buffer, char *out)
{
  sprintf (out, "%d.%d.%d.%d", (guchar)buffer[0], (guchar)buffer[1], (guchar)buffer[2], (guchar)buffer[3]);
}

GString *
phx_write_ip (char ip[4])
{
  char ipbuf[20];

  memset ((void*)ipbuf, 0, sizeof (ipbuf));
  swrite_ip (ip, ipbuf);
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
  if (getnameinfo ((struct sockaddr*)&sa, sizeof (struct sockaddr), hbuf, sizeof (hbuf),
                   NULL, 0, 8))
    return NULL;
  else
    return g_string_new (hbuf);
}

int parse_network(char* str, guchar* nw, guint32* mask)
{
  int i, j, prev = 0, num;
  char endch = '.';
  for (j=0; j<4; j++)
    {
      if (j == 3) endch = '/';
      for (i = prev; str[i] != endch && str[i] != '\0'; i++)
        if ((str[i] == '\0') || ( (str[i] != '.') && (str[i] != '/') && ((str[i] < '0') || (str[i] > '9')) ))
          return FALSE;
      str[i] = '\0';
      num = atoi(str+prev);
      if ((num < 0) || (num > 255))
        return FALSE;
      nw[j] = num;
      prev = i+1;
    }
  *mask = atoi(str+prev);
  if ((*mask < 0) || (*mask > 32))
    return FALSE;
  return TRUE;
}

int exec_with_fd(int open_fd, char** argv)
{
  int pipe_fd[2];
  int oldstream = dup(open_fd);
  pipe(pipe_fd);
  dup2(pipe_fd[open_fd],open_fd);
  int pid = fork();
  if (pid == 0)
    {
      close(pipe_fd[1-open_fd]);
      execv(argv[0], argv);

    }
  else
    {
      close(open_fd);
      close(pipe_fd[open_fd]);
      dup2(oldstream, open_fd);
      return pipe_fd[1-open_fd];
    }
}

void save_iptables()
{
  log_debug("Saving iptables\n");
  char buffer[4096];
  char* argv[] = { "/sbin/iptables-save", NULL };
  int fd = exec_with_fd(1, argv);
  unlink("phx.tables");
  int wfd = open("phx.tables", O_CREAT | O_WRONLY, 00700);
  if (wfd < 0)
    {
      log_debug("Cannot create tables file\n");
      return;
    }
  int bytes = 0;
  while ((bytes = read(fd, buffer, sizeof(buffer))) > 0)
    {
      write(wfd, buffer, bytes);
    }
  close(fd);
  close(wfd);
}

void restore_iptables()
{
  log_debug("Restoring iptables\n");
  char buffer[4096];
  char* argv[] = { "/sbin/iptables-restore", NULL };
  int fd = exec_with_fd(0, argv);
  int rfd = open("phx.tables", O_RDONLY);
  if (rfd < 0)
    {
      log_debug("Cannot open tables file\n");
      return;
    }
  int bytes = 0;
  while ((bytes =read(rfd, buffer, sizeof(buffer))) > 0)
    {
      write(fd, buffer, bytes);
    }
  close(fd);
  close(rfd);
  unlink("phx.tables");
}

void setup_iptables()
{
  log_debug("Setting up iptables\n");
  char* argv[] = { "/sbin/iptables-restore", NULL };
  int fd = exec_with_fd(0, argv);
  write(fd, rules, strlen(rules));
  close(fd);
}
#endif
