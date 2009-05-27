#ifndef _PHX_MISC_H
#define _PHX_MISC_H
#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <pwd.h>

static char hex[16]={'0','1','2','3','4','5','6','7',
                 '8','9','A','B','C','D','E','F' };

void write_ip(unsigned char* buffer)
{
    printf("%d.",buffer[0]);
    printf("%d.",buffer[1]);
    printf("%d.",buffer[2]);
    printf("%d",buffer[3]);
}

void swrite_ip(unsigned char* buffer,char* out, int buflen)
{
		sprintf(out,"%d.%d.%d.%d",buffer[0],buffer[1],buffer[2],buffer[3]);
}

int get_val_from_hex(char hex)
{
  if (hex >= 48 && hex <= 57)
  {
    return (int)hex - 48;
  }
  if (hex >= 65 && hex <= 70)
  {
    return (int)hex - 55;
  }
  return -1;
}


void dumphex(unsigned char* buffer, int len)
{
   int k = 0;
   printf("0: ");
   while  (k < len)
   {
      /*printf("i:%d ",i);*/
      printf("%c",hex[buffer[k]/16] );
      printf("%c ",hex[buffer[k]%16] );
      /*printf("n:%d ",buf[i]);*/
      k++;
      if ( (k  %  4) == 0)
      {
         if (k < len)
         {
            printf("\n %d:",k/4);
         
         }
         else
         {
           printf("\n");
         }  

      }
   }
   
}

void dumpascii(unsigned char* buffer,int len)
{
    int k = 0;
    while (k < len)
    {
       printf("%c",buffer[k]);
       k++;
    }
    printf("\n");
}

GString* get_user(guint32 pid)
{
  char buf[1024];
  sprintf(buf,"/proc/%d/status",pid);
  FILE* statf = fopen(buf,"r");
  int i = 0;
  while ( i < 7) { fgets(buf,sizeof(buf),statf); i++; }
  int uid;
  sscanf(buf,"%*s %d %*d %*d %*d",&uid);
//  printf("uid: %d\n",uid);
  struct passwd* pass = getpwuid(uid);
  return g_string_new(pass->pw_name);
}
#endif
