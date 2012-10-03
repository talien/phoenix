#define _PHX_DAEMON_C
#include "nfqueue.h"
#include "data.h"
#include "config.h"
#include "misc.h"

nf_queue_data testdata;

int main()
{
   global_cfg = phx_config_new();
   if (nf_queue_init(&testdata, 0, NULL))
   {
      printf("Error happened during queue init!\n");
      return -1;
   }
   nf_queue_close(&testdata);
   return 0;
}
