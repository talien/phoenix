#define _PHX_DAEMON_C
#include "nfqueue.h"
#include "data.h"

nf_queue_data testdata;

int main()
{
   nf_queue_init(&testdata, 0, NULL);
   nf_queue_close(&testdata);
   return 0;
}
