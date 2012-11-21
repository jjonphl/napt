#include "napt.h"
#include <linux/proc_fs.h>

/* this just "kills" ctracks */

int __init kill_init()
{
    napt_clear_ctracks();
    return -1;
}


module_init(kill_init);

