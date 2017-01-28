#include <stdio.h>
#include "datatypes.h"
#include "error_codes.h"
#include "time_utils.h"
#include "bgp.h"
#include "rs.h"
#include "rs_wo_sgx.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

void run_rs_wo_sgx(uint32_t num, as_conf_t *p_as_conf, int msg_num, bgp_msg_t **pp_bgp_msgs)
{
    uint32_t i = 0;
    rib_map_t **pp_ribs = NULL;
    void *sent_msg = NULL;
    size_t sent_msg_size = 0;

    pp_ribs = malloc(num * sizeof *pp_ribs);
    for (i = 0; i < num; i++) {
        pp_ribs[i] = NULL;
    }

    for (i = 0; i < msg_num; i++) {
        printf("\n");
        print_current_time_with_us("compute routes");
        compute_route((void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size, p_as_conf, pp_ribs, num, &sent_msg, &sent_msg_size);
        printf("\n");
        print_current_time_with_us("receive routes");
        //update_route(sent_msg, sent_msg_size);
        //printf("\n");
        //print_current_time_with_us("current rs routes");
        //print_rs_ribs(pp_ribs, num);
        SAFE_FREE(sent_msg);
    }
}
