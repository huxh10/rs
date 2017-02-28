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

uint32_t g_num = 0;
as_conf_t *g_p_policies = NULL;
rib_map_t **g_pp_ribs = NULL;
simplified_rib_map_t **g_pp_simplified_ribs = NULL;

void init_rs_wo_sgx(uint32_t num, as_conf_t *p_as_conf)
{
    uint32_t i = 0;

    g_num = num;
    g_p_policies = malloc(num * sizeof *g_p_policies);
    g_pp_ribs = malloc(num * sizeof *g_pp_ribs);
    g_pp_simplified_ribs = malloc(num * sizeof *g_pp_simplified_ribs);
    for (i = 0; i < num; i++) {
        g_pp_ribs[i] = NULL;
        g_pp_simplified_ribs[i] = NULL;
        g_p_policies[i].asn = i;
        g_p_policies[i].total_num = num;
        g_p_policies[i].import_policy = malloc(num * sizeof *g_p_policies[i].import_policy);
        memcpy(g_p_policies[i].import_policy, p_as_conf[i].import_policy, num * sizeof *p_as_conf[i].import_policy);
        g_p_policies[i].export_policy = malloc(num * num * sizeof *g_p_policies[i].export_policy);
        memcpy(g_p_policies[i].export_policy, p_as_conf[i].export_policy, num * num * sizeof *p_as_conf[i].export_policy);
    }
}

void run_rs_wo_sgx(int total_msg_num, int preloaded_msg_num, bgp_msg_t **pp_bgp_msgs, int method, int verbose)
{
    uint32_t i = 0;
    void *sent_msg = NULL;
    size_t sent_msg_size = 0;
    uint64_t time_start, time_end;

    for (i = 0; i < preloaded_msg_num; i++) {
        if (method == GLOBAL_ACCESS) {
            compute_route_by_global_access((void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size, g_p_policies, g_pp_simplified_ribs, g_num, &sent_msg, &sent_msg_size);
            SAFE_FREE(sent_msg);
        } else if (method == MSG_QUEUE) {
            compute_route_by_msg_queue((void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size, g_p_policies, g_pp_ribs, g_num, &sent_msg, &sent_msg_size);
            SAFE_FREE(sent_msg);
        }
    }
    if (preloaded_msg_num > 0) {
        if (method == GLOBAL_ACCESS) {
            get_rs_simplified_ribs_num(g_pp_simplified_ribs, g_num);
        } else if (method == MSG_QUEUE) {
            get_rs_ribs_num(g_pp_ribs, g_num);
        }
    }

    for (i = preloaded_msg_num; i < total_msg_num; i++) {
        if (method == GLOBAL_ACCESS) {
            time_start = get_us_time();
            compute_route_by_global_access((void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size, g_p_policies, g_pp_simplified_ribs, g_num, &sent_msg, &sent_msg_size);
            SAFE_FREE(sent_msg);
            time_end = get_us_time();
        } else if (method == MSG_QUEUE) {
            time_start = get_us_time();
            compute_route_by_msg_queue((void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size, g_p_policies, g_pp_ribs, g_num, &sent_msg, &sent_msg_size);
            SAFE_FREE(sent_msg);
            time_end = get_us_time();
        }
        i -= preloaded_msg_num;
        if (verbose == 0) {
            if (i == 0 || i == 1 || i == 50 || i == 51 || i == 100 || i == 101 || i == 150 || i == 151 || i == 200 || i == 201 || i == 250 || i == 251 || i == 300 || i == 301 || i == 350 || i == 351 || i == 400 || i == 401) {
                printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
            }
        } else if (verbose == 1) {
            if (i % 2 == 0) printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
        } else if (verbose == 2) {
            if (i % 2 == 1) printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
        } else if (verbose == 3) {
            printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
        } else if (verbose == 4) {
            printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
            if (method == GLOBAL_ACCESS) {
                print_rs_simplified_ribs(g_pp_simplified_ribs, g_num);
            } else if (method == MSG_QUEUE) {
                print_rs_ribs(g_pp_ribs, g_num);
            }
        }
        i += preloaded_msg_num;
    }
}
