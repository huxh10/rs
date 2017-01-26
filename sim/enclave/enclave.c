#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include "enclave_t.h"
#include "error_codes.h"
#include "sgx_trts.h"
#include "datatypes.h"
#include "bgp.h"
#include "uthash.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

uint32_t g_num = 0;
as_conf_t *g_p_policies = NULL;
rib_map_t **g_pp_ribs = NULL;

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

uint32_t load_as_conf(uint32_t asn, void *import_msg, size_t import_msg_size, void *export_msg, size_t export_msg_size)
{
    uint32_t i = 0, total_num = import_msg_size / sizeof(uint32_t);
    if (g_p_policies == NULL) {
        g_num = total_num;
        g_p_policies = malloc(total_num * sizeof *g_p_policies);
        g_pp_ribs = malloc(total_num * sizeof *g_pp_ribs);
        for (i = 0; i < total_num; i++) {
            g_pp_ribs[i] = NULL;
        }
    }
    g_p_policies[asn].asn = asn;
    g_p_policies[asn].total_num = total_num;
    g_p_policies[asn].import_policy = malloc(total_num * sizeof *g_p_policies[asn].import_policy);
    memcpy(g_p_policies[asn].import_policy, import_msg, import_msg_size);
    g_p_policies[asn].export_policy = malloc(total_num * total_num * sizeof *g_p_policies[asn].export_policy);
    memcpy(g_p_policies[asn].export_policy, export_msg, export_msg_size);
    return SGX_SUCCESS;
}

uint32_t compute_route(void *msg, size_t msg_size)
{
    uint32_t i = 0;
    char *key = NULL;
    bgp_msg_t *p_bgp_msg = msg;
    assert(p_bgp_msg->msg_size == msg_size);
    route_t *p_route = NULL;
    rs_inner_msg_t *tmp_p_inner_msg = NULL;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    int processed_as_num_in_one_loop = 0, iteration = 0;
    int sent_msg_num = 0, sent_msg_size = 0;

    // TODO change pointer to uuid
    route_node_t *p_orig_best_rn[g_num];
    route_node_t *p_old_best_rn[g_num];
    route_node_t *p_new_best_rn[g_num];
    for (i = 0; i < g_num; i++) {
        p_orig_best_rn[i] = NULL;
        p_old_best_rn[i] = NULL;
        p_new_best_rn[i] = NULL;
    }

    // get original route from msg
    parse_route_from_channel(&p_route, p_bgp_msg->route);
    key = my_strdup(p_route->prefix);

    // init inner msg lists for exchange
    rs_inner_msg_t **pp_inner_msgs = malloc(g_num * sizeof *pp_inner_msgs);
    for (i = 0; i < g_num; i++) {
        pp_inner_msgs[i] = NULL;
    }
    // add received bgp_msg to asn list
    tmp_p_inner_msg = malloc(sizeof *tmp_p_inner_msg);
    tmp_p_inner_msg->src_asn = p_bgp_msg->asn;
    tmp_p_inner_msg->oprt_type = p_bgp_msg->oprt_type;
    tmp_p_inner_msg->src_route = p_route;
    tmp_p_inner_msg->next = tmp_p_inner_msg;
    tmp_p_inner_msg->prev = tmp_p_inner_msg;
    pp_inner_msgs[p_bgp_msg->asn] = tmp_p_inner_msg;

    for (i = 0; i < g_num; i ++) {
        HASH_FIND_STR(g_pp_ribs[i], key, p_rib_entry);
        p_orig_best_rn[i] = get_selected_route_node(p_rib_entry);
    }

    while (1) {
        // iterate until routes are converged
        iteration++;
        processed_as_num_in_one_loop = 0;
        // process msgs to each as
        for (i = 0; i < g_num; i++) {
            if (pp_inner_msgs[i] == NULL) continue;
            HASH_FIND_STR(g_pp_ribs[i], key, p_rib_entry);
            p_old_best_rn[i] = get_selected_route_node(p_rib_entry);
            while (pp_inner_msgs[i]) {
                // FIFO process
                printf("iteration:%d, asn:%u\n", iteration, i);
                tmp_p_inner_msg = pp_inner_msgs[i]->prev;

                // update rib
                if (tmp_p_inner_msg->oprt_type == ANNOUNCE) {
                    printf("ANNOUNCE\n");
                    add_route(&p_rib_entry, tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, g_p_policies[i].import_policy);
                } else if (tmp_p_inner_msg->oprt_type == WITHDRAW) {
                    printf("WITHDRAW\n");
                    del_route(p_rib_entry, tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, g_p_policies[i].import_policy, p_old_best_rn[i]);
                }

                if (pp_inner_msgs[i]->prev == pp_inner_msgs[i]) {
                    free_route(&tmp_p_inner_msg->src_route);
                    SAFE_FREE(tmp_p_inner_msg);
                    pp_inner_msgs[i] = NULL;
                } else {
                    pp_inner_msgs[i]->prev = tmp_p_inner_msg->prev;
                    tmp_p_inner_msg->prev->next = pp_inner_msgs[i];
                    free_route(&tmp_p_inner_msg->src_route);
                    SAFE_FREE(tmp_p_inner_msg);
                }
            }
            p_new_best_rn[i] = get_selected_route_node(p_rib_entry);
            if (p_new_best_rn[i]) print_route(p_new_best_rn[i]->route);
            printf("p_new_best_rn[i] addr:%lu\n", (uint64_t) p_new_best_rn[i]);
            printf("p_rib_entry addr:%lu\n", (uint64_t) p_rib_entry);
            printf("p_rib_entry->routes addr:%lu\n", (uint64_t) p_rib_entry->routes);
            printf("is_selected:%d, next_hop:%d, ptr route:%lu\n", p_rib_entry->routes->is_selected, p_rib_entry->routes->next_hop, (uint64_t) p_rib_entry->routes->route);

            HASH_FIND_STR(g_pp_ribs[i], key, tmp_p_rib_entry);
            if (tmp_p_rib_entry) {
                tmp_p_rib_entry->routes = p_rib_entry->routes;
            } else if (p_rib_entry) {
                HASH_ADD_KEYPTR(hh, g_pp_ribs[i], key, strlen(key), p_rib_entry);
            }
            printf("ptr addr:%lu\n", (uint64_t) p_rib_entry);
            printf("ptr addr:%lu\n", (uint64_t) p_rib_entry->routes);
            printf("is_selected:%d, next_hop:%d, ptr route:%lu\n", p_rib_entry->routes->is_selected, p_rib_entry->routes->next_hop, (uint64_t) p_rib_entry->routes->route);

            tmp_p_rib_entry = NULL;
            HASH_FIND_STR(g_pp_ribs[i], key, tmp_p_rib_entry);
            printf("ptr addr:%lu\n", (uint64_t) tmp_p_rib_entry);
            printf("ptr addr:%lu\n", (uint64_t) tmp_p_rib_entry->routes);
            printf("is_selected:%d, next_hop:%d, ptr route:%lu\n", tmp_p_rib_entry->routes->is_selected, tmp_p_rib_entry->routes->next_hop, (uint64_t) tmp_p_rib_entry->routes->route);
            p_new_best_rn[i] = get_selected_route_node(tmp_p_rib_entry);
            if (p_new_best_rn[i]) {
                print_route(p_new_best_rn[i]->route);
            }
            tmp_p_rib_entry = NULL;
            p_rib_entry = NULL;
        }
        // add potential msgs to next iteration
        for (i = 0; i < g_num; i++) {
            if (p_old_best_rn[i] == p_new_best_rn[i]) continue;
            if (p_old_best_rn[i]) {
                tmp_p_inner_msg = malloc(sizeof *tmp_p_inner_msg);
                tmp_p_inner_msg->oprt_type = WITHDRAW;
                tmp_p_inner_msg->src_asn = i;
                execute_export_policy(pp_inner_msgs, g_num, p_old_best_rn[i]->next_hop, tmp_p_inner_msg, g_p_policies[i].export_policy);
                if (p_old_best_rn[i]->is_selected == TO_BE_DEL) {
                    free_route(&p_old_best_rn[i]->route);
                    SAFE_FREE(p_old_best_rn[i]);
                }
            }
            if (p_new_best_rn[i]) {
                tmp_p_inner_msg = malloc(sizeof *tmp_p_inner_msg);
                tmp_p_inner_msg->oprt_type = ANNOUNCE;
                tmp_p_inner_msg->src_asn = i;
                if (p_new_best_rn[i]->next_hop == i) {
                    route_cpy(&tmp_p_inner_msg->src_route, NULL, p_new_best_rn[i]->route);
                } else {
                    route_cpy(&tmp_p_inner_msg->src_route, &i, p_new_best_rn[i]->route);
                }
                execute_export_policy(pp_inner_msgs, g_num, p_new_best_rn[i]->next_hop, tmp_p_inner_msg, g_p_policies[i].export_policy);
            }
            // execute export policies and update inner msg lists 
            processed_as_num_in_one_loop++;
        }

        // converged
        if (!processed_as_num_in_one_loop) break;
    }

    // send updated routes back
    for (i = 0; i < g_num; i++) {
        if (p_orig_best_rn[i] == p_new_best_rn[i]) continue;
        if (p_new_best_rn[i]) {
            // ANNOUNCE
            // asn(4) + oprt_type(1) + route(route_size)
            sent_msg_size += 5 + get_route_size(p_new_best_rn[i]->route);
        } else {
            // WITHDRAW
            // asn(4) + oprt_type(1)
            sent_msg_size += 5;
        }
        sent_msg_num++;
    }
    if (!sent_msg_num)  return SUCCESS;
    sent_msg_size += 4; //sent_msg_num(4)
    int offset = 0;
    uint8_t *sent_msg = malloc(sent_msg_size);
    *((int *) sent_msg) = sent_msg_num;
    offset += 4;
    for (i = 0; i < g_num; i++) {
        if (p_orig_best_rn[i] == p_new_best_rn[i]) continue;
        *((uint32_t *) (sent_msg + offset)) = i;
        offset += 4;
        if (p_new_best_rn[i]) {
            // ANNOUNCE
            *((uint8_t *) (sent_msg + offset)) = ANNOUNCE;
            offset++;
            offset += write_route_msg(sent_msg + offset, p_new_best_rn[i]->route);
        } else {
            // WITHDRAW
            *((uint8_t *) (sent_msg + offset)) = WITHDRAW;
            offset++;
        }
    }
    uint32_t call_status, ret_status;
    call_status = ocall_update_route(&ret_status, (void *) sent_msg, sent_msg_size);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }

    return SUCCESS;
}
