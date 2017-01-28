#include <stdio.h>
#include <assert.h>
#include "error_codes.h"
#include "uthash.h"
#include "datatypes.h"
#include "bgp.h"
#include "rs.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

uint32_t compute_route(void *msg, size_t msg_size, as_conf_t *p_policies, rib_map_t **pp_ribs, uint32_t num, void **pp_sent_msg, size_t *p_sent_msg_size)
{
    uint32_t i = 0, orig_sender_asn = 0;
    char *key = NULL;
    bgp_msg_t *p_bgp_msg = msg;
    assert(p_bgp_msg->msg_size == msg_size);
    route_t *p_route = NULL;
    rs_inner_msg_t *tmp_p_inner_msg = NULL;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    int processed_as_num_in_one_loop = 0, iteration = 0;
    int pp_sent_msg_num = 0;

    // TODO change pointer to uuid
    route_node_t *p_orig_best_rn[num];
    route_node_t *p_old_best_rn[num];
    route_node_t *p_new_best_rn[num];
    for (i = 0; i < num; i++) {
        p_orig_best_rn[i] = NULL;
        p_old_best_rn[i] = NULL;
        p_new_best_rn[i] = NULL;
    }

    // get original route from msg
    parse_route_from_channel(&p_route, p_bgp_msg->route);
    assert(p_route);
    assert(p_route->as_path.asns);
    key = my_strdup(p_route->prefix);

    // init inner msg lists for exchange
    rs_inner_msg_t **pp_inner_msgs = malloc(num * sizeof *pp_inner_msgs);
    for (i = 0; i < num; i++) {
        pp_inner_msgs[i] = NULL;
    }
    // add received bgp_msg to asn list
    tmp_p_inner_msg = malloc(sizeof *tmp_p_inner_msg);
    tmp_p_inner_msg->src_asn = p_route->as_path.asns[0];
    orig_sender_asn = p_bgp_msg->asn;
    tmp_p_inner_msg->oprt_type = p_bgp_msg->oprt_type;
    tmp_p_inner_msg->src_route = p_route;
    tmp_p_inner_msg->next = tmp_p_inner_msg;
    tmp_p_inner_msg->prev = tmp_p_inner_msg;
    pp_inner_msgs[p_bgp_msg->asn] = tmp_p_inner_msg;

    for (i = 0; i < num; i ++) {
        HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
        p_orig_best_rn[i] = get_selected_route_node(p_rib_entry);
    }

    while (1) {
        // iterate until routes are converged
        iteration++;
        processed_as_num_in_one_loop = 0;
        // process msgs to each as
        for (i = 0; i < num; i++) {
            if (pp_inner_msgs[i] == NULL) continue;
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            p_old_best_rn[i] = get_selected_route_node(p_rib_entry);
            while (pp_inner_msgs[i]) {
                // FIFO process
                tmp_p_inner_msg = pp_inner_msgs[i]->prev;

                // update rib
                if (tmp_p_inner_msg->oprt_type == ANNOUNCE) {
                    // printf("iteration:%d, asn:%u, receive ANNOUNCE msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    add_route(&p_rib_entry, tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy);
                } else if (tmp_p_inner_msg->oprt_type == WITHDRAW) {
                    // printf("iteration:%d, asn:%u, receive WITHDRAW msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    del_route(p_rib_entry, tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy, p_old_best_rn[i]);
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
            /*
            if (p_new_best_rn[i]) {
                printf("as:%d new best after this iteration: ", i);
                print_route(p_new_best_rn[i]->route);
            } else {
                printf("as:%d new best after this iteration: NULL\n", i);
            }
            */

            HASH_FIND_STR(pp_ribs[i], key, tmp_p_rib_entry);
            if (tmp_p_rib_entry) {
                tmp_p_rib_entry->routes = p_rib_entry->routes;
            } else if (p_rib_entry) {
                HASH_ADD_KEYPTR(hh, pp_ribs[i], key, strlen(key), p_rib_entry);
            }

            tmp_p_rib_entry = NULL;
            p_rib_entry = NULL;
        }
        // add potential msgs to next iteration
        for (i = 0; i < num; i++) {
            if (p_old_best_rn[i] == p_new_best_rn[i]) continue;
            // printf("asn:%d prepares to send inner msg\n", i);
            // execute export policies and update inner msg lists 
            if (p_old_best_rn[i]) {
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_old_best_rn[i]->next_hop, WITHDRAW, NULL);
                if (p_old_best_rn[i]->is_selected == TO_BE_DEL) {
                    free_route(&p_old_best_rn[i]->route);
                    SAFE_FREE(p_old_best_rn[i]);
                }
            }
            if (p_new_best_rn[i]) {
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_new_best_rn[i]->next_hop, ANNOUNCE, p_new_best_rn[i]->route);
            }
            p_old_best_rn[i] = NULL;
            p_new_best_rn[i] = NULL;
            processed_as_num_in_one_loop++;
        }

        // converged
        if (!processed_as_num_in_one_loop) break;
    }

    // send updated routes back
    *p_sent_msg_size = 0;
    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
        p_new_best_rn[i] = get_selected_route_node(p_rib_entry);
        if (p_orig_best_rn[i] == p_new_best_rn[i]) continue;
        if (p_new_best_rn[i]) {
            // ANNOUNCE
            // asn(4) + oprt_type(1) + route(route_size)
            *p_sent_msg_size += 5 + get_route_size(p_new_best_rn[i]->route);
        } else {
            // WITHDRAW
            // asn(4) + oprt_type(1)
            *p_sent_msg_size += 5;
        }
        pp_sent_msg_num++;
    }
    if (!pp_sent_msg_num)  return SUCCESS;
    *p_sent_msg_size += 4; // pp_sent_msg_num(4)
    int offset = 0;
    //int ret;
    *pp_sent_msg = malloc(*p_sent_msg_size);
    *((int *) *pp_sent_msg) = pp_sent_msg_num;
    offset += 4;
    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        if (p_orig_best_rn[i] == p_new_best_rn[i]) continue;

        *((uint32_t *) ((uint8_t *) *pp_sent_msg + offset)) = i;
        offset += 4;
        if (p_new_best_rn[i]) {
            // ANNOUNCE
            *((uint8_t *) *pp_sent_msg + offset) = ANNOUNCE;
            offset++;
            //ret = write_route_msg((uint8_t *) *pp_sent_msg + offset, p_new_best_rn[i]->route);
            //offset += ret;
            //printf("asn:%d, write:%d bytes, ", i, ret);
            //print_route(p_new_best_rn[i]->route);
            offset += write_route_msg((uint8_t *) *pp_sent_msg + offset, p_new_best_rn[i]->route);
        } else {
            // WITHDRAW
            *((uint8_t *) *pp_sent_msg + offset) = WITHDRAW;
            offset++;
        }
    }

    return SUCCESS;
}

uint32_t print_rs_ribs(rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    route_node_t *p_best_rn = NULL;

    for (i = 0; i < num; i++) {
        printf("asn: %d:\n", i);
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            p_best_rn = get_selected_route_node(p_rib_entry);
            if (p_best_rn) {
                printf("next_hop: %d, route: ", p_best_rn->next_hop);
                print_route(p_best_rn->route);
            }
        }
    }
    return SUCCESS;
}

uint32_t update_route(void *msg, size_t msg_size)
{
    int msg_num = *((int *) msg), i = 0, offset = 4;
    uint32_t asn;
    uint8_t oprt_type;
    route_t *p_route = NULL;
    printf("update msg num:%d, msg_size:%lu\n", msg_num, msg_size);
    for (i = 0; i < msg_num; i++) {
        asn = *((uint32_t *) ((uint8_t *) msg + offset));
        offset += 4;
        oprt_type = *((uint8_t *) msg + offset);
        offset++;
        printf("msg_id:%d, asn:%u, oprt_type:%u\n", i, asn, oprt_type);
        if (oprt_type == ANNOUNCE) {
            offset += parse_route_from_channel(&p_route, (uint8_t *) msg + offset);
            print_route(p_route);
            free_route(&p_route);
        }
    }
    assert(msg_size == offset);

    return SUCCESS;
}
