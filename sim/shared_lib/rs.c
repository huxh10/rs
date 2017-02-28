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

uint32_t compute_route_by_msg_queue(void *msg, size_t msg_size, as_conf_t *p_policies, rib_map_t **pp_ribs, uint32_t num, void **pp_sent_msg, size_t *p_sent_msg_size)
{
    uint32_t i = 0, orig_sender_asn = 0;
    char *key = NULL;
    bgp_msg_t *p_bgp_msg = msg;
    assert(p_bgp_msg->msg_size == msg_size);
    route_t *p_route = NULL;
    rs_inner_msg_t *tmp_p_inner_msg = NULL;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    int processed_as_num_in_one_loop = 0, iteration = 0;
    int sent_msg_num = 0;

    // TODO change pointer to uuid
    route_node_t *p_orig_best_rn[num];
    route_node_t *p_old_best_rn[num];
    route_node_t *p_new_best_rn[num];
    for (i = 0; i < num; i++) {
        p_orig_best_rn[i] = NULL;
        p_old_best_rn[i] = NULL;
        p_new_best_rn[i] = NULL;
    }

    // get original sender asn
    orig_sender_asn = p_bgp_msg->asn;

    // get original route from msg
    parse_route_from_channel(&p_route, p_bgp_msg->route);
    assert(p_route);
    assert(p_route->as_path.asns);
    key = my_strdup(p_route->prefix);

    // record original rib entries
    route_node_t *p_curr_rns[num];
    for (i = 0; i < num; i++) {
        HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
        p_curr_rns[i] = p_rib_entry ? p_rib_entry->routes : NULL;
        p_orig_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
    }

    // initialize inner msg lists for exchange
    rs_inner_msg_t **pp_inner_msgs = malloc(num * sizeof *pp_inner_msgs);
    for (i = 0; i < num; i++) {
        pp_inner_msgs[i] = NULL;
    }

    // add received bgp_msg to asn list
    tmp_p_inner_msg = malloc(sizeof *tmp_p_inner_msg);
    //tmp_p_inner_msg->src_asn = p_route->as_path.asns[0];
    tmp_p_inner_msg->src_asn = p_bgp_msg->next_hop;
    tmp_p_inner_msg->oprt_type = p_bgp_msg->oprt_type;
    tmp_p_inner_msg->src_route = p_route;
    tmp_p_inner_msg->next = tmp_p_inner_msg;
    tmp_p_inner_msg->prev = tmp_p_inner_msg;
    pp_inner_msgs[orig_sender_asn] = tmp_p_inner_msg;

    while (1) {
        // iterate until routes are converged
        iteration++;
        processed_as_num_in_one_loop = 0;

        // process msgs to each as
        for (i = 0; i < num; i++) {
            if (pp_inner_msgs[i] == NULL) continue;
            p_old_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
            while (pp_inner_msgs[i]) {
                // FIFO process
                tmp_p_inner_msg = pp_inner_msgs[i]->prev;

                // update entry
                if (tmp_p_inner_msg->oprt_type == ANNOUNCE) {
                    //printf("iteration:%d, asn:%u, receive ANNOUNCE msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    add_route(&p_curr_rns[i], tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy);
                } else if (tmp_p_inner_msg->oprt_type == WITHDRAW) {
                    //printf("iteration:%d, asn:%u, receive WITHDRAW msg from:%d\n", iteration, i, tmp_p_inner_msg->src_asn);
                    del_route(&p_curr_rns[i], tmp_p_inner_msg->src_asn, tmp_p_inner_msg->src_route, p_policies[i].import_policy, p_old_best_rn[i]);
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
            p_new_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
            /*
            if (p_new_best_rn[i]) {
                printf("as:%d new best after this iteration: ", i);
                print_route(p_new_best_rn[i]->route);
            } else {
                printf("as:%d new best after this iteration: NULL\n", i);
            }
            */
        }
        // add potential msgs to next iteration
        for (i = 0; i < num; i++) {
            if (p_old_best_rn[i] == p_new_best_rn[i]) continue;
            //printf("asn:%d prepares to send inner msg\n", i);
            // execute export policies and update inner msg lists 
            if (p_old_best_rn[i]) {
                //printf("    old next_hop:%u\n", p_old_best_rn[i]->next_hop);
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_old_best_rn[i]->next_hop, WITHDRAW, NULL);
                if (p_old_best_rn[i]->is_selected == TO_BE_DEL) {
                    free_route(&p_old_best_rn[i]->route);
                    SAFE_FREE(p_old_best_rn[i]);
                }
            }
            if (p_new_best_rn[i]) {
                //printf("    new next_hop:%u\n", p_new_best_rn[i]->next_hop);
                execute_export_policy(pp_inner_msgs, num, p_policies[i].export_policy, i, p_new_best_rn[i]->next_hop, ANNOUNCE, p_new_best_rn[i]->route);
            }
            p_old_best_rn[i] = NULL;
            p_new_best_rn[i] = NULL;
            processed_as_num_in_one_loop++;
        }

        // converged
        if (!processed_as_num_in_one_loop) break;
    }

    SAFE_FREE(pp_inner_msgs);

    // update the sender rib
    p_new_best_rn[orig_sender_asn] = get_selected_route_node(p_curr_rns[orig_sender_asn]);
    if (p_orig_best_rn[orig_sender_asn] != p_new_best_rn[orig_sender_asn]) {
        if (p_new_best_rn[orig_sender_asn]) {
            HASH_FIND_STR(pp_ribs[orig_sender_asn], key, p_rib_entry);
            if (p_rib_entry) {
                p_rib_entry->routes = p_curr_rns[orig_sender_asn];
            } else {
                p_rib_entry = malloc(sizeof *p_rib_entry);
                p_rib_entry->key = my_strdup(key);
                p_rib_entry->routes = p_curr_rns[orig_sender_asn];
                HASH_ADD_KEYPTR(hh, pp_ribs[orig_sender_asn], p_rib_entry->key, strlen(key), p_rib_entry);
            }
        } else {
            HASH_FIND_STR(pp_ribs[orig_sender_asn], key, p_rib_entry);
            HASH_DEL(pp_ribs[orig_sender_asn], p_rib_entry);
            SAFE_FREE(p_rib_entry->key);
            SAFE_FREE(p_rib_entry);
        }
    }

    // send updated routes back and update related ribs
    *p_sent_msg_size = 0;
    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        p_new_best_rn[i] = get_selected_route_node(p_curr_rns[i]);
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
        sent_msg_num++;
    }
    if (!sent_msg_num)  return SUCCESS;
    *p_sent_msg_size += 4; // sent_msg_num(4)
    int offset = 0;
    //int ret;
    *pp_sent_msg = malloc(*p_sent_msg_size);
    *((int *) *pp_sent_msg) = sent_msg_num;
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
            // rib operation
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            if (p_rib_entry) {
                p_rib_entry->routes = p_curr_rns[i];
            } else {
                p_rib_entry = malloc(sizeof *p_rib_entry);
                p_rib_entry->key = my_strdup(key);
                p_rib_entry->routes = p_curr_rns[i];
                HASH_ADD_KEYPTR(hh, pp_ribs[i], p_rib_entry->key, strlen(key), p_rib_entry);
            }
        } else {
            // WITHDRAW
            *((uint8_t *) *pp_sent_msg + offset) = WITHDRAW;
            offset++;
            // rib operation
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            HASH_DEL(pp_ribs[i], p_rib_entry);
            SAFE_FREE(p_rib_entry->key);
            SAFE_FREE(p_rib_entry);
        }
    }

    return SUCCESS;
}

uint32_t compute_route_by_global_access(void *msg, size_t msg_size, as_conf_t *p_policies, simplified_rib_map_t **pp_ribs, uint32_t num, void **pp_sent_msg, size_t *p_sent_msg_size)
{
    uint32_t i = 0, j = 0, orig_sender_asn = 0;
    char *key = NULL;
    bgp_msg_t *p_bgp_msg = msg;
    assert(p_bgp_msg->msg_size == msg_size);
    route_t *p_route = NULL;
    simplified_rib_map_t *p_rib_entry = NULL;
    int processed_as_num_in_one_loop = 0, iteration = 0;
    int sent_msg_num = 0;

    uint8_t orig_is_valid[num];
    uint32_t orig_next_hop[num];
    uint8_t curr_is_valid[num];
    uint32_t curr_next_hop[num];
    for (i = 0; i < num; i++) {
        orig_is_valid[i] = 0;
        orig_next_hop[i] = 0;
        curr_is_valid[i] = 0;
        curr_next_hop[i] = 0;
    }

    // get original sender asn
    orig_sender_asn = p_bgp_msg->asn;

    // get original route from msg
    parse_route_from_channel(&p_route, p_bgp_msg->route);
    assert(p_route);
    assert(p_route->as_path.asns);
    key = my_strdup(p_route->prefix);

    // record original rib entries
    for (i = 0; i < num; i++) {
        HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
        if (p_rib_entry) {
            orig_is_valid[i] = 1;
            orig_next_hop[i] = p_rib_entry->next_hop;
            curr_is_valid[i] = 1;
            curr_next_hop[i] = p_rib_entry->next_hop;
        }
    }

    // process the sender route
    HASH_FIND_STR(pp_ribs[orig_sender_asn], key, p_rib_entry);
    if (p_bgp_msg->oprt_type == ANNOUNCE) {
        if (!p_rib_entry) {
            printf("iteration:0, asn:%u, create next_hop:%u\n", orig_sender_asn, p_bgp_msg->next_hop);
            p_rib_entry = malloc(sizeof *p_rib_entry);
            p_rib_entry->key = key;
            p_rib_entry->next_hop = p_bgp_msg->next_hop;
            HASH_ADD_KEYPTR(hh, pp_ribs[orig_sender_asn], key, strlen(key), p_rib_entry);
            curr_is_valid[orig_sender_asn] = 1;
            curr_next_hop[orig_sender_asn] = p_bgp_msg->next_hop;
        } else {
            printf("iteration:0, asn:%u, update next_hop:%u\n", orig_sender_asn, p_bgp_msg->next_hop);
            p_rib_entry->next_hop = p_bgp_msg->next_hop;
            curr_next_hop[orig_sender_asn] = p_bgp_msg->next_hop;
        }
    } else {
        if (p_rib_entry) {
            printf("iteration:0, asn:%u, WITHDRAW next_hop:%u\n", orig_sender_asn, p_rib_entry->next_hop);
            HASH_DEL(pp_ribs[orig_sender_asn], p_rib_entry);
            SAFE_FREE(p_rib_entry->key);
            SAFE_FREE(p_rib_entry);
            curr_is_valid[orig_sender_asn] = 0;
        }
    }

    // we'll update other ribs after routes are converged
    while (1) {
        // iterate until routes are converged
        iteration++;
        processed_as_num_in_one_loop = 0;

        // process msgs to each as
        for (i = 0; i < num; i++) {
            if (i == orig_sender_asn) continue;
            // WITHDRAW check first
            if (curr_is_valid[i] && !curr_is_valid[curr_next_hop[i]]) {
                printf("iteration:%u, asn:%u, WITHDRAW next_hop:%u\n", iteration, i, curr_next_hop[i]);
                curr_is_valid[i] = 0;
                processed_as_num_in_one_loop++;
            }
            for (j = 0; j < num; j++) {
                if (j == i) continue;
                if (!curr_is_valid[j]) continue;
                if (!p_policies[j].export_policy[curr_next_hop[j] * num + i]) continue;
                if (!curr_is_valid[i]) {
                    curr_is_valid[i] = 1;
                    curr_next_hop[i] = j;
                    processed_as_num_in_one_loop++;
                    printf("iteration:%u, asn:%u, create next_hop:%u\n", iteration, i, j);
                } else if (p_policies[i].import_policy[j] < p_policies[i].import_policy[curr_next_hop[i]]) {
                    curr_next_hop[i] = j;
                    processed_as_num_in_one_loop++;
                    printf("iteration:%u, asn:%u, update next_hop:%u\n", iteration, i, j);
                }
            }
        }

        // converged
        if (!processed_as_num_in_one_loop) break;
    }

    // update ribs and send updated routes back
    *p_sent_msg_size = 0;
    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        //HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
        if (curr_is_valid[i]) {
            if (orig_is_valid[i] && (orig_next_hop[i] == curr_next_hop[i])) continue;
            // ANNOUNCE
            // asn(4) + oprt_type(1) + next_hop(4)
            *p_sent_msg_size += 9;
        } else {
            if (!orig_is_valid[i]) continue;
            // WITHDRAW
            // asn(4) + oprt_type(1)
            *p_sent_msg_size += 5;
        }
        sent_msg_num++;
    }
    if (!sent_msg_num)  return SUCCESS;
    *p_sent_msg_size += 4; // sent_msg_num(4)
    *p_sent_msg_size += 4; // prefix length(4)
    *p_sent_msg_size += strlen(key); // prefix
    int offset = 0;
    *pp_sent_msg = malloc(*p_sent_msg_size);
    *((int *) *pp_sent_msg) = sent_msg_num;
    offset += 4;
    *((int *) ((uint8_t *) *pp_sent_msg + offset)) = strlen(key);
    offset += 4;
    memcpy((uint8_t *) *pp_sent_msg + offset, key, strlen(key));
    offset += strlen(key);
    for (i = 0; i < num; i++) {
        if (i == orig_sender_asn) continue;
        if (curr_is_valid[i]) {
            if (orig_is_valid[i] && (orig_next_hop[i] == curr_next_hop[i])) continue;
            // ANNOUNCE
            // asn(4) + oprt_type(1) + next_hop(4)
            *((uint32_t *) ((uint8_t *) *pp_sent_msg + offset)) = i;
            offset += 4;
            *((uint8_t *) *pp_sent_msg + offset) = ANNOUNCE;
            offset++;
            *((uint32_t *) ((uint8_t *) *pp_sent_msg + offset)) = curr_next_hop[i];
            offset += 4;
            // rib operation
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            if (p_rib_entry) {
                p_rib_entry->next_hop = curr_next_hop[i];
            } else {
                p_rib_entry = malloc(sizeof *p_rib_entry);
                p_rib_entry->key = my_strdup(key);
                p_rib_entry->next_hop = curr_next_hop[i];
                HASH_ADD_KEYPTR(hh, pp_ribs[i], p_rib_entry->key, strlen(key), p_rib_entry);
            }
        } else {
            if (!orig_is_valid[i]) continue;
            // WITHDRAW
            // asn(4) + oprt_type(1)
            *((uint32_t *) ((uint8_t *) *pp_sent_msg + offset)) = i;
            offset += 4;
            *((uint8_t *) *pp_sent_msg + offset) = WITHDRAW;
            offset++;
            // rib operation
            HASH_FIND_STR(pp_ribs[i], key, p_rib_entry);
            HASH_DEL(pp_ribs[i], p_rib_entry);
            SAFE_FREE(p_rib_entry->key);
            SAFE_FREE(p_rib_entry);
        }
    }

    return SUCCESS;
}

uint32_t get_rs_ribs_num(rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i, count = 0;
    rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;
    route_node_t *p_best_rn = NULL;

    for (i = 0; i < num; i++) {
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            count++;
        }
    }
    printf("total ribs entry num: %d\n", count);
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
            p_best_rn = p_rib_entry ? get_selected_route_node(p_rib_entry->routes) : NULL;
            if (p_best_rn) {
                printf("next_hop: %d, route: ", p_best_rn->next_hop);
                print_route(p_best_rn->route);
            }
        }
    }
    return SUCCESS;
}

uint32_t get_rs_simplified_ribs_num(simplified_rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i, count = 0;
    simplified_rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;

    for (i = 0; i < num; i++) {
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            count++;
        }
    }
    printf("total ribs entry num: %d\n", count);
    return SUCCESS;
}

uint32_t print_rs_simplified_ribs(simplified_rib_map_t **pp_ribs, uint32_t num)
{
    uint32_t i;
    simplified_rib_map_t *p_rib_entry = NULL, *tmp_p_rib_entry = NULL;

    for (i = 0; i < num; i++) {
        printf("asn: %d:\n", i);
        HASH_ITER(hh, pp_ribs[i], p_rib_entry, tmp_p_rib_entry) {
            if (p_rib_entry) {
                printf("    prefix:%s, next_hop: %d\n", p_rib_entry->key, p_rib_entry->next_hop);
            }
        }
    }
    return SUCCESS;
}

uint32_t update_route(void *msg, size_t msg_size)
{
    if (!msg) return SUCCESS;
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

uint32_t update_simplified_route(void *msg, size_t msg_size)
{
    if (!msg) return SUCCESS;
    int msg_num = *((int *) msg), prefix_length = 0, i = 0, offset = 4;
    uint32_t asn, next_hop;
    uint8_t oprt_type;
    prefix_length = *((uint32_t *) ((uint8_t *) msg + offset));
    offset += 4;
    char *prefix = malloc(prefix_length + 1);
    memcpy(prefix, (uint8_t *) msg + offset, prefix_length);
    prefix[prefix_length] = '\0';
    offset += prefix_length;
    printf("update msg num:%d, msg_size:%lu, prefix_length:%u, prefix:%s\n", msg_num, msg_size, prefix_length, prefix);
    for (i = 0; i < msg_num; i++) {
        asn = *((uint32_t *) ((uint8_t *) msg + offset));
        offset += 4;
        oprt_type = *((uint8_t *) msg + offset);
        offset++;
        if (oprt_type == ANNOUNCE) {
            next_hop = *((uint32_t *) ((uint8_t *) msg + offset));
            offset += 4;
            printf("msg_id:%d, asn:%u, oprt_type:%u, next_hop:%u\n", i, asn, oprt_type, next_hop);
        } else {
            printf("msg_id:%d, asn:%u, oprt_type:%u\n", i, asn, oprt_type);
        }
    }
    free(prefix);
    assert(msg_size == offset);

    return SUCCESS;
}
