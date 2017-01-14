#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bgp.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

char *my_strdup(const char *s)
{
    int l = strlen(s);
    char *d = malloc(l + 1);
    if (!d) return NULL;
    memcpy(d, s, l);
    d[l] = '\0';
    return d;
}

void free_route(route_t **pp_route)
{
    if (!pp_route || *pp_route) {
        return;
    }
    SAFE_FREE((*pp_route)->prefix);
    SAFE_FREE((*pp_route)->neighbor);
    SAFE_FREE((*pp_route)->next_hop);
    SAFE_FREE((*pp_route)->origin);
    SAFE_FREE((*pp_route)->as_path.asns);
    SAFE_FREE((*pp_route)->communities);
    SAFE_FREE(*pp_route);
}

void free_rib(rib_t **pp_rib)
{
    route_entry_t *tmp, *iter;
    if (!pp_rib || *pp_rib) {
        return;
    }

    iter = (*pp_rib)->head;
    while (iter) {
        tmp = iter;
        iter = iter->next;
        free_route(&tmp->route);
    }
    SAFE_FREE(*pp_rib);
}

void print_route(route_t *p_route)
{
    int i;
    if (!p_route) {
        return;
    }
    printf("%s,%s,%s,%s,", p_route->prefix, p_route->neighbor, p_route->next_hop, p_route->origin);
    if (!p_route->as_path.length) {
        printf(" ,");
    } else {
        for (i = 0; i < p_route->as_path.length - 1; i++) {
            printf("%d ", p_route->as_path.asns[i]);
        }
        printf("%d,", p_route->as_path.asns[i]);
    }
    printf("%s,%d,%d\n", p_route->communities, p_route->med, p_route->atomic_aggregate);
}

void print_rib(rib_t *p_rib)
{
    route_entry_t *iter;
    if (!p_rib) {
        return;
    }

    iter = p_rib->head;
    while (iter) {
        if (iter->is_selected) {
            printf("* ");
        } else {
            printf("  ");
        }
        print_route(iter->route);
        iter = iter->next;
    }
}

void parse_as_path_from_file(as_path_t *p_as_path, char *p_s_as_path)
{
    int delimiter_count = 0, i;
    char *token, *p_save, *p_s_as_path_tmp;
    char *delimiter = AS_PATH_DELIMITER_STR;

    if (!p_as_path || !p_s_as_path) {
        return;
    }

    if (strlen(p_s_as_path) == 1 && p_s_as_path[0] == AS_PATH_DELIMITER_CHAR) {
        p_as_path->length = 0;
        p_as_path->asns = NULL;
        return;
    }

    p_s_as_path_tmp = p_s_as_path;
    // ensure that we have correct delimiter number in the input
    while (*p_s_as_path_tmp) {
        delimiter_count += (*p_s_as_path_tmp++ == AS_PATH_DELIMITER_CHAR);
    }

    p_as_path->length = delimiter_count + 1;
    p_as_path->asns = malloc(sizeof(*p_as_path->asns) * (p_as_path->length));

    token = strtok_r(p_s_as_path, delimiter, &p_save);
    p_as_path->asns[0] = atoi(token);
    for (i = 1; i < p_as_path->length; i++) {
        token = strtok_r(0, delimiter, &p_save);
        p_as_path->asns[i] = atoi(token);
    }
}

void parse_route_from_file(route_t **pp_route, char *p_s_route)
{
    int delimiter_count = 0;
    char *token, *p_save, *p_s_route_tmp;
    char *delimiter = ROUTE_DELIMITER_STR;

    if (!pp_route || *pp_route || !p_s_route) {
        return;
    }

    // ensure that we have correct delimiter number in the input
    p_s_route_tmp = p_s_route;
    while (*p_s_route_tmp) {
        delimiter_count += (*p_s_route_tmp++ == ROUTE_DELIMITER_CHAR);
    }
    assert(delimiter_count == ROUTE_FIELD - 1);

    *pp_route = malloc(sizeof(route_t));
    if (!*pp_route) {
        return;
    }

    token = strtok_r(p_s_route, delimiter, &p_save);
    (*pp_route)->prefix = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->neighbor = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->next_hop = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->origin = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    parse_as_path_from_file(&(*pp_route)->as_path, token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->communities = my_strdup(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->med = atoi(token);
    token = strtok_r(0, delimiter, &p_save);
    (*pp_route)->atomic_aggregate = atoi(token);
}

void parse_route_from_channel(route_t **pp_route, uint8_t *p_s_route)
{
    int offset = 0;
    uint32_t size = 0;

    if (!pp_route || *pp_route || !p_s_route) {
        return;
    }

    *pp_route = malloc(sizeof(route_t));
    if (!*pp_route) {
        return;
    }

    size = *((uint8_t *) p_s_route);
    offset++;
    (*pp_route)->prefix = malloc(size + 1);
    memcpy((*pp_route)->prefix, p_s_route + offset, size);
    (*pp_route)->prefix[size] = '\0';
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->neighbor = malloc(size + 1);
    memcpy((*pp_route)->neighbor, p_s_route + offset, size);
    (*pp_route)->neighbor[size] = '\0';
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->next_hop = malloc(size + 1);
    memcpy((*pp_route)->next_hop, p_s_route + offset, size);
    (*pp_route)->next_hop[size] = '\0';
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->origin = malloc(size + 1);
    memcpy((*pp_route)->origin, p_s_route + offset, size);
    (*pp_route)->origin[size] = '\0';
    offset += size;

    size = *((uint32_t *) (p_s_route + offset));
    offset += 4;
    (*pp_route)->as_path.length = size / sizeof(int);
    (*pp_route)->as_path.asns = malloc(size);
    memcpy((*pp_route)->as_path.asns, p_s_route + offset, size);
    offset += size;

    size = *((uint8_t *) p_s_route + offset);
    offset++;
    (*pp_route)->communities = malloc(size + 1);
    memcpy((*pp_route)->communities, p_s_route + offset, size);
    (*pp_route)->communities[size] = '\0';
    offset += size;

    (*pp_route)->med = *((int *) (p_s_route + offset));
    offset += sizeof(int);
    (*pp_route)->atomic_aggregate = *((int *) (p_s_route + offset));
}

void generate_exch_route(exch_route_t **pp_exch_route, int *p_exch_route_size, route_t *input, as_para_t *p_as_para, uint8_t export_policy_class, uint8_t oprt_type)
{
    int offset = 0;
    if (!pp_exch_route || *pp_exch_route || !p_exch_route_size || !input) {
        return;
    }

    *p_exch_route_size = 0;
    *p_exch_route_size += strlen(input->prefix);
    *p_exch_route_size += strlen(input->neighbor);
    *p_exch_route_size += strlen(input->next_hop);
    *p_exch_route_size += strlen(input->origin);
    *p_exch_route_size += sizeof(int) * input->as_path.length;
    *p_exch_route_size += strlen(input->communities);
    *p_exch_route_size += sizeof(int);          // med
    *p_exch_route_size += sizeof(int);          // atomic_aggregate
    *p_exch_route_size += 11;                   // header count
    if (p_as_para) {
        *p_exch_route_size += sizeof(int);      // append as own number
    }

    *pp_exch_route = calloc(1, sizeof(exch_route_t) + *p_exch_route_size);
    if (!*pp_exch_route) {
        return;
    }

    // copy each field and add number header for each field
    (*pp_exch_route)->export_policy_class = export_policy_class;
    (*pp_exch_route)->oprt_type = oprt_type;
    *((uint8_t *) (*pp_exch_route)->route) = (uint8_t) strlen(input->prefix);
    offset++;
    memcpy((*pp_exch_route)->route + offset, input->prefix, strlen(input->prefix));
    offset += strlen(input->prefix);

    *((uint8_t *) (*pp_exch_route)->route + offset) = (uint8_t) strlen(input->neighbor);
    offset++;
    memcpy((*pp_exch_route)->route + offset, input->neighbor, strlen(input->neighbor));
    offset += strlen(input->neighbor);

    *((uint8_t *) (*pp_exch_route)->route + offset) = (uint8_t) strlen(input->next_hop);
    offset++;
    memcpy((*pp_exch_route)->route + offset, input->next_hop, strlen(input->next_hop));
    offset += strlen(input->next_hop);

    *((uint8_t *) (*pp_exch_route)->route + offset) = (uint8_t) strlen(input->origin);
    offset++;
    memcpy((*pp_exch_route)->route + offset, input->origin, strlen(input->origin));
    offset += strlen(input->origin);

    *((uint32_t *) ((*pp_exch_route)->route + offset)) = sizeof(*input->as_path.asns) * ((p_as_para) ? input->as_path.length + 1 : input->as_path.length);
    offset += 4;
    if (p_as_para) {
        memcpy((*pp_exch_route)->route + offset, &p_as_para->asn, sizeof(int));
        offset += 4;
    }
    if (input->as_path.length) {
        memcpy((*pp_exch_route)->route + offset, input->as_path.asns, sizeof(*input->as_path.asns) * input->as_path.length);
        offset += sizeof(*input->as_path.asns) * input->as_path.length;
    }

    *((uint8_t *) (*pp_exch_route)->route + offset) = (uint8_t) strlen(input->communities);
    offset++;
    memcpy((*pp_exch_route)->route + offset, input->communities, strlen(input->communities));
    offset += strlen(input->communities);

    memcpy((*pp_exch_route)->route + offset, &input->med, sizeof(input->med));
    offset += sizeof(input->med);

    memcpy((*pp_exch_route)->route + offset, &input->atomic_aggregate, sizeof(input->atomic_aggregate));
}

int _route_cmp(route_t *r1, route_t *r2)
{
    /*------- lowest path length -------*/
    if (r1->as_path.length > r2->as_path.length) {
        return -1;
    } else if (r1->as_path.length < r2->as_path.length) {
        return 1;
    } else {
        /*------- lowest med -------*/
        if (r1->med > r2->med) {
            return -1;
        } else if (r1->med < r2->med) {
            return 1;
        } else {
            /*------- lowest next_hop -------*/
            if (strcmp(r1->next_hop, r2->next_hop) > 0) {
                return -1;
            } else {
                return 1;
            }
        }
    }
}

route_entry_t *_get_rib_best_entry_by_prefix(rib_t *p_rib, char *prefix)
{
    if (!p_rib) {
        return NULL;
    }

    route_entry_t *tmp = p_rib->head;

    while (tmp) {
        if (!strcmp(tmp->route->prefix, prefix)) {
            if (tmp->is_selected) {
                return tmp;
            } else {
                tmp = tmp->next;
            }
        } else {
            tmp = tmp->next;
        }
    }

    return tmp;
}

// return: 1 best route changed, 0 best route not chagned
int add_rib_entry(rib_t *p_rib, route_t **old_best_route, route_t *p_route)
{
    int ret;
    route_entry_t *entry, *new_route;

    if (!p_rib || !old_best_route || *old_best_route || !p_route) {
        return 0;
    }

    entry = _get_rib_best_entry_by_prefix(p_rib, p_route->prefix);
    new_route = malloc(sizeof(route_entry_t));
    new_route->prev = NULL;
    new_route->next = NULL;
    if (!entry) {
        // input prefix doesnot exist
        // insert route to head
        new_route->is_selected = 1;
        ret = 1;
    } else {
        // input prefix exists
        // compare with the best route
        if (_route_cmp(entry->route, p_route) > 0) {
            new_route->is_selected = 0;
            ret = 0;
        } else {
            entry->is_selected = 0;
            new_route->is_selected = 1;
            *old_best_route = entry->route;
            ret = 1;
        }
    }

    p_rib->size++;
    new_route->route = p_route;
    new_route->next = p_rib->head;
    if (p_rib->head) {
        p_rib->head->prev = new_route;
    }
    p_rib->head = new_route;
    return ret;
}

// return: 1 best route deleted, 0 best route not deleted
int _del_rib_entry_by_route(rib_t *p_rib, route_t *p_route)
{
    int ret;
    route_entry_t *tmp;
    tmp = p_rib->head;

    while (tmp) {
        if (!strcmp(tmp->route->prefix, p_route->prefix)
                && !strcmp(tmp->route->next_hop, p_route->next_hop)) {
            tmp->next->prev = tmp->prev;
            tmp->prev->next = tmp->next;
            ret = tmp->is_selected;
            free_route(&tmp->route);
            p_rib->size++;
            return ret;
        } else {
            tmp->next = tmp;
        }
    }

    return 0;
}

// return: 1 best route changed, 0 best route not chagned
int del_rib_entry(rib_t *p_rib, route_t **new_best_route, route_t *del_route)
{
    route_entry_t *cur_best = NULL, *tmp;

    if (!p_rib || !new_best_route || *new_best_route || !del_route) {
        return 0;
    }

    // delete the target route
    if (!_del_rib_entry_by_route(p_rib, del_route)) {
        return 0;
    }

    // if the best route is deleted, we need find the new one
    tmp = p_rib->head;
    while (tmp) {
        if (!strcmp(tmp->route->prefix, del_route->prefix)) {
            if (!cur_best) {
                cur_best = tmp;
            } else {
                if (_route_cmp(cur_best->route, tmp->route) > 0) {
                    tmp = tmp->next;
                } else {
                    cur_best = tmp;
                    tmp = tmp->next;
                }
            }
        } else {
            tmp = tmp->next;
        }
    }
    if (cur_best) {
        cur_best->is_selected = 1;
        *new_best_route = cur_best->route;
    }
    return 1;
}
