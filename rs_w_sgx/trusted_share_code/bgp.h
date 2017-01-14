#ifndef _BGP_H_
#define _BGP_H_

#define ROUTE_FIELD             8
#define ROUTE_DELIMITER_CHAR    ','
#define ROUTE_DELIMITER_STR     ","
#define AS_PATH_DELIMITER_CHAR  ' '
#define AS_PATH_DELIMITER_STR   " "

// oprt_type
#define ANNOUNCE                1
#define WITHDRAW                2

// export_policy_class
#define CUSTOMER                0
#define PEER                    1
#define PROVIDER                2
#define POLICY_CLASS_NUM        3

#include <stdint.h>
#include "const.h"

typedef struct {
    int length;
    int *asns;
} as_path_t;

typedef struct {
    char *prefix;
    char *neighbor;
    char *next_hop;
    char *origin;
    as_path_t as_path;
    char *communities;
    int med;
    int atomic_aggregate;
} route_t;

typedef struct {
    int asn;
} as_para_t;

typedef struct {
    uint8_t export_policy_class;
    uint8_t oprt_type;
    uint8_t route[];
} exch_route_t;

typedef struct _route_entry route_entry_t;

struct _route_entry {
    uint8_t is_selected;
    route_t *route;
    route_entry_t *prev;
    route_entry_t *next;
};

typedef struct {
    int size;
    route_entry_t *head;
} rib_t;

typedef uint32_t export_policy_t[POLICY_CLASS_NUM][AS_NUM];

void free_rib(rib_t **pp_rib);
void print_route(route_t *p_route);
void print_rib(rib_t *p_rib);
void parse_route_from_file(route_t **pp_route, char *p_s_route);
void parse_route_from_channel(route_t **pp_route, uint8_t *p_s_route);
void generate_exch_route(exch_route_t **pp_exch_route, int *p_exch_route_size, route_t *input, as_para_t *p_as_para, uint8_t export_policy_class, uint8_t oprt_type);
int add_rib_entry(rib_t *p_rib, route_t **old_best_route, route_t *p_route);
int del_rib_entry(rib_t *p_rib, route_t **new_best_route, route_t *del_route);

#endif
