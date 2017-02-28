#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#include <stdint.h>

#define IO_STREAM stdout

#define BGP_UPDATE_FILE "conf/bgp_update.conf"
#define AS_TOPO_FILE    "conf/as.conf"

#define GLOBAL_ACCESS   0
#define MSG_QUEUE       1

#define VERBOSE         1

// next hop policy type
// import_policy[total_num] for route selection
//      import_policy[i] means the order of as i route
//      the lower the value is, the higher selection order the as route is
// export_policy[total_num][total_num] for route announcement
//      export_policy[i][j] means sending routes that which next hop is as i to as j
typedef struct {
    uint32_t asn;
    uint32_t total_num;
    uint8_t *import_policy;
    uint8_t *export_policy;
} as_conf_t;

#endif
