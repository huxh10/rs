#ifndef __RS_H__
#define __RS_H__

uint32_t compute_route_by_msg_queue(void *msg, size_t msg_size, as_conf_t *p_policies, rib_map_t **pp_ribs, uint32_t num, void **pp_sent_msg, size_t *p_sent_msg_size);

uint32_t compute_route_by_global_access(void *msg, size_t msg_size, as_conf_t *p_policies, simplified_rib_map_t **pp_ribs, uint32_t num, void **pp_sent_msg, size_t *p_sent_msg_size);

uint32_t print_rs_ribs(rib_map_t **pp_ribs, uint32_t num);

uint32_t print_rs_simplified_ribs(simplified_rib_map_t **pp_ribs, uint32_t num);

uint32_t update_route(void *msg, size_t msg_size);

uint32_t update_simplified_route(void *msg, size_t msg_size);

#endif
