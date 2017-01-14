#ifndef _APP_H_
#define _APP_H_

#include "const.h"

extern char g_rn_to_agnt_mq_name[AGNT_NUM][STR_LEN]; // remote network to agent
extern char g_agnt_to_rn_mq_name[AGNT_NUM][STR_LEN]; // agent to remote network

extern char g_ln_to_agnt_mq_name[AGNT_NUM][STR_LEN]; // local network to agent
extern char g_agnt_to_ln_mq_name[AGNT_NUM][STR_LEN]; // agent to local network

void app_init(int efd, char *port);

#endif
