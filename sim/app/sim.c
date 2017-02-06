#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <unistd.h>
#include "datatypes.h"
#include "const.h"
#include "bgp.h"

#ifdef W_SGX
#include "rs_w_sgx.h"
#else
#include "rs_wo_sgx.h"
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

static struct {
    char *trace_file;
    int method;
    int verbose;
} cfg = {NULL, MSG_QUEUE, 0};

static void print_help(void)
{
    static const char *help = 

        "Valid options:\n"
        "   -h, --help              display this help and exit\n"
        "   -v, --verbose num       0(default): print selected time, 1: print all the even time, 2: print all the odd time, 3: print all the time, 4: print the ribs\n"
        "   -t, --trace_file FILE   specify a trace file to process, default is conf/bgp_update.conf\n"
        "   -m, --method STR        specify the computation method global_access, msg_queue, default is msg_queue\n"
        "\n";

    printf("%s\n", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;
    static const char *optstr = "hv:t:m:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"verbose", required_argument, NULL, 'v'},
        {"trace_file", required_argument, NULL, 't'},
        {"method", required_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch(option) {
            case 'h':
                print_help();
                exit(0);

            case 'v':
                cfg.verbose = atoi(optarg);
                break;

            case 't':
                if (access(optarg, F_OK) == -1) {
                    perror(optarg);
                    exit(-1);
                } else {
                    cfg.trace_file = optarg;
                    break;
                }

            case 'm':
                if (strcmp(optarg, "msg_queue") == 0) {
                    cfg.method = MSG_QUEUE;
                } else if (strcmp(optarg, "global_access") == 0) {
                    cfg.method = GLOBAL_ACCESS;
                }
                break;

            default:
                print_help();
                exit(-1);
        }
    }

    return;
}

static void load_as_conf(uint32_t *p_total_num, as_conf_t **pp_as_conf)
{
    uint32_t i = 0, j = 0;
    assert(p_total_num != NULL && pp_as_conf != NULL);

    // TODO load configuration from file
    *p_total_num = N;
    *pp_as_conf = malloc(*p_total_num * sizeof **pp_as_conf);
    if (!*pp_as_conf) {
        fprintf(IO_STREAM, "Malloc error for pp_as_conf [%s]\n", __FUNCTION__);
        return;
    }

    for (i = 0; i < *p_total_num; i++) {
        (*pp_as_conf)[i].asn = i;
        (*pp_as_conf)[i].total_num = *p_total_num;
        (*pp_as_conf)[i].import_policy = malloc(*p_total_num * sizeof *(*pp_as_conf)[i].import_policy);
        memcpy((*pp_as_conf)[i].import_policy, g_import_policies[i], *p_total_num * sizeof *(*pp_as_conf)[i].import_policy);
        (*pp_as_conf)[i].export_policy = malloc(*p_total_num * *p_total_num * sizeof *(*pp_as_conf)[i].export_policy);
        for (j = 0; j < *p_total_num; j++) {
            memcpy((*pp_as_conf)[i].export_policy + j * *p_total_num, g_export_policies[i][j], *p_total_num * sizeof *(*pp_as_conf)[i].export_policy);
        }
    }
}

static void load_bgp_update(int *p_msg_num, bgp_msg_t ***ppp_bgp_msgs)
{
    int i = 0, msg_num = 0, asn = 0, oprt_type = 0;
    size_t read_bytes, len;
    char *line = NULL;
    route_t *tmp_route = NULL;
    FILE *fp;

    assert(ppp_bgp_msgs != NULL);

    if ((fp = fopen(cfg.trace_file, "r")) == NULL) {
        fprintf(IO_STREAM, "can not open file: %s [%s]\n", BGP_UPDATE_FILE, __FUNCTION__);
        exit(-1);
    }

    if (fscanf(fp, "%d\n", &msg_num) != 1) {
        fprintf(IO_STREAM, "illegal msg_num format [%s]\n", __FUNCTION__);
        exit(-1);
    }
    *p_msg_num = msg_num;

    *ppp_bgp_msgs = malloc(msg_num * sizeof **ppp_bgp_msgs);
    for (i = 0; i < msg_num; i++) {
        (*ppp_bgp_msgs)[i] = NULL;
    }

    for (i = 0; i < msg_num; i++) {
        if (fscanf(fp, "%d %d\n", &asn, &oprt_type) != 2) {
            fprintf(IO_STREAM, "illegal asn oprt_type format [%s]\n", __FUNCTION__);
            exit(-1);
        }
        read_bytes = getline(&line, &len, fp);
        line[read_bytes - 1] = '\0';    // strip '\n'
        parse_route_from_file(&tmp_route, line);
        if (tmp_route) {
            if (cfg.verbose == 4) {
                fprintf(IO_STREAM, "get one bgp update msg from asn:%d oprt_type:%d content:\n", asn, oprt_type);
                print_route(tmp_route);
            }
            generate_bgp_msg(&(*ppp_bgp_msgs)[i], tmp_route, asn, oprt_type);
            free_route(&tmp_route);
        }
        assert((*ppp_bgp_msgs)[i] != NULL);
    }
    SAFE_FREE(line);
}

int main(int argc, char *argv[])
{
    uint32_t total_num = 0;
    as_conf_t *p_as_conf = NULL;
    int msg_num = 0;
    bgp_msg_t **pp_bgp_msgs = NULL;

    parse_args(argc, argv);
    if (!cfg.trace_file) {
        cfg.trace_file = BGP_UPDATE_FILE;
    }

    load_as_conf(&total_num, &p_as_conf);
    load_bgp_update(&msg_num, &pp_bgp_msgs);
    fprintf(IO_STREAM, "loading passed\n");
    if (cfg.method == GLOBAL_ACCESS) {
        printf("computation method: global_access\n");
    } else if (cfg.method == MSG_QUEUE) {
        printf("computation method: msg_queue\n");
    }

#ifdef W_SGX
    printf("wsgx\n");
    init_rs_w_sgx(total_num, p_as_conf);
    run_rs_w_sgx(msg_num, pp_bgp_msgs, cfg.method, cfg.verbose);
#else
    printf("wosgx\n");
    init_rs_wo_sgx(total_num, p_as_conf);
    run_rs_wo_sgx(msg_num, pp_bgp_msgs, cfg.method, cfg.verbose);
#endif

    return 0;
}
