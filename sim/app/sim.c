#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <unistd.h>
#include "datatypes.h"
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
    char *as_topo_file;
    char *trace_file;
    int method;
    int verbose;
} cfg = {NULL, NULL, MSG_QUEUE, 0};

static void print_help(void)
{
    static const char *help = 

        "Valid options:\n"
        "   -h, --help              display this help and exit\n"
        "   -v, --verbose num       0(default): print selected time, 1: print all the even time, 2: print all the odd time, 3: print all the time, 4: print the ribs, 5: print policies\n"
        "   -a, --as_topo_file FILE specify a as topology file to process, default is conf/topo.conf\n"
        "   -t, --trace_file FILE   specify a trace file to process, default is conf/bgp_update.conf\n"
        "   -m, --method STR        specify the computation method global_access, msg_queue, default is msg_queue\n"
        "\n";

    printf("%s\n", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;
    static const char *optstr = "hv:a:t:m:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"verbose", required_argument, NULL, 'v'},
        {"as_topo_file", required_argument, NULL, 'a'},
        {"trace_file", required_argument, NULL, 't'},
        {"method", required_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
            case 'h':
                print_help();
                exit(0);

            case 'v':
                cfg.verbose = atoi(optarg);
                break;

            case 'a':
                if (access(optarg, F_OK) == -1) {
                    perror(optarg);
                    exit(-1);
                } else {
                    cfg.as_topo_file = optarg;
                    break;
                }

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
    uint32_t i, j, r;
    assert(p_total_num != NULL && pp_as_conf != NULL);
    FILE *fp;

    if ((fp = fopen(cfg.as_topo_file, "r")) == NULL) {
        fprintf(IO_STREAM, "can not open file: %s [%s]\n", cfg.as_topo_file, __FUNCTION__);
        exit(-1);
    }

    if (fscanf(fp, "%u\n", p_total_num) != 1) {
        fprintf(IO_STREAM, "illegal total_num and edge_num format [%s]\n", __FUNCTION__);
        exit(-1);
    }

    *pp_as_conf = malloc(*p_total_num * sizeof **pp_as_conf);
    if (!*pp_as_conf) {
        fprintf(IO_STREAM, "Malloc error for pp_as_conf [%s]\n", __FUNCTION__);
        return;
    }

    for (i = 0; i < *p_total_num; i++) {
        (*pp_as_conf)[i].asn = i;
        (*pp_as_conf)[i].total_num = *p_total_num;

        // import_policy
        // 0: me, 1: customer, 2: peer, 3: provider, N: no conn
        (*pp_as_conf)[i].import_policy = malloc(*p_total_num * sizeof *(*pp_as_conf)[i].import_policy);
        for (j = 0; j < *p_total_num; j++) {
            (*pp_as_conf)[i].import_policy[j] = *p_total_num;
        }
        (*pp_as_conf)[i].import_policy[i] = 0;

        // export_policy[N * N] represents policy[N][N]
        // policy[p][q] means if AS i would like to export prefixes
        //      with next_hop p to AS q
        //      0: do not export, 1: export
        // for each AS, export all routes to customers
        //              export customer and its own routes to all others
        (*pp_as_conf)[i].export_policy = malloc(*p_total_num * *p_total_num * sizeof *(*pp_as_conf)[i].export_policy);
        for (j = 0; j < *p_total_num * *p_total_num; j++) {
            (*pp_as_conf)[i].export_policy[j] = 0;
        }
    }

    uint32_t *tmp_customers = malloc(*p_total_num * sizeof(uint32_t));
    uint32_t *tmp_peers = malloc(*p_total_num * sizeof(uint32_t));
    uint32_t *tmp_providers = malloc(*p_total_num * sizeof(uint32_t));
    uint32_t customer_num = 0, peer_num = 0, provider_num = 0;
    for (i = 0; i < *p_total_num; i++) {
        fscanf(fp, "%u", &customer_num);
        for (j = 0; j < customer_num; j++) {
            fscanf(fp, " %u", &tmp_customers[j]);
            (*pp_as_conf)[i].import_policy[tmp_customers[j]] = 1;
        }
        fscanf(fp, "\n");
        fscanf(fp, "%u", &peer_num);
        for (j = 0; j < peer_num; j++) {
            fscanf(fp, " %u", &tmp_peers[j]);
            (*pp_as_conf)[i].import_policy[tmp_peers[j]] = 2;
        }
        fscanf(fp, "\n");
        fscanf(fp, "%u", &provider_num);
        for (j = 0; j < provider_num; j++) {
            fscanf(fp, " %u", &tmp_providers[j]);
            (*pp_as_conf)[i].import_policy[tmp_providers[j]] = 3;
        }
        fscanf(fp, "\n");

        // export_policy
        for (j = 0; j < customer_num; j++) {
            for (r = 0; r < *p_total_num; r++) {
                (*pp_as_conf)[i].export_policy[tmp_customers[j] + r * *p_total_num] = 1;
            }
            for (r = 0; r < peer_num; r++) {
                (*pp_as_conf)[i].export_policy[tmp_customers[j] * *p_total_num + tmp_peers[r]] = 1;
            }
            for (r = 0; r < provider_num; r++) {
                (*pp_as_conf)[i].export_policy[tmp_customers[j] * *p_total_num + tmp_providers[r]] = 1;
            }
            (*pp_as_conf)[i].export_policy[tmp_customers[j] * *p_total_num + tmp_customers[j]] = 0;
        }
        for (r = 0; r < peer_num; r++) {
            (*pp_as_conf)[i].export_policy[i * *p_total_num + tmp_peers[r]] = 1;
        }
        for (r = 0; r < provider_num; r++) {
            (*pp_as_conf)[i].export_policy[i * *p_total_num + tmp_providers[r]] = 1;
        }
    }

    if (cfg.verbose == 5) {
        for (i = 0; i < *p_total_num; i++) {
            printf("AS %u import_policy:\n", i);
            for (j = 0; j < *p_total_num; j++) {
                printf("%u ", (*pp_as_conf)[i].import_policy[j]);
            }
            printf("\n");
        }
        printf("\n");
        for (i = 0; i < *p_total_num; i++) {
            printf("AS %u export_policy:\n", i);
            for (j = 0; j < *p_total_num; j++) {
                for (r = 0; r < *p_total_num; r++) {
                    printf("%u ", (*pp_as_conf)[i].export_policy[r + j * *p_total_num]);
                }
                printf("\n");
            }
            printf("\n");
        }
    }
}

static void load_bgp_update(int *p_total_msg_num, int *p_preloaded_msg_num, bgp_msg_t ***ppp_bgp_msgs)
{
    int i = 0, total_msg_num = 0, preloaded_msg_num = 0, asn = 0, oprt_type = 0;
    size_t read_bytes, len;
    char *line = NULL;
    route_t *tmp_route = NULL;
    FILE *fp;

    assert(ppp_bgp_msgs != NULL);

    if ((fp = fopen(cfg.trace_file, "r")) == NULL) {
        fprintf(IO_STREAM, "can not open file: %s [%s]\n", cfg.trace_file, __FUNCTION__);
        exit(-1);
    }

    if (fscanf(fp, "%d %d\n", &total_msg_num, &preloaded_msg_num) != 2) {
        fprintf(IO_STREAM, "illegal msg_num format [%s]\n", __FUNCTION__);
        exit(-1);
    }
    *p_total_msg_num = total_msg_num;
    *p_preloaded_msg_num = preloaded_msg_num;

    *ppp_bgp_msgs = malloc(total_msg_num * sizeof **ppp_bgp_msgs);
    for (i = 0; i < total_msg_num; i++) {
        (*ppp_bgp_msgs)[i] = NULL;
    }

    for (i = 0; i < total_msg_num; i++) {
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
    int total_msg_num = 0;
    int preloaded_msg_num = 0;
    bgp_msg_t **pp_bgp_msgs = NULL;

    parse_args(argc, argv);
    if (!cfg.trace_file) {
        cfg.trace_file = BGP_UPDATE_FILE;
    }
    if (!cfg.as_topo_file) {
        cfg.as_topo_file = AS_TOPO_FILE;
    }

    load_as_conf(&total_num, &p_as_conf);
    load_bgp_update(&total_msg_num, &preloaded_msg_num, &pp_bgp_msgs);
    fprintf(IO_STREAM, "loading passed\n");
    if (cfg.method == GLOBAL_ACCESS) {
        printf("computation method: global_access\n");
    } else if (cfg.method == MSG_QUEUE) {
        printf("computation method: msg_queue\n");
    }

#ifdef W_SGX
    printf("wsgx\n");
    init_rs_w_sgx(total_num, p_as_conf);
    run_rs_w_sgx(total_msg_num, preloaded_msg_num, pp_bgp_msgs, cfg.method, cfg.verbose);
#else
    printf("wosgx\n");
    init_rs_wo_sgx(total_num, p_as_conf);
    run_rs_wo_sgx(total_msg_num, preloaded_msg_num, pp_bgp_msgs, cfg.method, cfg.verbose);
#endif

    return 0;
}
