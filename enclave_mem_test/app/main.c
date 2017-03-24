#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include "mem_oprt.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "../enclave/enclave_u.h"

#define _POSIX_C_SOURCE 200809L
#define SUCCESS 0

static struct {
    uint32_t pre_access;
    uint32_t access;
    uint64_t mem_size;
    uint64_t msg_size;
} cfg = {1,1,1,1};

static void print_help(void)
{
    static const char *help = 

        "Valid options:\n"
        "   -h, --help              display this help and exit\n"
        "   -p, --pre_access INT    specify the pre-memory-access times (K) before mesurement, default value is 1.\n"
        "   -a, --access INT        specify the memory access times (K) for mesurement, default value is 1.\n"
        "   -m, --mem_size INT      specify the mem_size (MB) to be allocated in enclave, default value is 1.\n"
        "   -g, --msg_size INT      specify the msg_size (KB) to be passed into enclave, default value is 1.\n"
        "\n";

    printf("%s\n", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;
    static const char *optstr = "hp:a:m:g:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"pre_access", required_argument, NULL, 'p'},
        {"access", required_argument, NULL, 'a'},
        {"mem_size", required_argument, NULL, 'm'},
        {"msg_size", required_argument, NULL, 'g'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
            case 'h':
                print_help();
                exit(0);

            case 'p':
                cfg.pre_access = ((uint32_t) atoi(optarg)) * 1000;
                break;

            case 'a':
                cfg.access = ((uint32_t) atoi(optarg)) * 1000;
                break;

            case 'm':
                cfg.mem_size = ((uint64_t) atoi(optarg)) * 1024 * 1024;
                break;

            case 'g':
                cfg.msg_size = ((uint64_t) atoi(optarg)) * 1024;
                break;

            default:
                print_help();
                exit(-1);
        }
    }

    return;
}

sgx_enclave_id_t load_enclave()
{
    char enclave_path[] = "libenclave.so";
    int launch_token_updated;
    sgx_launch_token_t launch_token;
    sgx_enclave_id_t enclave_id;
    uint32_t ret;

    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
        printf("sgx_create_enclave failed, errno:%d [%s]\n", ret, __FUNCTION__);
        exit(-1);
    } else {
        printf("enclave - id %lu [%s]\n", enclave_id, __FUNCTION__);
        return enclave_id;
    }
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

static inline uint64_t get_us_time()
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return spec.tv_sec * 1000000ul + spec.tv_nsec / 1.0e3;
}

int main(int argc, char *argv[])
{
    uint32_t ret_status, call_status;
    sgx_enclave_id_t enclave_id;
    uint64_t time_start, time_end;
    double time_cost_us;
    uint32_t *p_mem = NULL;
    //char c;

    parse_args(argc, argv);
    /*
    uint8_t *msg = malloc(cfg.msg_size);
    if (!msg) {
        printf("malloc edger8r msg err: out of memory in the preparation stage, msg_size:%lu\n", cfg.msg_size);
        exit(-1);
    }
    */

    rand_mem_pre_read(&p_mem, (uint32_t) cfg.mem_size, cfg.pre_access);
    //printf("Enter a character to start test:\n");
    //c = getchar();
    time_start = get_us_time();
    rand_mem_read_test(p_mem, (uint32_t) cfg.mem_size, cfg.access);
    time_end = get_us_time();
    if (p_mem) {
        free(p_mem);
        p_mem = NULL;
    }
    time_cost_us = (time_end - time_start) / ((double) cfg.access);
    printf("w/o sgx: allocate %u B memory, pre_access %u times, access %u times, time for each access %f us\n", (uint32_t) cfg.mem_size, cfg.pre_access, cfg.access, time_cost_us);

    enclave_id = load_enclave();
    call_status = enclave_ecall_rand_mem_pre_read(enclave_id, &ret_status, (uint32_t) cfg.mem_size, cfg.pre_access);
    time_start = get_us_time();
    call_status = enclave_ecall_rand_mem_read_test(enclave_id, &ret_status, (uint32_t) cfg.mem_size, cfg.access);
    time_end = get_us_time();
    call_status = enclave_ecall_free_rand_mem_test(enclave_id, &ret_status);
    time_cost_us = (time_end - time_start) / ((double) cfg.access);
    printf("w/ sgx:  allocate %u B memory, pre_access %u times, access %u times, time for each access %f us\n", (uint32_t) cfg.mem_size, cfg.pre_access, cfg.access, time_cost_us);

    /*
    call_status = enclave_ecall_memory_limitation(enclave_id, &ret_status, cfg.mem_size);
    if (call_status == SUCCESS) {
        if (ret_status == SUCCESS) {
            printf("enclave_ecall_memory_limitation succeeded, mem_size: %lu\n", cfg.mem_size);
        } else {
            printf("enclave_ecall_memory_limitation return failed, mem_size: %lu\n", cfg.mem_size);
        }
    } else {
        printf("enclave_ecall_memory_limitation call failed, mem_size: %lu\n", cfg.mem_size);
    }

    call_status = enclave_ecall_edger8r_limitation(enclave_id, &ret_status, (void *) msg, cfg.msg_size);
    if (call_status == SUCCESS) {
        if (ret_status == SUCCESS) {
            printf("enclave_ecall_edger8r_limitation succeeded, msg_size: %lu\n", cfg.msg_size);
        } else {
            printf("enclave_ecall_edger8r_limitation return failed, msg_size: %lu\n", cfg.msg_size);
        }
    } else {
        printf("enclave_ecall_edger8r_limitation call failed, msg_size: %lu\n", cfg.msg_size);
    }
    */

    return 0;
}
