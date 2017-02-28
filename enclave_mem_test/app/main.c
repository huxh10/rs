#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "../enclave/enclave_u.h"

#define SUCCESS 0

static struct {
    int mem_size;
    int msg_size;
} cfg = {1,1};

static void print_help(void)
{
    static const char *help = 

        "Valid options:\n"
        "   -h, --help              display this help and exit\n"
        "   -m, --mem_size INT specify the mem_size to be allocated in enclave\n"
        "   -g, --msg_size INT specify the msg_size to be passed into enclave\n"
        "\n";

    printf("%s\n", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;
    static const char *optstr = "hm:g:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"mem_size", required_argument, NULL, 'm'},
        {"msg_size", required_argument, NULL, 'g'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
            case 'h':
                print_help();
                exit(0);

            case 'm':
                cfg.mem_size = atoi(optarg);
                break;

            case 'g':
                cfg.msg_size = atoi(optarg);
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
        printf("sgx_create_enclave failed [%s]\n", __FUNCTION__);
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

int main(int argc, char *argv[])
{
    uint32_t ret_status, call_status;
    sgx_enclave_id_t enclave_id;

    parse_args(argc, argv);
    uint8_t *msg = malloc(cfg.msg_size);
    if (!msg) {
        printf("malloc edger8r msg err: out of memory in the preparation stage, msg_size:%d\n", cfg.msg_size);
        exit(-1);
    }

    enclave_id = load_enclave();

    call_status = enclave_ecall_memory_limitation(enclave_id, &ret_status, cfg.mem_size);
    if (call_status == SUCCESS) {
        if (ret_status == SUCCESS) {
            printf("enclave_ecall_memory_limitation succeeded, mem_size: %d\n", cfg.mem_size);
        } else {
            printf("enclave_ecall_memory_limitation return failed, mem_size: %d\n", cfg.mem_size);
        }
    } else {
        printf("enclave_ecall_memory_limitation call failed, mem_size: %d\n", cfg.mem_size);
    }

    call_status = enclave_ecall_edger8r_limitation(enclave_id, &ret_status, (void *) msg, cfg.msg_size);
    if (call_status == SUCCESS) {
        if (ret_status == SUCCESS) {
            printf("enclave_ecall_edger8r_limitation succeeded, msg_size: %d\n", cfg.msg_size);
        } else {
            printf("enclave_ecall_edger8r_limitation return failed, msg_size: %d\n", cfg.msg_size);
        }
    } else {
        printf("enclave_ecall_edger8r_limitation call failed, msg_size: %d\n", cfg.msg_size);
    }

    return 0;
}
