#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "mem_oprt.h"
#include "enclave_t.h"
#include "sgx_trts.h"

uint32_t *p_mem = NULL;

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

uint32_t ecall_rand_mem_pre_read(uint32_t mem_size, uint32_t pre_access)
{
    return rand_mem_pre_read(&p_mem, mem_size, pre_access);
}

uint32_t ecall_rand_mem_read_test(uint32_t mem_size, uint32_t access)
{
    return rand_mem_read_test(p_mem, mem_size, access);
}

uint32_t ecall_free_rand_mem_test()
{
    if (p_mem) {
        free(p_mem);
        p_mem = NULL;
    }
    return 0;
}

uint32_t ecall_memory_limitation(uint64_t mem_size)
{
    uint8_t *mem = malloc(mem_size);
    if (!mem) {
        printf("malloc err: out of memory [%s]\n", __FUNCTION__);
        return 10;
    } else {
        printf("malloc succeeded [%s]\n", __FUNCTION__);
        printf("mem[%lu]:%d [%s]\n", mem_size - 4, mem[mem_size - 4], __FUNCTION__);
        free(mem);
        return SGX_SUCCESS;
    }
}

uint32_t ecall_edger8r_limitation(void *msg, uint64_t msg_size)
{
    printf("receive a msg, msg_size:%lu [%s]\n", msg_size, __FUNCTION__);
    return SGX_SUCCESS;
}
