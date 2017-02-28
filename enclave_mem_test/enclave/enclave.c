#include <stdio.h>
#include <stdarg.h>
#include "enclave_t.h"
#include "sgx_trts.h"

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

uint32_t ecall_memory_limitation(uint32_t mem_size)
{
    uint32_t *mem = malloc(mem_size);
    if (!mem) {
        printf("malloc err: out of memory [%s]\n", __FUNCTION__);
        return 10;
    } else {
        printf("malloc succeeded [%s]\n", __FUNCTION__);
        free(mem);
        return SGX_SUCCESS;
    }
}

uint32_t ecall_edger8r_limitation(void *msg, size_t msg_size)
{
    printf("receive a msg, msg_size:%d [%s]\n", msg_size, __FUNCTION__);
    return SGX_SUCCESS;
}
