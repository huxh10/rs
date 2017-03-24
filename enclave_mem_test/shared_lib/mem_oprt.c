#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "mem_oprt.h"

int rand_mem_pre_read(uint32_t **pp_mem, uint32_t mem_size, uint32_t pre_access)
{
    if (!pp_mem || *pp_mem) {
        return 1;
    }
    *pp_mem = malloc(mem_size);
    if (!*pp_mem) {
        printf("malloc error: out of memory [%s]\n", __FUNCTION__);
        return 10;
    } else {
        memset(*pp_mem, 100, mem_size);
        return 0;
    }
}

int rand_mem_read_test(uint32_t *p_mem, uint32_t mem_size, uint32_t access)
{
    if (!p_mem) {
        return 1;
    }
    uint32_t i, j, addr, array_size = mem_size / 4;
    uint32_t l_seed = 1, h_seed = 10;
    for (i = 0; i < access; i++) {
        // fast random number generator
        l_seed = 214013 * l_seed + 2531011;
        h_seed = 214013 * h_seed + 2531011;
        addr = (((l_seed >> 16) & 0xFFFF) | (h_seed & 0xFFFF0000)) % array_size;
        addr = p_mem[addr];
    }
    return 0;
}
