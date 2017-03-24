#ifndef __MEM_OPRT_H__
#define __MEM_OPRT_H__

int rand_mem_pre_read(uint32_t **pp_mem, uint32_t mem_size, uint32_t pre_access);

int rand_mem_read_test(uint32_t *p_mem, uint32_t mem_size, uint32_t access);

#endif
