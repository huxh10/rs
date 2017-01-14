#ifndef _ISV_ENCLAVE_H_
#define _ISV_ENCLAVE_H_

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t *p_context);

sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* p_message, size_t message_size, uint8_t* p_mac, size_t mac_size);

sgx_status_t put_secret_data(sgx_ra_context_t context, uint8_t *p_secret, uint32_t secret_size, uint8_t *p_gcm_mac);

#endif
