#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "sgx_tcrypto.h"
#include "sgx_tkey_exchange.h"
#include "service_provider.h"
#include "ecp.h"
#include "ias_ra.h"
#include "as_process_message.h"
#include "bgp.h"
#include "datatypes.h"
#include "error_codes.h"
#include "time_utils.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif


uint32_t g_as_id;
ra_dh_session_t *g_p_ra_session_info;
rib_t *g_p_rib;
as_para_t g_as_para;

// This is supported extended epid group of SP. SP can support more than one
// extended epid group with different extended epid group id and credentials.
static const sample_extended_epid_group g_extended_epid_groups[] = {
    {
        0,
        ias_enroll,
        ias_get_sigrl,
        ias_verify_attestation_evidence
    }
};

// This is the private EC key of SP, the corresponding public EC key is
// hard coded in isv_enclave. It is based on NIST P-256 curve.
static const sgx_ec256_private_t g_sp_priv_key = {
    {
        0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
    }
};

// This is the public EC key of SP, this key is hard coded in isv_enclave.
// It is based on NIST P-256 curve. Not used in the SP code.
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

// This is a context data structure used on SP side
typedef struct _sp_db_item_t
{
    sgx_ec256_public_t          g_a;
    sgx_ec256_public_t          g_b;
    sgx_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
    sgx_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
    sgx_ec_key_128bit_t      sk_key;// Shared secret key for encryption
    sgx_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
    sgx_ec256_private_t            b;
    sgx_ps_sec_prop_desc_t   ps_sec_prop;
}sp_db_item_t;
static sp_db_item_t g_sp_db;

static const sample_extended_epid_group* g_sp_extended_epid_group_id= NULL;
static bool g_is_sp_registered = false;
static int g_sp_credentials = 0;
static int g_authentication_token = 0;

uint8_t g_secret[8] = {0,1,2,3,4,5,6,7};

sample_spid_t g_spid;

uint32_t as_send_message(int sfd, void *resp_message, size_t resp_message_size)
{
    int ret, diff, bytes, offset = 0;
    char *buffer = resp_message;

    // send the msg
    while (resp_message_size != offset) {
        diff = resp_message_size - offset;
        bytes = (diff <= MAX_MSG_SIZE) ? diff : MAX_MSG_SIZE;
        ret = write(sfd, buffer + offset, bytes);
        if (ret == -1) {
            // fprintf(stderr, "\n[as%d] write socket failed, err: %s [%s]\n", g_as_id, strerror(errno), __FUNCTION__);
            return SESSION_SEND_ERROR;
        } else {
            //// fprintf(stderr, "\nas %d sends %d bytes data [%s]\n", g_as_id, ret, __FUNCTION__);
            offset += ret;
        }
    }

    return SUCCESS;
}

/* --------------------------local rib processing------------------------- */

bgp_message_t *_assemble_one_route(route_t *p_route, uint8_t export_policy_class, uint8_t oprt_type)
{
    bgp_message_t *p_msg = NULL;
    exch_secure_message_t *p_exch_sec_msg;
    exch_route_t *p_exch_route = NULL;
    int exch_route_size = 0;
    uint32_t ret;

    generate_exch_route(&p_exch_route, &exch_route_size, p_route, &g_as_para, export_policy_class, oprt_type);

    // alloc msg memory
    p_msg = malloc(HEADER_LEN + sizeof(exch_secure_message_t) + exch_route_size);
    if (!p_msg) {
        // fprintf(stderr, "\nmalloc error [%s]\n", __FUNCTION__);
        return NULL;
    }
    p_msg->msg_len = HEADER_LEN + sizeof(exch_secure_message_t) + exch_route_size;
    p_msg->msg_type = R_EXCH_DATA;
    p_msg->src_id = g_as_id;
    p_msg->dst_id = g_as_id;

    // assemble secure msg
    p_exch_sec_msg = (exch_secure_message_t *) p_msg->msg;
    // TODO add nounce to iv
    uint8_t aes_gcm_iv[12] = {0};
    p_exch_sec_msg->secret.payload_size = exch_route_size;
    ret = sgx_rijndael128GCM_encrypt(
            (const sgx_ec_key_128bit_t *) &g_sp_db.sk_key,
            (const uint8_t *) p_exch_route,
            p_exch_sec_msg->secret.payload_size,
            p_exch_sec_msg->secret.payload,
            aes_gcm_iv,
            12,
            NULL,
            0,
            &p_exch_sec_msg->secret.payload_tag);
    if (ret) {
        SAFE_FREE(p_msg);
    }

    return p_msg;
}

uint32_t announce_routes(int sfd)
{
    route_entry_t *p_tmp_entry = NULL;
    bgp_message_t *p_msg = NULL;
    char *s_func = "send_out_route";

    p_tmp_entry = g_p_rib->head;
    while (p_tmp_entry) {
        p_msg = _assemble_one_route(p_tmp_entry->route, PEER, ANNOUNCE);
        if (p_msg) {
            print_current_time_with_us(s_func);
            as_send_message(sfd, (void *) p_msg, p_msg->msg_len);
        }
        p_tmp_entry = p_tmp_entry->next;
    }
}

int load_rib(const char *file_name)
{
    FILE *route_fp;
    route_entry_t *p_tmp_entry = NULL;
    char *line = NULL;
    size_t len = 0, read;

    if (g_p_rib) {
        free_rib(&g_p_rib);
    }
    g_p_rib = malloc(sizeof(rib_t));
    g_p_rib->head = NULL;
    g_p_rib->size = 0;

    if ((route_fp = fopen(file_name, "r")) == NULL) {
        // fprintf(stderr, "\ncan not open file: %s\n", file_name);
        return -1;
    }

    // read asn
    read = getline(&line, &len, route_fp);
    //// fprintf(stdout, "\nread %u bytes from line\n", (uint32_t) read);
    line[read - 1] = '\0';
    g_as_para.asn = atoi(line);
    // fprintf(stdout, "\nASN: %d\n", g_as_para.asn);
    // read initial routes and insert them to rib
    while ((read = getline(&line, &len, route_fp)) != -1) {
        if (line[0] == '*') continue;
        // strip '\n'
        line[read - 1] = '\0';
        //// fprintf(stdout, "\nraw entry %u bytes readed from file: %s\n", (uint32_t) read, line);
        p_tmp_entry = malloc(sizeof(route_entry_t));
        p_tmp_entry->prev = NULL;
        p_tmp_entry->next = NULL;
        parse_route_from_file(&p_tmp_entry->route, line);
        // insert route to the head of the rib
        if (p_tmp_entry->route) {
            //// fprintf(stdout, "\nget one route entry:\n");
            //print_route(p_tmp_entry->route);
            p_tmp_entry->is_selected = 1;
            p_tmp_entry->next = g_p_rib->head;
            if (g_p_rib->head) {
                g_p_rib->head->prev = p_tmp_entry;
            }
            g_p_rib->head = p_tmp_entry;
            g_p_rib->size++;
        }
        p_tmp_entry = NULL;
    }
    SAFE_FREE(line);
    // fprintf(stdout, "\nsummary: %d routes are loaded\n", g_p_rib->size);
    print_rib(g_p_rib);
    return 0;
}

/* --------------------------message processing part------------------------- */

uint32_t as_process_message(int sfd, void *req_message, size_t req_message_size)
{
    uint32_t status;
    bgp_message_t *bgp_msg = req_message;
    size_t msg_size = req_message_size - HEADER_LEN;

    if (!req_message) {
        return INVALID_PARAMETER_ERROR;
    }

    // handle different request message types
    switch (bgp_msg->msg_type) {
        case R_SEND_MSG0:
            // fprintf(stdout, "\n[as%d] received R_SEND_MSG0 msg, src%d->dst%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            status = handle_r_send_msg0(sfd, (void *) bgp_msg->msg, msg_size);
            if (status == SUCCESS) {
                // fprintf(stdout, "\n[as%d] R_SEND_MSG0 processing succeeded, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            } else {
                // fprintf(stdout, "\n[as%d] R_SEND_MSG0 processing failed, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            }
            break;
        case R_SEND_MSG1:
            // fprintf(stdout, "\n[as%d] received R_SEND_MSG1 msg, src%d->dst%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            status = handle_r_send_msg1(sfd, (void *) bgp_msg->msg, msg_size);
            if (status == SUCCESS) {
                // fprintf(stdout, "\n[as%d] R_SEND_MSG1 processing succeeded, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            } else {
                // fprintf(stdout, "\n[as%d] R_SEND_MSG1 processing failed, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            }
            break;
        case R_SEND_MSG3:
            // fprintf(stdout, "\n[as%d] received R_SEND_MSG3 msg, src%d->dst%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            status = handle_r_send_msg3(sfd, (void *) bgp_msg->msg, msg_size);
            if (status == SUCCESS) {
                // fprintf(stdout, "\n[as%d] R_SEND_MSG3 processing succeeded, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            } else {
                // fprintf(stdout, "\n[as%d] R_SEND_MSG3 processing failed, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            }
            break;
        case R_EXCH_DATA:
            // fprintf(stdout, "\n[as%d] received R_EXCH_DATA msg, src%d->dst%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            status = handle_r_exch_data(sfd, (void *) bgp_msg->msg, msg_size);
            if (status == SUCCESS) {
                // fprintf(stdout, "\n[as%d] R_EXCH_DATA processing succeeded, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            } else {
                // fprintf(stdout, "\n[as%d] R_EXCH_DATA processing failed, peer%d->me%d [%s]\n", g_as_id, bgp_msg->src_id, bgp_msg->dst_id, __FUNCTION__);
            }
            break;
        default:
            return INVALID_REQUEST_TYPE_ERROR;
    }

    return status;
}

uint32_t handle_r_send_msg0(int sfd, void *msg, size_t msg_size)
{
    size_t i;
    uint32_t ret;
    bgp_message_t *p_rep_msg;

    if (!msg || (msg_size != sizeof(r_msg0_t))) {
        return INVALID_PARAMETER_ERROR;
    }

    if (g_p_ra_session_info->status != R_WAIT_M0) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    uint32_t extended_epid_group_id = ((r_msg0_t *) msg)->extended_epid_group_id;

    // Check to see if we have registered with the attestation server yet?
    if (!g_is_sp_registered ||
        (g_sp_extended_epid_group_id != NULL && g_sp_extended_epid_group_id->extended_epid_group_id != extended_epid_group_id))
    {
        // Check to see if the extended_epid_group_id is supported?
        ret = SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
        for (i = 0; i < sizeof(g_extended_epid_groups) / sizeof(sample_extended_epid_group); i++)
        {
            if (g_extended_epid_groups[i].extended_epid_group_id == extended_epid_group_id)
            {
                g_sp_extended_epid_group_id = &(g_extended_epid_groups[i]);
                // In the product, the SP will establish a mutually
                // authenticated SSL channel. During the enrollment process, the ISV
                // registers it exchanges TLS certs with attestation server and obtains an SPID and
                // Report Key from the attestation server.
                // For a product attestation server, enrollment is an offline process.  See the 'on-boarding'
                // documentation to get the information required.  The enrollment process is
                // simulated by a call in this sample.
                ret = g_sp_extended_epid_group_id->enroll(g_sp_credentials, &g_spid,
                    &g_authentication_token);
                if (0 != ret)
                {
                    ret = SP_IAS_FAILED;
                    break;
                }

                g_is_sp_registered = true;
                ret = SP_OK;
                break;
            }
        }
    }
    else
    {
        ret = SP_OK;
    }

    // assemble and send msg0_resp
    p_rep_msg = malloc(sizeof *p_rep_msg);
    if (!p_rep_msg) {
        // fprintf(stderr, "\nmalloc failed [%s]\n", __FUNCTION__);
        return MALLOC_ERROR;
    }
    p_rep_msg->msg_len = HEADER_LEN;
    p_rep_msg->msg_type = R_REP_MSG0;
    p_rep_msg->src_id = g_as_id;
    p_rep_msg->dst_id = g_as_id;
    g_p_ra_session_info->status = R_WAIT_M1;
    as_send_message(sfd, (void *) p_rep_msg, p_rep_msg->msg_len);

    return ret;
}

uint32_t handle_r_send_msg1(int sfd, void *msg, size_t msg_size)
{
    uint32_t ret = SUCCESS;
    sgx_ra_msg1_t *p_msg1 = msg;
    bgp_message_t *p_rep_msg = NULL;
    sgx_ra_msg2_t *p_msg2 = NULL;
    sgx_ecc_state_handle_t ecc_state = NULL;
    bool derive_ret = false;

    if (!msg || (msg_size != sizeof(sgx_ra_msg1_t))) {
        return INVALID_PARAMETER_ERROR;
    }

    if (g_p_ra_session_info->status != R_WAIT_M1) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    // Check to see if we have registered?
    if (!g_is_sp_registered) {
        return SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
    }

    // ------------------------------------------------------------------
    // code moved from service_provider.cpp to process msg1 generate msg2
    // ------------------------------------------------------------------
    do
    {
        // Get the sig_rl from attestation server using GID.
        // GID is Base-16 encoded of EPID GID in little-endian format.
        // In the product, the SP and attesation server uses an established channel for
        // communication.
        uint8_t* sig_rl;
        uint32_t sig_rl_size = 0;

        // The product interface uses a REST based message to get the SigRL.
        ret = g_sp_extended_epid_group_id->get_sigrl(p_msg1->gid, &sig_rl_size, &sig_rl);
        if (0 != ret)
        {
            // fprintf(stderr, "\nError, ias_get_sigrl [%s].", __FUNCTION__);
            ret = SP_IAS_FAILED;
            break;
        }

        // Need to save the client's public ECCDH key to local storage
        if (memcpy_s(&g_sp_db.g_a, sizeof(g_sp_db.g_a), &p_msg1->g_a,
                     sizeof(p_msg1->g_a)))
        {
            // fprintf(stderr, "\nError, cannot do memcpy in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the Service providers ECCDH key pair.
        ret = sgx_ecc256_open_context(&ecc_state);
        if (ret != SUCCESS)
        {
            // fprintf(stderr, "\nError, cannot get ECC context in [%s].", __FUNCTION__);
            ret = -1;
            break;
        }
        sgx_ec256_public_t pub_key = {{0},{0}};
        sgx_ec256_private_t priv_key = {{0}};
        ret = sgx_ecc256_create_key_pair(&priv_key, &pub_key,
                                                   ecc_state);
        if(ret != SUCCESS)
        {
            // fprintf(stderr, "\nError, cannot generate key pair in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Need to save the SP ECCDH key pair to local storage.
        if(memcpy_s(&g_sp_db.b, sizeof(g_sp_db.b), &priv_key,sizeof(priv_key))
           || memcpy_s(&g_sp_db.g_b, sizeof(g_sp_db.g_b),
                       &pub_key,sizeof(pub_key)))
        {
            // fprintf(stderr, "\nError, cannot do memcpy in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the client/SP shared secret
        sgx_ec256_dh_shared_t dh_key = {{0}};
        ret = sgx_ecc256_compute_shared_dhkey(
                &priv_key,
                (sgx_ec256_public_t *) &p_msg1->g_a,
                (sgx_ec256_dh_shared_t *) &dh_key,
                ecc_state);
        if(ret != SUCCESS)
        {
            // fprintf(stderr, "\nError, compute share key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

#ifdef SUPPLIED_KEY_DERIVATION

        // smk is only needed for msg2 generation.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK_SK,
            &g_sp_db.smk_key, &g_sp_db.sk_key);
        if(derive_ret != true)
        {
            // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK_VK,
            &g_sp_db.mk_key, &g_sp_db.vk_key);
        if(derive_ret != true)
        {
            // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
#else
        // smk is only needed for msg2 generation.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK,
                                &g_sp_db.smk_key);
        if(derive_ret != true)
        {
            // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK,
                                &g_sp_db.mk_key);
        if(derive_ret != true)
        {
            // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SK,
                                &g_sp_db.sk_key);
        if(derive_ret != true)
        {
            // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_VK,
                                &g_sp_db.vk_key);
        if(derive_ret != true)
        {
            // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
#endif

        // alloc memory for rep_msg
        uint32_t msg2_size = sizeof(sgx_ra_msg2_t) + sig_rl_size;
        p_rep_msg = malloc(msg2_size + HEADER_LEN);
        if (!p_rep_msg) {
            // fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        memset(p_rep_msg, 0, msg2_size + HEADER_LEN);
        p_rep_msg->msg_len = msg2_size + HEADER_LEN;
        p_rep_msg->msg_type = R_SEND_MSG2;
        p_rep_msg->src_id = g_as_id;
        p_rep_msg->dst_id = g_as_id;
        p_msg2 = (sgx_ra_msg2_t *) p_rep_msg->msg;

        // Assemble MSG2
        if (memcpy_s(&p_msg2->g_b, sizeof(p_msg2->g_b), &g_sp_db.g_b,
                    sizeof(g_sp_db.g_b)) ||
           memcpy_s(&p_msg2->spid, sizeof(sample_spid_t),
                    &g_spid, sizeof(g_spid)))
        {
            // fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The service provider is responsible for selecting the proper EPID
        // signature type and to understand the implications of the choice!
        p_msg2->quote_type = SAMPLE_QUOTE_LINKABLE_SIGNATURE;

#ifdef SUPPLIED_KEY_DERIVATION
//isv defined key derivation function id
#define ISV_KDF_ID 2
        p_msg2->kdf_id = ISV_KDF_ID;
#else
        p_msg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;
#endif
        // Create gb_ga
        sgx_ec256_public_t gb_ga[2];
        if(memcpy_s(&gb_ga[0], sizeof(gb_ga[0]), &g_sp_db.g_b,
                    sizeof(g_sp_db.g_b))
           || memcpy_s(&gb_ga[1], sizeof(gb_ga[1]), &g_sp_db.g_a,
                       sizeof(g_sp_db.g_a)))
        {
            // fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Sign gb_ga
        ret = sgx_ecdsa_sign(
                (uint8_t *)&gb_ga,
                sizeof(gb_ga),
                (sgx_ec256_private_t *) &g_sp_priv_key,
                (sgx_ec256_signature_t *)&p_msg2->sign_gb_ga,
                ecc_state);
        if(ret != SUCCESS)
        {
            // fprintf(stderr, "\nError, sign ga_gb fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the CMACsmk for gb||SPID||TYPE||KDF_ID||Sigsp(gb,ga)
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};
        uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
        ret = sgx_rijndael128_cmac_msg(
                (const sgx_cmac_128bit_key_t *) &g_sp_db.smk_key,
                (const uint8_t *) &p_msg2->g_b,
                cmac_size,
                &mac);
        if(ret != SUCCESS)
        {
            // fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        if(memcpy_s(&p_msg2->mac, sizeof(p_msg2->mac), mac, sizeof(mac)))
        {
            // fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        if(memcpy_s(&p_msg2->sig_rl[0], sig_rl_size, sig_rl, sig_rl_size))
        {
            // fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        p_msg2->sig_rl_size = sig_rl_size;

    } while(0);

    if (ret) {
        SAFE_FREE(p_rep_msg);
    } else {
        // send msg1
        g_p_ra_session_info->status = R_WAIT_M3;
        as_send_message(sfd, (void *) p_rep_msg, p_rep_msg->msg_len);
    }

    if (ecc_state) {
        sgx_ecc256_close_context(ecc_state);
    }

    return ret;
}

uint32_t handle_r_send_msg3(int sfd, void *msg, size_t msg_size)
{
    sgx_ra_msg3_t *p_msg3 = msg;
    bgp_message_t *p_rep_msg = NULL;
    sample_ra_att_result_msg_t *p_att_result_msg = NULL;

    uint32_t ret = SUCCESS;
    uint8_t *p_msg3_cmaced = NULL;
    sgx_quote_t *p_quote = NULL;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = {0};
    uint32_t i;

    if (!msg || (msg_size < sizeof(sgx_ra_msg3_t))) {
        return INVALID_PARAMETER_ERROR;
    }

    if (g_p_ra_session_info->status != R_WAIT_M3) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    // Check to see if we have registered?
    if (!g_is_sp_registered) {
        return SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
    }

    // ------------------------------------------------------------------
    // code moved from service_provider.cpp to process msg3 generate rslt
    // ------------------------------------------------------------------
    do
    {
        // Compare g_a in message 3 with local g_a.
        ret = memcmp(&g_sp_db.g_a, &p_msg3->g_a, sizeof(sgx_ec256_public_t));
        if (ret) {
            // fprintf(stderr, "\nError, g_a is not same [%s].", __FUNCTION__);
            ret = SP_PROTOCOL_ERROR;
            break;
        }
        // Make sure that msg_size is bigger than sgx_mac_t.
        uint32_t mac_size = msg_size - sizeof(sgx_mac_t);
        p_msg3_cmaced = (uint8_t *) p_msg3;
        p_msg3_cmaced += sizeof(sgx_mac_t);

        // Verify the message mac using SMK
        sgx_cmac_128bit_tag_t mac = {0};
        ret = sgx_rijndael128_cmac_msg(
                (const sgx_cmac_128bit_key_t *) &g_sp_db.smk_key,
                (const uint8_t *) p_msg3_cmaced,
                mac_size,
                &mac);
        if (ret != SUCCESS) {
            // fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        // In real implementation, should use a time safe version of memcmp here,
        // in order to avoid side channel attack.
        ret = memcmp(&p_msg3->mac, mac, sizeof(mac));
        if (ret) {
            // fprintf(stderr, "\nError, verify cmac fail [%s].", __FUNCTION__);
            ret = SP_INTEGRITY_FAILED;
            break;
        }

        if (memcpy_s(&g_sp_db.ps_sec_prop, sizeof(g_sp_db.ps_sec_prop),
            &p_msg3->ps_sec_prop, sizeof(p_msg3->ps_sec_prop))) {
            // fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        p_quote = (sgx_quote_t *) p_msg3->quote;

        // Check the quote version if needed. Only check the Quote.version field if the enclave
        // identity fields have changed or the size of the quote has changed.  The version may
        // change without affecting the legacy fields or size of the quote structure.
        //if(p_quote->version < ACCEPTED_QUOTE_VERSION)
        //{
        //    // fprintf(stderr,"\nError, quote version is too old.", __FUNCTION__);
        //    ret = SP_QUOTE_VERSION_ERROR;
        //    break;
        //}

        // Verify the report_data in the Quote matches the expected value.
        // The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
        // The second 32 bytes of report_data are set to zero.
        ret = sgx_sha256_init(&sha_handle);
        if (ret != SUCCESS) {
            // fprintf(stderr,"\nError, init hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        ret = sgx_sha256_update((uint8_t *)&(g_sp_db.g_a),
                                     sizeof(g_sp_db.g_a), sha_handle);
        if (ret != SUCCESS) {
            // fprintf(stderr,"\nError, udpate hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        ret = sgx_sha256_update((uint8_t *)&(g_sp_db.g_b),
                                     sizeof(g_sp_db.g_b), sha_handle);
        if (ret != SUCCESS) {
            // fprintf(stderr,"\nError, udpate hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        ret = sgx_sha256_update((uint8_t *)&(g_sp_db.vk_key),
                                     sizeof(g_sp_db.vk_key), sha_handle);
        if (ret != SUCCESS) {
            // fprintf(stderr,"\nError, udpate hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        ret = sgx_sha256_get_hash(sha_handle,
                (sgx_sha256_hash_t *)&report_data);
        if (ret != SUCCESS) {
            // fprintf(stderr,"\nError, Get hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        ret = memcmp((uint8_t *)&report_data,
                     (uint8_t *)&(p_quote->report_body.report_data),
                     sizeof(report_data));
        if (ret) {
            // fprintf(stderr, "\nError, verify hash fail [%s].", __FUNCTION__);
            ret = SP_INTEGRITY_FAILED;
            break;
        }

        // Verify Enclave policy (an attestation server may provide an API for this if we
        // registered an Enclave policy)

        // Verify quote with attestation server.
        // In the product, an attestation server could use a REST message and JSON formatting to request
        // attestation Quote verification.  The sample only simulates this interface.
        ias_att_report_t attestation_report = {0};
        ret = g_sp_extended_epid_group_id->verify_attestation_evidence(p_quote, NULL,
                                              &attestation_report);
        if (ret) {
            ret = SP_IAS_FAILED;
            break;
        }
        /*
        FILE* OUTPUT = stdout;
        // fprintf(OUTPUT, "\n\n\tAtestation Report:");
        // fprintf(OUTPUT, "\n\tid: 0x%0x.", attestation_report.id);
        // fprintf(OUTPUT, "\n\tstatus: %d.", attestation_report.status);
        // fprintf(OUTPUT, "\n\trevocation_reason: %u.",
                attestation_report.revocation_reason);
        // attestation_report.info_blob;
        // fprintf(OUTPUT, "\n\tpse_status: %d.",  attestation_report.pse_status);
        */
        // Note: This sample always assumes the PIB is sent by attestation server.  In the product
        // implementation, the attestation server could only send the PIB for certain attestation 
        // report statuses.  A product SP implementation needs to handle cases
        // where the PIB is zero length.

        // Respond the client with the results of the attestation.
        uint32_t att_result_msg_size = sizeof(sample_ra_att_result_msg_t);
        p_rep_msg = (bgp_message_t *) malloc(HEADER_LEN + att_result_msg_size + sizeof(g_secret));
        if (!p_rep_msg) {
            // fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        memset(p_rep_msg, 0, HEADER_LEN + att_result_msg_size  + sizeof(g_secret));
        p_rep_msg->msg_len = HEADER_LEN + att_result_msg_size + sizeof(g_secret);
        p_rep_msg->msg_type = R_SEND_RESULT;
        p_rep_msg->src_id = g_as_id;
        p_rep_msg->dst_id = g_as_id;
        /*
        if (IAS_QUOTE_OK != attestation_report.status) {
            p_att_result_msg_full->status[0] = 0xFF;
        }
        if (IAS_PSE_OK != attestation_report.pse_status) {
            p_att_result_msg_full->status[1] = 0xFF;
        }
        */

        p_att_result_msg = (sample_ra_att_result_msg_t *) p_rep_msg->msg;

        // In a product implementation of attestation server, the HTTP response header itself could have
        // an RK based signature that the service provider needs to check here.

        // The platform_info_blob signature will be verified by the client
        // when sent. No need to have the Service Provider to check it.  The SP
        // should pass it down to the application for further analysis.

        /*
        // fprintf(OUTPUT, "\n\n\tEnclave Report:");
        // fprintf(OUTPUT, "\n\tSignature Type: 0x%x", p_quote->sign_type);
        // fprintf(OUTPUT, "\n\tSignature Basename: ");
        for(i=0; i<sizeof(p_quote->basename.name) && p_quote->basename.name[i];
            i++)
        {
            // fprintf(OUTPUT, "%c", p_quote->basename.name[i]);
        }
#ifdef __x86_64__
        // fprintf(OUTPUT, "\n\tattributes.flags: 0x%0lx",
                p_quote->report_body.attributes.flags);
        // fprintf(OUTPUT, "\n\tattributes.xfrm: 0x%0lx",
                p_quote->report_body.attributes.xfrm);
#else
        // fprintf(OUTPUT, "\n\tattributes.flags: 0x%0llx",
                p_quote->report_body.attributes.flags);
        // fprintf(OUTPUT, "\n\tattributes.xfrm: 0x%0llx",
                p_quote->report_body.attributes.xfrm);
#endif
        // fprintf(OUTPUT, "\n\tmr_enclave: ");
        for(i=0;i<sizeof(sample_measurement_t);i++)
        {

            // fprintf(OUTPUT, "%02x",p_quote->report_body.mr_enclave[i]);

            //// fprintf(stderr, "%02x",p_quote->report_body.mr_enclave.m[i]);

        }
        // fprintf(OUTPUT, "\n\tmr_signer: ");
        for(i=0;i<sizeof(sample_measurement_t);i++)
        {

            // fprintf(OUTPUT, "%02x",p_quote->report_body.mr_signer[i]);

            //// fprintf(stderr, "%02x",p_quote->report_body.mr_signer.m[i]);

        }
        // fprintf(OUTPUT, "\n\tisv_prod_id: 0x%0x",
                p_quote->report_body.isv_prod_id);
        // fprintf(OUTPUT, "\n\tisv_svn: 0x%0x",p_quote->report_body.isv_svn);
        // fprintf(OUTPUT, "\n");
        */

        // A product service provider needs to verify that its enclave properties 
        // match what is expected.  The SP needs to check these values before
        // trusting the enclave.  For the sample, we always pass the policy check.
        // Attestation server only verifies the quote structure and signature.  It does not 
        // check the identity of the enclave.
        bool isv_policy_passed = true;

        // Assemble Attestation Result Message
        // Note, this is a structure copy.  We don't copy the policy reports
        // right now.
        p_att_result_msg->platform_info_blob = attestation_report.info_blob;

        // Generate mac based on the mk key.
        mac_size = sizeof(ias_platform_info_blob_t);
        ret = sgx_rijndael128_cmac_msg(
                (const sgx_cmac_128bit_key_t *) &g_sp_db.mk_key,
                (const uint8_t *) &p_att_result_msg->platform_info_blob,
                mac_size,
                &p_att_result_msg->mac);
        if(ret != SUCCESS)
        {
            // fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate shared secret and encrypt it with SK, if attestation passed.
        uint8_t aes_gcm_iv[12] = {0};
        p_att_result_msg->secret.payload_size = 8;
        if((IAS_QUOTE_OK == attestation_report.status) &&
           (IAS_PSE_OK == attestation_report.pse_status) &&
           (isv_policy_passed == true))
        {
            ret = sgx_rijndael128GCM_encrypt(
                    (const sgx_ec_key_128bit_t *) &g_sp_db.sk_key,
                    &g_secret[0],
                    p_att_result_msg->secret.payload_size,
                    p_att_result_msg->secret.payload,
                    aes_gcm_iv,
                    12,
                    NULL,
                    0,
                    &p_att_result_msg->secret.payload_tag);
        }
    } while(0);

    if (ret) {
        SAFE_FREE(p_rep_msg);
    } else {
        // send result
        g_p_ra_session_info->status = R_WAIT_DATA;
        as_send_message(sfd, (void *) p_rep_msg, p_rep_msg->msg_len);
        sleep(8);
        announce_routes(sfd);
    }

    return ret;
}

uint32_t handle_r_exch_data(int sfd, void *msg, size_t msg_size)
{
    uint32_t ret;
    bgp_message_t *p_msg = NULL;
    exch_secure_message_t *p_exch_sec_msg = msg;
    exch_route_t *p_exch_route = NULL;
    route_t *p_route = NULL;
    route_t *p_potential_best_route = NULL;
    uint8_t *decrypted_data = NULL;
    int decrypted_data_length = msg_size - sizeof(exch_secure_message_t);
    int exch_route_size;
    char *s_func = "get_route";

    if (g_p_ra_session_info->status != R_WAIT_DATA) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    if (!msg) {
        return INVALID_PARAMETER_ERROR;
    }
    if (msg_size < sizeof(exch_secure_message_t)) {
        return INVALID_PARAMETER_ERROR;
    }

    decrypted_data = malloc(decrypted_data_length);
    if (!decrypted_data) {
        return MALLOC_ERROR;
    }
    memset(decrypted_data, 0, decrypted_data_length);
    // TODO add nounce to iv
    uint8_t aes_gcm_iv[12] = {0};

    ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t *) &g_sp_db.sk_key,
            p_exch_sec_msg->secret.payload,
            decrypted_data_length,
            decrypted_data,
            aes_gcm_iv,
            12,
            NULL,
            0,
            (const sgx_aes_gcm_128bit_tag_t *) p_exch_sec_msg->secret.payload_tag);
    if (ret) {
        return ret;
    }

    p_exch_route = (exch_route_t *) decrypted_data;
    // convert data to route
    parse_route_from_channel(&p_route, p_exch_route->route);
    print_current_time_with_us(s_func);
    // process route, send route msgs when updates happen
    if (p_exch_route->oprt_type == ANNOUNCE) {
        if (add_rib_entry(g_p_rib, &p_potential_best_route, p_route)) {
            // the best route has been added, send out announce msg
            // fprintf(stdout, "\n[as%u] add new route [%s]\n", g_as_id, __FUNCTION__);
            // print_route(p_route);
            /*
            p_msg = _assemble_one_route(p_route, PEER, ANNOUNCE);
            if (p_msg) {
                as_send_message(sfd, (void *) p_msg, p_msg->msg_len);
                // fprintf(stdout, "\n[as%u] announce new best route [%s]\n", g_as_id, __FUNCTION__);
            }
            // if old best route existed, send out withdraw msg
            if (p_potential_best_route) {
                p_msg = _assemble_one_route(p_potential_best_route, PEER, WITHDRAW);
                if (p_msg) {
                    // fprintf(stdout, "\n[as%u] withdraw old best route [%s]\n", g_as_id, __FUNCTION__);
                    as_send_message(sfd, (void *) p_msg, p_msg->msg_len);
                }
            }
            */
        }
    } else if (p_exch_route->oprt_type == WITHDRAW) {
        if (del_rib_entry(g_p_rib, &p_potential_best_route, p_route)) {
            // the best route has been deleted, send out withdraw msg
            // fprintf(stdout, "\n[as%u] del old route [%s]\n", g_as_id, __FUNCTION__);
            // print_route(p_route);
            /*
            p_msg = _assemble_one_route(p_route, PEER, WITHDRAW);
            if (p_msg) {
                as_send_message(sfd, (void *) p_msg, p_msg->msg_len);
                // fprintf(stdout, "\n[as%u] withdraw old best route [%s]\n", g_as_id, __FUNCTION__);
            }
            // if new best route is selected, send out announce msg
            if (p_potential_best_route) {
                p_msg = _assemble_one_route(p_potential_best_route, PEER, ANNOUNCE);
                if (p_msg) {
                    // fprintf(stdout, "\n[as%u] announce new best route [%s]\n", g_as_id, __FUNCTION__);
                    as_send_message(sfd, (void *) p_msg, p_msg->msg_len);
                }
            }
            */
        }
    }
    // fprintf(stdout, "\n[as%u] Current rib: [%s]\n", g_as_id, __FUNCTION__);
    print_rib(g_p_rib);
    return SUCCESS;
}

void as_start_session_handshake_to_agnt(int sfd, uint32_t id)
{
    g_as_id = id;
    bgp_message_t *p_init_msg = malloc(sizeof *p_init_msg);
    if (!p_init_msg) {
        // fprintf(stderr, "\nmalloc failed [%s]\n", __FUNCTION__);
        return;
    }
    p_init_msg->msg_len = HEADER_LEN;
    p_init_msg->msg_type = R_INIT_SESSION;
    p_init_msg->src_id = g_as_id;
    p_init_msg->dst_id = g_as_id;

    g_p_ra_session_info = malloc(sizeof *g_p_ra_session_info);
    if (!g_p_ra_session_info) {
        // fprintf(stderr, "\nmalloc failed [%s]\n", __FUNCTION__);
        free(p_init_msg);
        return;
    }
    g_p_ra_session_info->status = R_WAIT_M0;

    // fprintf(stdout, "\n[as%u] start handshake to rs [%s]\n", g_as_id, __FUNCTION__);
    as_send_message(sfd, (void *) p_init_msg, p_init_msg->msg_len);
}
