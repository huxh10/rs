#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#include "sgx_dh.h"
#include "sgx_key_exchange.h"
#include "sgx_tseal.h"

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}


#define CLOSED      0x0
#define IN_PROGRESS 0x1
#define ACTIVE      0x2

// describe the channel direction
#define AGNT_TO_RN 0
#define AGNT_TO_LN 1

/* local communication with the route server */
                            /*              agent         rs        */
#define L_INIT_SESSION  1   /*   handshake: init                    */
#define L_REQ_SESSION   2   /*   handshake:           --> init      */
#define L_REP_MSG1      3   /*   handshake: proc_msg1 <--           */
#define L_EXCH_REPORT   4   /*   handshake:           --> proc_msg2 */
#define L_REP_MSG3      5   /*   handshake: proc_msg3 <--           */
#define L_EXCH_DATA     6   /* communicate:           <-->          */

/* remote communication with the AS */
                            /*              as            agent     */
#define R_INIT_SESSION 12   /*   handshake:           --> init      */
#define R_SEND_MSG0    13   /*   handshake: proc_msg0 <--           */
#define R_REP_MSG0     14   /*   handshake:           --> confirm   */
#define R_SEND_MSG1    15   /*   handshake: proc_msg1 <--           */
#define R_SEND_MSG2    16   /*   handshake:           --> proc_msg2 */
#define R_SEND_MSG3    17   /*   handshake: proc_msg3 <--           */
#define R_SEND_RESULT  18   /*   handshake:           --> proc_rslt */
#define R_EXCH_DATA    19   /* communicate:           <-->          */

/* remote communication handshake status */
#define R_WAIT_M0      1    // AS
#define R_WAIT_M0_RESP 2    // AGENT
#define R_WAIT_M1      3    // AS
#define R_WAIT_M2      4    // AGENT
#define R_WAIT_M3      5    // AS
#define R_WAIT_RSLT    6    // AGENT
#define R_WAIT_DATA    7    // BOTH

#define HEADER_LEN     12   // msg_len and msg_type

typedef struct _bgp_message_t {
    uint16_t msg_len;
    uint16_t msg_type;
    uint32_t src_id;
    uint32_t dst_id;
    uint8_t msg[];
} bgp_message_t;

/* local attestation message type */
typedef struct {
    uint32_t session_id;
    sgx_dh_msg1_t dh_msg1;
} l_rep_msg1_t;

typedef struct {
    uint32_t session_id;
    sgx_dh_msg2_t dh_msg2;
} l_rep_msg2_t;

typedef struct {
    sgx_dh_msg3_t dh_msg3;
} l_rep_msg3_t;


/* remote attestation consts */
#define EXTENDED_EPID_GROUP_ID 0

/* remote attestation message type */

typedef struct _ra_dh_session_t {
    uint32_t session_id;
    uint32_t status;
    sgx_ra_context_t context;
} ra_dh_session_t;

typedef struct {
    uint32_t extended_epid_group_id;
} r_msg0_t;

//Format of the AES-GCM message being exchanged between the source and the destination enclaves
typedef struct _exch_secure_message_t {
    //uint32_t session_id; //Session ID identifyting the session to which the message belongs
    sgx_aes_gcm_data_t secret;
} exch_secure_message_t;

#endif
