/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef _SLTGS23_H
#define _SLTGS23_H

#include "key.h"
#include "gml.h"
#include "signature.h"
#include "proof.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "groupsig.h"
#include "bigz.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_SLTGS23_CODE
 * @brief SLTGS23 scheme code.
 */
#define GROUPSIG_SLTGS23_CODE 1

/**
 * @def GROUPSIG_SLTGS23_NAME
 * @brief SLTGS23 scheme name.
 */
#define GROUPSIG_SLTGS23_NAME "SLTGS23"

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define SLTGS23_JOIN_START 0

/* Number of exchanged messages */
#define SLTGS23_JOIN_SEQ 1

/**
 * @var sltgs23_description
 * @brief SLTGS23's description.
 */
static const groupsig_description_t sltgs23_description = {
  GROUPSIG_SLTGS23_CODE, /**< SLTGS23's scheme code. */
  GROUPSIG_SLTGS23_NAME, /**< SLTGS23's scheme name. */
  1, /**< SLTGS23 has a GML. */
  0, /**< SLTGS23 does not have a CRL. */
  1, /**< SLTGS23 uses PBC. */
  0, /**< SLTGS23 does not have verifiable openings. */
  1, /**< SLTGS23's issuer key is the first manager key. */
  1 /**< SLTGS23's inspector (opener) key is the first manager key. */
};

/**
 * @fn int sltgs23_init()
 * @brief Initializes the internal variables needed by SLTGS23. In this case,
 *  it only sets up the pairing module.
 *
 * @return IOK or IERROR.
 */
int sltgs23_init();

/**
 * @fn int sltgs23_clear()
 * @brief Frees the memory initialized by sltgs23_init.
 *
 * @return IOK or IERROR.
 */
int sltgs23_clear();

/**
 * @fn int sltgs23_setup(groupsig_key_t *grpkey,
 *                     groupsig_key_t *mgrkey,
 *                     gml_t *gml)
 * @brief The setup function for the SLTGS23 scheme.
 *
 * @param[in,out] grpkey An initialized group key, will be updated with the newly
 *   created group's group key.
 * @param[in,out] mgrkey An initialized manager key, will be updated with the
 *   newly created group's manager key.
 * @param[in,out] gml An initialized GML, will be set to an empty GML.
 *
 * @return IOK or IERROR.
 */
int sltgs23_setup(groupsig_key_t *grpkey,
                groupsig_key_t *mgrkey,
                gml_t *gml);

/**
 * @fn int sltgs23_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 *
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */
int sltgs23_get_joinseq(uint8_t *seq);

/**
 * @fn int sltgs23_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 *
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */
int sltgs23_get_joinstart(uint8_t *start);

/**
 * @fn int sltgs23_join_mem(message_t **mout,
 *                        groupsig_key_t *memkey,
 *			  int seq, message_t *min,
 *                        groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the SLTGS23 scheme.
 *
 * @param[in,out] mout Message to be produced by the current step of the
 *  join/issue protocol.
 * @param[in,out] memkey An initialized group member key. Must have been
 *  initialized by the caller. Will be set to the final member key once
 *  the join/issue protocol is completed.
 * @param[in] seq The step to run of the join/issue protocol.
 * @param[in] min Input message received from the manager for the current step
 *  of the join/issue protocol.
 * @param[in] grpkey The group key.
 *
 * @return IOK or IERROR.
 */
int sltgs23_join_mem(message_t **mout,
                   groupsig_key_t *memkey,
                   int seq,
                   message_t *min,
                   groupsig_key_t *grpkey);

/**
 * @fn int sltgs23_join_mgr(message_t **mout,
 *                        gml_t *gml,
 *                        groupsig_key_t *mgrkey,
 *                        int seq,
 *                        message_t *min,
 *			  groupsig_key_t *grpkey)
 * @brief Executes the manager-side join of the join procedure.
 *
 * @param[in,out] mout Message to be produced by the current step of the join/
 *  issue protocol.
 * @param[in,out] gml The group membership list that may be updated with
 *  information related to the new member.
// * @param[in,out] memkey The partial member key to be completed by the group
* @param[in] seq The step to run of the join/issue protocol.
 *  manager.
 * @param[in] min Input message received from the member for the current step of
 *  the join/issue protocol.
 * @param[in] mgrkey The group manager key.
 * @param[in] grpkey The group key.
 *
 * @return IOK or IERROR.
 */
int sltgs23_join_mgr(message_t **mout,
                   gml_t *gml,
                   groupsig_key_t *mgrkey,
                   int seq,
                   message_t *min,
                   groupsig_key_t *grpkey);

/**
 * @fn int sltgs23_sign(groupsig_signature_t *sig,
 *                    message_t *msg,
 *                    groupsig_key_t *memkey,
 *	              groupsig_key_t *grpkey,
 *                    unsigned int seed)
 * @brief Issues SLTGS23 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized SLTGS23 group signature. Will be updated with
 *  the generated signature data.
 * @param[in] msg The message to sign.
 * @param[in] memkey The member key to use for signing.
 * @param[in] grpkey The group key.
 * @param[in] seed The seed. If it is set to UINT_MAX, the current system PRNG
 *  will be used normally. Otherwise, it will be reseeded with the specified
 *  seed before issuing the signature.
 *
 * @return IOK or IERROR.
 */
int sltgs23_sign(groupsig_signature_t *sig,
               message_t *msg,
               groupsig_key_t *memkey,
               groupsig_key_t *grpkey,
               unsigned int seed);

/**
 * @fn int sltgs23_verify(uint8_t *ok,
 *                      groupsig_signature_t *sig,
 *                      message_t *msg,
 *		        groupsig_key_t *grpkey);
 * @brief Verifies a SLTGS23 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 *
 * @return IOK or IERROR.
 */
int sltgs23_verify(uint8_t *ok,
                 groupsig_signature_t *sig,
                 message_t *msg,
                 groupsig_key_t *grpkey);

/**
 * @fn int sltgs23_open(uint64_t *index,
 *                    groupsig_proof_t *proof,
 *                    crl_t *crl,
 *                    groupsig_signature_t *sig,
 *                    groupsig_key_t *grpkey,
 *	              groupsig_key_t *mgrkey,
 *                    gml_t *gml)
 * @brief Opens a SLTGS23 group signature.
 *
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] id An initialized identity. Will be updated with the signer's
 *  real identity.
 * @param[in,out] proof SLTGS23 ignores this parameter.
 * @param[in,out] crl Unused. Ignore.
 * @param[in] sig The signature to open.
 * @param[in] grpkey The group key.
 * @param[in] mgrkey The manager's key.
 * @param[in] gml The GML.
 *
 * @return IOK if it was possible to open the signature. IFAIL if the open
 *  trapdoor was not found, IERROR otherwise.
 */
int sltgs23_open(uint64_t *index,
               groupsig_proof_t *proof,
               crl_t *crl,
               groupsig_signature_t *sig,
               groupsig_key_t *grpkey,
               groupsig_key_t *mgrkey,
               gml_t *gml);

/**
 * @var sltgs23_groupsig_bundle
 * @brief The set of functions to manage SLTGS23 groups.
 */
static const groupsig_t sltgs23_groupsig_bundle = {
 desc: &sltgs23_description, /**< Contains the SLTGS23 scheme description. */
 init: &sltgs23_init, /**< Initializes the variables needed by SLTGS23. */
 clear: &sltgs23_clear, /**< Frees the varaibles needed by SLTGS23. */
 setup: &sltgs23_setup, /**< Sets up SLTGS23 groups. */
 get_joinseq: &sltgs23_get_joinseq, /**< Returns the number of messages in the join
				     protocol. */
 get_joinstart: &sltgs23_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &sltgs23_join_mem, /**< Executes member-side joins. */
 join_mgr: &sltgs23_join_mgr, /**< Executes maanger-side joins. */
 sign: &sltgs23_sign, /**< Issues SLTGS23 signatures. */
 verify: &sltgs23_verify, /**< Verifies SLTGS23 signatures. */
 verify_batch: NULL,
 open: &sltgs23_open, /**< Opens SLTGS23 signatures. */
 open_verify: NULL,
 reveal: NULL,
 trace: NULL,
 claim: NULL,
 claim_verify: NULL,
 prove_equality: NULL,
 prove_equality_verify: NULL,
 blind: NULL,
 convert: NULL,
 unblind: NULL,
 identify: NULL,
 link: NULL,
 verify_link: NULL,
 seqlink: NULL,
 verify_seqlink: NULL
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _SLTGS23_H */

/* sltgs23.h ends here */
