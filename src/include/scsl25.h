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

#ifndef _SCSL25_H
#define _SCSL25_H

#include "key.h"
#include "gml.h"
#include "crl.h"
#include "signature.h"
#include "proof.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "groupsig.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_SCSL25_CODE
 * @brief SCSL25 scheme code.
 */
#define GROUPSIG_SCSL25_CODE 8

/**
 * @def GROUPSIG_SCSL25_NAME
 * @brief SCSL25 scheme name.
 */
#define GROUPSIG_SCSL25_NAME "SCSL25"

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define SCSL25_JOIN_START 0

/* Number of exchanged messages */
#define SCSL25_JOIN_SEQ 3

/**
 * @var dl21_description
 * @brief DL21's description.
 */
static const groupsig_description_t scsl25_description = {
  GROUPSIG_SCSL25_CODE, /**< SCSL25's scheme code. */
  GROUPSIG_SCSL25_NAME, /**< SCSL25's scheme name. */
  0, /**< SCSL25 does not have a GML. */
  0, /**< SCSL25 does not have a CRL. */
  1, /**< SCSL25 uses PBC. */
  0, /**< SCSL25 does not have verifiable openings. */
  1, /**< SCSL25's issuer key is the first manager key. */
  0 /**< SCSL25's does not have inspector key. */
};

/**
 * @fn int scsl25_init()
 * @brief Initializes the internal variables needed by SCSL25. In this case,
 *  it only sets up the pairing module.
 *
 * @return IOK or IERROR.
 */
int scsl25_init();

/**
 * @fn int scsl25_clear()
 * @brief Frees the memory initialized by scsl25_init.
 *
 * @return IOK or IERROR.
 */
int scsl25_clear();

/**
 * @fn int scsl25_setup(groupsig_key_t *grpkey,
 *                       groupsig_key_t *mgrkey,
 *                       gml_t *gml)
 * @brief The setup function for the SCSL25 scheme.
 *
 * @param[in,out] grpkey An initialized group key, will be updated with the newly
 *   created group's group key.
 * @param[in,out] mgrkey An initialized manager key, will be updated with the
 *   newly created group's manager key.
 * @param[in,out] gml An initialized GML, will be set to an empty GML.
 * @param[in] config A SCSL25 configuration structure.
 *
 * @return IOK or IERROR.
 */
int scsl25_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml);

/**
 * @fn int scsl25_get_joinseq(uint8_t *seq)
 *
 * @brief Returns the number of messages to be exchanged in the join protocol.
 *
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */
int scsl25_get_joinseq(uint8_t *seq);

/**
 * @fn int scsl25_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 *
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */
int scsl25_get_joinstart(uint8_t *start);

/**
 * @fn int scsl25_join_mem(message_t **mout,
 *                          groupsig_key_t *memkey,
 *			    int seq,
 *                          message_t *min,
 *                          groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the SCSL25 scheme.
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
int scsl25_join_mem(message_t **mout,
                     groupsig_key_t *memkey,
                     int seq,
                     message_t *min,
                     groupsig_key_t *grpkey);

/**
 * @fn int scsl25_join_mgr(message_t **mout,
 *                          gml_t *gml,
 *                          groupsig_key_t *mgrkey,
 *                          int seq,
 *                          message_t *min,
 *			    groupsig_key_t *grpkey)
 * @brief Executes the manager-side join of the join procedure.
 *
 * @param[in,out] mout Message to be produced by the current step of the join/
 *  issue protocol.
 * @param[in,out] gml The group membership list that may be updated with
 *  information related to the new member.
 * @param[in] mgrkey The group manager key.
 * @param[in] seq The step to run of the join/issue protocol.
 *  manager.
 * @param[in] min Input message received from the member for the current step of
 *  the join/issue protocol.
 * @param[in] grpkey The group key.
 *
 * @return IOK or IERROR.
 */
int scsl25_join_mgr(message_t **mout,
                     gml_t *gml,
                     groupsig_key_t *mgrkey,
                     int seq,
                     message_t *min,
                     groupsig_key_t *grpkey);

/**
 * @fn int scsl25_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey,
 *	              groupsig_key_t *grpkey, unsigned int seed)
 * @brief Issues SCSL25 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized SCSL25 group signature. Will be updated with
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
int scsl25_sign(groupsig_signature_t *sig, message_t *msg,
                 groupsig_key_t *memkey,
                 groupsig_key_t *grpkey, unsigned int seed);

/**
 * @fn int scsl25_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg,
 *		        groupsig_key_t *grpkey);
 * @brief Verifies a SCSL25 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 *
 * @return IOK or IERROR.
 */
int scsl25_verify(uint8_t *ok, groupsig_signature_t *sig,
                   message_t *msg,
                   groupsig_key_t *grpkey);

/**
 * @fn int scsl25_identify(uint8_t *ok,
 *                           groupsig_proof_t **proof,
 *                           groupsig_key_t *grpkey,
 *                           groupsig_key_t *memkey,
 *                           groupsig_signature_t *sig,
 *                           message_t *msg)
 * @brief Enables a member to determine whether a specific SCSL25 signature has
 *  been issued by him/herself or not.
 *
 * @param[in,out] ok Will be set to 1 (signature issued by member) or 0 (not
 *  issued by member.)
 * @param[in,out] proof If not null, and the algorithm supports it, will be
 * set to contain a proof of having issued the given signature.
 * @param[in] grpkey The group key.
 * @param[in] memkey The key used for issuing the signature.
 * @param[in] sigs The signature.
 * @param[in] msg The signed message.
 *
 * @return IOK or IERROR.
 */
int scsl25_identify(uint8_t *ok,
                     groupsig_proof_t **proof,
                     groupsig_key_t *grpkey,
                     groupsig_key_t *memkey,
                     groupsig_signature_t *sig,
                     message_t *msg);

/**
 * @typedef int scsl25_link(groupsig_proof_t **proof,
 *                        groupsig_key_t *grpkey,
 *                        groupsig_key_t *memkey,
 *                        message_t *msg,
 *                        groupsig_signature_t **sigs,
 *                        message_t **msgs,
 *                        uint32_t n)
 * @brief Issues a proof of several SCSL25 signatures being
 *        linked (issued by the same member.)
 *
 * @param[in,out] proof The proof to be issued.
 * @param[in] grpkey The group key.
 * @param[in] memkey The key used for issuing the individual signatures.
 * @param[in] msg The message to add to the created proof (prevents replays.)
 * @param[in] sigs The signatures to link.
 * @param[in] msgs The signed messages.
 * @param[in] n The size of the sig and msg arrays.
 *
 * @return IOK or IERROR.
 */
int scsl25_link(groupsig_proof_t **proof,
                 groupsig_key_t *grpkey,
                 groupsig_key_t *memkey,
                 message_t *msg,
                 groupsig_signature_t **sigs,
                 message_t **msgs,
                 uint32_t n);

/**
 * @fn int groupsig_verify_link(uint8_t *ok,
 *                              groupsig_key_t *grpkey,
 *                              groupsig_proof_t *proof,
 *                              message_t *msg,
 *                              groupsig_signature_t **sigs,
 *                              message_t **msgs,
 *                              uint32_t n)
 * @brief Verifies proofs of several SCSL25 signatures being linked.
 *
 * @param[in,out] ok Will be set to 1 (proof valid) or 0 (proof invalid).
 * @param[in] proof The proof to be verified.
 * @param[in] grpkey The group key.
 * @param[in] msg The message to add to the created proof (prevents replays.)
 * @param[in] sigs The signatures.
 * @param[in] msgs The signed messages.
 * @param[in] n The size of the sig and msg arrays.
 *
 * @return IOK or IERROR.
 */
int scsl25_verify_link(uint8_t *ok,
                        groupsig_key_t *grpkey,
                        groupsig_proof_t *proof,
                        message_t *msg,
                        groupsig_signature_t **sigs,
                        message_t **msgs,
                        uint32_t n);


/**
 * @typedef int scsl25_seqlink(groupsig_proof_t **proof,
 *                              groupsig_key_t *grpkey,
 *                              groupsig_key_t *memkey,
 *                              message_t *msg,
 *                              groupsig_signature_t **sigs,
 *                              message_t **msgs,
 *                              uint32_t n)
 * @brief Issues a proof of several SCSL25 signatures being
 *        sequentially linked (issued by the same member.)
 *
 * @param[in,out] proof The proof to be issued.
 * @param[in] grpkey The group key.
 * @param[in] memkey The key used for issuing the individual signatures.
 * @param[in] msg The message to add to the created proof (prevents replays.)
 * @param[in] sigs The signatures to link.
 * @param[in] msgs The signed messages.
 * @param[in] n The size of the sig and msg arrays.
 *
 * @return IOK or IERROR.
 */
int scsl25_seqlink(groupsig_proof_t **proof,
                    groupsig_key_t *grpkey,
                    groupsig_key_t *memkey,
                    message_t *msg,
                    groupsig_signature_t **sigs,
                    message_t **msgs,
                    uint32_t n);

/**
 * @fn int groupsig_verify_seqlink(uint8_t *ok,
 *                              groupsig_key_t *grpkey,
 *                              groupsig_proof_t *proof,
 *                              message_t *msg,
 *                              groupsig_signature_t **sigs,
 *                              message_t **msgs,
 *                              uint32_t n)
 * @brief Verifies proofs of several SCSL25 signatures being sequentially
 *  linked.
 *
 * @param[in,out] ok Will be set to 1 (proof valid) or 0 (proof invalid).
 * @param[in] proof The proof to be verified.
 * @param[in] grpkey The group key.
 * @param[in] msg The message to add to the created proof (prevents replays.)
 * @param[in] sigs The signatures.
 * @param[in] msgs The signed messages.
 * @param[in] n The size of the sig and msg arrays.
 *
n * @return IOK or IERROR.
 */
int scsl25_verify_seqlink(uint8_t *ok,
                           groupsig_key_t *grpkey,
                           groupsig_proof_t *proof,
                           message_t *msg,
                           groupsig_signature_t **sigs,
                           message_t **msgs,
                           uint32_t n);

/**
 * @var scsl25_groupsig_bundle
 * @brief The set of functions to manage SCSL25 groups.
 */
static const groupsig_t scsl25_groupsig_bundle = {
 desc: &scsl25_description, /**< Contains the SCSL25 scheme description. */
 init: &scsl25_init, /**< Initializes the variables needed by SCSL25. */
 clear: &scsl25_clear, /**< Frees the variables needed by SCSL25. */
 setup: &scsl25_setup, /**< Sets up SCSL25 groups. */
 get_joinseq: &scsl25_get_joinseq, /**< Returns the number of messages in the join protocol. */
 get_joinstart: &scsl25_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &scsl25_join_mem, /**< Executes member-side joins. */
 join_mgr: &scsl25_join_mgr, /**< Executes manager-side joins. */
 sign: &scsl25_sign, /**< Issues SCSL25 signatures. */
 verify: &scsl25_verify, /**< Verifies SCSL25 signatures. */
 open: NULL,
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
 identify: &scsl25_identify, /**< Determines whether a signature has been issued by a member. */
 link: &scsl25_link, /**< Links a set of SCSL25 signatures. */
 verify_link: &scsl25_verify_link, /**< Verifies a proof of link. */
 seqlink: &scsl25_seqlink, /**< Sequentially links a set of SCSL25 sigs. */
 verify_seqlink: &scsl25_verify_seqlink, /**< Verifies a proof of sequential link. */
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _SCSL25_H */

/* scsl25.h ends here */
