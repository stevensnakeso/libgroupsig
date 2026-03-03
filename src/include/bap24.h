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

#ifndef _BAP24_H
#define _BAP24_H

#include "key.h"
#include "gml.h"
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
 * @def GROUPSIG_BAP24_CODE
 * @brief BAP24 scheme code.
 */
#define GROUPSIG_BAP24_CODE 9

/**
 * @def GROUPSIG_BAP24_NAME
 * @brief BAP24 scheme name.
 */
#define GROUPSIG_BAP24_NAME "BAP24"

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define BAP24_JOIN_START 0

/* Number of exchanged messages */
#define BAP24_JOIN_SEQ 3

/**
 * @var bap24_description
 * @brief BAP24's description.
 */
static const groupsig_description_t bap24_description = {
  GROUPSIG_BAP24_CODE, /**< BAP24's scheme code. */
  GROUPSIG_BAP24_NAME, /**< BAP24's scheme name. */
  1, /**< BAP24 has a GML. */
  0, /**< BAP24 does not have a CRL. */
  1, /**< BAP24 uses PBC. */
  1, /**< BAP24 has verifiable openings. */
  1, /**< BAP24's issuer key is the first manager key. */
  0 /**< BAP24 relies only on GML for opening. */
};

/**
 * @fn int bap24_init()
 * @brief Initializes the internal variables needed by BAP24. In this case,
 *  it only sets up the pairing module.
 *
 * @return IOK or IERROR.
 */
int bap24_init();

/**
 * @fn int bap24_clear()
 * @brief Frees the memory initialized by bap24_init.
 *
 * @return IOK or IERROR.
 */
int bap24_clear();

/**
 * @fn int bap24_setup(groupsig_key_t *grpkey,
 *                    groupsig_key_t *mgrkey,
 *                    gml_t *gml)
 * @brief The setup function for the BAP24 scheme.
 *
 * @param[in,out] grpkey An initialized group key, will be updated with the newly
 *   created group's group key.
 * @param[in,out] mgrkey An initialized manager key, will be updated with the
 *   newly created group's manager key.
 * @param[in,out] gml An initialized GML, will be set to an empty GML.
 *
 * @return IOK or IERROR.
 */
int bap24_setup(groupsig_key_t *grpkey,
               groupsig_key_t *mgrkey,
               gml_t *gml);

/**
 * @fn int bap24_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 *
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */
int bap24_get_joinseq(uint8_t *seq);

/**
 * @fn int bap24_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 *
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */
int bap24_get_joinstart(uint8_t *start);

/**
 * @fn int bap24_join_mem(message_t **mout,
 *                       groupsig_key_t *memkey,
 *			 int seq,
 *                       message_t *min,
 *                       groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the BAP24 scheme.
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
int bap24_join_mem(message_t **mout,
                  groupsig_key_t *memkey,
                  int seq,
                  message_t *min,
                  groupsig_key_t *grpkey);

/**
 * @fn int bap24_join_mgr(message_t **mout,
 *                       gml_t *gml,
 *                       groupsig_key_t *mgrkey,
 *                       int seq,
 *                       message_t *min,
 *			 groupsig_key_t *grpkey)
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
int bap24_join_mgr(message_t **mout,
                  gml_t *gml,
                  groupsig_key_t *mgrkey,
                  int seq,
                  message_t *min,
                  groupsig_key_t *grpkey);

/**
 * @fn int bap24_sign(groupsig_signature_t *sig,
 *                   message_t *msg,
 *                   groupsig_key_t *memkey,
 *	             groupsig_key_t *grpkey,
 *                   unsigned int seed)
 * @brief Issues BAP24 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized BAP24 group signature. Will be updated with
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
int bap24_sign(groupsig_signature_t *sig,
              message_t *msg,
              groupsig_key_t *memkey,
              groupsig_key_t *grpkey,
              unsigned int seed);

/**
 * @fn int bap24_verify(uint8_t *ok,
 *                     groupsig_signature_t *sig,
 *                     message_t *msg,
 *		       groupsig_key_t *grpkey);
 * @brief Verifies a BAP24 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 *
 * @return IOK or IERROR.
 */
int bap24_verify(uint8_t *ok,
                groupsig_signature_t *sig,
                message_t *msg,
                groupsig_key_t *grpkey);

/**
 * @fn int bap24_open(uint64_t *index, groupsig_proof_t *proof, crl_t *crl,
 *                    groupsig_signature_t *sig, groupsig_key_t *grpkey,
 *	              groupsig_key_t *mgrkey, gml_t *gml)
 * @brief Opens a BAP24 group signature.
 *
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] index Will be updated with the signer's index in the GML.
 * @param[in,out] proof BAP24 ignores this parameter.
 * @param[in,out] crl Unused. Ignore.
 * @param[in] sig The signature to open.
 * @param[in] grpkey The group key.
 * @param[in] mgrkey The manager's key.
 * @param[in] gml The GML.
 *
 * @return IOK if it was possible to open the signature. IFAIL if the open
 *  trapdoor was not found, IERROR otherwise.
 */
int bap24_open(uint64_t *index,
              groupsig_proof_t *proof,
              crl_t *crl,
              groupsig_signature_t *sig,
              groupsig_key_t *grpkey,
              groupsig_key_t *mgrkey,
              gml_t *gml);

/**
 * @fn int bap24_open_verify(uint8_t *ok,
 *                          groupsig_proof_t *proof,
 *                          groupsig_signature_t *sig,
 *                          groupsig_key_t *grpkey)
 *
 * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
 *  signature.
 * @param[in] id The identity produced by the open algorithm. Unused. Can be NULL.
 * @param[in] proof The proof of opening.
 * @param[in] sig The group signature associated to the proof.
 * @param[in] grpkey The group key.
 *
 * @return IOK or IERROR
 */
int bap24_open_verify(uint8_t *ok,
                     groupsig_proof_t *proof,
                     groupsig_signature_t *sig,
                     groupsig_key_t *grpkey);

/**
 * @var bap24_groupsig_bundle
 * @brief The set of functions to manage BAP24 groups.
 */
static const groupsig_t bap24_groupsig_bundle = {
 desc: &bap24_description, /**< Contains the BAP24 scheme description. */
 init: &bap24_init, /**< Initializes the variables needed by BAP24. */
 clear: &bap24_clear, /**< Frees the varaibles needed by BAP24. */
 setup: &bap24_setup, /**< Sets up BAP24 groups. */
 get_joinseq: &bap24_get_joinseq, /**< Returns the number of messages in the join protocol. */
 get_joinstart: &bap24_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &bap24_join_mem, /**< Executes member-side joins. */
 join_mgr: &bap24_join_mgr, /**< Executes manager-side joins. */
 sign: &bap24_sign, /**< Issues BAP24 signatures. */
 verify: &bap24_verify, /**< Verifies BAP24 signatures. */
 verify_batch: NULL,
 open: &bap24_open, /**< Opens BAP24 signatures. */
 open_verify: &bap24_open_verify, /**< Verifies proofs of opening. */
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

#endif /* _BAP24_H */

/* bap24.h ends here */
