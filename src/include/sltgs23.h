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
#include "crl.h"
#include "signature.h"
#include "proof.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "groupsig.h"
#include "shim/pbc_ext.h"
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @def GROUPSIG_SLTGS23_CODE
 * @brief SLTGS23 scheme code.
 */
#define GROUPSIG_SLTGS23_CODE 10

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
#define SLTGS23_JOIN_SEQ 3

/**
 * @var sltgs23_description
 * @brief SLTGS23's description.
 */
static const groupsig_description_t sltgs23_description = {
  GROUPSIG_SLTGS23_CODE, /**< SLTGS23's scheme code. */
  GROUPSIG_SLTGS23_NAME, /**< SLTGS23's scheme name. */
  0, /**< SLTGS23 does not have a GML. */
  0, /**< SLTGS23 does not have a CRL. */
  1, /**< SLTGS23 uses PBC. */
  0, /**< SLTGS23 does not have verifiable openings. */
  1, /**< SLTGS23's issuer key is the first manager key. */
  0 /**< SLTGS23's does not have inspector key. */
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
 * @fn int sltgs23_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
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
 * @fn int sltgs23_join_mem(message_t **mout, groupsig_key_t *memkey,
 *			      int seq, message_t *min, groupsig_key_t *grpkey)
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
 * @fn int sltgs23_join_mgr(message_t **mout, gml_t *gml,
 *                       groupsig_key_t *mgrkey,
 *                       int seq, message_t *min,
 *			 groupsig_key_t *grpkey)
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
int sltgs23_join_mgr(message_t **mout,
                  gml_t *gml,
                  groupsig_key_t *mgrkey,
                  int seq,
                  message_t *min,
                  groupsig_key_t *grpkey);

/**
 * @fn int sltgs23_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey,
 *	              groupsig_key_t *grpkey, unsigned int seed)
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
int sltgs23_sign(groupsig_signature_t *sig, message_t *msg,
              groupsig_key_t *memkey,
              groupsig_key_t *grpkey, unsigned int seed);

/**
 * @fn int sltgs23_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg,
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
int sltgs23_verify(uint8_t *ok, groupsig_signature_t *sig,
                message_t *msg,
                groupsig_key_t *grpkey);

/**
 * @fn int sltgs23_identify(uint8_t *ok,
 *                           groupsig_proof_t **proof,
 *                           groupsig_key_t *grpkey,
 *                           groupsig_key_t *memkey,
 *                           groupsig_signature_t *sig,
 *                           message_t *msg)
 * @brief Enables a member to determine whether a specific SLTGS23 signature has
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
int sltgs23_identify(uint8_t *ok,
                  groupsig_proof_t **proof,
                  groupsig_key_t *grpkey,
                  groupsig_key_t *memkey,
                  groupsig_signature_t *sig,
                  message_t *msg);

/**
 * @typedef int sltgs23_link(groupsig_proof_t **proof,
 *                        groupsig_key_t *grpkey,
 *                        groupsig_key_t *memkey,
 *                        message_t *msg,
 *                        groupsig_signature_t **sigs,
 *                        message_t **msgs,
 *                        uint32_t n)
 * @brief Issues a proof of several SLTGS23 signatures being
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
// int sltgs23_link(groupsig_proof_t **proof,
//               groupsig_key_t *grpkey,
//               groupsig_key_t *memkey,
//               message_t *msg,
//               groupsig_signature_t **sigs,
//               message_t **msgs,
//               uint32_t n);

/**
 * @fn int groupsig_verify_link(uint8_t *ok,
 *                              groupsig_key_t *grpkey,
 *                              groupsig_proof_t *proof,
 *                              message_t *msg,
 *                              groupsig_signature_t **sigs,
 *                              message_t **msgs,
 *                              uint32_t n)
 * @brief Verifies proofs of several SLTGS23 signatures being linked.
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
// int sltgs23_verify_link(uint8_t *ok,
//                      groupsig_key_t *grpkey,
//                      groupsig_proof_t *proof,
//                      message_t *msg,
//                      groupsig_signature_t **sigs,
//                      message_t **msgs,
//                      uint32_t n);

/**
 * @fn int sltgs23_blind(groupsig_blindsig_t *bsig,
 *                    groupsig_key_t *bldkey,
 *                    groupsig_key_t *grpkey,
 *                    message_t *msg,
 *                    groupsig_signature_t *sig)
 * @brief Blinding of group signatures.
 *
 * @param[in,out] bsig The produced blinded group signature.
 * @param[in,out] bldkey The key used for blinding. If NULL, a fresh one
 *  is created.
 * @param[in] grpkey The group key.
 * @param[in] sig The group signature to blind.
 * @param[in] msg The signed message.
 *
 * @return IOK or IERROR.
 */
int sltgs23_blind(groupsig_blindsig_t *bsig,
               groupsig_key_t **bldkey,
               groupsig_key_t *grpkey,
               groupsig_signature_t *sig,
               message_t *msg);


/**
 * @fn int sltgs23_trace_blind(groupsig_blindsig_t *bsig,
 *                    groupsig_key_t *bldkey,
 *                    groupsig_key_t *grpkey,
 *                    message_t *msg,
 *                    groupsig_signature_t *sig)
 * @brief Blinding of group signatures.
 *
 * @param[in,out] bsig The produced blinded group signature.
 * @param[in,out] bldkey The key used for blinding. If NULL, a fresh one
 *  is created.
 * @param[in] grpkey The group key.
 * @param[in] sig The group signature to blind.
 *
 * @return IOK or IERROR.
 */
int sltgs23_trace_blind(identity_t *nym, groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
	       groupsig_key_t *grpkey, groupsig_blindsig_t *sig
	      );
/**
 * @fn int sltgs23_blind(groupsig_blindsig_t *bsig,
 *                    groupsig_key_t *bldkey,
 *                    groupsig_key_t *grpkey,
 *                    message_t *msg,
 *                    groupsig_signature_t *sig)
 * @brief Blinding of group signatures.
 *
 * @param[in,out] bsig The produced blinded group signature.
 * @param[in,out] bldkey The key used for blinding. If NULL, a fresh one
 *  is created.
 * @param[in] grpkey The group key.
 * @param[in] sig The group signature to blind.
 *
 * @return IOK or IERROR.
 */
int sltgs23_trace_blind(identity_t *nym, groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
	       groupsig_key_t *grpkey, groupsig_blindsig_t *sig);


/**
 * @fn int sltgs23_convert(groupsig_blindsig_t **csig,
 *                      groupsig_blindsig_t **bsig,
 *                      uint32_t n_bsigs,
 *	                groupsig_key_t *grpkey,
 *                      groupsig_key_t *mgrkey,
 *                      groupsig_key_t *bldkey,
 *                      message_t *msg)
 * @brief Converts blinded group signatures.
 *
 * @param[in,out] csig Array to store the converted signatures.
 * @param[in] bsig The blinded signatures to be converted.
 * @param[in] n_bsigs The size of the previous array.
 * @param[in] grpkey The group public key.
 * @param[in] mgrkey The 'manager' key (containing at least
 *  the converting key).
 * @param[in] bldkey The public blinding key.
 * @param[in] msg The signed messages. Optional.
 * @return IOK or IERROR.
 */
int sltgs23_convert(groupsig_blindsig_t **csig,
                 groupsig_blindsig_t **bsig,
                 uint32_t n_bsigs,
                 groupsig_key_t *grpkey,
                 groupsig_key_t *mgrkey,
                 groupsig_key_t *bldkey,
                 message_t *msg
                );

/**
 * @fn int sltgs23_convert(groupsig_blindsig_t **csig,
 *                      groupsig_blindsig_t **bsig,
 *                      uint32_t n_bsigs,
 *	                groupsig_key_t *grpkey,
 *                      groupsig_key_t *mgrkey,
 *                      groupsig_key_t *bldkey,
 *                      message_t *msg)
 * @brief Converts blinded group signatures.
 *
 * @param[in,out] csig Array to store the converted signatures.
 * @param[in] bsig The blinded signatures to be converted.
 * @param[in] n_bsigs The size of the previous array.
 * @param[in] grpkey The group public key.
 * @param[in] mgrkey The 'manager' key (containing at least
 *  the converting key).
 * @param[in] bldkey The public blinding key.
 * @param[in] msg The signed messages. Optional.
 * @return IOK or IERROR.
 */
int sltgs23_trace_convert(groupsig_blindsig_t **csig,
                 groupsig_blindsig_t **bsig,
                 uint32_t n_bsigs,
                 groupsig_key_t *grpkey,
                 groupsig_key_t *mgrkey,
                 groupsig_key_t *bldkey,
                 message_t *msg
                );

/**
 * @fn int sltgs23_unblind(identity_t *nym,
 *                      groupsig_signature_t *sig,
 *                      groupsig_blindsig_t *bsig,
 *                      groupsig_key_t *grpkey,
 *                      groupsig_key_t *bldkey,
 *                      message_t *msg)
 * @brief Unblinds the nym in a SLTGS23 group signature.
 *
 * @param[in,out] nym The unblinded nym.
 * @param[in,out] sig The unblinded signature. Ignored.
 * @param[in] bsig The blinded signature.
 * @param[in] grpkey The group key.
 * @param[in] bldkey The key used for blinding. If NULL, a fresh one
 *  is created.
 * @param[in] msg The signed message. Optional.
 *
 * @return IOK or IERROR.
 */
int sltgs23_unblind(identity_t *nym,
                 groupsig_signature_t *sig,
                 groupsig_blindsig_t *bsig,
                 groupsig_key_t *grpkey,
                 groupsig_key_t *bldkey,
                 message_t *msg);
/**
 * @fn int sltgs23_trace_unblind(identity_t *nym,
 *                      groupsig_signature_t *sig,
 *                      groupsig_blindsig_t *bsig,
 *                      groupsig_key_t *grpkey,
 *                      groupsig_key_t *bldkey,
 *                      message_t *msg)
 * @brief Unblinds the nym in a SLTGS23 group signature.
 *
 * @param[in,out] nym The unblinded nym.
 * @param[in,out] sig The unblinded signature. Ignored.
 * @param[in] bsig The blinded signature.
 * @param[in] grpkey The group key.
 * @param[in] bldkey The key used for blinding. If NULL, a fresh one
 *  is created.
 * @param[in] msg The signed message. Optional.
 *
 * @return IOK or IERROR.
 */
int sltgs23_trace_unblind(identity_t *nym,
                 groupsig_signature_t *sig,
                 groupsig_blindsig_t *bsig,
                 groupsig_key_t *grpkey,
                 groupsig_key_t *bldkey,
                 message_t *msg);

/**
 * @var sltgs23_groupsig_bundle
 * @brief The set of functions to manage SLTGS23 groups.
 */
static const groupsig_t sltgs23_groupsig_bundle = {
 desc: &sltgs23_description, /**< Contains the SLTGS23 scheme description. */
 init: &sltgs23_init, /**< Initializes the variables needed by SLTGS23. */
 clear:  &sltgs23_clear, /**< Frees the variables needed by SLTGS23. */
 setup: &sltgs23_setup, /**< Sets up SLTGS23 groups. */
 get_joinseq:  &sltgs23_get_joinseq, /**< Returns the number of messages in the join
			protocol. */
 get_joinstart: &sltgs23_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &sltgs23_join_mem, /**< Executes member-side joins. */
 join_mgr: &sltgs23_join_mgr, /**< Executes manager-side joins. */
 sign: &sltgs23_sign, /**< Issues SLTGS23 signatures. */
 verify:  &sltgs23_verify, /**< Verifies SLTGS23 signatures. */
 verify_batch: NULL,
 open: NULL, // &sltgs23_open, /**< Opens SLTGS23 signatures. */
 open_verify: NULL, // &sltgs23_open_verify_f, /**< SLTGS23 does not create proofs of opening. */
 reveal: NULL, // &sltgs23_reveal, /**< Reveals the tracing trapdoor from SLTGS23 signatures. */
 trace: NULL, // &sltgs23_trace, /**< Traces the issuer of a signature. */
 claim: NULL, // &sltgs23_claim, /**< Claims, in ZK, "ownership" of a signature. */
 claim_verify: NULL, // &sltgs23_claim_verify, /**< Verifies claims. */
 prove_equality: NULL, // &sltgs23_prove_equality, /**< Issues "same issuer" ZK proofs for several signatures. */
 prove_equality_verify: NULL, // &sltgs23_prove_equality_verify, /**< Verifies "same issuer" ZK proofs. */
 blind:  &sltgs23_blind, // &sltgs23_blind, /**< Blinds group signatures. */
 convert:  &sltgs23_convert, // &sltgs23_convert, /**< Converts blinded group signatures. */
 unblind:  &sltgs23_unblind, // &sltgs23_unblind, /**< Unblinds converted group signatures. */
 identify:  &sltgs23_identify, /**< Determines whether a signature has been issued by a member. */
 link: NULL, /**< Links a set of SLTGS23 signatures. */
 verify_link: NULL, /**< Verifies a proof of link. */
 seqlink: NULL, // &sltgs23_seqlink, /**< Sequentially links a st of SLTGS23 signatures. */
 verify_seqlink: NULL, // &sltgs23_verify_seqlink, /**< Verifies a proof of sequential link. */
 trace_blind: &sltgs23_trace_blind, // &sltgs23_trace_blind, /**< Traces the issuer of a blinded signature. */
trace_convert: &sltgs23_trace_convert, // &sltgs23_trace_convert, /**< Converts a blinded signature for tracing. */
trace_unblind: &sltgs23_trace_unblind, // &sltgs23_trace_unblind, /**< Unblinds a converted signature for tracing. */
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _SLTGS23_H */

/* sltgs23.h ends here */
