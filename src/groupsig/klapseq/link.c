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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "types.h"
#include "sysenv.h"
#include "bigz.h"
#include "sys/mem.h"
#include "klapseq.h"
#include "groupsig/klapseq/grp_key.h"
#include "groupsig/klapseq/mem_key.h"
#include "groupsig/klapseq/signature.h"
//#include "groupsig/klapseq/identity.h"
#include "groupsig/klapseq/proof.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int klapseq_link(groupsig_proof_t **proof,
		 groupsig_key_t *grpkey,
		 groupsig_key_t *memkey,
		 message_t *msg,
		 groupsig_signature_t **sigs,
		 message_t **msgs,
		 uint32_t n) {

  pbcext_element_G1_t *hscp, *hscp_, *nym_;
  klapseq_signature_t *klapseq_sig;
  klapseq_mem_key_t *klapseq_memkey;
  spk_dlog_t *spk;
  hash_t *hc;
  char *msg_scp, *msg_msg;
  int rc;
  uint32_t i;
  uint8_t ok;
  klapseq_proof_t *klapseq_proof;
  
  if(!proof ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !memkey || memkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_link", __LINE__, LOGERROR);
    return IERROR;
  }
  
  rc = IOK;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;

  klapseq_memkey = memkey->key;
  klapseq_proof =  ((klapseq_proof_t *)(*proof)->proof);


  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_link);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_link);
  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, klapseq_link);
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_link);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, klapseq_link);

  /* Iterate through all signatures, verify, identify and
     compute batched scope and nym */
  for (i=0; i<n; i++ ) {

    /* Verify signature */
    if (klapseq_verify(&ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, klapseq_link);
    if (!ok) GOTOENDRC(IFAIL, klapseq_link);

    /* Check if it is a signature issued by memkey */
    // if (klapseq_identify(&ok, NULL, grpkey, memkey, sigs[i], msgs[i]) == IERROR)
    //   GOTOENDRC(IERROR, klapseq_link); signer should know that the signature is from memkey, so we can skip this step
    


    if (!ok) {
      GOTOENDRC(IFAIL, klapseq_link);
    }

    /* "Accumulate" scp */
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, klapseq_link);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, klapseq_link);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, klapseq_link);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, klapseq_link);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;

    if(pbcext_element_G1_add(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, klapseq_link);

  }

  /* nym_ = hscp_^alpha */
  if(pbcext_element_G1_mul(nym_, hscp_, klapseq_memkey->alpha) == IERROR)
    GOTOENDRC(IERROR, klapseq_link);

  /* Do the SPK */

  // For now, we just use the .msg part of the msg JSON, but
  // the .scp part might come in handy in the future
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, klapseq_link);

  spk = klapseq_proof->seq_proof->spk;

  if(spk_dlog_G1_sign(spk, nym_, hscp_, klapseq_memkey->alpha, (byte_t *) msg_msg,
		      strlen(msg_msg)) == IERROR) GOTOENDRC(IERROR, klapseq_link);

 klapseq_link_end:

  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  return rc;

}

/* link.c ends here */
