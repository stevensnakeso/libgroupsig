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
#include "sltgs23.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mem_key.h"
#include "groupsig/sltgs23/signature.h"
#include "groupsig/sltgs23/identity.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int sltgs23_identify(uint8_t *ok,
		  groupsig_proof_t **proof,
		  groupsig_key_t *grpkey,
		  groupsig_key_t *memkey,
		  groupsig_signature_t *sig,
		  message_t *msg) {
  
  pbcext_element_G1_t *hscp;
  sltgs23_signature_t *sltgs23_sig;
  sltgs23_mem_key_t *sltgs23_memkey;
  hash_t *hc;
  char *msg_scp;
  int rc;
  uint8_t _ok;
  
  if(!ok ||
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !memkey || memkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !sig || sig->scheme != GROUPSIG_SLTGS23_CODE ||
     !msg) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_identify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL;
  hc = NULL;
  msg_scp = NULL;
  
  sltgs23_sig = sig->sig;
  sltgs23_memkey = memkey->key;

  /* Recompute nym */
  
  /* Parse scope value from msg */
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, sltgs23_identify);

  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_identify);
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, sltgs23_identify);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, sltgs23_identify);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, sltgs23_identify);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  if(pbcext_element_G1_mul(hscp, hscp, sltgs23_memkey->y) == IERROR)
    GOTOENDRC(IERROR, sltgs23_identify);
  
  /* Check if nym = h(scp)^y */
  if(pbcext_element_G1_cmp(hscp, sltgs23_sig->nym)) {
    *ok = 0;
    GOTOENDRC(IOK, sltgs23_identify);
  } else {
    *ok = 1;
  }
    
 sltgs23_identify_end:

  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  
  return rc;

}

/* identify.c ends here */
