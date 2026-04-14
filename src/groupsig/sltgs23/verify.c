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

#include <stdlib.h>

#include "sltgs23.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/signature.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

/* Private functions */
static int _sltgs23_verify_spk(uint8_t *ok, sltgs23_signature_t *sltgs23_sig,
			    pbcext_element_G1_t *hscp,
			    char *msg, sltgs23_grp_key_t *sltgs23_grpkey) {

  pbcext_element_G1_t *A_d, *y[3], *g[5];  
  uint16_t i[6][2], prods[3];
  
  /* No input checks, as the parameters have been checked by the caller. */
  
  /* Auxiliar variables for the spk */
  if(!(A_d = pbcext_element_G1_init())) return IERROR;
  if(pbcext_element_G1_sub(A_d, sltgs23_sig->A_, sltgs23_sig->d) == IERROR)
    return IERROR;

  /* Isn't there a more concise way to do the following? */
  y[0] = sltgs23_sig->nym;
  y[1] = A_d;
  y[2] = sltgs23_grpkey->g1;

  g[0] = hscp;
  g[1] = sltgs23_sig->AA;
  g[2] = sltgs23_grpkey->h2;
  g[3] = sltgs23_sig->d;
  g[4] = sltgs23_grpkey->h1;

  i[0][0] = 1; i[0][1] = 0; // hscp^y = (g[0],x[1])
  i[1][0] = 0; i[1][1] = 1; // AA^-x = (g[1],x[0])
  i[2][0] = 2; i[2][1] = 2; // h2^r2 = (g[2],x[2])
  i[3][0] = 3; i[3][1] = 3; // d^r3 = (g[3],x[3])
  i[4][0] = 4; i[4][1] = 2; // h2^-ss = (g[2],x[4])
  i[5][0] = 5; i[5][1] = 4; // h1^-y = (g[4],x[5])

  prods[0] = 1;
  prods[1] = 2;
  prods[2] = 3;

  /* Verify the SPK */
  if(spk_rep_verify(ok,
		    y, 3,
		    g, 5,
		    i, 6,
		    prods,
		    sltgs23_sig->pi,
		    (byte_t *) msg, strlen(msg)) == IERROR) {
    pbcext_element_G1_free(A_d); A_d = NULL;
    return IERROR;
  }
  
  pbcext_element_G1_free(A_d); A_d = NULL;
  
  return IOK;

}

/* Public functions */
int sltgs23_verify(uint8_t *ok,
		groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *grpkey) {

  pbcext_element_GT_t *e1, *e2;
  pbcext_element_G1_t *hscp;
  sltgs23_signature_t *sltgs23_sig;
  sltgs23_grp_key_t *sltgs23_grpkey;
  /* sltgs23_sysenv_t *sltgs23_sysenv; */
  hash_t *hc;
  char *msg_msg, *msg_scp;
  int rc;
  
  if(!ok || !sig || !msg || 
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  e1 = NULL; e2 = NULL;
  msg_msg = NULL; msg_scp = NULL;
  hc = NULL;
  hscp = NULL;
  
  sltgs23_sig = sig->sig;
  sltgs23_grpkey = grpkey->key;
  /* sltgs23_sysenv = sysenv->data; */

  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);

  /* AA must not be 1 (since we use additive notation for G1, 
     it must not be 0) */
  if(pbcext_element_G1_is0(sltgs23_sig->AA)) {
    *ok = 0;
    GOTOENDRC(IOK, sltgs23_verify);
  }

  /* e(AA,ipk) must equal e(A_,g2) */
  if(!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_pairing(e1, sltgs23_sig->AA, sltgs23_grpkey->ipk) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if(!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_pairing(e2, sltgs23_sig->A_, sltgs23_grpkey->g2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);

  if(pbcext_element_GT_cmp(e1, e2)) {
    *ok = 0;
    GOTOENDRC(IOK, sltgs23_verify);
  }

  /* Verify the SPK */

  /* Recompute hscp */
  hscp = pbcext_element_G1_init();
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, sltgs23_verify);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  if(_sltgs23_verify_spk(ok, sltgs23_sig, hscp, msg_msg, sltgs23_grpkey) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  
 sltgs23_verify_end:

  if(e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if(e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
    
  return rc;

}

/* verify.c ends here */
