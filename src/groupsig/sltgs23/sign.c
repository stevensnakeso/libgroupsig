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
#include <limits.h>

#include "sltgs23.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mem_key.h"
#include "groupsig/sltgs23/signature.h"
#include "shim/hash.h"
#include "sys/mem.h"

int sltgs23_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	      groupsig_key_t *grpkey, unsigned int seed) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the SLTGS23 paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk and appending a '_' for
     variables named with a hat or something similar). Auxiliar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux[_<name>]. */

  pbcext_element_Fr_t *r1, *r2, *r3, *ss, *negy, *aux_Zr, *x[7];
  pbcext_element_Fr_t *zeta1, *zeta2;
  pbcext_element_G1_t *aux, *aux_h2negr2, *A_d, *hscp;
  pbcext_element_G1_t *y[3], *g[5];
  sltgs23_signature_t *sltgs23_sig;
  sltgs23_grp_key_t *sltgs23_grpkey;
  sltgs23_mem_key_t *sltgs23_memkey;
  /* sltgs23_sysenv_t *sltgs23_sysenv; */
  hash_t *hc;
  char *msg_msg, *msg_scp;
  uint16_t i[6][2], prods[3];
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_sig = sig->sig;
  sltgs23_grpkey = grpkey->key;
  sltgs23_memkey = memkey->key;
  /* sltgs23_sysenv = sysenv->data; */
  rc = IOK;

  r1 = r2 = r3 = ss = negy = aux_Zr = NULL;
  aux = aux_h2negr2 = A_d = NULL;
  msg_msg = NULL; msg_scp = NULL;
  hc = NULL;
  
  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  
  /* r1, r2 \in_R Z_p */
  if(!(r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(r1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(r2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  /* nym = Hash(scp)^y */
  sltgs23_sig->nym = pbcext_element_G1_init();
  hscp = pbcext_element_G1_init();
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, sltgs23_sign);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  if(pbcext_element_G1_mul(sltgs23_sig->nym, hscp, sltgs23_memkey->y) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign); 

  /* AA = A^r1*/
  if(!(sltgs23_sig->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(sltgs23_sig->AA, sltgs23_memkey->A, r1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

  /* A_ = AA^{-x}(g1*h1^y*h2^s)^r1 */
  /* Good thing we precomputed much of this... */
  if(!(aux = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(!(aux_Zr = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(aux, sltgs23_memkey->H, sltgs23_memkey->h2s) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(aux, sltgs23_grpkey->g1, aux) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(aux, aux, r1) == IERROR) // aux = (g1*h1^y*h2^s)^r1
    GOTOENDRC(IERROR, sltgs23_sign); 
  if(pbcext_element_Fr_neg(aux_Zr, sltgs23_memkey->x) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(sltgs23_sig->A_, sltgs23_sig->AA, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(sltgs23_sig->A_, sltgs23_sig->A_, aux) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  /* d = (g1*h1^y*h2^s)^r1*h2^{-r2} */
  if(!(sltgs23_sig->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(!(aux_h2negr2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_neg(aux_Zr, r2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(sltgs23_sig->d, sltgs23_grpkey->h2, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(sltgs23_sig->d, aux, sltgs23_sig->d) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

  /* r3 = r1^{-1} */
  if(!(r3 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_inv(r3, r1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

  /* ss = s - r2*r3 */
  if(!(ss = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_mul(aux_Zr, r2, r3) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(ss, sltgs23_memkey->s, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

  /* Auxiliar variables for the spk */
  if(pbcext_element_Fr_neg(aux_Zr, sltgs23_memkey->x) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_neg(ss, ss) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(!(negy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_neg(negy, sltgs23_memkey->y) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(!(A_d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_sub(A_d, sltgs23_sig->A_, sltgs23_sig->d) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

  // @TODO Check
  /* Isn't there a more concise way to do the following? */
  y[0] = sltgs23_sig->nym;
  y[1] = A_d;
  y[2] = sltgs23_grpkey->g1;

  g[0] = hscp;
  g[1] = sltgs23_sig->AA;
  g[2] = sltgs23_grpkey->h2;
  g[3] = sltgs23_sig->d;
  g[4] = sltgs23_grpkey->h1;

  x[0] = aux_Zr; // -x
  x[1] = sltgs23_memkey->y;
  x[2] = r2;
  x[3] = r3;
  x[4] = ss; // -ss
  x[5] = negy;

  i[0][0] = 1; i[0][1] = 0; // hscp^y = (g[0],x[1])
  i[1][0] = 0; i[1][1] = 1; // AA^-x = (g[1],x[0])
  i[2][0] = 2; i[2][1] = 2; // h2^r2 = (g[2],x[2])
  i[3][0] = 3; i[3][1] = 3; // d^r3 = (g[3],x[3])
  i[4][0] = 4; i[4][1] = 2; // h2^-ss = (g[2],x[4])
  i[5][0] = 5; i[5][1] = 4; // h1^-y = (g[4],x[5])

  prods[0] = 1;
  prods[1] = 2;
  prods[2] = 3;
  
  if(!(sltgs23_sig->pi = spk_rep_init(6))) GOTOENDRC(IERROR, sltgs23_sign);
  if(spk_rep_sign(sltgs23_sig->pi,
		  y, 3, // element_t *y, uint16_t ny,
		  g, 5, // element_t *g, uint16_t ng,
		  x, 6, // element_t *x, uint16_t nx,
		  i, 6, // uint16_t **i, uint16_t ni,
		  prods,
		  (byte_t *) msg_msg, strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

 sltgs23_sign_end:

  if(r1) { pbcext_element_Fr_free(r1); r1 = NULL; }
  if(r2) { pbcext_element_Fr_free(r2); r2 = NULL; }
  if(r3) { pbcext_element_Fr_free(r3); r3 = NULL; }
  if(ss) { pbcext_element_Fr_free(ss); ss = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(aux_Zr) { pbcext_element_Fr_free(aux_Zr); aux = NULL; }
  if(aux_h2negr2) { pbcext_element_G1_free(aux_h2negr2); aux_h2negr2 = NULL; }
  if(negy) { pbcext_element_Fr_free(negy); negy = NULL; }
  if(A_d) { pbcext_element_G1_free(A_d); A_d = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  
  if (rc == IERROR) {
    
    if(sltgs23_sig->nym) {
      pbcext_element_G1_free(sltgs23_sig->nym);
      sltgs23_sig->nym = NULL;
    }
    if(sltgs23_sig->AA) {
      pbcext_element_G1_free(sltgs23_sig->AA);
      sltgs23_sig->AA = NULL;
    }
    if(sltgs23_sig->A_) {
      pbcext_element_G1_free(sltgs23_sig->A_);
      sltgs23_sig->A_ = NULL;
    }
    if(sltgs23_sig->d) {
      pbcext_element_G1_free(sltgs23_sig->d);
      sltgs23_sig->d = NULL;
    }
    if(sltgs23_sig->pi) {
      spk_rep_free(sltgs23_sig->pi);
      sltgs23_sig->pi = NULL;
    }
    
  }
  
  return rc;
  
}

/* sign.c ends here */
