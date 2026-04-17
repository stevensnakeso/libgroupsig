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

  pbcext_element_Fr_t *r1, *r2, *rho, *_x;
  pbcext_element_Fr_t *zeta1, *zeta2;
  pbcext_element_G1_t *aux;
  sltgs23_signature_t *sltgs23_sig;
  sltgs23_grp_key_t *sltgs23_grpkey;
  sltgs23_mem_key_t *sltgs23_memkey;
  /* sltgs23_sysenv_t *sltgs23_sysenv; */
  char *msg_msg, *msg_scp;
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

  r1 = r2 =_x = zeta1 = zeta2 = NULL;
  aux = NULL;
  msg_msg = NULL; msg_scp = NULL;
  
  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

  if(!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  /* rho */
  if(!(rho = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(rho) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  /* r1, r2  */
  if(!(r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(r1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(r2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  
  /* zeta1 */
  if(!(zeta1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_mul(zeta1, r1, sltgs23_memkey->x) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  /* zeta2 */
  if(!(zeta2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_mul(zeta2, r2, sltgs23_memkey->x) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  /* nym1 = g^rho*/
  if(!(sltgs23_sig->nym1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(sltgs23_sig->nym1, sltgs23_grpkey->g, rho) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  /* nym2 = cpk^rho * h1 ^ y*/
  if(!(sltgs23_sig->nym2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(aux, sltgs23_grpkey->cpk, rho) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(sltgs23_sig->nym2, sltgs23_grpkey->h1, sltgs23_memkey->y) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(sltgs23_sig->nym2, sltgs23_sig->nym2, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  /* A1 = g1^r1*g2^r2  A2 = A*g2^r1*/
  if(!(sltgs23_sig->A1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(sltgs23_sig->A1, sltgs23_grpkey->h1, r1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

   if(!(sltgs23_sig->A2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_element_G1_mul(sltgs23_sig->A2, sltgs23_grpkey->h2, r2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(sltgs23_sig->A1, sltgs23_sig->A1, sltgs23_sig->A2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

 
  if(pbcext_element_G1_mul(aux, sltgs23_grpkey->h2, r1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(sltgs23_sig->A2, sltgs23_memkey->A, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(_x = pbcext_element_Fr_init()) {
    if(pbcext_element_Fr_neg(_x, sltgs23_memkey->x) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  }

  /* Compute the SOK */
  pbcext_element_Fr_t *pr1, *pr2, *px, *pzeta1, *pzeta2, *py, *prho, *ps, *_px;
  if(!(pr1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(pr1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(pr2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(pr2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(px = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(px) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(pzeta1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(pzeta1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(pzeta2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(pzeta2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(py = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(py) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(prho = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(prho) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(ps = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_random(ps) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(_px = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_neg(_px, px) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);


 
  pbcext_element_G1_t *t1, *t2, *t3, *t4;
  pbcext_element_GT_t *t5, *aux_GT;
  
  if(!(t1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(t1, sltgs23_grpkey->g, prho) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  
  if(!(t2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(t2, sltgs23_grpkey->cpk, prho) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(aux, sltgs23_grpkey->h1, py) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(t2, t2, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(!(t3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(t3, sltgs23_grpkey->h1, pr1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(aux, sltgs23_grpkey->h2, pr2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(t3, t3, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);


  // int64_t zero = 0;
  // pbcext_element_Fr_t *ftmp1;
  // if(!(ftmp1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);


  if(!(t4 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(t4, sltgs23_grpkey->h1, pzeta1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(aux, sltgs23_grpkey->h2, pzeta2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(t4, t4, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_mul(aux, sltgs23_sig->A1, _px) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_G1_add(t4, t4, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  // pbcext_element_Fr_set2(ftmp1,zero);
  // pbcext_element_G1_random(t4);
  // //pbcext_element_G1_set(ftmp2,scsl25_grpkey->g);
  // pbcext_element_G1_mul(t4,t4,ftmp1);


  // $t5 = (E_{A2\_h0})^{-k_e} \cdot (E_{g2\_ipk})^{k_{r1}} \cdot (E_{g2\_h0})^{k_{\delta1}} \cdot (E_{g1\_h0})^{k_y} \cdot (E_{g2\_h0})^{k_s}$
  if(!(t5 = pbcext_element_GT_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(aux_GT = pbcext_element_GT_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_pairing(t5, sltgs23_sig->A2, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_pow(t5, t5, _px) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h2, sltgs23_grpkey->ipk) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, pr1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_mul(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h2, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, pzeta1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_mul(t5,t5,aux_GT) == IERROR) GOTOENDRC(IERROR,sltgs23_sign);

  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h1,sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_pow(aux_GT, aux_GT,py) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_mul(t5,t5,aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h2, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, ps) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_GT_mul(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  /* Compute c = H(m, sc, zeta1, zeta2, t1, t2, t3, t4, t5) */
  
  uint64_t len = 0;
  hash_t *hc = NULL;
  byte_t *aux_bytes = NULL;
  
  if (!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, sltgs23_sign);
  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);

  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t3) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t4) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, t5) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  mem_free(aux_bytes); aux_bytes = NULL;

  if (hash_update(hc, msg->bytes, msg->length) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
  mem_free(aux_bytes); aux_bytes = NULL;

  if (hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if (!(sltgs23_sig->c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if (pbcext_element_Fr_from_hash(sltgs23_sig->c, hc->hash, hc->length) == IERROR)
    GOTOENDRC(IERROR, sltgs23_sign);
                      //*pr1, *pr2, *px, *pzeta1, *pzeta2, *py, *prho, *ps, *_px;
  pbcext_element_Fr_t  *aux_fr; //*sx
  if(!(aux_fr = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->sr1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->sr2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->szeta1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->szeta2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->sy = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->srho = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->ss = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);
  if(!(sltgs23_sig->s_x = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, r1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->sr1, pr1, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, r2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->sr2, pr2, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  // if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, px) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  // if(pbcext_element_Fr_sub(sltgs23_sig->s_x, pr1, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, zeta1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->szeta1, pzeta1, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  // if(pbcext_element_G1_mul(t4, sltgs23_grpkey->h1, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);//

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, zeta2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->szeta2, pzeta2, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  // if(pbcext_element_G1_mul(aux, sltgs23_grpkey->h2, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);//
  // if(pbcext_element_G1_add(t4, t4, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);//

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, sltgs23_memkey->y) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->sy, py, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, rho) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->srho, prho, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, sltgs23_memkey->s) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->ss, ps, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  if(pbcext_element_Fr_mul(aux_fr, sltgs23_sig->c, _x) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  if(pbcext_element_Fr_sub(sltgs23_sig->s_x, _px, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);

  // if(pbcext_element_G1_mul(aux, sltgs23_sig->A1, aux_fr) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);//
  // if(pbcext_element_G1_add(t4, t4, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);//


  // if(!(sltgs23_sig->t1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  // if(!(sltgs23_sig->t2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  // if(!(sltgs23_sig->t3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  // if(!(sltgs23_sig->t4 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_sign);
  // if(!(sltgs23_sig->t5 = pbcext_element_GT_init())) GOTOENDRC(IERROR, sltgs23_sign);
  // if(pbcext_element_G1_set(sltgs23_sig->t1, t1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign); 
  // if(pbcext_element_G1_set(sltgs23_sig->t2, t2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign); 
  // if(pbcext_element_G1_set(sltgs23_sig->t3, t3) == IERROR) GOTOENDRC(IERROR, sltgs23_sign); 
  // if(pbcext_element_G1_set(sltgs23_sig->t4, t4) == IERROR) GOTOENDRC(IERROR, sltgs23_sign); 
  // if(pbcext_element_GT_set(sltgs23_sig->t5, t5) == IERROR) GOTOENDRC(IERROR, sltgs23_sign); 

  // if(pbcext_element_G1_mul(t4, sltgs23_grpkey->h1, sltgs23_sig->szeta1) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  // if(pbcext_element_G1_mul(aux, sltgs23_grpkey->h2, sltgs23_sig->szeta2) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  // if(pbcext_element_G1_add(t4, t4, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);  
  // if(pbcext_element_G1_mul(aux, sltgs23_sig->A1, sltgs23_sig->s_x) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);
  // if(pbcext_element_G1_add(t4, t4, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_sign);  
  // if(pbcext_element_G1_cmp(t4, sltgs23_sig->t4) != 0) GOTOENDRC(IERROR, sltgs23_sign);
 sltgs23_sign_end:

  if(r1) { pbcext_element_Fr_free(r1); r1 = NULL; }
  if(r2) { pbcext_element_Fr_free(r2); r2 = NULL; }
  if(rho) { pbcext_element_Fr_free(rho); rho = NULL; }
  if(_x) { pbcext_element_Fr_free(_x); _x = NULL; }
  if(zeta1) { pbcext_element_Fr_free(zeta1); zeta1 = NULL; }
  if(zeta2) { pbcext_element_Fr_free(zeta2); zeta2 = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(aux_fr) { pbcext_element_Fr_free(aux_fr); aux_fr = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  if(pr1) { pbcext_element_Fr_free(pr1); pr1 = NULL; }
  if(pr2) { pbcext_element_Fr_free(pr2); pr2 = NULL; }
  if(px) { pbcext_element_Fr_free(px); px = NULL; }
  if(pzeta1) { pbcext_element_Fr_free(pzeta1); pzeta1 = NULL; }
  if(pzeta2) { pbcext_element_Fr_free(pzeta2); pzeta2 = NULL; }
  if(py) { pbcext_element_Fr_free(py); py = NULL; }
  if(prho) { pbcext_element_Fr_free(prho); prho = NULL; }
  if(ps) { pbcext_element_Fr_free(ps); ps = NULL; }
  if(_px) { pbcext_element_Fr_free(_px); _px = NULL; }
  if(t1) { pbcext_element_G1_free(t1); t1 = NULL; }
  if(t2) { pbcext_element_G1_free(t2); t2 = NULL; }
  if(t3) { pbcext_element_G1_free(t3); t3 = NULL; }
  if(t4) { pbcext_element_G1_free(t4); t4 = NULL; }
  if(t5) { pbcext_element_GT_free(t5); t5 = NULL; }
  if(aux_GT) { pbcext_element_GT_free(aux_GT); aux_GT = NULL; }
  

  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }

  if (rc == IERROR) {
    
    if(sltgs23_sig->A1) {
      pbcext_element_G1_free(sltgs23_sig->A1);
      sltgs23_sig->A1 = NULL;
    }
    if(sltgs23_sig->A2) {
      pbcext_element_G1_free(sltgs23_sig->A2);
      sltgs23_sig->A2 = NULL;
    }
    if(sltgs23_sig->nym1) {
      pbcext_element_G1_free(sltgs23_sig->nym1);
      sltgs23_sig->nym1 = NULL;
    }
    if(sltgs23_sig->nym2) {
      pbcext_element_G1_free(sltgs23_sig->nym2);
      sltgs23_sig->nym2 = NULL;
    }
    if(sltgs23_sig->c) {
      pbcext_element_Fr_free(sltgs23_sig->c);
      sltgs23_sig->c = NULL;
    }
    if(sltgs23_sig->sr1) {
      pbcext_element_Fr_free(sltgs23_sig->sr1);
      sltgs23_sig->sr1 = NULL;
    }
    if(sltgs23_sig->sr2) {
      pbcext_element_Fr_free(sltgs23_sig->sr2);
      sltgs23_sig->sr2 = NULL;
    }
    if(sltgs23_sig->s_x) {
      pbcext_element_Fr_free(sltgs23_sig->s_x);
      sltgs23_sig->s_x = NULL;
    }
    if(sltgs23_sig->szeta1) {
      pbcext_element_Fr_free(sltgs23_sig->szeta1);
      sltgs23_sig->szeta1 = NULL;
    }
    if(sltgs23_sig->szeta2) {
      pbcext_element_Fr_free(sltgs23_sig->szeta2);
      sltgs23_sig->szeta2 = NULL;
    }
    if(sltgs23_sig->sy) {
      pbcext_element_Fr_free(sltgs23_sig->sy);
      sltgs23_sig->sy = NULL;
    }
    if(sltgs23_sig->srho) {
      pbcext_element_Fr_free(sltgs23_sig->srho);
      sltgs23_sig->srho = NULL;
    }
    if(sltgs23_sig->ss) {
      pbcext_element_Fr_free(sltgs23_sig->ss);
      sltgs23_sig->ss = NULL;
    }
    if(sltgs23_sig->s_x) {
      pbcext_element_Fr_free(sltgs23_sig->s_x);
      sltgs23_sig->s_x = NULL;
    }
    
  }
  
  return rc;
  
}

/* sign.c ends here */
