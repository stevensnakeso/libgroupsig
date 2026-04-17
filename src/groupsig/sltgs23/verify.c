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


/* Public functions */
int sltgs23_verify(uint8_t *ok,
		groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *grpkey) {

  sltgs23_signature_t *sltgs23_sig;
  sltgs23_grp_key_t *sltgs23_grpkey;
  byte_t *b = NULL;
  uint64_t len = 0;
  hash_t *hc = NULL;
  byte_t *aux_bytes = NULL;
  pbcext_element_Fr_t *_c = NULL;
  /* sltgs23_sysenv_t *sltgs23_sysenv; */

  char *msg_msg, *msg_scp;
  int rc;
  
  if(!ok || !sig || !msg || 
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;

  msg_msg = NULL; msg_scp = NULL;


  
  sltgs23_sig = sig->sig;
  sltgs23_grpkey = grpkey->key;
  /* sltgs23_sysenv = sysenv->data; */

  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);

  pbcext_element_G1_t *t1, *t2, *t3, *t4, *aux_G1;
  pbcext_element_GT_t *t5, *aux_GT;

  if(!(t1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(!(t2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(!(t3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(!(t4 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(!(aux_G1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(!(t5 = pbcext_element_GT_init())) GOTOENDRC(IERROR, sltgs23_verify);
  if(!(aux_GT = pbcext_element_GT_init())) GOTOENDRC(IERROR, sltgs23_verify);

  if(pbcext_element_G1_mul(t1, sltgs23_sig->nym1, sltgs23_sig->c) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_mul(aux_G1, sltgs23_grpkey->g, sltgs23_sig->srho) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_add(t1, t1, aux_G1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);

  if(pbcext_element_G1_mul(t2, sltgs23_sig->nym2, sltgs23_sig->c) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_mul(aux_G1, sltgs23_grpkey->cpk, sltgs23_sig->srho) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_add(t2, t2, aux_G1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_mul(aux_G1, sltgs23_grpkey->h1, sltgs23_sig->sy) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_add(t2, t2, aux_G1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);

  if(pbcext_element_G1_mul(t3, sltgs23_sig->A1, sltgs23_sig->c) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_mul(aux_G1, sltgs23_grpkey->h1, sltgs23_sig->sr1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_add(t3, t3, aux_G1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_mul(aux_G1, sltgs23_grpkey->h2, sltgs23_sig->sr2) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_add(t3, t3, aux_G1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);

 
  if(pbcext_element_G1_mul(t4, sltgs23_grpkey->h1, sltgs23_sig->szeta1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_mul(aux_G1, sltgs23_grpkey->h2, sltgs23_sig->szeta2) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_add(t4, t4, aux_G1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);  
  if(pbcext_element_G1_mul(aux_G1, sltgs23_sig->A1, sltgs23_sig->s_x) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_G1_add(t4, t4, aux_G1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);  
  // pbcext_element_G1_mul(t4, sltgs23_grpkey->h 1, sltgs23_sig->szeta1);
  // pbcext_element_G1_mul(aux_G1, sltgs23_grpkey->h2, sltgs23_sig->szeta2);
  // pbcext_element_G1_add(t4, t4, aux_G1);
  // pbcext_element_G1_mul(aux_G1, sltgs23_sig->A1, sltgs23_sig->s_x);
  // pbcext_element_G1_add(t4, t4, aux_G1);

  if(pbcext_pairing(t5, sltgs23_sig->A2, sltgs23_grpkey->ipk) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_pairing(aux_GT, sltgs23_grpkey->g1, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_div(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_pow(t5, t5, sltgs23_sig->c) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);

  if(pbcext_pairing(aux_GT, sltgs23_sig->A2, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, sltgs23_sig->s_x) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_mul(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h2, sltgs23_grpkey->ipk) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, sltgs23_sig->sr1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_mul(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h2, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, sltgs23_sig->szeta1) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_mul(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h1, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, sltgs23_sig->sy) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_mul(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);  
  if(pbcext_pairing(aux_GT, sltgs23_grpkey->h2, sltgs23_grpkey->g2) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_pow(aux_GT, aux_GT, sltgs23_sig->ss) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  if(pbcext_element_GT_mul(t5, t5, aux_GT) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  
  // if(pbcext_element_G1_cmp(t1, sltgs23_sig->t1) != 0) GOTOENDRC(IERROR, sltgs23_verify);
  // if(pbcext_element_G1_cmp(t2, sltgs23_sig->t2) != 0) GOTOENDRC(IERROR, sltgs23_verify);
  // if(pbcext_element_G1_cmp(t3, sltgs23_sig->t3) != 0) GOTOENDRC(IERROR, sltgs23_verify);
  // if(pbcext_element_G1_cmp(t4, sltgs23_sig->t4) != 0) GOTOENDRC(IERROR, sltgs23_verify);  //??
  // if(pbcext_element_GT_cmp(t5, sltgs23_sig->t5) != 0) GOTOENDRC(IERROR, sltgs23_verify);

  
  if(!(_c = pbcext_element_Fr_init()))  GOTOENDRC(IERROR, sltgs23_verify);
  
  if (!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, sltgs23_verify);
  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t3) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, t4) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, t5) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  if (hash_update(hc, aux_bytes, len) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
   if (hash_update(hc, msg->bytes, msg->length) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  if (hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, sltgs23_verify);
 
  if (pbcext_element_Fr_from_hash(_c, hc->hash, hc->length) == IERROR)
    GOTOENDRC(IERROR, sltgs23_verify);

  if(pbcext_element_Fr_cmp(_c, sltgs23_sig->c) == 0) {
    *ok = 1;
  }
  else {
    *ok = 0;  
  }


  
 sltgs23_verify_end:

  if(hc) { hash_free(hc); hc = NULL; }
  if(aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }
  if(_c) { pbcext_element_Fr_free(_c); _c = NULL; }
  if(t1) { pbcext_element_G1_free(t1); t1 = NULL; }
  if(t2) { pbcext_element_G1_free(t2); t2 = NULL; }
  if(t3) { pbcext_element_G1_free(t3); t3 = NULL; }
  if(t4) { pbcext_element_G1_free(t4); t4 = NULL; }
  if(aux_G1) { pbcext_element_G1_free(aux_G1); aux_G1 = NULL; }
  if(t5) { pbcext_element_GT_free(t5); t5 = NULL; }
  if(aux_GT) { pbcext_element_GT_free(aux_GT); aux_GT = NULL; }
  

  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
    
  return rc;

}

/* verify.c ends here */
