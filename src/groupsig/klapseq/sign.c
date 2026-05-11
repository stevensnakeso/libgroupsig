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

#include "klapseq.h"
#include "groupsig/klapseq/grp_key.h"
#include "groupsig/klapseq/mem_key.h"
#include "groupsig/klapseq/signature.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int klapseq_sign(groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *memkey,
		groupsig_key_t *grpkey,
		unsigned int seed) {

  pbcext_element_Fr_t *r;
  klapseq_signature_t *klapseq_sig;
  klapseq_grp_key_t *klapseq_grpkey;
  klapseq_mem_key_t *klapseq_memkey;
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_sig = sig->sig;
  klapseq_grpkey = grpkey->key;
  klapseq_memkey = memkey->key;
  r = NULL;
  rc = IOK;

  /* Randomize u, v and w */
  if (!(r = pbcext_element_Fr_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_Fr_random(r) == IERROR) GOTOENDRC(IERROR, klapseq_sign);

  if (!(klapseq_sig->uu = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->uu, klapseq_memkey->u, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if (!(klapseq_sig->vv = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->vv, klapseq_memkey->v, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if (!(klapseq_sig->ww = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->ww, klapseq_memkey->w, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  
  /* Compute signature of knowledge of alpha */
  if (!(klapseq_sig->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, klapseq_sign);
  if (spk_dlog_G1_sign(klapseq_sig->pi,
		       klapseq_sig->ww,
		       klapseq_sig->uu,
		       klapseq_memkey->alpha,
		       msg->bytes,
		       msg->length) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  

 klapseq_sign_end:

  if (r) { pbcext_element_Fr_free(r); r = NULL; }

  if (rc == IERROR) {
    
    if (klapseq_sig->uu) {
      pbcext_element_G1_free(klapseq_sig->uu);
      klapseq_sig->uu = NULL;
    }
    if (klapseq_sig->vv) {
      pbcext_element_G1_free(klapseq_sig->vv);
      klapseq_sig->vv = NULL;
    }
    if (klapseq_sig->ww) {
      pbcext_element_G1_free(klapseq_sig->ww);
      klapseq_sig->ww = NULL;
    }
    if (klapseq_sig->pi) {
      spk_dlog_free(klapseq_sig->pi);
      klapseq_sig->pi = NULL;
    }    
    
  }
  
  return rc;
  
}

/* sign.c ends here */
