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

#include "klapseq.h"
#include "groupsig/klapseq/grp_key.h"
#include "groupsig/klapseq/signature.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

/* 
   L is used for the "small" exponents test in batch verification. 
   We fix it to 11. This will cause the "small" exponents that are randomly
   chosen to be in the interval [0,2^11-1=2047]. Is this good?
   @TODO Check with https://cseweb.ucsd.edu/~mihir/papers/batch.pdf
   (issueXX)
*/
#define L 11

/* Private functions */

/* Public functions */
int klapseq_verify(uint8_t *ok,
		 groupsig_signature_t *sig,
		 message_t *msg,
		 groupsig_key_t *grpkey) {

  pbcext_element_GT_t *e1, *e2, *e3;
  klapseq_signature_t *klapseq_sig;
  klapseq_grp_key_t *klapseq_grpkey;
  int rc;
  uint8_t _ok;

  if(!ok || !msg || !sig || sig->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_sig = sig->sig;
  klapseq_grpkey = grpkey->key;
  rc = IOK;

  e1 = e2 = e3 = NULL;
  _ok = 0;

  /* Verify SPK */
  if (spk_dlog_G1_verify(&_ok,
			 klapseq_sig->ww,
			 klapseq_sig->uu,
			 klapseq_sig->pi,
			 msg->bytes,
			 msg->length) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify);

  if (!_ok) {
    *ok = 0;
    GOTOENDRC(IOK, klapseq_verify);
  }

  /* e1 = e(vv,gg) */
  if (!(e1 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_verify);
  if (pbcext_pairing(e1, klapseq_sig->vv, klapseq_grpkey->gg))
    GOTOENDRC(IERROR, klapseq_verify);
  
  /* e2 = e(uu,XX) */
  if (!(e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_verify);
  if (pbcext_pairing(e2, klapseq_sig->uu, klapseq_grpkey->XX))
    GOTOENDRC(IERROR, klapseq_verify);
  
  /* e3 = e(ww,YY) */
  if (!(e3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_verify);
  if (pbcext_pairing(e3, klapseq_sig->ww, klapseq_grpkey->YY))
    GOTOENDRC(IERROR, klapseq_verify);

  if (pbcext_element_GT_mul(e2, e2, e3) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify);
  
  /* Compare the result with the received challenge */
  if (pbcext_element_GT_cmp(e1, e2)) { /* Different: sig fail */
    *ok = 0;
  } else { /* Same: sig OK */
    *ok = 1;
  }

 klapseq_verify_end:

  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }

  return rc;

}

int klapseq_verify_batch(uint8_t *ok,
			groupsig_signature_t **sigs,
			message_t **msgs,
			uint32_t n,
			groupsig_key_t *grpkey) {

  pbcext_element_Fr_t *ei;
  pbcext_element_G1_t *g1, *uu, *vv, *ww;
  pbcext_element_GT_t *e1, *e2, *e3;
  bigz_t bei;
  char *sei;
  klapseq_signature_t *klapseq_sig;
  klapseq_grp_key_t *klapseq_grpkey;
  message_t *msg;
  int rc;
  uint32_t i;
  uint8_t _ok;

  if(!ok || !msgs || !sigs ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_verify_batch", __LINE__, LOGERROR);
    return IERROR;
  }


  ei = NULL;
  g1 = uu = vv = ww = NULL;
  e1 = e2 = e3 = NULL;
  bei = NULL;
  sei = NULL;
  _ok = 0;
  rc = IOK;    
  
  klapseq_grpkey = grpkey->key;

  if (!(ei = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
if (!(g1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);  
  if (!(uu = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (pbcext_element_G1_clear(uu) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (!(vv = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (pbcext_element_G1_clear(vv) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify_batch);  
  if (!(ww = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (pbcext_element_G1_clear(ww) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify_batch);  

  if (!(bei = bigz_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
  
  for (i=0; i<n; i++) {

    if (sigs[i]->scheme != GROUPSIG_KLAPSEQ_CODE)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    
    klapseq_sig = sigs[i]->sig;
    msg = msgs[i];

    /* Verify SPK */
    if (spk_dlog_G1_verify(&_ok,
			   klapseq_sig->ww,
			   klapseq_sig->uu,
			   klapseq_sig->pi,
			   msg->bytes,
			   msg->length) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);

    if (!_ok) {
      *ok = 0;
      GOTOENDRC(IOK, klapseq_verify_batch);
    }

    /*
      This is a bit cumbersome because pbcext does not include a function to
      compute random numbers in a given interval. But bigz does. So we first 
      compute a random number in the desired interval using bigz, we export it 
      to a string, and then import it with pbcext.
      Try to look for more efficient options (issueXX+1).
    */    
    if (bigz_urandomb(bei, L) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    if (!(sei = bigz_get_str16(bei)))
      GOTOENDRC(IERROR, klapseq_verify_batch);
    if (pbcext_element_Fr_from_string(&ei, sei, 16) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    mem_free(sei); sei = NULL;

    if (pbcext_element_G1_mul(g1, klapseq_sig->uu, ei) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    if (pbcext_element_G1_add(uu, uu, g1) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    if (pbcext_element_G1_mul(g1, klapseq_sig->vv, ei) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    if (pbcext_element_G1_add(vv, vv, g1) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    if (pbcext_element_G1_mul(g1, klapseq_sig->ww, ei) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);
    if (pbcext_element_G1_add(ww, ww, g1) == IERROR)
      GOTOENDRC(IERROR, klapseq_verify_batch);

  }

  if (!(e1 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (pbcext_pairing(e1, vv, klapseq_grpkey->gg) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (!(e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (pbcext_pairing(e2, uu, klapseq_grpkey->XX) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify_batch);  
  if (!(e3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (pbcext_pairing(e3, ww, klapseq_grpkey->YY) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify_batch);
  if (pbcext_element_GT_mul(e2, e2, e3) == IERROR)
    GOTOENDRC(IERROR, klapseq_verify_batch);

  if (pbcext_element_GT_cmp(e1, e2)) *ok = 0;
  else *ok = 1;

 klapseq_verify_batch_end:

  if (ei) { pbcext_element_Fr_free(ei); ei = NULL; }  
  if (g1) { pbcext_element_G1_free(g1); g1 = NULL; }
  if (uu) { pbcext_element_G1_free(uu); uu = NULL; }
  if (vv) { pbcext_element_G1_free(vv); vv = NULL; }
  if (ww) { pbcext_element_G1_free(ww); ww = NULL; }  
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if (bei) { bigz_free(bei); bei = NULL; }
  if (sei) { mem_free(sei); sei = NULL; }

  return rc;

}

/* verify.c ends here */
