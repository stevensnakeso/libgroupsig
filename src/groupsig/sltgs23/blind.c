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
#include "sltgs23.h"
#include "logger.h"
#include "bigz.h"
#include "sys/mem.h"
#include "groupsig/sltgs23/bld_key.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mgr_key.h"
#include "groupsig/sltgs23/signature.h"
#include "groupsig/sltgs23/blindsig.h"
#include "groupsig/sltgs23/identity.h"
#include "shim/hash.h"

int sltgs23_blind(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
	       groupsig_key_t *grpkey, groupsig_signature_t *sig,
	       message_t *msg) {

  pbcext_element_Fr_t *alpha, *beta, *gamma;
  pbcext_element_G1_t *aux, *h;
  groupsig_key_t *_bldkey;
  sltgs23_signature_t *sltgs23_sig;
  sltgs23_blindsig_t *sltgs23_bsig;
  sltgs23_grp_key_t *sltgs23_grpkey;
  sltgs23_bld_key_t *sltgs23_bldkey;
  hash_t *hm;
  int rc;
  
  if(!bsig || bsig->scheme != GROUPSIG_SLTGS23_CODE ||
     !sig || sig->scheme != GROUPSIG_SLTGS23_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !msg) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_blind", __LINE__, LOGERROR);
    return IERROR;
  }

  /* NOTE: This is the first scheme in the library that uses the encrypt and prove
     approach. If new schemes using this approach are added, it may be a good
     idea to create an internal abstraction for encryption. I have already created
     some of the stubs in the crypto/ folder, but then /regretted/ it (too much load
     as long as only one scheme in the library uses this). Keep it in mind. */
  
  sltgs23_grpkey = (sltgs23_grp_key_t *) grpkey->key;
  sltgs23_sig = (sltgs23_signature_t *) sig->sig;
  sltgs23_bsig = (sltgs23_blindsig_t *) bsig->sig;
  _bldkey = NULL;
  rc = IOK;

  alpha = NULL; beta = NULL; gamma = NULL;
  aux = NULL; h = NULL; hm = NULL;

  /* Create fresh blinding keypair */
  if(!*bldkey) {
    if(!(_bldkey = groupsig_bld_key_init(GROUPSIG_SLTGS23_CODE)))
      GOTOENDRC(IERROR, sltgs23_blind);
    sltgs23_bldkey = (sltgs23_bld_key_t *) _bldkey->key;
    if(!(sltgs23_bldkey->sk = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, sltgs23_blind);
    if(pbcext_element_Fr_random(sltgs23_bldkey->sk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_blind);
    if(!(sltgs23_bldkey->pk = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_blind);
    if(pbcext_element_G1_mul(sltgs23_bldkey->pk,
			     sltgs23_grpkey->g,
			     sltgs23_bldkey->sk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_blind);
  } else {
    sltgs23_bldkey = (sltgs23_bld_key_t *) (*bldkey)->key;
  }

  /* Pick alpha, beta, gamma at random from Z^*_p */
  if(!(alpha = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_Fr_random(alpha) == IERROR) GOTOENDRC(IERROR, sltgs23_blind);
  if(!(beta = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_Fr_random(beta) == IERROR) GOTOENDRC(IERROR, sltgs23_blind);
  if(!(gamma = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_Fr_random(gamma) == IERROR) GOTOENDRC(IERROR, sltgs23_blind);
    
  /* Rerandomize the pseudonym encryption under the cpk and 
     add an encryption layer for the pseudonym under the bpk */

  if(!(sltgs23_bsig->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_blind);
  if(!(sltgs23_bsig->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_blind);
  if(!(sltgs23_bsig->nym3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_blind);
  if(!(sltgs23_bsig->c1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_blind);
  if(!(sltgs23_bsig->c2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_blind);
  
  if(!(aux = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_mul(aux, sltgs23_grpkey->g, beta) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_add(sltgs23_bsig->nym1, sltgs23_sig->nym1, aux) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_mul(sltgs23_bsig->nym2, sltgs23_grpkey->g, alpha) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_mul(aux, sltgs23_grpkey->cpk, beta) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_add(sltgs23_bsig->nym3, sltgs23_sig->nym2, aux) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_mul(aux, sltgs23_bldkey->pk, alpha) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_add(sltgs23_bsig->nym3, sltgs23_bsig->nym3, aux) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);

  /* Encrypt the (hash of the) message */
  if(!(hm = hash_init(HASH_BLAKE2)))
    GOTOENDRC(IERROR, sltgs23_blind);
  if(hash_update(hm, msg->bytes, msg->length) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(hash_finalize(hm) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);

  if(!(h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_from_hash(h, hm->hash, hm->length) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_mul(sltgs23_bsig->c1, sltgs23_grpkey->g, gamma) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_mul(aux, sltgs23_bldkey->pk, gamma) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);
  if(pbcext_element_G1_add(sltgs23_bsig->c2, h, aux) == IERROR)
    GOTOENDRC(IERROR, sltgs23_blind);

  if(!*bldkey) *bldkey = _bldkey;
  
 sltgs23_blind_end:

  if(rc == IERROR) {

    if(_bldkey) {
      if(sltgs23_bldkey->pk) {
	pbcext_element_G1_free(sltgs23_bldkey->pk);
	sltgs23_bldkey->pk = NULL;
      }
      if(sltgs23_bldkey->sk) {
	pbcext_element_Fr_free(sltgs23_bldkey->sk);
	sltgs23_bldkey->sk = NULL;
      }
    }
    
    if(sltgs23_bsig->nym1) {
      pbcext_element_G1_free(sltgs23_bsig->nym1);
      sltgs23_bsig->nym1 = NULL;
    }
    if(sltgs23_bsig->nym2) {
      pbcext_element_G1_free(sltgs23_bsig->nym2);
      sltgs23_bsig->nym2 = NULL;
    }
    if(sltgs23_bsig->nym3) {
      pbcext_element_G1_free(sltgs23_bsig->nym3);
      sltgs23_bsig->nym3 = NULL;
    }
    if(sltgs23_bsig->c1) {
      pbcext_element_G1_free(sltgs23_bsig->c1);
      sltgs23_bsig->c1 = NULL;
    }
    if(sltgs23_bsig->c2) {
      pbcext_element_G1_free(sltgs23_bsig->c2);
      sltgs23_bsig->c2 = NULL;
    }
  }
  
  if(alpha) { pbcext_element_Fr_free(alpha); alpha = NULL; }
  if(beta) { pbcext_element_Fr_free(beta); beta = NULL; }
  if(gamma) { pbcext_element_Fr_free(gamma); gamma = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(h) { pbcext_element_G1_free(h); h = NULL; }
  if(hm) { hash_free(hm); hm = NULL; }
  
  return rc;

}

/* blind.c ends here */
