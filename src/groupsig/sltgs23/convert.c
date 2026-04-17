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
#include "math/perm.h"
#include "groupsig/sltgs23/bld_key.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mgr_key.h"
#include "groupsig/sltgs23/signature.h"
#include "groupsig/sltgs23/blindsig.h"
#include "groupsig/sltgs23/identity.h"

int sltgs23_convert(groupsig_blindsig_t **csigs,
		 groupsig_blindsig_t **bsigs, uint32_t n_bsigs,
		 groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
		 groupsig_key_t *bldkey, message_t *msg) {

  pbcext_element_Fr_t *r, *r1, *r2, *neg_csk;
  pbcext_element_G1_t *aux, *cnym1p, *cnym2p;
  sltgs23_blindsig_t *sltgs23_csig;
  sltgs23_blindsig_t *sltgs23_bsig;
  sltgs23_grp_key_t *sltgs23_grpkey;
  sltgs23_mgr_key_t *sltgs23_mgrkey;
  sltgs23_bld_key_t *sltgs23_bldkey;
  int i, rc;

  if(!csigs ||
     !bsigs || n_bsigs <= 0 ||
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !bldkey || bldkey->scheme != GROUPSIG_SLTGS23_CODE) {
     LOG_EINVAL(&logger, __FILE__, "sltgs23_convert", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_grpkey = (sltgs23_grp_key_t *) grpkey->key;
  sltgs23_mgrkey = (sltgs23_mgr_key_t *) mgrkey->key;
  sltgs23_bldkey = (sltgs23_bld_key_t *) bldkey->key;
  rc = IOK;

  r = NULL; r1 = NULL; r2 = NULL; neg_csk = NULL;
  aux = NULL; cnym1p = NULL; cnym2p = NULL;

  if(!(r = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_convert);
  if(!(r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_convert);
  if(!(r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_convert);
  if(!(neg_csk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_convert);
  if(!(cnym1p = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_convert);
  if(!(cnym2p = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_convert);
  if(!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_convert);

  if(pbcext_element_Fr_random(r)) GOTOENDRC(IERROR, sltgs23_convert);
  if(pbcext_element_Fr_neg(neg_csk, sltgs23_mgrkey->csk) == IERROR)
    GOTOENDRC(IERROR, sltgs23_convert);

  for(i=0; i<n_bsigs; i++) {

    if (bsigs[i]->scheme != GROUPSIG_SLTGS23_CODE) GOTOENDRC(IERROR, sltgs23_convert);
    if (csigs[i]->scheme != GROUPSIG_SLTGS23_CODE) GOTOENDRC(IERROR, sltgs23_convert);
    
    sltgs23_bsig = (sltgs23_blindsig_t *) bsigs[i]->sig;
    sltgs23_csig = (sltgs23_blindsig_t *) csigs[i]->sig;

    if(pbcext_element_Fr_random(r1) == IERROR) GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_Fr_random(r2) == IERROR) GOTOENDRC(IERROR, sltgs23_convert);
      
    /* Decrypt nym and raise to r */
    if(pbcext_element_G1_mul(cnym1p, sltgs23_bsig->nym2, r) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_mul(aux, sltgs23_bsig->nym1, neg_csk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_add(aux, aux, sltgs23_bsig->nym3) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_mul(cnym2p, aux, r) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    
    /* Re-randomize nym */
    if(!(sltgs23_csig->nym1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_mul(aux, sltgs23_grpkey->g, r1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_add(sltgs23_csig->nym1, cnym1p, aux) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);

    if(!(sltgs23_csig->nym2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_mul(aux, sltgs23_bldkey->pk, r1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_add(sltgs23_csig->nym2, cnym2p, aux) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);

    /* Just for convenience, set nym3 to an empty element. This is to avoid
       having to create a new data type for converted sigs. However, it makes
       converted sigs be larger than needed. Keep it in mind. */
    if(!(sltgs23_csig->nym3 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_convert);

    /* Re-randomize ciphertext */
    if(!(sltgs23_csig->c1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_mul(aux, sltgs23_grpkey->g, r2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_add(sltgs23_csig->c1, sltgs23_bsig->c1, aux) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    
    if(!(sltgs23_csig->c2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_mul(aux, sltgs23_bldkey->pk, r2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    if(pbcext_element_G1_add(sltgs23_csig->c2, sltgs23_bsig->c2, aux) == IERROR)
      GOTOENDRC(IERROR, sltgs23_convert);
    
  }

  /* Choose random permutation */
  rc = perm_durstenfeld_inplace((void **) csigs, n_bsigs);

 sltgs23_convert_end:

  pbcext_element_Fr_free(r); r = NULL;
  pbcext_element_Fr_free(r1); r1 = NULL;
  pbcext_element_Fr_free(r2); r2 = NULL;
  pbcext_element_Fr_free(neg_csk); neg_csk = NULL;
  pbcext_element_G1_free(cnym1p); cnym1p = NULL;
  pbcext_element_G1_free(cnym2p); cnym2p = NULL;
  pbcext_element_G1_free(aux); aux = NULL;
  
  return rc;

}

/* convert.c ends here */
