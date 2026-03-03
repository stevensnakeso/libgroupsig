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
#include "bap24.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "groupsig/bap24/proof.h"
#include "groupsig/bap24/grp_key.h"
#include "groupsig/bap24/mgr_key.h"
#include "groupsig/bap24/signature.h"
#include "groupsig/bap24/gml.h"

int bap24_open(uint64_t *index,
	      groupsig_proof_t *proof, 
	      crl_t *crl,
	      groupsig_signature_t *sig, 
	      groupsig_key_t *grpkey,
	      groupsig_key_t *mgrkey,
	      gml_t *gml) {

  pbcext_element_GT_t *e1, *e2, *e3;
  bap24_signature_t *bap24_sig;
  bap24_proof_t *bap24_proof;
  bap24_grp_key_t *bap24_grpkey;
  bap24_mgr_key_t *bap24_mgrkey;
  gml_entry_t *bap24_entry;
  byte_t *bsig;
  uint64_t i;
  uint32_t slen;
  uint8_t match;
  int rc;

  if (!index || !sig || sig->scheme != GROUPSIG_BAP24_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_BAP24_CODE ||
      !mgrkey || mgrkey->scheme != GROUPSIG_BAP24_CODE ||
      !gml) {
    LOG_EINVAL(&logger, __FILE__, "bap24_open", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_sig = sig->sig;
  bap24_grpkey = grpkey->key;
  bap24_mgrkey = mgrkey->key;
  rc = IOK;
  e1 = e2 = e3 = NULL;
  
  if (!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_open);
  if (pbcext_pairing(e1, bap24_sig->sigma2, bap24_grpkey->gg) == IERROR)
    GOTOENDRC(IERROR, bap24_open);
  if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_open);
  if (pbcext_pairing(e2, bap24_sig->sigma1, bap24_grpkey->X) == IERROR)
    GOTOENDRC(IERROR, bap24_open);
  if (pbcext_element_GT_div(e1, e1, e2) == IERROR) GOTOENDRC(IERROR, bap24_open);

  if (!(e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_open);
  
  /* Look up the recovered e1 in the GML */
  match = 0;
  for (i=0; i<gml->n; i++) {  

    if (!(bap24_entry = gml_get(gml, i))) GOTOENDRC(IERROR, bap24_open);

    if (pbcext_pairing(e3, bap24_sig->sigma1,
		       ((bap24_gml_entry_data_t *) bap24_entry->data)->ttau) == IERROR)
      GOTOENDRC(IERROR, bap24_open);

    if (!pbcext_element_GT_cmp(e1, e3)) {

      /* Get the identity from the matched entry. */
      *index = bap24_entry->id;
      match = 1;
      break;

    }

  }

  /* No match: FAIL */
  if(!match) GOTOENDRC(IFAIL, bap24_open);

  /* If there is a match, we need to proof knowledge of ttau in 
     e(sigma1, ttau), where ttau = bap24_entry->ttau and e(sigma1,ttau) = e3. 

     We use an SPK (over the byte representation of the opened signature) to 
     make the process non-interactive.
  */


  /* Export the signature as an array of bytes */
  bsig = NULL;
  if (bap24_signature_export(&bsig, &slen, sig) == IERROR)
    GOTOENDRC(IERROR, bap24_open);

  if (!(proof->proof = spk_pairing_homomorphism_G2_init()))
    GOTOENDRC(IERROR, bap24_open);

  if (spk_pairing_homomorphism_G2_sign(proof->proof,
				       bap24_sig->sigma1,
				       e3,
				       ((bap24_gml_entry_data_t *) bap24_entry->data)->ttau,
				       bsig,
				       slen) == IERROR)
    GOTOENDRC(IERROR, bap24_open);

 bap24_open_end:

  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if (bsig) { mem_free(bsig); bsig = NULL; }
  
  if (rc == IERROR) {
    if (bap24_proof) {
      spk_pairing_homomorphism_G2_free(bap24_proof);
      bap24_proof = NULL;
    }
  }
  
  return rc;
  
}

/* open.c ends here */
