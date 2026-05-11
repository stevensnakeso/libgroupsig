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
#include "klapseq.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "math/rnd.h"
#include "groupsig/klapseq/proof.h"
#include "groupsig/klapseq/grp_key.h"
#include "groupsig/klapseq/mgr_key.h"
#include "groupsig/klapseq/signature.h"
#include "groupsig/klapseq/gml.h"

int klapseq_open(uint64_t *index,
	      groupsig_proof_t *proof, 
	      crl_t *crl,
	      groupsig_signature_t *sig, 
	      groupsig_key_t *grpkey,
	      groupsig_key_t *mgrkey,
	      gml_t *gml) {

  pbcext_element_G2_t *ff;
  pbcext_element_GT_t *e1, *e2, *e3;
  klapseq_signature_t *klapseq_sig;
  klapseq_grp_key_t *klapseq_grpkey;
  klapseq_mgr_key_t *klapseq_mgrkey;
  gml_entry_t *klapseq_entry;
  klapseq_gml_entry_data_t *klapseq_data;
  byte_t *bsig;
  uint64_t i, b;
  uint32_t slen;
  uint8_t match;
  int rc;

  if (!index || !sig || sig->scheme != GROUPSIG_KLAPSEQ_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
      !mgrkey || mgrkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
      !gml) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_open", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_sig = sig->sig;
  klapseq_grpkey = grpkey->key;
  klapseq_mgrkey = mgrkey->key;
  rc = IOK;
  e1 = e2 = e3 = NULL;

  /* Pick random b from [0,1] */
  if ((rnd_get_random_int_in_range(&b, 1)) == IERROR)
    GOTOENDRC(IERROR, klapseq_open);

  if (!(ff = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_open);
  if (!(e1 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_open);
  if (!(e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_open);
  if (!(e3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_open);
  
  /* Look up the recovered e1 in the GML */
  match = 0;
  for (i=0; i<gml->n; i++) {  

    if (!(klapseq_entry = gml_get(gml, i))) GOTOENDRC(IERROR, klapseq_open);
    klapseq_data = klapseq_entry->data;
    if (!klapseq_data) GOTOENDRC(IERROR, klapseq_open);

    if (b) {
      if (pbcext_element_G2_mul(ff, klapseq_data->SS1, klapseq_mgrkey->z1) == IERROR)
	GOTOENDRC(IERROR, klapseq_open);
      if (pbcext_element_G2_neg(ff, ff) == IERROR)
	GOTOENDRC(IERROR, klapseq_open);
      if (pbcext_element_G2_add(ff, klapseq_data->ff1, ff) == IERROR)
	GOTOENDRC(IERROR, klapseq_open);    
    } else { 
      if (pbcext_element_G2_mul(ff, klapseq_data->SS0, klapseq_mgrkey->z0) == IERROR)
	GOTOENDRC(IERROR, klapseq_open);
      if (pbcext_element_G2_neg(ff, ff) == IERROR)
	GOTOENDRC(IERROR, klapseq_open);
      if (pbcext_element_G2_add(ff, klapseq_data->ff0, ff) == IERROR)
	GOTOENDRC(IERROR, klapseq_open);
    }

    if (pbcext_pairing(e1, klapseq_sig->uu, ff) == IERROR)
      GOTOENDRC(IERROR, klapseq_open);
    if (pbcext_pairing(e2, klapseq_sig->ww, klapseq_grpkey->gg) == IERROR)
      GOTOENDRC(IERROR, klapseq_open);
    if (pbcext_pairing(e3, klapseq_grpkey->g, ff) == IERROR)
      GOTOENDRC(IERROR, klapseq_open);
    
    if (!pbcext_element_GT_cmp(e1, e2) &&
	!pbcext_element_GT_cmp(klapseq_data->tau, e3)) {

      /* Get the identity from the matched entry. */
      *index = klapseq_entry->id;
      match = 1;
      break;

    }

  }

  /* No match: FAIL */
  if(!match) GOTOENDRC(IFAIL, klapseq_open);

  /* Export the signature as an array of bytes */
  bsig = NULL;
  if (klapseq_signature_export(&bsig, &slen, sig) == IERROR)
    GOTOENDRC(IERROR, klapseq_open);

  if (!(proof->proof = klapseq_spk1_init()))
    GOTOENDRC(IERROR, klapseq_open);

  if (!(((klapseq_spk1_t *) proof->proof)->tau = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klapseq_open);
  if (pbcext_element_GT_set(((klapseq_spk1_t *) proof->proof)->tau, e3) == IERROR)
    GOTOENDRC(IERROR, klapseq_open);
  
  if (klapseq_spk1_sign(proof->proof,
		       ff,
		       klapseq_sig->uu,
		       klapseq_grpkey->g,
		       e2,
		       e3,
		       bsig,
		       slen) == IERROR) 
    GOTOENDRC(IERROR, klapseq_open);

 klapseq_open_end:

  if (ff) { pbcext_element_G2_free(ff); ff = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if (bsig) { mem_free(bsig); bsig = NULL; }
  
  if (rc == IERROR) {
    if (proof->proof) {
      klapseq_spk1_free(proof->proof);
      proof->proof = NULL;
    }
  }
  
  return rc;
  
}

/* open.c ends here */
