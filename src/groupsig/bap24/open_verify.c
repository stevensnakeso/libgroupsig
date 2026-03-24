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
#include "groupsig/bap24/signature.h"
#include "groupsig/bap24/gml.h"

int bap24_open_verify(uint8_t *ok,
		     groupsig_proof_t *proof, 
		     groupsig_signature_t *sig,
		     groupsig_key_t *grpkey) {

  pbcext_element_GT_t *e1, *e2;
  bap24_signature_t *bap24_sig;
  bap24_proof_t *bap24_proof;
  bap24_grp_key_t *bap24_grpkey;
  byte_t *bsig;
  int rc;
  uint32_t slen;
  uint8_t _ok;

  if (!proof || proof->scheme != GROUPSIG_BAP24_CODE ||
      !sig || sig->scheme != GROUPSIG_BAP24_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_open_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_sig = sig->sig;
  bap24_grpkey = grpkey->key;
  bap24_proof = proof->proof;
  rc = IOK;
  e1 = e2 = NULL;

  if (!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_open_verify);
  if (pbcext_pairing(e1, bap24_sig->sigma2, bap24_grpkey->gg) == IERROR)
    GOTOENDRC(IERROR, bap24_open_verify);
  if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_open_verify);
  if (pbcext_pairing(e2, bap24_sig->sigma1, bap24_grpkey->X) == IERROR)
    GOTOENDRC(IERROR, bap24_open_verify);
  if (pbcext_element_GT_div(e1, e1, e2) == IERROR) GOTOENDRC(IERROR, bap24_open_verify);
  
  /* Export the signature as an array of bytes */
  bsig = NULL;
  if (bap24_signature_export(&bsig, &slen, sig) == IERROR)
    GOTOENDRC(IERROR, bap24_open_verify);

  if (spk_pairing_homomorphism_G2_verify(&_ok,
					 bap24_sig->sigma1,
					 e1,
					 bap24_proof,
					 bsig,
					 slen) == IERROR)
    GOTOENDRC(IERROR, bap24_open_verify);

  *ok = _ok;

 bap24_open_verify_end:

  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (bsig) { mem_free(bsig); bsig = NULL; }

  return rc;
  
}

/* open.c ends here */
