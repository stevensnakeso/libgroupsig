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
#include "groupsig/klapseq/proof.h"
#include "groupsig/klapseq/grp_key.h"
#include "groupsig/klapseq/signature.h"
#include "groupsig/klapseq/gml.h"

int klapseq_open_verify(uint8_t *ok,
		     groupsig_proof_t *proof, 
		     groupsig_signature_t *sig,
		     groupsig_key_t *grpkey) {

  pbcext_element_GT_t *e2;
  klapseq_signature_t *klapseq_sig;
  klapseq_proof_t *klapseq_proof;
  klapseq_grp_key_t *klapseq_grpkey;
  byte_t *bsig;
  int rc;
  uint32_t slen;
  uint8_t _ok;

  if (!proof || proof->scheme != GROUPSIG_KLAPSEQ_CODE ||
      !sig || sig->scheme != GROUPSIG_KLAPSEQ_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_open_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_sig = sig->sig;
  klapseq_grpkey = grpkey->key;
  klapseq_proof = proof->proof;
  rc = IOK;
  e2 = NULL;

  if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, klapseq_open_verify);
  if (pbcext_pairing(e2, klapseq_sig->ww, klapseq_grpkey->gg) == IERROR)
    GOTOENDRC(IERROR, klapseq_open_verify);

  /* Export the signature as an array of bytes */
  bsig = NULL;
  if (klapseq_signature_export(&bsig, &slen, sig) == IERROR)
    GOTOENDRC(IERROR, klapseq_open_verify);

  if (klapseq_spk1_verify(&_ok,
			 klapseq_proof,
			 klapseq_sig->uu,
			 klapseq_grpkey->g,
			 e2,
			 klapseq_proof->tau,
			 bsig,
			 slen) == IERROR)
    GOTOENDRC(IERROR, klapseq_open_verify);

  *ok = _ok;

 klapseq_open_verify_end:

  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (bsig) { mem_free(bsig); bsig = NULL; }

  return rc;
  
}

/* open.c ends here */
