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
#include "bigz.h"
#include "sltgs23.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mgr_key.h"
#include "groupsig/sltgs23/signature.h"
#include "groupsig/sltgs23/gml.h"

int sltgs23_open(uint64_t *index,
	       groupsig_proof_t *proof, 
	       crl_t *crl,
	       groupsig_signature_t *sig, 
	       groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml) {

  pbcext_element_G1_t *A, *aux;
  sltgs23_signature_t *sltgs23_sig;
  sltgs23_grp_key_t *sltgs23_grpkey;
  sltgs23_mgr_key_t *sltgs23_mgrkey;
  gml_entry_t *entry;
  uint64_t i;
  uint8_t match;
  int rc;

  if(!index || !sig || sig->scheme != GROUPSIG_SLTGS23_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_open", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_sig = sig->sig;
  sltgs23_grpkey = grpkey->key;
  sltgs23_mgrkey = mgrkey->key;
  rc = IOK;
  A = aux = NULL;

  /* In the paper, a signature verification process is included within the open
     procedure to check that the signature is valid. Here, we sepatarate the two
     processes (verify can always be called before opening...) */
  
  /* Recover the signer's A as: A = T3/(T1^xi1 * T2^xi2) */
  if(!(A = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_open);
  if(!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_open);
  if(pbcext_element_G1_mul(A, sltgs23_sig->T1, sltgs23_mgrkey->xi1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_open);
  if(pbcext_element_G1_mul(aux, sltgs23_sig->T2, sltgs23_mgrkey->xi2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_open);
  if(pbcext_element_G1_add(A, A, aux) == IERROR) GOTOENDRC(IERROR, sltgs23_open);
  if(pbcext_element_G1_sub(A, sltgs23_sig->T3, A) == IERROR)
    GOTOENDRC(IERROR, sltgs23_open);

  /* Look up the recovered A in the GML */
  match = 0;
  for(i=0; i<gml->n; i++) {  

    if(!(entry = gml_get(gml, i))) GOTOENDRC(IERROR, sltgs23_open);

    if(!pbcext_element_G1_cmp(entry->data, A)) {

      /* Get the index from the matched entry. */
      *index = entry->id;
      match = 1;
      break;

    }

  }

  /* No match: FAIL */
  if(!match) GOTOENDRC(IFAIL, sltgs23_open);
  
  /* /\* If we have received a CRL, update it with the "revoked" member *\/ */
  /* if(crl) { */

  /*   if(!(crl_entry = sltgs23_crl_entry_init())) { */
  /*     return IERROR; */
  /*   } */
    
  /*   if(sltgs23_identity_copy(crl_entry->id, gml_entry->id) == IERROR) { */
  /*     sltgs23_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */
    
  /*   crl_entry->trapdoor = trap; */

  /*   if(sltgs23_crl_insert(crl, crl_entry) == IERROR) { */
  /*     sltgs23_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */

  /* } */

 sltgs23_open_end:

  if(A) { pbcext_element_G1_free(A); A = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }

  return rc;
  
}

/* open.c ends here */
