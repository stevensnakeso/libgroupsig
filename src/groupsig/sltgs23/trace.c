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
#include <stdint.h>
#include <errno.h>

#include "include/crl.h"
#include "bigz.h"
#include "sltgs23.h"
#include "groupsig/sltgs23/signature.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mgr_key.h"
#include "groupsig/sltgs23/crl.h"
#include "groupsig/sltgs23/gml.h"
#include "groupsig/sltgs23/trapdoor.h"
#include "groupsig/sltgs23/identity.h"

int sltgs23_trace(uint8_t *ok, groupsig_signature_t *sig, groupsig_key_t *grpkey, crl_t *crl, groupsig_key_t *mgrkey, gml_t *gml) {

  /* sltgs23_signature_t *sltgs23_sig; */
  /* sltgs23_grp_key_t *gkey; */
  /* sltgs23_mgr_key_t *mkey; */
  /* identity_t *id; */
  /* trapdoor_t *trap, *trapi; */
  /* uint64_t i; */
  /* uint8_t revoked; */

  /* if(!ok || !sig || sig->scheme != GROUPSIG_SLTGS23_CODE || */
  /*    !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE || */
  /*    !mgrkey || mgrkey->scheme != GROUPSIG_SLTGS23_CODE || */
  /*    !gml || !crl) { */
  /*   LOG_EINVAL(&logger, __FILE__, "sltgs23_trace", __LINE__, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* gkey = (sltgs23_grp_key_t *) grpkey->key; */
  /* mkey = (sltgs23_mgr_key_t *) mgrkey->key; */
  /* sltgs23_sig = (sltgs23_signature_t *) sig->sig; */

  /* /\* In SLTGS23, tracing implies opening the signature to get the signer's  */
  /*    identity, and using the signer's identity to get her A, which */
  /*    is then matched against those of the users in a CRL *\/ */
  /* if(!(id = sltgs23_identity_init())) { */
  /*   LOG_EINVAL(&logger, __FILE__, "sltgs23_trace", __LINE__, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* /\* Open the signature *\/ */
  /* if(sltgs23_open(id, NULL, crl, sig, grpkey, mgrkey, gml) == IERROR) { */
  /*   LOG_EINVAL(&logger, __FILE__, "sltgs23_trace", __LINE__, LOGERROR); */
  /*   identity_free(id); id = NULL; */
  /*   return IERROR; */
  /* } */

  /* if(!(trap = sltgs23_trapdoor_init())) { */
  /*   LOG_EINVAL(&logger, __FILE__, "sltgs23_trace", __LINE__, LOGERROR); */
  /*   identity_free(id); id = NULL; */
  /*   return IERROR; */
  /* } */

  /* /\* We pass a NULL crl because we do not want to update it *\/ */
  /* if(sltgs23_reveal(trap, NULL, gml, *(sltgs23_identity_t *) id->id) == IERROR) { */
  /*   LOG_EINVAL(&logger, __FILE__, "sltgs23_trace", __LINE__, LOGERROR); */
  /*   identity_free(id); id = NULL; */
  /*   trapdoor_free(trap); trap = NULL; */
  /*   return IERROR; */
  /* } */
  
  /* i = 0; revoked = 0; */
  /* while(i < crl->n) { */

  /*   if(!(trapi = sltgs23_trapdoor_init())) { */
  /*     LOG_EINVAL(&logger, __FILE__, "sltgs23_trace", __LINE__, LOGERROR); */
  /*     identity_free(id); id = NULL; */
  /*     trapdoor_free(trap); trap = NULL; */
  /*     return IERROR; */
  /*   } */

  /*   /\* Get the next trapdoor to test *\/ */
  /*   trapi = ((sltgs23_crl_entry_t *) crl_get(crl, i))->trapdoor; */
  
  /*   if(!element_cmp(((sltgs23_trapdoor_t *) trap->trap)->open, */
  /* 		    ((sltgs23_trapdoor_t *) trapi->trap)->open)) { */
  /*     revoked = 1; */
  /*     break; */
  /*   } */

  /*   /\* trapdoor_free(trapi); trapi = NULL; *\/ */

  /*   i++; */

  /* } */

  /* *ok = revoked; */

  /* identity_free(id); id = NULL; */
  /* trapdoor_free(trap); trap = NULL; */

  return IOK;


}

/* trace.c ends here */
