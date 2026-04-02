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

#include "sysenv.h"
#include "bigz.h"
#include "sltgs23.h"
#include "groupsig/sltgs23/mem_key.h"
#include "groupsig/sltgs23/gml.h"
#include "groupsig/sltgs23/crl.h"
#include "groupsig/sltgs23/trapdoor.h"

int sltgs23_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index) {

  /* sltgs23_crl_entry_t *crl_entry; */
  /* sltgs23_gml_entry_t *gml_entry; */
  /* trapdoor_t* crl_trap; */

  /* if(!trap || trap->scheme != GROUPSIG_SLTGS23_CODE || */
  /*    !gml || gml->scheme != GROUPSIG_SLTGS23_CODE || */
  /*    (crl && crl->scheme != GROUPSIG_SLTGS23_CODE)) { */
  /*   LOG_EINVAL(&logger, __FILE__, "sltgs23_reveal", __LINE__, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* if(!(crl_trap = trapdoor_init(trap->scheme))){ */
  /*   LOG_EINVAL(&logger, __FILE__, "sltgs23_trace", __LINE__, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* /\* SLTGS23 does not implement actual "tracing trapdoors" (according to the recent  */
  /*    meaning of tracing in the literature of group signatures). Instead, it uses */
  /*    the open trapdoor to enable tracing. That is, in order to know if a member */
  /*    key (used to create a group signature) has been revoked, it opens the */
  /*    group signature, getting the ID of the signer, and compares this ID with  */
  /*    the IDs in a CRL. It is a valid approach, although more privacy invasive. *\/ */
  /* /\* The tracing trapdoor for the i-th member is the x field of its member key *\/ */
  /* if(!(gml_entry = ((sltgs23_gml_entry_t *) gml_get(gml, index)))) { */
  /*   return IERROR; */
  /* } */

  /* if(sltgs23_trapdoor_copy(trap, (trapdoor_t *) gml_entry->trapdoor) == IERROR) { */
  /*   return IERROR; */
  /* } */

  /* /\* If we have received a CRL, update it with the "revoked" member *\/ */
  /* if(crl) { */

  /*   if(!(crl_entry = sltgs23_crl_entry_init())) { */
  /*     return IERROR; */
  /*   } */
    
  /*   if(sltgs23_identity_copy(crl_entry->id, gml_entry->id) == IERROR) { */
  /*     sltgs23_crl_entry_free(crl_entry); crl_entry = NULL; */
  /*     return IERROR; */
  /*   } */
  /*   sltgs23_trapdoor_copy(crl_trap, trap); */
  /*   crl_entry->trapdoor = crl_trap; */

  /*   if(sltgs23_crl_insert(crl, crl_entry) == IERROR) { */
  /*     sltgs23_crl_entry_free(crl_entry); crl_entry = NULL; */
  /*     return IERROR; */
  /*   } */

  /* } */

  return IERROR;

}

/* reveal.c ends here */
