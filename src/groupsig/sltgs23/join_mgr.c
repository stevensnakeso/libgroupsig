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
#include <errno.h>
#include <stdlib.h>

#include "sltgs23.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mgr_key.h"
#include "groupsig/sltgs23/mem_key.h"
#include "groupsig/sltgs23/gml.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int sltgs23_get_joinseq(uint8_t *seq) {
  *seq = SLTGS23_JOIN_SEQ;
  return IOK;
}

int sltgs23_get_joinstart(uint8_t *start) {
  *start = SLTGS23_JOIN_START;
  return IOK;
}

int sltgs23_join_mgr(message_t **mout, gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq, message_t *min,
		   groupsig_key_t *grpkey) {

  groupsig_key_t *memkey;
  sltgs23_mem_key_t *sltgs23_memkey;
  sltgs23_mgr_key_t *sltgs23_mgrkey;
  sltgs23_grp_key_t *sltgs23_grpkey;
  gml_entry_t *sltgs23_entry;
  pbcext_element_Fr_t *gammax;
  message_t *_mout;
  byte_t *bkey;
  uint32_t size;
  int rc;

  if(!mout || !gml || gml->scheme != GROUPSIG_SLTGS23_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_mgrkey = (sltgs23_mgr_key_t *) mgrkey->key;
  sltgs23_grpkey = (sltgs23_grp_key_t *) grpkey->key;
  rc = IOK;
  bkey = NULL;
  gammax = NULL;
  memkey = NULL;

  if(!(memkey = sltgs23_mem_key_init())) GOTOENDRC(IERROR, sltgs23_join_mgr);
  sltgs23_memkey = (sltgs23_mem_key_t *) memkey->key;

  /* Select memkey->x randomly in Z_p^* */
  if(!(sltgs23_memkey->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  if(pbcext_element_Fr_random(sltgs23_memkey->x) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);

  /* Compute memkey->A = g_1^(1/(mgrkey->gamma+memkey->x)) */
  if(!(gammax = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  if(pbcext_element_Fr_add(gammax, sltgs23_mgrkey->gamma, sltgs23_memkey->x) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);

  if(!(sltgs23_memkey->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  if(pbcext_element_G1_set(sltgs23_memkey->A, sltgs23_grpkey->g1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  if(pbcext_element_Fr_inv(gammax, gammax) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  if(pbcext_element_G1_mul(sltgs23_memkey->A, sltgs23_memkey->A, gammax) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);

  /* Optimization */
  if(!(sltgs23_memkey->Ag2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, sltgs23_join_mgr);

  if(pbcext_pairing(sltgs23_memkey->Ag2, sltgs23_memkey->A, sltgs23_grpkey->g2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);

  /* Update the GML */
    
  /* Initialize the GML entry */
  if(!(sltgs23_entry = sltgs23_gml_entry_init()))
    GOTOENDRC(IERROR, sltgs23_join_mgr);

  if(!(sltgs23_entry->data = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  if(pbcext_element_G1_set(sltgs23_entry->data, sltgs23_memkey->A) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  sltgs23_entry->id = gml->n;
  
  if(gml_insert(gml, sltgs23_entry) == IERROR) GOTOENDRC(IERROR, sltgs23_join_mgr);

  /* Dump the key into a msg */
  bkey = NULL; 
  if (sltgs23_mem_key_export(&bkey, &size, memkey) == IERROR)
    GOTOENDRC(IERROR, sltgs23_join_mgr);
  
  if(!*mout) {
    if(!(_mout = message_from_bytes(bkey, size)))
      GOTOENDRC(IERROR, sltgs23_join_mgr);
    *mout = _mout;
    
  } else {
    
    _mout = *mout;
    if(message_set_bytes(_mout, bkey, size) == IERROR)
      GOTOENDRC(IERROR, sltgs23_join_mgr);
  }
  
 sltgs23_join_mgr_end:

  if (gammax) { pbcext_element_Fr_free(gammax); gammax = NULL; }
  if (memkey) { sltgs23_mem_key_free(memkey); memkey = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (rc == IERROR) { sltgs23_gml_entry_free(sltgs23_entry); sltgs23_entry = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
