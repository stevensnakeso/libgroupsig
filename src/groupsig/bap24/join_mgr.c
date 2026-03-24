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

#include "bap24.h"
#include "groupsig/bap24/grp_key.h"
#include "groupsig/bap24/mgr_key.h"
#include "groupsig/bap24/mem_key.h"
#include "groupsig/bap24/gml.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int bap24_get_joinseq(uint8_t *seq) {
  *seq = BAP24_JOIN_SEQ;
  return IOK;
}

int bap24_get_joinstart(uint8_t *start) {
  *start = BAP24_JOIN_START;
  return IOK;
}

/**
 * This process deviates slightly from what the BAP24 paper defines, as the PKI
 * functionality is not integrated here. See the comment in the join_mem 
 * function for a detailed explanation.
 * 
 * In the join_mgr implemented here, we do not verify any signature of tau using
 * a "standard" keypair+certificate. Nor do we add the signature of tau to the
 * GML (because we don't receive such signature). Rather, it should be the caller
 * who takes care of that using some well tested library/software for PKI 
 * management. 
 *
 * This can be easily done by a calling library as follows:
 *   1) The member digitally signs, using his PKI-backed identity, the bytearray
 *      representation of the <i>min</i> parameter when <i>seq</i>=2 (this
 *      contains the challenge response). 
 *   2) If the join is successful, the manager exports the newly created GML
 *      entry, producing a byte array (which contains the libgroupsig-internal
 *      identity -- an integer). 
 *   3) All the server running the issuer needs to store in its database, is
 *      the output of the previous steps. This can then be queried when an open
 *      is requested.
 */
int bap24_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey) {

  groupsig_key_t *memkey;
  bap24_mem_key_t *bap24_memkey;
  bap24_mgr_key_t *bap24_mgrkey;
  bap24_grp_key_t *bap24_grpkey;
  gml_entry_t *bap24_entry;
  pbcext_element_Fr_t *u;
  pbcext_element_Fr_t *uid;
  pbcext_element_G1_t *n, *tau, *aux;
  pbcext_element_Fr_t *aux1;
  pbcext_element_G2_t *ttau;
  pbcext_element_GT_t *e1, *e2;
  spk_dlog_t *pi;
  message_t *_mout;
  byte_t *bn, *bkey;
  uint64_t len, nlen, taulen, ttaulen, pilen;
  uint32_t size = 0;
  uint8_t ok;
  int rc;

  if((seq != 0 && seq != 2) ||
     !mout || !gml || gml->scheme != GROUPSIG_BAP24_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_BAP24_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_mgrkey = (bap24_mgr_key_t *) mgrkey->key;
  bap24_grpkey = (bap24_grp_key_t *) grpkey->key;
  bap24_entry = NULL;
  bn = bkey = NULL;
  u = NULL;
  n = tau = aux = NULL;
  ttau = NULL;
  e1 = e2 = NULL;
  pi = NULL;
  memkey = NULL;
  rc = IOK;
  
  if (!seq) { /* First step */

    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_join_mgr);
    if(pbcext_element_G1_random(n) == IERROR) GOTOENDRC(IERROR, bap24_join_mgr);
    
    /* Dump the element into a message */
    if(pbcext_dump_element_G1_bytes(&bn, &len, n) == IERROR) 
      GOTOENDRC(IERROR, bap24_join_mgr);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bn, len))) {
	GOTOENDRC(IERROR, bap24_join_mgr);
      }

      *mout = _mout;
      
    } else {

      _mout = *mout;
      if(message_set_bytes(*mout, bn, len) == IERROR)
	        GOTOENDRC(IERROR, bap24_join_mgr);
      
    }
    
  } else { /* Third step */

    /* Import the (n,tau,ttau,pi) ad hoc message */

    if (!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (!(tau = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_get_element_G1_bytes(tau, &taulen, min->bytes + nlen) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (!(ttau = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_get_element_G2_bytes(ttau, &ttaulen, min->bytes + nlen + taulen) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (!(pi = spk_dlog_import(min->bytes + nlen + taulen + ttaulen, &pilen)))
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);

    /* Check the SPK and the pairings */ 
    if (spk_dlog_G1_verify(&ok, tau, bap24_grpkey->g,
			   pi, bn, nlen) == IERROR) {
      GOTOENDRC(IERROR, bap24_join_mgr);
    }
    if (!ok) GOTOENDRC(IERROR, bap24_join_mgr);

    if (!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_join_mgr);

    if (pbcext_pairing(e1, tau, bap24_grpkey->Y) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);

    if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_pairing(e2, bap24_grpkey->g, ttau) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);
    
    if (pbcext_element_GT_cmp(e1, e2) != 0) GOTOENDRC(IERROR, bap24_join_mgr);

    /* Compute the partial member key */
    if (!(uid = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_join_mgr); //The uid has not been transmitted by the member.
    if (pbcext_element_Fr_random(uid) == IERROR) GOTOENDRC(IERROR, bap24_join_mgr);

    if (!(u = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_element_Fr_random(u) == IERROR) GOTOENDRC(IERROR, bap24_join_mgr);

    if (!(memkey = bap24_mem_key_init())) GOTOENDRC(IERROR, bap24_join_mgr);
    bap24_memkey = memkey->key;

    if (!(bap24_memkey->uid = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_element_Fr_set(bap24_memkey->uid,uid) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);
    //sigma1
    if (!(bap24_memkey->sigma1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_element_G1_mul(bap24_memkey->sigma1, bap24_grpkey->g, u) == IERROR) //u is t in paper
      GOTOENDRC(IERROR, bap24_join_mgr);
    //simga2
    if (!(bap24_memkey->sigma2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_join_mgr);    
    
    if (pbcext_element_G1_mul(bap24_memkey->sigma2, //simga2 ==g^x
			      bap24_grpkey->g,
			      bap24_mgrkey->x) == IERROR) 
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_element_G1_mul(aux, tau, bap24_mgrkey->y) == IERROR) //aux == tao ^ y == g^(ski y1)
      GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_element_G1_add(bap24_memkey->sigma2,
			       bap24_memkey->sigma2,
			     aux) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);

    pbcext_element_Fr_t *aux_fr;
    if (!(aux_fr = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_join_mgr);    
    if (pbcext_element_Fr_mul(aux_fr, uid, bap24_mgrkey->yy) == IERROR) 
      GOTOENDRC(IERROR, bap24_join_mgr);//aux == g^(uid)
    if (pbcext_element_G1_mul(aux, bap24_grpkey->g, aux_fr) == IERROR) //aux == g^(uid * y2)
      GOTOENDRC(IERROR, bap24_join_mgr);
    
    if (pbcext_element_G1_add(bap24_memkey->sigma2,
			      bap24_memkey->sigma2,
			      aux) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);  
      
    if (pbcext_element_G1_mul(bap24_memkey->sigma2,
			      bap24_memkey->sigma2,
			      u) == IERROR) 
      GOTOENDRC(IERROR, bap24_join_mgr);    

    /* Compute and update acc and compute witness w*/
    // Set witness w first
    if ( !(bap24_memkey->w = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_join_mgr);   
    if((pbcext_element_G1_set(bap24_memkey->w,bap24_grpkey->acc)) == IERROR ) GOTOENDRC(IERROR, bap24_join_mgr);   
    //Then compute and update acc
    if (!(aux1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_join_mgr);   
    if ((pbcext_element_Fr_add(aux1, bap24_mgrkey->ask, uid)) == IERROR) //aux == g^(uid)
       GOTOENDRC(IERROR, bap24_join_mgr);
    if (pbcext_element_G1_mul(bap24_grpkey->acc,bap24_grpkey->acc, aux1) == IERROR) //aux == g^(uid)
       GOTOENDRC(IERROR, bap24_join_mgr);


    /* Add the tuple (i,tau,ttau) to the GML */

    if(!(bap24_entry = bap24_gml_entry_init()))
      GOTOENDRC(IERROR, bap24_join_mgr);
    
    /* Currently, BAP24 identities are just uint64_t's */
    bap24_entry->id = gml->n;
    
    if (!(bap24_entry->data = mem_malloc(sizeof(bap24_gml_entry_data_t))))
      GOTOENDRC(IERROR, bap24_join_mgr);
    ((bap24_gml_entry_data_t *) bap24_entry->data)->tau = tau;
    ((bap24_gml_entry_data_t *) bap24_entry->data)->ttau = ttau;
    ((bap24_gml_entry_data_t *) bap24_entry->data)->uid = uid;  
    if(gml_insert(gml, bap24_entry) == IERROR) GOTOENDRC(IERROR, bap24_join_mgr);

    /* Export the (partial) member key into a msg */
    bkey = NULL;
    if (bap24_mem_key_export(&bkey, &size, memkey) == IERROR)
      GOTOENDRC(IERROR, bap24_join_mgr);

    if(!*mout) {
      
      if(!(_mout = message_from_bytes(bkey, size)))
	GOTOENDRC(IERROR, bap24_join_mgr);
      *mout = _mout;

    } else {

      _mout = *mout;
      if(message_set_bytes(_mout, bkey, size) == IERROR)
	GOTOENDRC(IERROR, bap24_join_mgr);

    }    
  
  }
  
  bap24_join_mgr_end:

  if (rc == IERROR) {
    if (tau) { pbcext_element_G1_free(tau); tau = NULL; }  
    if (ttau) { pbcext_element_G2_free(ttau); ttau = NULL; }
    if (bap24_entry) { bap24_gml_entry_free(bap24_entry); bap24_entry = NULL; }
  }
  
  if (u) { pbcext_element_Fr_free(u); u = NULL; }
  if (n) { pbcext_element_G1_free(n); n = NULL; }  
  if (aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (pi) { spk_dlog_free(pi); pi = NULL; }
  if (bn) { mem_free(bn); bn = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (memkey) { bap24_mem_key_free(memkey); memkey = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
 