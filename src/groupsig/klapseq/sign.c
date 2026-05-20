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

#include <stdlib.h>
#include <limits.h>

#include "klapseq.h"
#include "groupsig/klapseq/grp_key.h"
#include "groupsig/klapseq/mem_key.h"
#include "groupsig/klapseq/signature.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"
#include "crypto/prf.h"
#include "shim/hash.h"

static int _klap_compute_seq(klapseq_mem_key_t *memkey,
			     klapseq_seqinfo_t *seq,
			     unsigned int state) {

  hash_t *hc;
  byte_t *xi, *xi1, *ni1;
  uint64_t len, i;
  unsigned int state1;
  int rc;

  if (!memkey || !seq) {
    LOG_EINVAL(&logger, __FILE__, "_klap_compute_seq", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  xi = xi1 = ni1 = NULL;
  hc = NULL;

  /* Compute seq3 = PRF(k,state) */
  seq->seq3 = NULL;
  if (prf_compute(&seq->seq3, &seq->len3,
		  memkey->k, (byte_t*) &state, sizeof(unsigned int)) == IERROR)
    GOTOENDRC(IERROR, _klap_compute_seq);
  
  /* Compute x_i = PRF(k',state) */
  if (prf_compute(&xi, &len, memkey->kk, seq->seq3, seq->len3) == IERROR)
    GOTOENDRC(IERROR, _klap_compute_seq);
  
  /* seq1 = Hash(x_i) */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_update(hc, xi, len) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if (!(seq->seq1 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
    GOTOENDRC(IERROR, _klap_compute_seq);
  memcpy(seq->seq1, hc->hash, hc->length);
  seq->len1 = hc->length;
  hash_free(hc); hc = NULL;

  /* Compute x_{i-1} = PRF(k',PRF(k,state-1)) */
  ni1 = NULL; xi1 = NULL;
  if (state >= 1) {


    /* Recompute n_{i-1} = PRF(k,state-1) */
    state1 = state - 1;
    if (prf_compute(&ni1, &len, memkey->k,
		    (byte_t*) &state1, sizeof(unsigned int)) == IERROR)
      GOTOENDRC(IERROR, _klap_compute_seq);
  
    if (prf_compute(&xi1, &len, memkey->kk, ni1, len) == IERROR)
      GOTOENDRC(IERROR, _klap_compute_seq);

    /* seq2 = Hash(x_i \xor x_{i-1}) */
    for (i=0; i<len; i++) xi[i] = xi[i] ^ xi1[i];
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _klap_compute_seq);
    if(hash_update(hc, xi, len) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
    if (!(seq->seq2 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
      GOTOENDRC(IERROR, _klap_compute_seq);
    memcpy(seq->seq2, hc->hash, hc->length);
    seq->len2 = hc->length;
    hash_free(hc); hc = NULL;
    
  } else {
    seq->seq2 = NULL;
    seq->len2 = 0;
  }

 _klap_compute_seq_end:

  if (hc) { hash_free(hc); hc = NULL; }
  if (xi) { mem_free(xi); xi = NULL; }
  if (xi1) { mem_free(xi1); xi1 = NULL; }
  if (ni1) { mem_free(ni1); ni1 = NULL; }
    
  return rc;

}

static int _klap_compute_seq2(klapseq_mem_key_t *memkey,
			     klapseq_seqinfo_t *seq,
			     unsigned int *x_state,
           unsigned int *y_state,
           int header) {

  hash_t *hc;
  byte_t *xi, *xi1, *xxy,*x_1y, *xy_1, *ni1, *nxy, *nx_1y, *nxy_1, *aux;
  uint64_t len, i;
  unsigned int state1;
  int rc;

  if (!memkey || !seq) {
    LOG_EINVAL(&logger, __FILE__, "_klap_compute_seq", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  xi = xi1 = ni1 = NULL;
  xxy = x_1y = xy_1 = NULL;
  nxy = nx_1y = nxy_1 = NULL;
  hc = NULL;
  seq->seq4 = NULL;
  seq->len4 = 0;
  seq->header = header;
  /* nxy = PRF(k,x_state,y_state) */
  // temp = x_state || y_state
  unsigned int temp_state[2];
  temp_state[0] = *x_state;
  temp_state[1] = *y_state;
  if (prf_compute(&nxy, &len, memkey->k, (byte_t*) temp_state, sizeof(unsigned int) * 2) == IERROR)
    GOTOENDRC(IERROR, _klap_compute_seq);
  
  /*nx_1y = PRF(k,x_state-1,y_state) */
  //temp = (x_state-1) || y_state
  temp_state[0] = *x_state - 1;
  temp_state[1] = *y_state;
   if (prf_compute(&nx_1y, &len, memkey->k, (byte_t*) temp_state, sizeof(unsigned int) * 2) == IERROR)
      GOTOENDRC(IERROR, _klap_compute_seq);

  /*nxy_1 = PRF(k,x_state,y_state-1) */
  //temp = x_state || (y_state-1)
  temp_state[0] = *x_state;
  temp_state[1] = *y_state - 1;
  if (prf_compute(&nxy_1, &len, memkey->k, (byte_t*) temp_state, sizeof(unsigned int) * 2) == IERROR)
      GOTOENDRC(IERROR, _klap_compute_seq);

  /* Compute xxy = PRF(k',nxy) */
  if (prf_compute(&xxy, &len, memkey->kk, nxy, len) == IERROR)
    GOTOENDRC(IERROR, _klap_compute_seq);

  /* Compute x_1y = PRF(k',nx_1y) */
  if (prf_compute(&x_1y, &len, memkey->kk, nx_1y, len) == IERROR)
    GOTOENDRC(IERROR, _klap_compute_seq);

  /* Compute xxy_1 = PRF(k',nxy_1) */
  if (prf_compute(&xy_1, &len, memkey->kk, nxy_1, len) == IERROR)
    GOTOENDRC(IERROR, _klap_compute_seq);

  /* seq1 = Hash(xxy) */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_update(hc, xxy, len) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if (!(seq->seq1 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
    GOTOENDRC(IERROR, _klap_compute_seq);
  memcpy(seq->seq1, hc->hash, hc->length);
  seq->len1 = hc->length;
  hash_free(hc); hc = NULL;

  /* seq2 = Hash(xxy \xor x_1y) */
  if(!(aux = (byte_t *) mem_malloc(sizeof(byte_t)*len))) GOTOENDRC(IERROR, _klap_compute_seq);
  for (i=0; i<len; i++) aux[i] = xxy[i] ^ x_1y[i];
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_update(hc, aux, len) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if (!(seq->seq2 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
    GOTOENDRC(IERROR, _klap_compute_seq);
  memcpy(seq->seq2, hc->hash, hc->length);
  seq->len2 = hc->length;
  hash_free(hc); hc = NULL;
  
  free(aux); aux = NULL;

  /* seq3 = Hash(xxy \xor xxy_1) */
  if(!(aux = (byte_t *) mem_malloc(sizeof(byte_t)*len))) GOTOENDRC(IERROR, _klap_compute_seq);
  for (i=0; i<len; i++) aux[i] = xxy[i] ^ xy_1[i];
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_update(hc, aux, len) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _klap_compute_seq);
  if (!(seq->seq3 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
    GOTOENDRC(IERROR, _klap_compute_seq);
  memcpy(seq->seq3, hc->hash, hc->length);
  seq->len3 = hc->length;
  hash_free(hc); hc = NULL;

  free(aux); aux = NULL;

  /* seq4 = nxy */
  if (!(seq->seq4 = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
    GOTOENDRC(IERROR, _klap_compute_seq);
  memcpy(seq->seq4, nxy, len);
  seq->len4 = len;

  if(seq->header == 1) {
    *x_state = *x_state + 1;
  } else {
    *y_state = *y_state + 1;
  }
  

  

 _klap_compute_seq_end:

  if (hc) { hash_free(hc); hc = NULL; }
  if (xi) { mem_free(xi); xi = NULL; }
  if (xi1) { mem_free(xi1); xi1 = NULL; }
  if (ni1) { mem_free(ni1); ni1 = NULL; }
  if(xxy) { mem_free(xxy); xxy = NULL; }
  if(x_1y) { mem_free(x_1y); x_1y = NULL; }
  if(xy_1) { mem_free(xy_1); xy_1 = NULL; }
  if(nxy) { mem_free(nxy); nxy = NULL; }
  if(nx_1y) { mem_free(nx_1y); nx_1y = NULL; }
  if(nxy_1) { mem_free(nxy_1); nxy_1 = NULL; }
  if(aux) { mem_free(aux); aux = NULL; }
  return rc;

}


int klapseq_sign(groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *memkey,
		groupsig_key_t *grpkey,
		unsigned int state) {

  pbcext_element_Fr_t *r;
  klapseq_signature_t *klapseq_sig;
  klapseq_grp_key_t *klapseq_grpkey;
  klapseq_mem_key_t *klapseq_memkey;
  int rc;
  klapseq_seqinfo_t *seq;
  pbcext_element_G1_t *hscp;
  hash_t *hc;
  byte_t *msg_scp, *msg_msg;
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_sig = sig->sig;
  klapseq_grpkey = grpkey->key;
  klapseq_memkey = memkey->key;
  msg_msg = NULL; msg_scp = NULL;
  r = NULL;
  rc = IOK;
  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  /* Randomize u, v and w */
  if (!(r = pbcext_element_Fr_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_Fr_random(r) == IERROR) GOTOENDRC(IERROR, klapseq_sign);

  if (!(klapseq_sig->uu = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->uu, klapseq_memkey->u, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if (!(klapseq_sig->vv = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->vv, klapseq_memkey->v, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if (!(klapseq_sig->ww = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->ww, klapseq_memkey->w, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  
  /* Compute signature of knowledge of alpha */
  if (!(klapseq_sig->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, klapseq_sign);
  if (spk_dlog_G1_sign(klapseq_sig->pi,
		       klapseq_sig->ww,
		       klapseq_sig->uu,
		       klapseq_memkey->alpha,
		       (byte_t *) msg_msg, strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  
  /* Compute seq */
  if(!(seq = (klapseq_seqinfo_t *) mem_malloc(sizeof(klapseq_seqinfo_t))))
    GOTOENDRC(IERROR, klapseq_sign);

  /* Compute h_{scp} = Hash(scp) */
  if (!(hscp = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_sign);
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, klapseq_sign);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, klapseq_sign);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  /* Compute nym*/
  if (!(klapseq_sig->nym = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_sign);

  
  if (pbcext_element_G1_mul(klapseq_sig->nym, hscp, klapseq_memkey->alpha) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  

  if (_klap_compute_seq(klapseq_memkey, seq, state) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);

  klapseq_sig->seq = seq;

 klapseq_sign_end:

  if (r) { pbcext_element_Fr_free(r); r = NULL; }

  if (rc == IERROR) {
    
    if (klapseq_sig->uu) {
      pbcext_element_G1_free(klapseq_sig->uu);
      klapseq_sig->uu = NULL;
    }
    if (klapseq_sig->vv) {
      pbcext_element_G1_free(klapseq_sig->vv);
      klapseq_sig->vv = NULL;
    }
    if (klapseq_sig->ww) {
      pbcext_element_G1_free(klapseq_sig->ww);
      klapseq_sig->ww = NULL;
    }
    if (klapseq_sig->pi) {
      spk_dlog_free(klapseq_sig->pi);
      klapseq_sig->pi = NULL;
    }    
    
  }
  
  return rc;
  
}

int klapseq_sign2(groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *memkey,
		groupsig_key_t *grpkey,
		unsigned int *x,
    unsigned int *y,
    int header) {

  pbcext_element_Fr_t *r;
  klapseq_signature_t *klapseq_sig;
  klapseq_grp_key_t *klapseq_grpkey;
  klapseq_mem_key_t *klapseq_memkey;
  int rc;
  klapseq_seqinfo_t *seq;
  pbcext_element_G1_t *hscp;
  hash_t *hc;
  byte_t *msg_scp, *msg_msg;
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_sig = sig->sig;
  klapseq_grpkey = grpkey->key;
  klapseq_memkey = memkey->key;
  msg_msg = NULL; msg_scp = NULL;
  r = NULL;
  rc = IOK;
  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  /* Randomize u, v and w */
  if (!(r = pbcext_element_Fr_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_Fr_random(r) == IERROR) GOTOENDRC(IERROR, klapseq_sign);

  if (!(klapseq_sig->uu = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->uu, klapseq_memkey->u, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if (!(klapseq_sig->vv = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->vv, klapseq_memkey->v, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if (!(klapseq_sig->ww = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_sign);
  if (pbcext_element_G1_mul(klapseq_sig->ww, klapseq_memkey->w, r) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  
  /* Compute signature of knowledge of alpha */
  if (!(klapseq_sig->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, klapseq_sign);
  if (spk_dlog_G1_sign(klapseq_sig->pi,
		       klapseq_sig->ww,
		       klapseq_sig->uu,
		       klapseq_memkey->alpha,
		       (byte_t *) msg_msg, strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  
  /* Compute seq */
  if(!(seq = (klapseq_seqinfo_t *) mem_malloc(sizeof(klapseq_seqinfo_t))))
    GOTOENDRC(IERROR, klapseq_sign);

  /* Compute h_{scp} = Hash(scp) */
  if (!(hscp = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_sign);
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, klapseq_sign);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, klapseq_sign);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  /* Compute nym*/
  if (!(klapseq_sig->nym = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_sign);

  
  if (pbcext_element_G1_mul(klapseq_sig->nym, hscp, klapseq_memkey->alpha) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);
  

  if (_klap_compute_seq2(klapseq_memkey, seq, x, y, header) == IERROR)
    GOTOENDRC(IERROR, klapseq_sign);

  klapseq_sig->seq = seq;

 klapseq_sign_end:

  if (r) { pbcext_element_Fr_free(r); r = NULL; }

  if (rc == IERROR) {
    
    if (klapseq_sig->uu) {
      pbcext_element_G1_free(klapseq_sig->uu);
      klapseq_sig->uu = NULL;
    }
    if (klapseq_sig->vv) {
      pbcext_element_G1_free(klapseq_sig->vv);
      klapseq_sig->vv = NULL;
    }
    if (klapseq_sig->ww) {
      pbcext_element_G1_free(klapseq_sig->ww);
      klapseq_sig->ww = NULL;
    }
    if (klapseq_sig->pi) {
      spk_dlog_free(klapseq_sig->pi);
      klapseq_sig->pi = NULL;
    }    
    
  }
  
  return rc;
  
}

/* sign.c ends here */
