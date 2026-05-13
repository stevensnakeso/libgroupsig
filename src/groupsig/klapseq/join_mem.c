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

#include "klapseq.h"
#include "groupsig/klapseq/grp_key.h"
#include "groupsig/klapseq/mem_key.h"
#include "sys/mem.h"
#include "groupsig/klapseq/spk.h" /* To be replaced in issue23. */
#include "shim/pbc_ext.h"
#include "shim/hash.h"

/** 
 * In the paper, it is the member who begins the protocol and, during join,
 * an interactive ZK protocol is done where the member proves knowledge of
 * her secret exponent. Here, we replace this with having the protocol start
 * by the manager, who sends a fresh random number. Then, the member responds
 * with an SPK over that random number, where she also proves knowledge of
 * her secret exponent. This saves one message. 
 *
 * @TODO: This should not break security, but cross-check!
 *
 * Additionally, the KLAPSEQ scheme requires the member to have a previous
 * keypair+ccertificate from some "traditional" PKI system (e.g., an RSA/ECDSA 
 * certificate). During the join protocol, the member has to send a signature
 * of the value tau (see below, or the paper) under that keypair. IMHO, it makes
 * little sense to code that here, and it would be best to just "require" that
 * some external mechanism using a well tested PKI library is used for that.
 * Instead of signing tau, we can just sign the first message produced by the
 * member (which includes tau). 
 */
int klapseq_join_mem(message_t **mout, groupsig_key_t *memkey,
		    int seq, message_t *min, groupsig_key_t *grpkey) {
  
  klapseq_mem_key_t *klapseq_memkey;
  klapseq_grp_key_t *klapseq_grpkey;
  spk_rep_t *pi;
  hash_t *h;
  pbcext_element_Fr_t *s0, *s1, *x[3];
  pbcext_element_G1_t *n, *f;
  pbcext_element_G2_t *SS0, *SS1, *ff0, *ff1, *ggalpha, *ZZ0s0, *ZZ1s1;
  pbcext_element_GT_t *tau, *e1, *e2, *e3;  
  message_t *_mout;
  byte_t *bn, *bf, *bw, *bSS0, *bSS1, *bff0, *bff1, *bpi, *bmsg;
  void *y[6], *g[5];
  uint64_t len, nlen, flen, wlen, SS0len, SS1len, ff0len, ff1len, pilen, offset;
  int rc;
  uint16_t i[8][2], prods[6];  
  
  if(!memkey || memkey->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !min || (seq != 1 && seq != 3)) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_memkey = memkey->key;
  klapseq_grpkey = grpkey->key;
  _mout = NULL;
  n = f = NULL;
  s0 = s1 = NULL;
  SS0 = SS1 = ff0 = ff1 = ggalpha = ZZ0s0 = ZZ1s1 = NULL;
  tau = e1 = e2 = e3 = NULL;
  pi = NULL;
  bn = bf = bw = bSS0 = bSS1 = bff0 = bff1 = bmsg = bpi = NULL;
  h = NULL;
  rc = IOK;
  
  if (seq == 1) { /* Second step of the <join,issue> interactive protocol.*/
    /*init prf keys*/
    if(!(klapseq_memkey->kk = prf_key_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(prf_key_init_random(klapseq_memkey->kk) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(!(klapseq_memkey->k = prf_key_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(prf_key_init_random(klapseq_memkey->k) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* The manager sends a random element in G1 */
    if(!(n = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* Compute secret alpha, s0 and s1 */
    if(!(klapseq_memkey->alpha = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_Fr_random(klapseq_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(!(s0 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_Fr_random(s0) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(!(s1 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_Fr_random(s1) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* f = g^alpha */
    if(!(f = pbcext_element_G1_init())) GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G1_mul(f,
			     klapseq_grpkey->g,
			     klapseq_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* u = Hash(f) */
    if(pbcext_dump_element_G1_bytes(&bf, &len, f) == IERROR) 
      GOTOENDRC(IERROR, klapseq_join_mem);    
    if(!(h = hash_init(HASH_BLAKE2)))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(hash_update(h, bf, len) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(hash_finalize(h) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(!(klapseq_memkey->u = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G1_from_hash(klapseq_memkey->u,
				   h->hash,
				   h->length) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* w = u^alpha */
    if(!(klapseq_memkey->w = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G1_mul(klapseq_memkey->w,
			     klapseq_memkey->u,
			     klapseq_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* SS0 = gg^s0 */
    if(!(SS0 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G2_mul(SS0, klapseq_grpkey->gg, s0) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);    

    /* SS1 = gg^s1 */
    if(!(SS1 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G2_mul(SS1, klapseq_grpkey->gg, s1) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* ff0 = gg^alpha*ZZ0^s0 */
    if(!(ggalpha = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G2_mul(ggalpha,
			     klapseq_grpkey->gg,
			     klapseq_memkey->alpha) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);    
    if(!(ZZ0s0 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G2_mul(ZZ0s0, klapseq_grpkey->ZZ0, s0) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(!(ff0 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G2_add(ff0, ggalpha, ZZ0s0) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* ff1 = gg^alpha*ZZ1^s1 */
    if(!(ZZ1s1 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G2_mul(ZZ1s1, klapseq_grpkey->ZZ1, s1) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(!(ff1 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_element_G2_add(ff1, ggalpha, ZZ1s1) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    /* tau = e(f,gg) */
    if(!(tau = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_pairing(tau, f, klapseq_grpkey->gg) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);   

    /* Compute the SPK for sk -- this will be replaced in issue23 */
    y[0] = f;
    y[1] = klapseq_memkey->w;
    y[2] = SS0;
    y[3] = SS1;
    y[4] = ff0;
    y[5] = ff1;
  
    g[0] = klapseq_grpkey->g;
    g[1] = klapseq_memkey->u;
    g[2] = klapseq_grpkey->gg;
    g[3] = klapseq_grpkey->ZZ0;
    g[4] = klapseq_grpkey->ZZ1;

    x[0] = klapseq_memkey->alpha;
    x[1] = s0;
    x[2] = s1;

    i[0][0] = 0; i[0][1] = 0; // alpha, g
    i[1][0] = 0; i[1][1] = 1; // alpha, u
    i[2][0] = 1; i[2][1] = 2; // s0, gg
    i[3][0] = 2; i[3][1] = 2; // s1, gg
    i[4][0] = 0; i[4][1] = 2; // alpha, gg
    i[5][0] = 1; i[5][1] = 3; // s0, ZZ0
    i[6][0] = 0; i[6][1] = 2; // alpha, gg
    i[7][0] = 2; i[7][1] = 4; // s1, ZZ1
  
    prods[0] = 1;
    prods[1] = 1;
    prods[2] = 1;
    prods[3] = 1;
    prods[4] = 2;
    prods[5] = 2;

    if(!(pi = spk_rep_init(3))) GOTOENDRC(IERROR, klapseq_join_mem);
    if(klapseq_spk0_sign(pi,
			y, 6,
			g, 5,
			x, 3,
			i, 8,
			prods,
			bn, nlen) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    
    /* Need to send (n, f, w, SS0, SS1, ff0, ff1, pi): prepare ad hoc message */
    mem_free(bn); bn = NULL;
    if (pbcext_dump_element_G1_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    len = nlen;
    
    if(pbcext_dump_element_G1_bytes(&bf,
				    &flen,
				    f) == IERROR) 
      GOTOENDRC(IERROR, klapseq_join_mem);
    len += flen;

    if(pbcext_dump_element_G1_bytes(&bw,
				    &wlen,
				    klapseq_memkey->w) == IERROR) 
      GOTOENDRC(IERROR, klapseq_join_mem);
    len += wlen;

    if(pbcext_dump_element_G2_bytes(&bSS0,
				    &SS0len,
				    SS0) == IERROR) 
      GOTOENDRC(IERROR, klapseq_join_mem);
    len += SS0len;

    if(pbcext_dump_element_G2_bytes(&bSS1,
				    &SS1len,
				    SS1) == IERROR) 
      GOTOENDRC(IERROR, klapseq_join_mem);
    len += SS1len;

    if(pbcext_dump_element_G2_bytes(&bff0,
				    &ff0len,
				    ff0) == IERROR) 
      GOTOENDRC(IERROR, klapseq_join_mem);
    len += ff0len;

    if(pbcext_dump_element_G2_bytes(&bff1,
				    &ff1len,
				    ff1) == IERROR) 
      GOTOENDRC(IERROR, klapseq_join_mem);
    len += ff1len;

    bpi = NULL;
    if(spk_rep_export(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);
    len += pilen;

    if(!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, klapseq_join_mem);

    memcpy(bmsg, bn, nlen); offset = nlen;
    memcpy(&bmsg[offset], bf, flen); offset += flen;
    memcpy(&bmsg[offset], bw, wlen); offset += wlen;
    memcpy(&bmsg[offset], bSS0, SS0len); offset += SS0len;
    memcpy(&bmsg[offset], bSS1, SS1len); offset += SS1len;
    memcpy(&bmsg[offset], bff0, ff0len); offset += ff0len;
    memcpy(&bmsg[offset], bff1, ff1len); offset += ff1len;
    memcpy(&bmsg[offset], bpi, pilen); offset += pilen;

    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len)))
	GOTOENDRC(IERROR, klapseq_join_mem);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR)
	GOTOENDRC(IERROR, klapseq_join_mem);
    }
    
  } else { /* Third (last) message of interactive protocol */

    /* Min = v */
    if(!(klapseq_memkey->v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if(pbcext_get_element_G1_bytes(klapseq_memkey->v,
				   &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);    
    
    /* Check correctness: e(v,gg) = e(u,XX)e(w,YY) */
    if (!(e1 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if (pbcext_pairing(e1, klapseq_memkey->v, klapseq_grpkey->gg) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    if (!(e2 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if (pbcext_pairing(e2, klapseq_memkey->u, klapseq_grpkey->XX) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    if (!(e3 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, klapseq_join_mem);
    if (pbcext_pairing(e3, klapseq_memkey->w, klapseq_grpkey->YY) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    if (pbcext_element_GT_mul(e2, e2, e3) == IERROR)
      GOTOENDRC(IERROR, klapseq_join_mem);

    if (pbcext_element_GT_cmp(e1, e2)) rc = IERROR;
    
  }

 klapseq_join_mem_end:

  if (rc == IERROR) {
    if (seq == 1) {
      if (klapseq_memkey->alpha) {
	pbcext_element_Fr_free(klapseq_memkey->alpha);
	klapseq_memkey->alpha = NULL;
      }
      if (klapseq_memkey->u) {
	pbcext_element_G1_free(klapseq_memkey->u);
	klapseq_memkey->u = NULL;
      }
      if (klapseq_memkey->w) {
	pbcext_element_G1_free(klapseq_memkey->w);
	klapseq_memkey->w = NULL;
      }
    }
    if (seq == 3) {
      if (klapseq_memkey->v) {
	pbcext_element_G1_free(klapseq_memkey->v);
	klapseq_memkey->v = NULL;
      }
    }
  }

  if (pi) { spk_rep_free(pi); pi = NULL; }
  if (s0) { pbcext_element_Fr_free(s0); s0 = NULL; }
  if (s1) { pbcext_element_Fr_free(s1); s1 = NULL; }  
  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (f) { pbcext_element_G1_free(f); f = NULL; }
  if (SS0) { pbcext_element_G2_free(SS0); SS0 = NULL; }
  if (SS1) { pbcext_element_G2_free(SS1); SS1 = NULL; }
  if (ff0) { pbcext_element_G2_free(ff0); ff0 = NULL; }
  if (ff1) { pbcext_element_G2_free(ff1); ff1 = NULL; }  
  if (ggalpha) { pbcext_element_G2_free(ggalpha); ggalpha = NULL; }
  if (ZZ0s0) { pbcext_element_G2_free(ZZ0s0); ZZ0s0 = NULL; }
  if (ZZ1s1) { pbcext_element_G2_free(ZZ1s1); ZZ1s1 = NULL; }  
  if (tau) { pbcext_element_GT_free(tau); tau = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; } 
  if (bn) { mem_free(bn); bn = NULL; }      
  if (bf) { mem_free(bf); bf = NULL; }
  if (bw) { mem_free(bw); bw = NULL; }
  if (bSS0) { mem_free(bSS0); bSS0 = NULL; }
  if (bSS1) { mem_free(bSS1); bSS1 = NULL; }  
  if (bff0) { mem_free(bff0); bff0 = NULL; }
  if (bff1) { mem_free(bff1); bff1 = NULL; }   
  if (bpi) { mem_free(bpi); bpi = NULL; }
  if (bmsg) { mem_free(bmsg); bmsg = NULL; }
  if (h) { hash_free(h); h = NULL; }

  return rc;

}

/* join_mem.c ends here */
