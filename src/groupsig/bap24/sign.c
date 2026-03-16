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

#include "bap24.h"
#include "groupsig/bap24/grp_key.h"
#include "groupsig/bap24/mem_key.h"
#include "groupsig/bap24/signature.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

#if defined (SHA2) || defined (SHA3)
#include <openssl/evp.h>
#ifdef SHA3
#define HASH_DIGEST_LENGTH 64
#else
#define HASH_DIGEST_LENGTH 32
#endif
#endif

/* Private functions */

int bap24_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey,
	      groupsig_key_t *grpkey, unsigned int seed) {

  pbcext_element_Fr_t *t, *k, *alpha;
  pbcext_element_GT_t *e;
  pbcext_element_G1_t *hscp,*cnym1,*cnym2,*aux;
  hash_t *hc;
#if defined (SHA2) || defined (SHA3)
  byte_t aux_sc[HASH_DIGEST_LENGTH+1];
#else
  hash_t *aux_c;
#endif
  byte_t *aux_bytes;
  bap24_signature_t *bap24_sig;
  bap24_grp_key_t *bap24_grpkey;
  bap24_mem_key_t *bap24_memkey;
  uint64_t len;
  int rc;
  char *msg_msg, *msg_scp;        
  if(!sig || !msg ||
     !memkey || memkey->scheme != GROUPSIG_BAP24_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_sig = sig->sig;
  bap24_grpkey = grpkey->key;
  bap24_memkey = memkey->key;
  t = k = NULL;
  e = NULL;
#if !defined(SHA2) && !defined(SHA3)
  aux_c = NULL;
#endif
  aux_bytes = NULL;
  rc = IOK;

  /* de message and scope */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR) GOTOENDRC(IERROR, bap24_sign);

  /* Randomize sigma1 and sigma2 */
  if (!(t = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_random(t) == IERROR) GOTOENDRC(IERROR, bap24_sign);

  if (!(bap24_sig->sigma1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_G1_mul(bap24_sig->sigma1, bap24_memkey->sigma1, t) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  if (!(bap24_sig->sigma2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_G1_mul(bap24_sig->sigma2, bap24_memkey->sigma2, t) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);

  /* Compute signature of knowledge of sk */

  /* The SPK in BAP24 is a dlog spk, but does not follow exactly the
     pattern of spk_dlog, so we must implement it manually.
     A good improvement would be to analyze how to generalize spk_dlog
     to fit this. */

  if (!(k = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_random(k) == IERROR) GOTOENDRC(IERROR, bap24_sign);

  if (!(e = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_pairing(e, bap24_sig->sigma1, bap24_grpkey->Y) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_GT_pow(e, e, k) == IERROR) GOTOENDRC(IERROR, bap24_sign);

  /* Hash(scp)^sk */

  hscp = pbcext_element_G1_init();
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bap24_sign);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  /* gen alpha*/
  alpha = pbcext_element_Fr_init();
  if (pbcext_element_Fr_random(alpha) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  /*cnym1 = g^a*/
  cnym1 = pbcext_element_G1_init();
  if( pbcext_element_G1_mul(cnym1, bap24_grpkey->g, alpha) == IERROR) GOTOENDRC(IERROR, bap24_sign);

  /*cnuym2 = dpk^alpha hscp^sk*/
  cnym2 = pbcext_element_G1_init();
  if (pbcext_element_G1_mul(cnym2, bap24_grpkey->dpk, alpha) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_G1_mul(aux, hscp, bap24_memkey->sk) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_G1_add(cnym2, cnym2, aux) == IERROR) GOTOENDRC(IERROR, bap24_sign);

  /*Manually do the SOK. Wrapper later*/
  /*T1=e(sigma1',X_), T2=e(sigma1',Y1_), T3=e(sigma1',Y2_), T4=e(sigma2',g_), T5=hscp*/
  pbcext_element_GT_t *T1, *T2, *T3, *T4;  
  pbcext_element_G1_t *T5;
  if (!(T1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_pairing(T1, bap24_sig->sigma1, bap24_grpkey->X) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (!(T2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_pairing(T2, bap24_sig->sigma1, bap24_grpkey->Y) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (!(T3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_pairing(T3, bap24_sig->sigma1, bap24_grpkey->dpk) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (!(T4 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_pairing(T4, bap24_sig->sigma2, bap24_grpkey->gg) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (!(T5 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_sign);
  
  if( pbcext_element_Fr_set(T5, hscp) == IERROR) GOTOENDRC(IERROR, bap24_sign);

  pbcext_element_Fr_t *zeta1, *zeta2, *theta1,*theta2;
  if (!(zeta1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_random(zeta1) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (!(zeta2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_random(zeta2) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  
  if (!(theta1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if(pbcext_element_Fr_mul(theta1,zeta1,bap24_memkey->uid) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (!(theta2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if(pbcext_element_Fr_mul(theta2,zeta2,bap24_memkey->uid) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  
  pbcext_element_G1_t *B1;
  pbcext_element_G2_t *B2;
  if (!(B1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_G1_mul(B1, bap24_grpkey->g, zeta1) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_G1_mul(aux, bap24_grpkey->h, zeta2) == IERROR) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_G1_add(B1, B1, aux) == IERROR) GOTOENDRC(IERROR, bap24_sign);

  if (!(B2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_sign);




  


  /* c = hash(bap24_sig->sigma1,bap24_sig->sigma2,e,m); */
#if defined (SHA2) || defined (SHA3)
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
                      "EVP_MD_CTX_new", LOGERROR);
    GOTOENDRC(IERROR, bap24_sign);
  }
#ifdef SHA3
  if(EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1) {
#else
  if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
#endif
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestInit_ex", LOGERROR);
    GOTOENDRC(IERROR, bap24_sign);
  }
#else
  if (!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bap24_sign);
#endif

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, bap24_sig->sigma1) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  /* Put the message into the hash */
#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_sign);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, bap24_sig->sigma2) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_sign);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, e) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_sign);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, msg->bytes, msg->length) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_sign);
  }
  memset(aux_sc, 0, HASH_DIGEST_LENGTH+1);
#else
  if (hash_update(aux_c, msg->bytes, msg->length) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
#endif

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestFinal_ex(mdctx, aux_sc, NULL) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
			"EVP_DigestFinal_ex", LOGERROR);
      GOTOENDRC(IERROR, bap24_sign);
  }
#else
  if (hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, bap24_sign);
#endif

  /* Complete the sig */
  if (!(bap24_sig->c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);

#if defined (SHA2) || defined (SHA3)
  if (pbcext_element_Fr_from_hash(bap24_sig->c, aux_sc, HASH_DIGEST_LENGTH) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
#else
  if (pbcext_element_Fr_from_hash(bap24_sig->c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
#endif

  if (!(bap24_sig->s = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_mul(bap24_sig->s, bap24_sig->c, bap24_memkey->sk) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_add(bap24_sig->s, k, bap24_sig->s) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);

 bap24_sign_end:
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if (k) { pbcext_element_Fr_free(k); k = NULL; }
  if (t) { pbcext_element_Fr_free(t); t = NULL; }
  if (e) { pbcext_element_GT_free(e); e = NULL; }
#if !defined(SHA2) && !defined(SHA3)
  if (aux_c) { hash_free(aux_c); aux_c = NULL; }
#endif
  if (aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }

  if (rc == IERROR) {
    if (bap24_sig->c) {
      pbcext_element_Fr_free(bap24_sig->c);
      bap24_sig->c = NULL;
    }
    if (bap24_sig->s) {
      pbcext_element_Fr_free(bap24_sig->s);
      bap24_sig->s = NULL;
    }
    if (bap24_sig->sigma1) {
      pbcext_element_G1_free(bap24_sig->sigma1);
      bap24_sig->sigma1 = NULL;
    }
    if (bap24_sig->sigma2) {
      pbcext_element_G1_free(bap24_sig->sigma2);
      bap24_sig->sigma2 = NULL;
    }
  }
  return rc;
}

/* sign.c ends here */
