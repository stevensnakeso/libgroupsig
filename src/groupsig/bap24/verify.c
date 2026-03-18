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

#include "bap24.h"
#include "groupsig/bap24/grp_key.h"
#include "groupsig/bap24/signature.h"
#include "shim/pbc_ext.h"
#include "shim/hash.h"
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

/* Public functions */
int bap24_verify(uint8_t *ok,
		 groupsig_signature_t *sig,
		 message_t *msg,
		 groupsig_key_t *grpkey) {

  pbcext_element_Fr_t *c;
  pbcext_element_GT_t *e1, *e2, *e3;
  bap24_signature_t *bap24_sig;
  bap24_grp_key_t *bap24_grpkey;
#if defined (SHA2) || defined (SHA3)
  byte_t aux_sc[HASH_DIGEST_LENGTH+1];
#else
  hash_t *aux_c;
#endif
  byte_t *aux_bytes;
  uint64_t len;
  int rc;

  if(!ok || !msg || !sig || sig->scheme != GROUPSIG_BAP24_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_sig = sig->sig;
  bap24_grpkey = grpkey->key;
  rc = IOK;

  c = NULL;
  e1 = e2 = e3 = NULL;
#if !defined(SHA2) && !defined(SHA3)
  aux_c = NULL;
#endif
  aux_bytes = NULL;
  //delete and rewrite the code here, since we need to parse the message content and scope

  pbcext_element_G1_t *D1, *D2, *aux1_g1,*aux2_g1;
  pbcext_element_G2_t *aux_g2;
  pbcext_element_GT_t *D3, *D4, *D6, *aux_gt;
  char *msg_msg, *msg_scp;
  pbcext_element_GT_t *T1, *T2, *T3, *T4;  
  pbcext_element_G2_t *D5, *T5, *aux1_g2,*aux2_g2;
  pbcext_element_GT_t *T6, *T7, *T8, *T9,*aux_gt1, *aux_gt2;
  pbcext_element_Fr_t *_c;
  
  

  /*rebuild T1 to T9*/
  if (!(aux_gt1 = pbcext_element_GT_init())) GOTOENDRC( IERROR, bap24_verify);
  if (!(aux_gt2 = pbcext_element_GT_init())) GOTOENDRC( IERROR, bap24_verify);

  if (!(T1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T1,bap24_sig->sigma1,bap24_grpkey->X) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (!(T2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T2,bap24_sig->sigma1,bap24_grpkey->Y) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (!(T3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T3,bap24_sig->sigma1,bap24_grpkey->YY) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (!(T4 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T4,bap24_sig->sigma2,bap24_grpkey->gg) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (!(T5 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G2_set(T5, bap24_sig->hscp) == IERROR) GOTOENDRC(IERROR, bap24_verify);

  /*T6-T9*/
  if ((T6 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T6,bap24_sig->B2,bap24_grpkey->apk) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(aux_gt1,bap24_grpkey->acc,bap24_grpkey->hh) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_div(T6,T6,aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);


  if (!(T7 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T7,bap24_grpkey->h,bap24_grpkey->hh) == IERROR) GOTOENDRC(IERROR, bap24_verify);

  if (!(T8 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T8,bap24_grpkey->h,bap24_grpkey->apk) == IERROR) GOTOENDRC(IERROR, bap24_verify);

  if (!(T9 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_pairing(T9,bap24_sig->B2,bap24_grpkey->hh) == IERROR) GOTOENDRC(IERROR, bap24_verify);


  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR) GOTOENDRC(IERROR, bap24_verify);
  

  /*rebuild D1 to T6*/
  if (!(D1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D4 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D5 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D6 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(aux1_g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(aux2_g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(aux_g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D4 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);
  if (!(D6 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bap24_verify);

  //if (pbcext_element_G1_mul(D1, B1, bap24_sig->s) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (!(aux1_g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_verify);

  if (pbcext_element_G1_mul(aux1_g1, bap24_sig->B1, bap24_sig->c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if ((pbcext_element_G1_set(D1, aux1_g1)) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G1_mul(aux1_g1, bap24_grpkey->g, bap24_sig->z_zeta1) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if ((pbcext_element_G1_add(D1, D1, aux1_g1)) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G1_mul(aux1_g1, bap24_grpkey->h, bap24_sig->z_zeta2) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if ((pbcext_element_G1_add(D1, D1, aux1_g1)) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  
  pbcext_element_Fr_t *aux_fr;
  if (!(aux_fr = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_Fr_neg(aux_fr, bap24_sig->z_uid) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G1_mul(D2, bap24_sig->B1, aux_fr) == IERROR) GOTOENDRC(IERROR, bap24_verify);  

  if (pbcext_element_G1_mul(aux1_g1, bap24_grpkey->g, bap24_sig->z_theta1) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if ((pbcext_element_G1_add(D2, D2, aux1_g1)) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G1_mul(aux1_g1, bap24_grpkey->h, bap24_sig->z_theta2) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if ((pbcext_element_G1_add(D2, D2, aux1_g1)) == IERROR) GOTOENDRC(IERROR, bap24_verify);


  if (pbcext_element_GT_div(D3, T4, T1) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(D3, D3, bap24_sig->c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_set(aux_gt1, T2) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(aux_gt1,aux_gt1,bap24_sig->z_sk) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_mul(D3, D3, aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_set(aux_gt1, T3) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(aux_gt1,aux_gt1,bap24_sig->z_uid) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_mul(D3, D3, aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);

  if (pbcext_element_GT_set(aux_gt1, T6) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(aux_gt1,aux_gt1,bap24_sig->c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_set(D4, aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(aux_gt1,T7,bap24_sig->z_theta2) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_mul(D4, D4, aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(aux_gt1,T8,bap24_sig->z_zeta2) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_mul(D4, D4, aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(aux_gt1,T9,aux_fr) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_mul(D4, D4, aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);


  if (!(aux1_g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_verify);

  if (pbcext_element_G2_mul(D5, bap24_sig->cnym1, bap24_sig->c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G2_mul(aux1_g2, bap24_grpkey->gg, bap24_sig->z_alpha) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G2_add(D5, D5, aux1_g2) == IERROR) GOTOENDRC(IERROR, bap24_verify);

  //D6 =cnym2^c dpk^z_alpha T6^z_sk
  if (!(aux1_g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G2_set(aux1_g2, bap24_sig->cnym2) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G2_mul(aux1_g2,aux1_g2, bap24_sig->c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G2_mul(aux2_g2, bap24_grpkey->dpk, bap24_sig->z_alpha) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G2_add(aux1_g2, aux1_g2, aux2_g2) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  
  pbcext_element_G1_t *tmp_g1;
  if (!(tmp_g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G1_setInt(tmp_g1, 1) == IERROR) GOTOENDRC(IERROR, bap24_verify);

  if (pbcext_pairing(aux_gt1, tmp_g1, aux1_g2) == IERROR) GOTOENDRC(IERROR, bap24_verify);


  if (pbcext_element_GT_set(D6, T6) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_pow(D6, D6, bap24_sig->z_sk) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_GT_mul(D6, D6, aux_gt1) == IERROR) GOTOENDRC(IERROR, bap24_verify);





  /* _c = hash(D1,D2,D3,D4,D5,D6,m) */
  
#if defined (SHA2) || defined (SHA3)
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
                      "EVP_MD_CTX_new", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#ifdef SHA3
  if(EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1) {
#else
  if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
#endif
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestInit_ex", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bap24_verify);
#endif

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, D1) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
  /* Put the message into the hash */
#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, D2) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, D3) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, D4) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G2_to_bytes(&aux_bytes, &len, D5) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, D6) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_verify", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, msg->bytes, msg->length) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
  memset(aux_sc, 0, HASH_DIGEST_LENGTH+1);
#else
  if (hash_update(aux_c, msg->bytes, msg->length) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestFinal_ex(mdctx, aux_sc, NULL) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_sign", __LINE__, EDQUOT,
			"EVP_DigestFinal_ex", LOGERROR);
      GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
#endif

  /* Complete the sig */
  if (!(_c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_verify);

#if defined (SHA2) || defined (SHA3)
  if (pbcext_element_Fr_from_hash(_c, aux_sc, HASH_DIGEST_LENGTH) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#else
  if (pbcext_element_Fr_from_hash(_c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif

  /* Compare the result with the received challenge */
  if (pbcext_element_Fr_cmp(bap24_sig->c, _c)) { /* Different: sig fail */
    *ok = 0;
  } else { /* Same: sig OK */
    *ok = 1;
  }

 bap24_verify_end:
  if (_c) { pbcext_element_Fr_free(_c); _c = NULL; }
  if (aux1_g1) { pbcext_element_G1_free(aux1_g1); aux1_g1 = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }
#if !defined(SHA2) && !defined(SHA3)
  if (aux_c) { hash_free(aux_c); aux_c = NULL; }
#endif
  if (aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }
  return rc;
}

/* verify.c ends here */
