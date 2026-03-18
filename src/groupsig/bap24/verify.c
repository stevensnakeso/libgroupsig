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
  pbcext_element_G1_t *aux_G1;
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
  aux_G1 = NULL;
  e1 = e2 = e3 = NULL;
#if !defined(SHA2) && !defined(SHA3)
  aux_c = NULL;
#endif
  aux_bytes = NULL;
  //delete and rewrite the code here, since we need to parse the message content and scope
  if (!(aux_G1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_verify);

  pbcext_element_G1_t *D1, *D2, *D5,*aux1_g1,*aux2_g1;
  pbcext_element_G2_t *aux_g2;
  pbcext_element_GT_t *D3, *D4, *D6, *aux_gt;
  char *msg_msg, *msg_scp;
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR) GOTOENDRC(IERROR, bap24_verify);
  
  if (D1 = pbcext_element_G1_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D2 = pbcext_element_G1_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D3 = pbcext_element_GT_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D4 = pbcext_element_GT_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D5 = pbcext_element_G1_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D6 = pbcext_element_GT_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (aux1_g1 = pbcext_element_G1_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (aux2_g1 = pbcext_element_G1_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (aux_g2 = pbcext_element_G2_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D3 = pbcext_element_GT_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D4 = pbcext_element_GT_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (D6 = pbcext_element_GT_init() == IERROR) GOTOENDRC(IERROR, bap24_verify);

  if (pbcext_element_G1_mul(D1, B1, bap24_sig->s) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G1_mul(aux_G1, bap24_grpkey->g, bap24_sig->c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
  if (pbcext_element_G1_add(D1, D1, aux_G1) == IERROR) GOTOENDRC(IERROR, bap24_verify);

  /* c = Hash(sigma1,sigma2,R,m); */
#if defined (SHA2) || defined (SHA3)
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_verify", __LINE__, EDQUOT,
		      "EVP_MD_CTX_new", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#ifdef SHA3
  if(EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1) {
#else
  if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
#endif
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_verify", __LINE__, EDQUOT,
		      "EVP_DigestInit_ex", LOGERROR);
    GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bap24_verify);
#endif

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, bap24_sig->sigma1) == IERROR)
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

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, bap24_sig->sigma2) == IERROR)
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

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, e1) == IERROR)
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_verify", __LINE__, EDQUOT,
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_verify", __LINE__, EDQUOT,
			"EVP_DigestFinal_ex", LOGERROR);
      GOTOENDRC(IERROR, bap24_verify);
  }
#else
  if (hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, bap24_verify);
#endif

  /* Complete the sig */
  if (!(c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_verify);

#if defined (SHA2) || defined (SHA3)
  if (pbcext_element_Fr_from_hash(c, aux_sc, HASH_DIGEST_LENGTH) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#else
  if (pbcext_element_Fr_from_hash(c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, bap24_verify);
#endif

  /* Compare the result with the received challenge */
  if (pbcext_element_Fr_cmp(bap24_sig->c, c)) { /* Different: sig fail */
    *ok = 0;
  } else { /* Same: sig OK */
    *ok = 1;
  }

 bap24_verify_end:
  if (c) { pbcext_element_Fr_free(c); c = NULL; }
  if (aux_G1) { pbcext_element_G1_free(aux_G1); aux_G1 = NULL; }
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
