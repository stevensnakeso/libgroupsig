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

/* Private functions */

int bap24_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey,
	      groupsig_key_t *grpkey, unsigned int seed) {

  pbcext_element_Fr_t *t, *k;
  pbcext_element_GT_t *e;
  byte_t *aux_c;
  byte_t *aux_bytes;
  bap24_signature_t *bap24_sig;
  bap24_grp_key_t *bap24_grpkey;
  bap24_mem_key_t *bap24_memkey;
  uint64_t len;
  int rc;

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
  aux_c = NULL;
  aux_bytes = NULL;
  rc = IOK;
  uint64_t msg_len = 0;
  byte_t to_be_hashed[999999] = {0}; // Adjust size as needed

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

  /* c = hash(bap24_sig->sigma1,bap24_sig->sigma2,e,m) */
  /* if (!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bap24_sign); */

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, bap24_sig->sigma1) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);

  /* if (hash_update(aux_c, aux_bytes, len) == IERROR) */
  /*   GOTOENDRC(IERROR, bap24_sign); */
  strcat(to_be_hashed, aux_bytes);
  msg_len += len;
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, bap24_sig->sigma2) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  /* if (hash_update(aux_c, aux_bytes, len) == IERROR) */
  /*   GOTOENDRC(IERROR, bap24_sign); */
  strcat(to_be_hashed, aux_bytes);
  msg_len += len;
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, e) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  /* if (hash_update(aux_c, aux_bytes, len) == IERROR) */
  /*   GOTOENDRC(IERROR, bap24_sign); */
  strcat(to_be_hashed, aux_bytes);
  msg_len += len;
  mem_free(aux_bytes); aux_bytes = NULL;

  /* if (hash_update(aux_c, msg->bytes, msg->length) == IERROR)  */
  /*   GOTOENDRC(IERROR, bap24_sign); */
  strcat(to_be_hashed, msg->bytes);
  msg_len += msg->length;

  /* if (hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, bap24_sign); */
  aux_c = (byte_t*) hash_message_hw((byte_t*) to_be_hashed, (int) msg_len);

  /* Complete the sig */
  if (!(bap24_sig->c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_from_hash(bap24_sig->c, aux_c, HASH_DIGEST_LENGTH) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);

  if (!(bap24_sig->s = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_mul(bap24_sig->s, bap24_sig->c, bap24_memkey->sk) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);
  if (pbcext_element_Fr_add(bap24_sig->s, k, bap24_sig->s) == IERROR)
    GOTOENDRC(IERROR, bap24_sign);

 bap24_sign_end:

  if (k) { pbcext_element_Fr_free(k); k = NULL; }
  if (t) { pbcext_element_Fr_free(t); t = NULL; }
  if (e) { pbcext_element_GT_free(e); e = NULL; }
  if (aux_c) { free(aux_c); aux_c = NULL; }
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
