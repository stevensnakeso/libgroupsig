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

#include "types.h"
#include "sysenv.h"
#include "bigz.h"
#include "sys/mem.h"
#include "bap24.h"
#include "groupsig/bap24/grp_key.h"
#include "groupsig/bap24/mem_key.h"
#include "groupsig/bap24/signature.h"
// #include "groupsig/bap24/identity.h"
#include "groupsig/bap24/proof.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int bap24_link(groupsig_proof_t **proof,
     groupsig_key_t *grpkey,
     groupsig_key_t *memkey,
     message_t *msg,
     groupsig_signature_t **sigs,
     message_t **msgs,
     uint32_t n) {

  pbcext_element_G2_t *hscp, *hscp_, *nym_;
  bap24_signature_t *bap24_sig;
  bap24_mem_key_t *bap24_memkey;
  spk_dlog_t *spk;
  hash_t *hc;
  char *msg_scp, *msg_msg;
  int rc;
  uint32_t i;
  uint8_t ok;
  uint64_t index = 0;
  if(!proof ||
     !grpkey || grpkey->scheme != GROUPSIG_BAP24_CODE ||
     !memkey || memkey->scheme != GROUPSIG_BAP24_CODE ||
     !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "bap24_link", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;

  bap24_memkey = memkey->key;

  if(!(hscp = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_link);
  if(!(hscp_ = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_link);

  if(pbcext_element_G2_clear(hscp_) == IERROR) GOTOENDRC(IERROR, bap24_link);
  if(!(nym_ = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_link);
  if(pbcext_element_G2_clear(nym_) == IERROR) GOTOENDRC(IERROR, bap24_link);

  /* 遍历所有签名，验证、识别并计算批量的范围哈希累加值 */
  for (i=0; i<n; i++ ) {

    /* 验证签名有效性 */
    if (bap24_verify(&ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, bap24_link);
    if (!ok) GOTOENDRC(IFAIL, bap24_link);

    

    if (!ok) {
      GOTOENDRC(IFAIL, bap24_link);
    }

    /* 提取范围标识并计算 Hash(scp) */
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, bap24_link);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bap24_link);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, bap24_link);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, bap24_link);
    pbcext_element_G2_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;

    
    if(pbcext_element_G2_add(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, bap24_link);

  }

  /* nym_ = hscp_^e (使用 memkey 中的秘密指数 e) */
  if(pbcext_element_G2_mul(nym_, hscp_, bap24_memkey->sk) == IERROR)
    GOTOENDRC(IERROR, bap24_link);

  /* 生成链接性 SPK 证明 */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, bap24_link);

  spk = (bap24_proof_t *)((*proof)->proof);

  /* 证明 nym_ 以 hscp_ 为基底的离散对数是秘密指数 e */
  if(spk_dlog_G2_sign(spk, nym_, hscp_, bap24_memkey->sk, (byte_t *) msg_msg,
          strlen(msg_msg)) == IERROR) GOTOENDRC(IERROR, bap24_link);

 bap24_link_end:

  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G2_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G2_free(hscp_); hscp_ = NULL; }
  if(nym_) { pbcext_element_G2_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  return rc;

}
/* link.c ends here */
