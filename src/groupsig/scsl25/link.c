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
#include "scsl25.h"
#include "groupsig/scsl25/grp_key.h"
#include "groupsig/scsl25/mem_key.h"
#include "groupsig/scsl25/signature.h"
#include "groupsig/scsl25/identity.h"
#include "groupsig/scsl25/proof.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int scsl25_link(groupsig_proof_t **proof,
     groupsig_key_t *grpkey,
     groupsig_key_t *memkey,
     message_t *msg,
     groupsig_signature_t **sigs,
     message_t **msgs,
     uint32_t n) {

  pbcext_element_G1_t *hscp, *hscp_, *nym_;
  scsl25_signature_t *scsl25_sig;
  scsl25_mem_key_t *scsl25_memkey;
  spk_dlog_t *spk;
  hash_t *hc;
  char *msg_scp, *msg_msg;
  int rc;
  uint32_t i;
  uint8_t ok;

  if(!proof ||
     !grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE ||
     !memkey || memkey->scheme != GROUPSIG_SCSL25_CODE ||
     !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_link", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;

  scsl25_memkey = memkey->key;

  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_link);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_link);

  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, scsl25_link);
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_link);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, scsl25_link);

  /* 遍历所有签名，验证、识别并计算批量的范围哈希累加值 */
  for (i=0; i<n; i++ ) {

    /* 验证签名有效性 */
    if (scsl25_verify(&ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, scsl25_link);
    if (!ok) GOTOENDRC(IFAIL, scsl25_link);

    /* 识别该签名是否由指定的 memkey 签发 */
    if (scsl25_identify(&ok, NULL, grpkey, memkey, sigs[i], msgs[i]) == IERROR)
      GOTOENDRC(IERROR, scsl25_link);

    if (!ok) {
      GOTOENDRC(IFAIL, scsl25_link);
    }

    /* 提取范围标识并计算 Hash(scp) */
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, scsl25_link);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_link);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, scsl25_link);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_link);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;

    /* 累加（在 RSA 乘法群下为乘法）: hscp_ = \prod H(scp_i) */ //？？？
    if(pbcext_element_G1_mul(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, scsl25_link);

  }

  /* nym_ = hscp_^e (使用 memkey 中的秘密指数 e) */
  if(pbcext_element_G1_mul(nym_, hscp_, scsl25_memkey->e) == IERROR)
    GOTOENDRC(IERROR, scsl25_link);

  /* 生成链接性 SPK 证明 */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, scsl25_link);

  spk = ((scsl25_proof_t *)(*proof)->proof)->spk;

  /* 证明 nym_ 以 hscp_ 为基底的离散对数是秘密指数 e */
  if(spk_dlog_G1_sign(spk, nym_, hscp_, scsl25_memkey->e, (byte_t *) msg_msg,
          strlen(msg_msg)) == IERROR) GOTOENDRC(IERROR, scsl25_link);

 scsl25_link_end:

  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  return rc;

}
/* link.c ends here */
