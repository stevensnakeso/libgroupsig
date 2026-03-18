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

int scsl25_verify_link(uint8_t *ok,
          groupsig_key_t *grpkey,
          groupsig_proof_t *proof,
          message_t *msg,
          groupsig_signature_t **sigs,
          message_t **msgs,
          uint32_t n) {
  
  pbcext_element_G1_t *hscp, *hscp_, *nym_;
  scsl25_signature_t *scsl25_sig;
  spk_dlog_t *spk;  
  hash_t *hc;
  char *msg_scp, *msg_msg;
  int rc;
  uint32_t i;
  uint8_t _ok;

  if(!ok || !proof || proof->scheme != GROUPSIG_SCSL25_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE ||
     !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_verify_link", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK; _ok = 0;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;
  
  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify_link);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify_link);
  /* RSA 轨道：乘法群初始化为单位元 1 */
  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, scsl25_verify_link);
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify_link);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, scsl25_verify_link);
  
  /* 遍历所有签名：验证单签名并累加假名和范围哈希 */
  for (i=0; i<n; i++ ) {

#ifndef PROFILE
    /* 验证单个群签名的有效性 */
    if (scsl25_verify(&_ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_link);

    if (!_ok)  GOTOENDRC(IOK, scsl25_verify_link);
#endif
    
    /* 提取范围标识并计算 Hash(scp) */
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_link);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_verify_link);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_link);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_verify_link);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;
    
    /* RSA 累加：hscp_ = \prod H(scp_i) */
    if(pbcext_element_G1_add(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_link);

    /* 累加签名的假名分量：nym_ = \prod psd_i */
    scsl25_sig = (scsl25_signature_t *) sigs[i]->sig;
    if(pbcext_element_G1_add(nym_, nym_, scsl25_sig->psd) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_link);

  }

  /* 验证链接 SPK：证明 \prod psd_i 与 \prod H(scp_i) 具有相同的指数秘密 e */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, scsl25_verify_link);

  spk = ((scsl25_proof_t *) proof->proof)->spk;
  if(spk_dlog_G1_verify(&_ok, nym_, hscp_, spk, (byte_t *) msg_msg,
      strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, scsl25_verify_link);
 
 scsl25_verify_link_end:

  *ok = _ok;
    
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }  
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  return rc;

}

/* link.c ends here */
