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

/* 内部函数：计算顺序证明分量 x[i] = PRF(y, seq3[i]) */
static int _scsl25_compute_sequence(scsl25_proof_t *proof,
             scsl25_mem_key_t *memkey,
             groupsig_signature_t **sigs) {

  scsl25_signature_t *scsl25_sig;
  byte_t **xi;
  uint64_t len, *xilen, n;
  uint32_t i;
  int rc;

  if (!proof || !memkey || !sigs || !proof->n) {
    LOG_EINVAL(&logger, __FILE__, "_scsl25_compute_sequence",
         __LINE__, LOGERROR);
    return IERROR; 
  }

  rc = IOK;
  n = proof->n;
  
  if (!(xi = (byte_t **) mem_malloc(sizeof(byte_t *)*n))) {
    return IERROR;
  }

  memset(xi, 0, n*sizeof(byte_t *));
  if (!(xilen = (uint64_t *) mem_malloc(sizeof(uint64_t)*n))) {
    if (xi) mem_free(xi);
    return IERROR;
  }

  /* 在 SCSL25 中，x[i] 是利用成员 PRF 密钥 y 对签名中的序列种子 seq3 进行重计算得到的证据 */
  for (i=0; i<n; i++) {
    scsl25_sig = sigs[i]->sig;
    if(prf_compute(&xi[i], &len, memkey->y,
       scsl25_sig->seq->seq3,
       scsl25_sig->seq->len3) == IERROR) {
      
      GOTOENDRC(IERROR, _scsl25_compute_sequence);
    }
    xilen[i] = len;
  }

  proof->x = xi;
  proof->xlen = xilen;
  proof->n = n;

 _scsl25_compute_sequence_end:

  if (rc == IERROR) {
    if (xi) {
      for (i=0; i<n; i++) { if (xi[i]) { mem_free(xi[i]); xi[i] = NULL; } }
      mem_free(xi); xi = NULL;
    }
    if (xilen) { mem_free(xilen); xilen = NULL; }
  }

  return rc;
  
}

/* 公开接口：生成带有顺序证明的链接证明 */
int scsl25_seqlink(groupsig_proof_t **proof,
        groupsig_key_t *grpkey,
        groupsig_key_t *memkey,
        message_t *msg,
        groupsig_signature_t **sigs,
        message_t **msgs,
        uint32_t n) {
  
  pbcext_element_G1_t *hscp, *hscp_, *nym_;
  scsl25_signature_t *scsl25_sig;
  scsl25_mem_key_t *scsl25_memkey;
  groupsig_proof_t *_proof;
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
    LOG_EINVAL(&logger, __FILE__, "scsl25_seqlink", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL; _proof = NULL;
  msg_scp = NULL; msg_msg = NULL;
  
  scsl25_memkey = memkey->key;

  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_seqlink);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_seqlink);
  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, scsl25_seqlink);
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_seqlink);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, scsl25_seqlink);

  /* 遍历签名：验证有效性、识别身份并累加范围哈希 */
  for (i=0; i<n; i++ ) {

    if (scsl25_verify(&ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, scsl25_seqlink);
    if (!ok) GOTOENDRC(IFAIL, scsl25_seqlink);

    if (scsl25_identify(&ok, NULL, grpkey, memkey, sigs[i], msgs[i]) == IERROR)
      GOTOENDRC(IERROR, scsl25_seqlink);
    
    if (!ok) {
      GOTOENDRC(IFAIL, scsl25_seqlink);
    }
    
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, scsl25_seqlink);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_seqlink);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, scsl25_seqlink);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_seqlink);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;
    
    /* RSA 轨道累加：hscp_ = \prod H(scp_i) */
    if(pbcext_element_G1_add(hscp_, hscp_, hscp) == IERROR) //??? mul -> add
      GOTOENDRC(IERROR, scsl25_seqlink);

  }

  /* 1. 计算批量假名：nym_ = hscp_^e */
  if(pbcext_element_G1_mul(nym_, hscp_, scsl25_memkey->e) == IERROR)
    GOTOENDRC(IERROR, scsl25_seqlink);

  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, scsl25_seqlink);  

  /* 2. 初始化并计算链接证明 (SPK) */
  if(!(_proof = scsl25_proof_init())) GOTOENDRC(IERROR, scsl25_seqlink);
  spk = ((scsl25_proof_t *) _proof->proof)->spk;
  if(spk_dlog_G1_sign(spk, nym_, hscp_, scsl25_memkey->e, (byte_t *) msg_msg,
          strlen(msg_msg)) == IERROR) GOTOENDRC(IERROR, scsl25_seqlink);

  ((scsl25_proof_t *) _proof->proof)->n = n;

  /* 3. 计算顺序证明链 */
  if(_scsl25_compute_sequence(_proof->proof,
               scsl25_memkey,
               sigs) == IERROR)
    GOTOENDRC(IERROR, scsl25_seqlink);

  /* 将生成的证明拷贝至输出参数 */
  if (!*proof) {
    *proof = _proof;
  } else {
    if (scsl25_proof_copy(*proof, _proof) == IERROR)
      GOTOENDRC(IERROR, scsl25_seqlink);
    scsl25_proof_free(_proof); _proof = NULL;
  }
  
 scsl25_seqlink_end:

  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }  
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(rc == IERROR && _proof) { groupsig_proof_free(_proof); _proof = NULL; }
  
  return rc;

}
/* seqlink.c ends here */
