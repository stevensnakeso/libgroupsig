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
#include "sys/mem.h"
#include "scsl25.h"
#include "groupsig/scsl25/grp_key.h"
#include "groupsig/scsl25/mem_key.h"
#include "groupsig/scsl25/signature.h"
#include "groupsig/scsl25/identity.h"
#include "groupsig/scsl25/proof.h"
#include "shim/hash.h"
#include "misc/misc.h"

/* 内部函数：验证序列证据链的完整性 */
static int _scsl25_verify_sequence(uint8_t *ok,
            scsl25_proof_t *proof,
            groupsig_signature_t **sigs) {

  scsl25_signature_t *scsl25_sig;
  hash_t *hc;
  byte_t *aux;
  uint64_t n;
  uint32_t i, j;
  int rc;

  if (!proof || !sigs || !proof->n) {
    LOG_EINVAL(&logger, __FILE__, "_scsl25_verify_sequence",
         __LINE__, LOGERROR);
    return IERROR; 
  }

  rc = IOK;
  n = proof->n;
  aux = NULL; hc = NULL;

  /* 验证第一个签名的 seq1 = Hash(x[0]) */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _scsl25_verify_sequence);
  if(hash_update(hc, proof->x[0], proof->xlen[0]) == IERROR)
    GOTOENDRC(IERROR, _scsl25_verify_sequence);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _scsl25_verify_sequence);
  scsl25_sig = sigs[0]->sig;

  if(memcmp(hc->hash, scsl25_sig->seq->seq1, scsl25_sig->seq->len1)) {
    *ok = 0;
    GOTOENDRC(IOK, _scsl25_verify_sequence);
  }
  hash_free(hc); hc = NULL;
  
  /* 遍历后续签名，验证 seq1 (当前状态) 和 seq2 (链接状态) */
  for (i=1; i<n; i++) {

    scsl25_sig = sigs[i]->sig;

    /* 校验 sig[i]->seq1 = Hash(x[i]) */
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _scsl25_verify_sequence);
    if(hash_update(hc, proof->x[i], proof->xlen[i]) == IERROR)
      GOTOENDRC(IERROR, _scsl25_verify_sequence);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _scsl25_verify_sequence);

    if(memcmp(hc->hash, scsl25_sig->seq->seq1, scsl25_sig->seq->len1)) {
      *ok = 0;
      GOTOENDRC(IOK, _scsl25_verify_sequence);
    }
    hash_free(hc); hc = NULL;

    /* 校验 sig[i]->seq2 = Hash(x[i] ^ x[i-1]) */
    if(!(aux = (byte_t *) mem_malloc(sizeof(byte_t)*proof->xlen[i]))) {
      GOTOENDRC(IERROR, _scsl25_verify_sequence);
    }
    
    /* 执行异或操作重建链接种子 */
    for(j=0; j<proof->xlen[i]; j++) { aux[j] = proof->x[i-1][j] ^ proof->x[i][j]; }
    
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _scsl25_verify_sequence);
    if(hash_update(hc, aux, proof->xlen[i]) == IERROR)
      GOTOENDRC(IERROR, _scsl25_verify_sequence);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _scsl25_verify_sequence);
    
    if(memcmp(hc->hash, scsl25_sig->seq->seq2, scsl25_sig->seq->len2)) {
      *ok = 0;
      GOTOENDRC(IOK, _scsl25_verify_sequence);
    }
    hash_free(hc); hc = NULL;
    mem_free(aux); aux = NULL;

  }

  *ok = 1;

 _scsl25_verify_sequence_end:
  if (hc) { hash_free(hc); hc = NULL; }
  if (aux) { mem_free(aux); aux = NULL; }
  return rc;
}

/* 公开接口：验证包含顺序证据的完整链接证明 */
int scsl25_verify_seqlink(uint8_t *ok,
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
    LOG_EINVAL(&logger, __FILE__, "scsl25_verify_seqlink", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK; _ok = 0;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;
  
  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify_seqlink);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify_seqlink);
  /* RSA 轨道初始化：乘法单位元 1 */
  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, scsl25_verify_seqlink);//?
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify_seqlink);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, scsl25_verify_seqlink); //?

  /* 1. 验证签名有效性并累加假名与范围哈希 */
  for (i=0; i<n; i++ ) {

    if (scsl25_verify(&_ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_seqlink);
    if (!_ok)  GOTOENDRC(IOK, scsl25_verify_seqlink);
      
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_seqlink);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_verify_seqlink);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_seqlink);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_verify_seqlink);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;
    
    if(pbcext_element_G1_add(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_seqlink);

    scsl25_sig = (scsl25_signature_t *) sigs[i]->sig;
    if(pbcext_element_G1_add(nym_, nym_, scsl25_sig->psd) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_seqlink);
  }

  /* 2. 验证链接性 SPK */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, scsl25_verify_seqlink);

  spk = ((scsl25_proof_t *) proof->proof)->spk;
  if(spk_dlog_G1_verify(&_ok, nym_, hscp_, spk, (byte_t *) msg_msg,
      strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, scsl25_verify_seqlink);

  if (!_ok) GOTOENDRC(IOK, scsl25_verify_seqlink);

  /* 3. 验证序列证据链 */
  if (_scsl25_verify_sequence(&_ok, proof->proof, sigs) == IERROR)
      GOTOENDRC(IERROR, scsl25_verify_seqlink);

 scsl25_verify_seqlink_end:
  *ok = _ok;
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }  
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  return rc;
}

/* link.c ends here */
