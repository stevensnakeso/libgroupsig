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
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int scsl25_identify(uint8_t *ok,
      groupsig_proof_t **proof,
      groupsig_key_t *grpkey,
      groupsig_key_t *memkey,
      groupsig_signature_t *sig,
      message_t *msg) {
  
  pbcext_element_G1_t *hscp;
  scsl25_signature_t *scsl25_sig;
  scsl25_mem_key_t *scsl25_memkey;
  hash_t *hc;
  char *msg_scp;
  int rc;
  
  if(!ok ||
      !grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE ||
      !memkey || memkey->scheme != GROUPSIG_SCSL25_CODE ||
      !sig || sig->scheme != GROUPSIG_SCSL25_CODE ||
      !msg) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_identify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL;
  hc = NULL;
  msg_scp = NULL;
  
  scsl25_sig = sig->sig;
  scsl25_memkey = memkey->key;

  /* Recompute psd (Pseudonym) */
  
  /* 从消息中解析范围标识 scope (scp) */
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, scsl25_identify);

  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_identify);
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_identify);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, scsl25_identify);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_identify);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  /* 在 RSA 轨道上，psd = H(scp)^e mod n */
  /* 使用成员密钥中的秘密指数 e 进行重计 */
  if(pbcext_element_G1_mul(hscp, hscp, scsl25_memkey->e) == IERROR)
    GOTOENDRC(IERROR, scsl25_identify);
  
  /* 检查计算出的假名是否与签名中的 psd 一致 */
  if(pbcext_element_G1_cmp(hscp, scsl25_sig->psd)) {
    *ok = 0;
  } else {
    *ok = 1;
  }
    
 scsl25_identify_end:

  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  
  return rc;

}

/* identify.c ends here */
