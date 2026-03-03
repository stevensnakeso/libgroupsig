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

#include "scsl25.h"
#include "groupsig/scsl25/grp_key.h"
#include "groupsig/scsl25/signature.h"
#include "shim/hash.h"
#include "sys/mem.h"

static int _scsl25_verify_spk(uint8_t *ok,
             scsl25_signature_t *scsl25_sig,
             pbcext_element_G1_t *hscp,
             char *msg,
             scsl25_grp_key_t *scsl25_grpkey) {

  /* y 包含 4 个声明，g 包含 5 个基点，i 包含 6 个映射 */
  pbcext_element_G1_t *y[4], *g[5];
  uint16_t i[6][2], prods[4];
  int rc = IOK;

  /* 初始化数组和临时基点 */
  for(int j=0; j<4; j++) y[j] = NULL;


  /* --- 1. 重构 y 数组 (公开声明) --- */
  
  /* y0: psd (直接对应 H(scp)^e) */
  y[0] = scsl25_sig->psd;

  /* y1: g1 (对应 w2^r1' * Y^-r2' 的验证) */
  y[1] = scsl25_grpkey->g1;

  /* y2: 1 (单位元，对应 w1^r1' * g^-r2' = 1) */
  
  

  pbcext_element_G1_t *ftmp2;
  pbcext_element_Fr_t *ftmp1;
  int64_t zero = 0;
  ftmp2 = pbcext_element_G1_init();
  ftmp1 = pbcext_element_Fr_init();
  pbcext_element_Fr_set2(ftmp1,zero);
  pbcext_element_G1_random(ftmp2);
  //pbcext_element_G1_set(ftmp2, scsl25_grpkey->g);
  pbcext_element_G1_mul(ftmp2,ftmp2,ftmp1);
  
  y[2] = ftmp2;
  /* y3: w1 */
  y[3] = scsl25_sig->w1;
  

  /* --- 2. 重构 g 数组 (生成元) --- */
  g[0] = scsl25_sig->w2;
  g[1] = scsl25_grpkey->Y; // 使用 Y，配合 x 数组中的 -r2'
  g[2] = scsl25_sig->w1;
  g[3] = scsl25_grpkey->g;
  g[4] = hscp;

  /* --- 3. 重构 i 映射 (必须与签名端完全一致) --- */
  /* i[映射序号][秘密索引, 基点索引] */
  i[0][0] = 0; i[0][1] = 4; // y0 = hscp^e
  i[1][0] = 1; i[1][1] = 0; // y1 包含 w2^r1'
  i[2][0] = 2; i[2][1] = 1; // y1 包含 Y^-r2' (x2 = -r2')
  i[3][0] = 1; i[3][1] = 2; // y2 包含 w1^r1'
  i[4][0] = 2; i[4][1] = 3; // y2 包含 g^-r2'
  i[5][0] = 3; i[5][1] = 3; // y3 = g^x3 (x3 = r2'/r1')

              


  prods[0] = 1; prods[1] = 2; prods[2] = 2; prods[3] = 1;

  /* --- 4. 调用 SPK 验证 --- */
  if(spk_rep_verify(ok, y, 4, g, 5, i, 6, prods, 
                    scsl25_sig->pi, (byte_t *) msg, strlen(msg)) == IERROR) {
    rc = IERROR;
  }

  /* 清理资源 */
  // if(y[1]) pbcext_element_G1_free(y[1]);
  if(y[2]) { pbcext_element_G1_free(y[2]); y[2] = NULL;}
  // if(y[3]) pbcext_element_G1_free(y[3]);
  if(ftmp1) { pbcext_element_Fr_free(ftmp1); ftmp1 = NULL; }
  //if(ftmp2) { pbcext_element_G1_free(ftmp2); ftmp2 = NULL; }


  return rc;
}

/* 公开接口：验证 SCSL25 签名 */
int scsl25_verify(uint8_t *ok,
       groupsig_signature_t *sig,
       message_t *msg,
       groupsig_key_t *grpkey) {
  
  pbcext_element_G1_t *hscp, *aux_w1, *aux_w2;
  pbcext_element_G1_t *s1, *s2, *s3,*tmp1, *tmp2;
  pbcext_element_Fr_t *c_, *ftmp1,*ftmp2;
  scsl25_signature_t *scsl25_sig;
  scsl25_grp_key_t *scsl25_grpkey;
  hash_t *hc;
  char *msg_msg, *msg_scp;
  int rc;
  
  if(!ok || !sig || !msg || 
     !grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  msg_msg = NULL; msg_scp = NULL;
  hc = NULL;
  hscp = NULL;
  aux_w1 = aux_w2 = NULL;
  
  scsl25_sig = sig->sig;
  scsl25_grpkey = grpkey->key;

  /* 解析消息内容与范围标识 scp */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, scsl25_verify);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, scsl25_verify);
  


  /* 重新计算范围哈希 hscp = Hash(scp) */
  hscp = pbcext_element_G1_init();
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_verify);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, scsl25_verify);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_verify);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
  //calculate s1, s2, s3 and c. update message at last to calculate hash
  if(!(s1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify);
  if(!(s2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify);
  if(!(s3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify);
  if(!(tmp1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify);
  if(!(tmp2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_verify);
  if(!(ftmp1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_verify);
  if(!(ftmp2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_verify);
  if(!(c_ = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_verify);
  
  //calculate s1
  pbcext_element_G1_mul(tmp1,scsl25_grpkey->g1,scsl25_sig->c); // tmp1 = g1^c

  pbcext_element_Fr_set2(ftmp1,scsl25_grpkey->lambda1); // ftmp1 
  pbcext_element_Fr_mul(ftmp1,ftmp1,scsl25_sig->c);
  pbcext_element_Fr_sub(ftmp1,scsl25_sig->t1,ftmp1);
  pbcext_element_G1_mul(tmp2,scsl25_sig->w2,ftmp1);//Y??

  
  pbcext_element_G1_add(s1,tmp1,tmp2); //tmp1 == s1
  pbcext_element_Fr_neg(ftmp2,scsl25_sig->t2);//-t2
  pbcext_element_G1_mul(tmp1,scsl25_grpkey->Y,ftmp2);
  pbcext_element_G1_add(s1,s1,tmp1); //tmp1 == s1

  //calculate s2
  pbcext_element_G1_mul(tmp1,scsl25_sig->w1,ftmp1);//left
  pbcext_element_G1_mul(tmp2,scsl25_grpkey->g,ftmp2);
  pbcext_element_G1_add(s2,tmp1,tmp2);
  
  //calculate s3
  pbcext_element_G1_mul(tmp1,scsl25_sig->w1,scsl25_sig->c);
  pbcext_element_G1_mul(tmp2,scsl25_grpkey->g,scsl25_sig->t3);
  pbcext_element_G1_add(s3,tmp1,tmp2);

  //calculate c^
  /* 按照图片 (3) 顺序压入 G1 元素 */

  /* --- 计算挑战值 c --- */
byte_t *b = NULL;
uint64_t len;

if (!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_verify);
  pbcext_element_G1_t *elements_to_hash[] = {
    scsl25_grpkey->g, scsl25_grpkey->g1, scsl25_grpkey->Y, 
    scsl25_sig->w1, scsl25_sig->w2, s1, s2, s3, scsl25_sig->psd
};
for (int j = 0; j < 9; j++) {
    b = NULL;
    if (pbcext_element_G1_to_bytes(&b, &len, elements_to_hash[j]) == IERROR)
        GOTOENDRC(IERROR, scsl25_verify);
    if (hash_update(hc, b, len) == IERROR) {
        mem_free(b); GOTOENDRC(IERROR, scsl25_verify);
    }
    mem_free(b); b = NULL;
}


if (hash_update(hc, (byte_t *) msg_msg, strlen(msg_msg)) == IERROR) 
    GOTOENDRC(IERROR, scsl25_verify);

if (hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_verify);


pbcext_element_Fr_from_hash(c_, hc->hash, hc->length);

if(pbcext_element_Fr_cmp(c_, scsl25_sig->c)==0) {
    *ok = 1;
  } else {
    *ok = 0;
  }


  /* 调用内部 SPK 验证函数 */
  if(_scsl25_verify_spk(ok, scsl25_sig, hscp, msg_msg, scsl25_grpkey) == IERROR)
    GOTOENDRC(IERROR, scsl25_verify);
  
 scsl25_verify_end:
  
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(aux_w1) { pbcext_element_G1_free(aux_w1); aux_w1 = NULL; }
  if(aux_w2) { pbcext_element_G1_free(aux_w2); aux_w2 = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  
  return rc;

}
/* verify.c ends here */
