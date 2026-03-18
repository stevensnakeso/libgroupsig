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
#include <errno.h>
#include <stdlib.h>


#include "scsl25.h"
#include "groupsig/scsl25/identity.h"
#include "groupsig/scsl25/grp_key.h"
#include "groupsig/scsl25/mem_key.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"

/**
 * SCSL25 Join 协议 Member (EV) 端实现
 * Seq 1: EV 生成秘密指数 e, x, 计算 U = g1^e mod n 并生成 pi_U
 * Seq 3: EV 接收凭证 v，验证 v^isk = U mod n 的正确性 (通过公钥 Y 验证)
 */
int scsl25_join_mem(message_t **mout,
          groupsig_key_t *memkey,
          int seq,
          message_t *min,
          groupsig_key_t *grpkey) {

  pbcext_element_G1_t *n, *U, *aux;
  scsl25_mem_key_t *scsl25_memkey;
  scsl25_mem_key_t *tmp_scsl25_memkey;
  groupsig_key_t *_scsl25_memkey;
  scsl25_grp_key_t *scsl25_grpkey;
  message_t *_mout;
  spk_rep_t *pi;
  byte_t *bn, *bmsg, *bU, *bpi, *bu ;
  uint64_t len, nlen, Ulen, pilen, ulen;
  int rc;

  if((seq != 1 && seq != 3) ||
     !min || !mout ||
     !memkey || memkey->scheme != GROUPSIG_SCSL25_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  pi = NULL; bn = bmsg = bU = bpi = bu = NULL;
  n = NULL; U = NULL; aux = NULL;
  _scsl25_memkey = tmp_scsl25_memkey = NULL;
  
  scsl25_memkey = (scsl25_mem_key_t *) memkey->key;
  scsl25_grpkey = (scsl25_grp_key_t *) grpkey->key;

  /* 第一步：EV 收到系统参数 n，生成秘密 (e, x, u, y) 并发送 U 和 pi_U */
  if (seq == 1) {

    if(!(n = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, scsl25_join_mem);
    if(pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);

    if(pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);

    /* 1. 生成秘密指数 e 和 x */
    if(!(scsl25_memkey->e = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, scsl25_join_mem);
    if(pbcext_element_Fr_random(scsl25_memkey->e) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);

    if(!(scsl25_memkey->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, scsl25_join_mem);
    if(pbcext_element_Fr_random(scsl25_memkey->x) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);

    /* 2. 计算 u = e * x 和 PRF 密钥y  */
    if(!(scsl25_memkey->u = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, scsl25_join_mem);
    if(pbcext_element_Fr_mul(scsl25_memkey->u, scsl25_memkey->e, scsl25_memkey->x) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);

    if(!(scsl25_memkey->y = prf_key_init()))
      GOTOENDRC(IERROR, scsl25_join_mem);
    if(!prf_key_init_random(scsl25_memkey->y))
      GOTOENDRC(IERROR, scsl25_join_mem);

    if(!(scsl25_memkey->yy = prf_key_init()))
      GOTOENDRC(IERROR, scsl25_join_mem);
    if(!prf_key_init_random(scsl25_memkey->yy))
      GOTOENDRC(IERROR, scsl25_join_mem);  

    /* 3. 计算注册公钥 U = g1^e mod n */
    if(!(scsl25_memkey->U = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, scsl25_join_mem);
    if(pbcext_element_G1_mul(scsl25_memkey->U,
           scsl25_grpkey->g1, scsl25_memkey->e) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);
    
    if(pbcext_element_G1_to_bytes(&bU, &Ulen, scsl25_memkey->U) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);


    /* 4. 生成知识证明 pi_U */
    // if(!(pi = spk_dlog_init())) GOTOENDRC(IERROR, scsl25_join_mem);
    // if(spk_dlog_G1_sign(pi, scsl25_memkey->U,
    //   scsl25_grpkey->g1, scsl25_memkey->e, bU, Ulen) == IERROR)
    //   GOTOENDRC(IERROR, scsl25_join_mem);

    /* --- 补充：g1^u = U^x 的 SPK 证明 --- */
    pbcext_element_G1_t *y[2], *g[2];
    pbcext_element_Fr_t *x[2];
    uint16_t i[2][2], prods[2];



    /* y 数组：公开声明 */
    y[0] = pbcext_element_G1_init();         
    y[1] = scsl25_memkey->U;       
    pbcext_element_G1_mul(y[0],scsl25_grpkey->g1,scsl25_memkey->u);    
    

    /* g 数组：基点 */
    g[0] = scsl25_memkey->U;         
    g[1] = scsl25_grpkey->g1;                 

    /* x_vals 数组：秘密值 */
    x[0] = scsl25_memkey->x;         
    x[1] = scsl25_memkey->e;                


    /* i 数组：索引映射 [秘密值索引][基点索引] */
    // 等式1: y[0] = g[0]^x_vals[0] (U = g1^e)
    i[0][0] = 0; i[0][1] = 0; 

    // 等式2: y[1] = g[0]^x_vals[1] * g[1]^x_vals[2] (1 = g1^-u * U^x)
    i[1][0] = 1; i[1][1] = 1; 


    prods[0] = 1; // 
    prods[1] = 1; // 

    /* 初始化并生成 pi_U */
    if(!(pi = spk_rep_init(2))) GOTOENDRC(IERROR, scsl25_join_mem);
    
    // 调用通用表示证明接口
    if(spk_rep_sign(pi, y, 2, g, 2, x, 2, i, 2, prods, bU, Ulen) == IERROR)
        GOTOENDRC(IERROR, scsl25_join_mem);


    pbcext_element_G1_free(y[0]);

    /* 打包输出消息: (u, U, pi_U) */
    if(bU){mem_free(bU); bU = NULL; Ulen = 0;}

    if(pbcext_dump_element_Fr_bytes(&bu, &ulen, scsl25_memkey->u) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);
    
    if(pbcext_dump_element_G1_bytes(&bU, &Ulen, scsl25_memkey->U) == IERROR) 
      GOTOENDRC(IERROR, scsl25_join_mem);
   
    // if(spk_dlog_export(&bpi, &pilen, pi) == IERROR)
    //   GOTOENDRC(IERROR, scsl25_join_mem);

    if(spk_rep_export(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mem);
    
    len = ulen + Ulen + pilen;
    if(!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, scsl25_join_mem);

    memcpy(bmsg, bu, ulen);
    memcpy(&bmsg[ulen], bU, Ulen);
    memcpy(&bmsg[ulen+Ulen], bpi, pilen);
    
    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len))) GOTOENDRC(IERROR, scsl25_join_mem);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR) GOTOENDRC(IERROR, scsl25_join_mem);
    }
    
  } else {

    /* 第三步：EV 接收来自 TA 的凭证 v，验证并更新 memkey */

    /* 导入包含 v 的部分 memkey */
    _scsl25_memkey = scsl25_mem_key_import(min->bytes, min->length);

    if(!_scsl25_memkey) GOTOENDRC(IERROR, scsl25_join_mem);

    tmp_scsl25_memkey = _scsl25_memkey->key;

    /* 验证凭证正确性：检查 v^isk = U mod n -> 即检查 v = U^(1/isk) */
    if(!(scsl25_memkey->v = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_join_mem);
    if(pbcext_element_G1_set(scsl25_memkey->v, tmp_scsl25_memkey->v) == IERROR) {GOTOENDRC(IERROR, scsl25_join_mem); rc = IERROR;}
    
    if(!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_join_mem);

    /* 验证：v^isk = U  => 对应本地验证 Y 对 v 的约束 */

    if(pbcext_element_G1_mul(aux, tmp_scsl25_memkey->v, scsl25_memkey->u) == IERROR) /* 底层调用公共验证 */
       GOTOENDRC(IERROR, scsl25_join_mem);

    if(pbcext_element_G1_cmp(scsl25_memkey->U,aux) == IERROR) {GOTOENDRC(IERROR, scsl25_join_mem); rc = IERROR;}

    rc = IOK;

  }

 scsl25_join_mem_end:
  
  if(bn) { mem_free(bn); bn = NULL; }
  if(bmsg) { mem_free(bmsg); bmsg = NULL; }
  if(bpi) { mem_free(bpi); bpi = NULL; }
  if(bU) { mem_free(bU); bU = NULL; }  
  if(bu) { mem_free(bu); bu = NULL; }  
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(n) { pbcext_element_G1_free(n); n = NULL; }
    if(tmp_scsl25_memkey) {
    mem_free(tmp_scsl25_memkey);
    tmp_scsl25_memkey = NULL;
  }

  if(_scsl25_memkey) {
    mem_free(_scsl25_memkey);
    _scsl25_memkey = NULL;
  }

  //if(pi) { spk_dlog_free(pi); pi = NULL; }
  if(pi) { spk_rep_free(pi); pi = NULL; }
  return rc;

}

/* join.c ends here */// /snap/bin/valgrind --leak-check=full --track-origins=yes ./build/bin/SCSL25Test

