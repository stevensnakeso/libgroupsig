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
#include "groupsig/scsl25/grp_key.h"
#include "groupsig/scsl25/mgr_key.h"
#include "groupsig/scsl25/mem_key.h"
#include "groupsig/scsl25/identity.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"

int scsl25_get_joinseq(uint8_t *seq) {
  *seq = SCSL25_JOIN_SEQ;
  return IOK;
}

int scsl25_get_joinstart(uint8_t *start) {
  *start = SCSL25_JOIN_START;
  return IOK;
}

/**
 * SCSL25 Join 协议 Manager 端实现
 * Seq 0: Manager 发送挑战或初始化参数
 * Seq 2: Manager 接收 U 和 pi_U，验证并签发 v = U^(1/isk) mod n
 */
int scsl25_join_mgr(message_t **mout,
      gml_t *gml,
      groupsig_key_t *mgrkey,
      int seq,
      message_t *min,
      groupsig_key_t *grpkey) {
  pbcext_element_Fr_t *u, *inv_u;
  pbcext_element_G1_t  *U;
  pbcext_element_G1_t *n;
  scsl25_mem_key_t *scsl25_memkey;
  scsl25_grp_key_t *scsl25_grpkey;
  scsl25_mgr_key_t *scsl25_mgrkey;
  groupsig_key_t *memkey;
  message_t *_mout;
  spk_rep_t *spk;
  byte_t *bn, *bkey, *bu,*bU ;
  uint64_t len, _len;
  uint32_t size;
  int rc;
  uint8_t ok;
  
  if((seq != 0 && seq != 2) ||
     !mout ||
     !mgrkey || mgrkey->scheme != GROUPSIG_SCSL25_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  bn = bkey = bU = bu = NULL;

  n = NULL;
  u = NULL;
  U = NULL;
  inv_u = NULL;
  memkey = NULL;
  spk = NULL;
  
  scsl25_grpkey = (scsl25_grp_key_t *) grpkey->key;
  scsl25_mgrkey = (scsl25_mgr_key_t *) mgrkey->key;

  /* 第一步：Manager 发送系统参数或 nonce (对应原方案中的初始化交互) */
  if (seq == 0) {
    
    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_join_mgr);
    /* 在 RSA 轨道上，直接从公钥中获取 n */
    if(pbcext_element_G1_set(n, scsl25_grpkey->n) == IERROR) GOTOENDRC(IERROR, scsl25_join_mgr);
    
    if(pbcext_dump_element_G1_bytes(&bn, &len, n) == IERROR) 
      GOTOENDRC(IERROR, scsl25_join_mgr);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bn, len))) {
        GOTOENDRC(IERROR, scsl25_join_mgr);
      }
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bn, len) == IERROR)
        GOTOENDRC(IERROR, scsl25_join_mgr);
    }      
             
  } else {

    /* 第二步：Manager 接收来自 EV 的 (u, U, pi_U)，验证并签发凭证 */

    if(!(u = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_join_mgr);
    if(pbcext_get_element_Fr_bytes(u, &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mgr);
    
    /* 获取 EV 发送的注册公钥 U */
    if(!(U = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_join_mgr);
    if(pbcext_get_element_G1_bytes(U, &_len, min->bytes + len) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mgr);
    
    /* 导入零知识证明 pi_U */
    // if(!(spk = spk_dlog_import(min->bytes + len + _len, &len)))
    //   GOTOENDRC(IERROR, scsl25_join_mgr);
    if(!(spk = spk_rep_import(min->bytes + len + _len, &len)))
      GOTOENDRC(IERROR, scsl25_join_mgr);

    /* 验证证明：证明 EV 知道 U 对应的私钥指数 e 且在合法区间内 */
    if(pbcext_element_G1_to_bytes(&bU, &len, U) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mgr);
    
    pbcext_element_G1_t *y[2], *g[2];

    uint16_t i[2][2], prods[2];



    /* y 数组：公开声明 */
    y[0] = pbcext_element_G1_init();         
    y[1] = U;       
    pbcext_element_G1_mul(y[0],scsl25_grpkey->g1,u);    
    

    /* g 数组：基点 */
    g[0] = U;         
    g[1] = scsl25_grpkey->g1;              

    i[0][0] = 0; i[0][1] = 0; 
    i[1][0] = 1; i[1][1] = 1; 


    prods[0] = 1; // 
    prods[1] = 1; // 

    if(spk_rep_verify(&ok, y, 2, g, 2, i, 2, prods, 
                    spk, bU, len) == IERROR) {
    rc = IERROR;
    pbcext_element_G1_free(y[0]);
  }

    // if(spk_dlog_G1_verify(&ok, U, scsl25_grpkey->g1,
    //     spk, bU, len) == IERROR) {
    //   GOTOENDRC(IERROR, scsl25_join_mgr);
    // }

    if(!ok) GOTOENDRC(IERROR, scsl25_join_mgr);

    /* 签发成员凭证：计算 v = U^(1/u) mod n */
    if(!(memkey = scsl25_mem_key_init())) GOTOENDRC(IERROR, scsl25_join_mgr);
    scsl25_memkey = memkey->key;

    if(!(scsl25_memkey->v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, scsl25_join_mgr);

    
    if(!(inv_u = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_join_mgr);
    if(pbcext_element_Fr_inv(inv_u,u) == IERROR)  GOTOENDRC(IERROR,scsl25_join_mgr);

    if(pbcext_element_G1_mul(scsl25_memkey->v, U, inv_u) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mgr);

    //tmp check it works
    // pbcext_element_G1_t *tmp_aux;
    // tmp_aux = pbcext_element_G1_init();
    // pbcext_element_G1_mul(tmp_aux,scsl25_memkey->v,u);
    //Original memkey->U
    // if(pbcext_element_G1_cmp(U,tmp_aux) == IOK) {printf("Test Passed!");} else {printf("Test Failed!"); GOTOENDRC(IERROR,scsl25_join_mgr);}

    /* 此时 memkey 包含 A=v，导出并发送给 EV */
    bkey = NULL; 
    if (scsl25_mem_key_export(&bkey, &size, memkey) == IERROR)
      GOTOENDRC(IERROR, scsl25_join_mgr);

    if(!*mout) {
      if(!(_mout = message_from_bytes(bkey, size)))
        GOTOENDRC(IERROR, scsl25_join_mgr);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(_mout, bkey, size) == IERROR)
        GOTOENDRC(IERROR, scsl25_join_mgr);
    }    
    
  }
  
 scsl25_join_mgr_end:

  if (memkey) { scsl25_mem_key_free(memkey); memkey = NULL; }
  //if (spk) { spk_dlog_free(spk); spk = NULL; }
  if (spk) { spk_rep_free(spk); spk = NULL; }
  if (u) { pbcext_element_Fr_free(u); u = NULL; }
  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (U) { pbcext_element_G1_free(U); U = NULL; }
  if (bn) { mem_free(bn); bn = NULL; } 
  if (bU) { mem_free(bU); bU = NULL; }   
  if (bu) { mem_free(bu); bu = NULL; }      
  if (inv_u) { pbcext_element_Fr_free(inv_u); inv_u = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
