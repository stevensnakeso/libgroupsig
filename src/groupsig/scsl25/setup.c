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
#include <math.h>

#include "scsl25.h"
#include "groupsig/scsl25/grp_key.h"
#include "groupsig/scsl25/mgr_key.h"
#include "sys/mem.h"


int scsl25_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }
  
  return IOK;

}

int scsl25_clear() {
  return IOK;  
}

int scsl25_setup(groupsig_key_t *grpkey,
      groupsig_key_t *mgrkey,
      gml_t *gml) {

  scsl25_grp_key_t *gkey;
  scsl25_mgr_key_t *mkey;
  int rc, status;

  if(!grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;

  /* 1. 生成 RSA 分量：p 和 q (管理密钥) */
  if(!(mkey->p = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_setup);
  if(pbcext_element_G1_random(mkey->p) == IERROR)
    GOTOENDRC(IERROR,scsl25_setup);

  if(!(mkey->q = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_setup);
  if(pbcext_element_G1_random(mkey->q) == IERROR)
    GOTOENDRC(IERROR,scsl25_setup);

  if(!(gkey->n = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_setup);
  if(pbcext_element_G1_random(gkey->n) == IERROR)
    GOTOENDRC(IERROR,scsl25_setup);
  
  /* 注意：此处假设 pbcext_element_RSA_gen 生成 p, q 并计算出 n */
  if(pbcext_element_G1_add(mkey->p, mkey->q, gkey->n) == IERROR) //not used 
    GOTOENDRC(IERROR, scsl25_setup);

  /* 2. 初始化 TA 私钥 isk (Manager key) */
  if(!(mkey->isk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_setup);
  if(pbcext_element_Fr_random(mkey->isk) == IERROR)
    GOTOENDRC(IERROR, scsl25_setup);

  /* 3. 初始化组公钥参数 (Group key) */
  
  /* 生成随机元 g, g1 */
  if(!(gkey->g = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_setup);
  if(pbcext_element_G1_random(gkey->g) == IERROR)
    GOTOENDRC(IERROR, scsl25_setup);

  if(!(gkey->g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_setup);
  if(pbcext_element_G1_random(gkey->g1) == IERROR)
    GOTOENDRC(IERROR, scsl25_setup);

  /* 4. 计算 TA 公钥 Y = g^isk mod n */
  if(!(gkey->Y = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_setup);
  if(pbcext_element_G1_mul(gkey->Y, gkey->g, mkey->isk) == IERROR)
    GOTOENDRC(IERROR, scsl25_setup);

  /* 5. 设置默认安全参数 */
  gkey->lambda = 1024; //????
  gkey->lambda1 = 256; ///？？？？
  gkey->lambda2 = 80;

scsl25_setup_end:

  if (rc == IERROR) {
    /* 失败时清理所有已分配的内存，保留安全内存管理风格 */
    if (mkey->isk) { pbcext_element_Fr_free(mkey->isk); mkey->isk = NULL; }
    if (mkey->p) { pbcext_element_G1_free(mkey->p); mkey->p = NULL; }
    if (mkey->q) { pbcext_element_G1_free(mkey->q); mkey->q = NULL; }
    if (gkey->n) { pbcext_element_G1_free(gkey->n); gkey->n = NULL; }
    if (gkey->g) { pbcext_element_G1_free(gkey->g); gkey->g = NULL; }
    if (gkey->g1) { pbcext_element_G1_free(gkey->g1); gkey->g1 = NULL; }
    if (gkey->Y) { pbcext_element_G1_free(gkey->Y); gkey->Y = NULL; }
  }

  return rc;

}

/* setup.c ends here */
