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
#include <limits.h>

#include "scsl25.h"
#include "groupsig/scsl25/grp_key.h"
#include "groupsig/scsl25/mem_key.h"
#include "groupsig/scsl25/signature.h"
#include "shim/hash.h"
#include "crypto/prf.h"
#include "sys/mem.h"

static int _scsl25_compute_seq(scsl25_mem_key_t *memkey,
			     scsl25_seqinfo_t *seq,
			     unsigned int state) {

  hash_t *hc;
  byte_t *xi, *xi1, *ni1;
  uint64_t len, i;
  unsigned int state1;
  int rc;

  if (!memkey || !seq) {
    LOG_EINVAL(&logger, __FILE__, "_scsl25_compute_seq", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  xi = xi1 = ni1 = NULL;
  hc = NULL;

  /* Compute seq3 = PRF(y,state) */
  seq->seq3 = NULL;
  if (prf_compute(&seq->seq3, &seq->len3,
		  memkey->y, (byte_t*) &state, sizeof(unsigned int)) == IERROR)
    GOTOENDRC(IERROR, _scsl25_compute_seq);
  
  /* Compute x_i = PRF(k',state) */
  if (prf_compute(&xi, &len, memkey->yy, seq->seq3, seq->len3) == IERROR)
    GOTOENDRC(IERROR, _scsl25_compute_seq);
  
  /* seq1 = Hash(x_i) */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _scsl25_compute_seq);
  if(hash_update(hc, xi, len) == IERROR) GOTOENDRC(IERROR, _scsl25_compute_seq);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _scsl25_compute_seq);
  if (!(seq->seq1 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
    GOTOENDRC(IERROR, _scsl25_compute_seq);
  memcpy(seq->seq1, hc->hash, hc->length);
  seq->len1 = hc->length;
  hash_free(hc); hc = NULL;

  /* Compute x_{i-1} = PRF(k',PRF(k,state-1)) */
  ni1 = NULL; xi1 = NULL;
  if (state >= 1) {


    /* Recompute n_{i-1} = PRF(k,state-1) */
    state1 = state - 1;
    if (prf_compute(&ni1, &len, memkey->y,
		    (byte_t*) &state1, sizeof(unsigned int)) == IERROR)
      GOTOENDRC(IERROR, _scsl25_compute_seq);
  
    if (prf_compute(&xi1, &len, memkey->yy, ni1, len) == IERROR)
      GOTOENDRC(IERROR, _scsl25_compute_seq);

    /* seq2 = Hash(x_i \xor x_{i-1}) */
    for (i=0; i<len; i++) xi[i] = xi[i] ^ xi1[i];
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _scsl25_compute_seq);
    if(hash_update(hc, xi, len) == IERROR) GOTOENDRC(IERROR, _scsl25_compute_seq);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _scsl25_compute_seq);
    if (!(seq->seq2 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
      GOTOENDRC(IERROR, _scsl25_compute_seq);
    memcpy(seq->seq2, hc->hash, hc->length);
    seq->len2 = hc->length;
    hash_free(hc); hc = NULL;
    
  } else {
    seq->seq2 = NULL;
    seq->len2 = 0;
  }

 _scsl25_compute_seq_end:

  if (hc) { hash_free(hc); hc = NULL; }
  if (xi) { mem_free(xi); xi = NULL; }
  if (xi1) { mem_free(xi1); xi1 = NULL; }
  if (ni1) { mem_free(ni1); ni1 = NULL; }
    
  return rc;

}

/* Public functions */

/* 公开接口：生成 SCSL25 签名 */
int scsl25_sign(groupsig_signature_t *sig,
     message_t *msg,
     groupsig_key_t *memkey, 
     groupsig_key_t *grpkey,
     unsigned int state) {

  pbcext_element_G1_t  *hscp;
  pbcext_element_G1_t *s1, *s2, *s3;
  pbcext_element_Fr_t *r,*r1,*r2,*r3,*nr2,*x[4];
  pbcext_element_G1_t *y[4], *g[5] ; // 用于 SPK 接口适配
  scsl25_signature_t *scsl25_sig;
  scsl25_grp_key_t *scsl25_grpkey;
  scsl25_mem_key_t *scsl25_memkey;
  scsl25_seqinfo_t *seq;
  hash_t *hc;
  char *msg_msg, *msg_scp;
  uint16_t i[6][2], prods[4];
  int rc;

  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_SCSL25_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  scsl25_sig = sig->sig;
  scsl25_grpkey = grpkey->key;
  scsl25_memkey = memkey->key;
  rc = IOK;

  r = r1 = r2 = r3 = NULL;
  hscp = NULL;
  msg_msg = msg_scp = NULL;
  seq = NULL; hc = NULL;

  /* 解析消息内容与范围标识 scp */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR) GOTOENDRC(IERROR, scsl25_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR) GOTOENDRC(IERROR, scsl25_sign);
  
  /* 随机数 r \in Z_n */
  if(!(r = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_Fr_random(r) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

  if(!(r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_Fr_random(r1) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

  if(!(r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_Fr_random(r2) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

  if(!(nr2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_Fr_neg(nr2,r2) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

  if(!(r3 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_Fr_random(r3) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

  /* 1. 生成假名 psd = Hash(scp)^e */
  scsl25_sig->psd = pbcext_element_G1_init();
  hscp = pbcext_element_G1_init();
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_sign);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);


  if(pbcext_element_G1_mul(scsl25_sig->psd, hscp, scsl25_memkey->e) == IERROR) GOTOENDRC(IERROR, scsl25_sign); 

  /* 2. 生成签名主体 w1 = g^r, w2 = v * Y^r */
  if(!(scsl25_sig->w1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_G1_mul(scsl25_sig->w1, scsl25_grpkey->g, r) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

  if(!(scsl25_sig->w2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_G1_mul(scsl25_sig->w2, scsl25_grpkey->Y, r) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
  if(pbcext_element_G1_add(scsl25_sig->w2, scsl25_memkey->v, scsl25_sig->w2) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

  
 
/* --- y 数组：声明 (需根据验证等式变形) --- */
/* 注意：spk_rep 验证 y = g^x * h^r。对于验证式 s1 = g1^c * w2^(t1-c2^L) * Y^-t2 */
/* 我们需要把已知的 c 幂项移到等式左边作为 y */
/* --- y 数组：公开声明 (Knowns) --- */
if(!(s1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
if(!(s2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
if(!(s3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
/* 计算 s1 = w2^r1 * (Y^-1)^-r2 */
pbcext_element_G1_t *tmp1, *tmp2;
if(!(tmp1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
if(!(tmp2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
if( pbcext_element_G1_mul(tmp1, scsl25_sig->w2, r1) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
if( pbcext_element_G1_mul(tmp2, scsl25_grpkey->Y, nr2) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
if( pbcext_element_G1_add(s1, tmp1, tmp2) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

if( pbcext_element_G1_mul(tmp1, scsl25_sig->w1, r1) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
if (pbcext_element_G1_mul(tmp2, scsl25_grpkey->g, nr2) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
if( pbcext_element_G1_add(s2, tmp1, tmp2) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

if( pbcext_element_G1_mul(s3, scsl25_grpkey->g, r3) == IERROR) GOTOENDRC(IERROR, scsl25_sign);


/* --- 计算挑战值 c --- */
byte_t *b = NULL;
uint64_t len;

if (!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, scsl25_sign);

/* 按照图片 (3) 顺序压入 G1 元素 */
pbcext_element_G1_t *elements_to_hash[] = {
    scsl25_grpkey->g, scsl25_grpkey->g1, scsl25_grpkey->Y, 
    scsl25_sig->w1, scsl25_sig->w2, s1, s2, s3, scsl25_sig->psd
};

for (int j = 0; j < 9; j++) {
    b = NULL;
    if (pbcext_element_G1_to_bytes(&b, &len, elements_to_hash[j]) == IERROR)
        GOTOENDRC(IERROR, scsl25_sign);
    if (hash_update(hc, b, len) == IERROR) {
        mem_free(b); GOTOENDRC(IERROR, scsl25_sign);
    }
    mem_free(b); b = NULL;
}

/* 压入消息 m_i */
if (hash_update(hc, (byte_t *) msg_msg, strlen(msg_msg)) == IERROR) 
    GOTOENDRC(IERROR, scsl25_sign);

if (hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, scsl25_sign);

/* 将哈希结果转换为 Fr 类型的 challenge c */
if (!(scsl25_sig->c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
pbcext_element_Fr_from_hash(scsl25_sig->c, hc->hash, hc->length);



//calculate t1, t2, t3
if (!(scsl25_sig->t1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
if (!(scsl25_sig->t2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
if (!(scsl25_sig->t3 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
pbcext_element_Fr_t *ftmp1,  *r2_, *_r2, *r2_r1;
pbcext_element_G1_t *ftmp2;
if(!(ftmp1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
if(!(ftmp2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
if(!(r2_ = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
if(!(_r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
if(!(r2_r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);

pbcext_element_Fr_set2(ftmp1,scsl25_grpkey->lambda1);
pbcext_element_Fr_sub(ftmp1,scsl25_memkey->x,ftmp1);
pbcext_element_Fr_mul(ftmp1,scsl25_sig->c,ftmp1);
pbcext_element_Fr_sub(scsl25_sig->t1,r1,ftmp1);

pbcext_element_Fr_mul(ftmp1, scsl25_sig->c, scsl25_memkey->x);
pbcext_element_Fr_mul(ftmp1, ftmp1, r);
pbcext_element_Fr_sub(scsl25_sig->t2, r2, ftmp1);

pbcext_element_Fr_mul(ftmp1, scsl25_sig->c, r);
pbcext_element_Fr_sub(scsl25_sig->t3, r3, ftmp1);
/////////////////////////////////////////////////////
// pbcext_element_Fr_t *ftttmp1,*ftttmp2;
// pbcext_element_G1_t *tttmp1,*tttmp2,*tttmp3;
// //calculate s2
// if(!(ftttmp1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(ftttmp2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// pbcext_element_Fr_neg(ftttmp1,scsl25_sig->t2);
// pbcext_element_G1_mul(tttmp1,scsl25_grpkey->g,ftttmp1);

// pbcext_element_Fr_neg(ftttmp1,scsl25_sig->c);
// pbcext_element_Fr_set2(ftttmp2,scsl25_grpkey->lambda1);
// pbcext_element_Fr_mul(ftttmp2,scsl25_sig->c,ftttmp2);
// pbcext_element_Fr_sub(ftttmp1,scsl25_sig->t1,ftttmp2);
// pbcext_element_G1_mul(tttmp2,scsl25_sig->w1,ftttmp1);
// pbcext_element_G1_add(tttmp3,tttmp1,tttmp2);


// if(pbcext_element_G1_cmp(s2,tttmp3)==0)
// {
//   printf("Equal!");
// }
// else
// {
//   printf("Not equal!");
// }

// pbcext_element_Fr_t *ftttmp1,*ftttmp2;
// pbcext_element_G1_t *tttmp1,*tttmp2,*tttmp3;
// //calculate s2
// if(!(ftttmp1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(ftttmp2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// pbcext_element_Fr_neg(ftttmp1,scsl25_sig->t2);
// pbcext_element_G1_mul(tttmp1,scsl25_grpkey->g,ftttmp1);

// pbcext_element_Fr_neg(ftttmp1,scsl25_sig->c);
// pbcext_element_Fr_set2(ftttmp2,scsl25_grpkey->lambda1);
// pbcext_element_Fr_mul(ftttmp2,scsl25_sig->c,ftttmp2);
// pbcext_element_Fr_sub(ftttmp1,scsl25_sig->t1,ftttmp2);
// pbcext_element_G1_mul(tttmp2,scsl25_sig->w1,ftttmp1);
// pbcext_element_G1_add(tttmp3,tttmp1,tttmp2);


// if(pbcext_element_G1_cmp(s2,tttmp3)==0)
// {
//   printf("Equal!");
// }
// else
// {
//   printf("Not equal!");
// }


// pbcext_element_G1_t *tttmp1,*tttmp2,*tttmp3;
// //calculate s3
// if(!(tttmp1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// if(!(tttmp3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_sign);
// pbcext_element_G1_mul(tttmp1,scsl25_sig->w1,scsl25_sig->c);
// pbcext_element_G1_mul(tttmp2,scsl25_grpkey->g,scsl25_sig->t3);
// pbcext_element_G1_add(tttmp3,tttmp1,tttmp2); 
// if(pbcext_element_G1_cmp(s3,tttmp3)==0)
// {
//   printf("Equal!");
// }
// else
// {
//   printf("Not equal!");
// }
/////////////////////////////////////////////////////
int64_t zero = 0;
pbcext_element_Fr_set2(ftmp1,zero);
pbcext_element_G1_random(ftmp2);
//pbcext_element_G1_set(ftmp2,scsl25_grpkey->g);
pbcext_element_G1_mul(ftmp2,ftmp2,ftmp1);



/* 3. 生成知识证明 pi_sigma (此处简化为 SPK 逻辑) */
// To generate r2'

pbcext_element_Fr_set(r2_,scsl25_memkey->x);
pbcext_element_Fr_mul(r2_,r2_,r);
pbcext_element_Fr_neg(_r2,r2_);

//pbcext_element_Fr_div(r2_r1,r2_,scsl25_memkey->x);
pbcext_element_Fr_set(r2_r1,r);
if(!(scsl25_sig->pi = spk_rep_init(4))) GOTOENDRC(IERROR, scsl25_sign);



y[0] = scsl25_sig->psd;

y[1] = scsl25_grpkey->g1;

y[2] = ftmp2;

y[3] = scsl25_sig->w1;



/* --- g 数组：生成元 (Base points) --- */
g[0] = scsl25_sig->w2;      /* w2 */
g[1] = scsl25_grpkey->Y;    /* Y */
g[2] = scsl25_sig->w1;      /* w1 */
g[3] = scsl25_grpkey->g;    /* g */
g[4] = hscp;    /* hscp */



/* --- x 数组：秘密值 (Randomness/Witnesses) --- */
/* 注意：SPK 证明的是原始随机数 r1, r2, r3 的知识 */
x[0] = scsl25_memkey->e;  /* e  */
x[1] = scsl25_memkey->x;  /* r1'  */ 
x[2] = _r2; /* -r2'  */
x[3] = r2_r1; /* r2'/r1' */

/* --- 5. i 数组：[映射序列][秘密x索引, 基点g索引] --- */

/* 等式 1 (psd): y[0] = g[4]^x[0] */
i[0][0] = 0; i[0][1] = 4; // e, hscp

/* 等式 2 (g1): y[1] = g[0]^x[1] * g[1]^x[2] */
i[1][0] = 1; i[1][1] = 0; // r1', w2
i[2][0] = 2; i[2][1] = 1; // -r2', Y

/* 等式 3 (1): y[2] = g[2]^x[1] * g[3]^x[2] */
i[3][0] = 1; i[3][1] = 2; // r1', w1
i[4][0] = 2; i[4][1] = 3; // -r2', g

/* 等式 4 (w1): y[3] = g[3]^x[3] */
/* 核心：证明 w1 = g^(r2'/r1') */
i[5][0] = 3; i[5][1] = 3; // r2'/r1', g

/* --- 6. prods 数组 --- */
prods[0] = 1; // y[0] 有 1 项
prods[1] = 2; // y[1] 有 2 项
prods[2] = 2; // y[2] 有 2 项
prods[3] = 1; // y[3] 有 1 项

//test equal
pbcext_element_G1_t *ttmp0;
pbcext_element_G1_t *ttmp1;

ttmp0 = pbcext_element_G1_init();
ttmp1 = pbcext_element_G1_init();

pbcext_element_G1_mul(ttmp0,g[4],x[0]);

if(pbcext_element_G1_cmp(ttmp0,y[0])==IERROR) GOTOENDRC(IERROR, scsl25_sign);


pbcext_element_G1_mul(ttmp0,g[0],x[1]);

pbcext_element_G1_mul(ttmp1,g[1],x[2]);

pbcext_element_G1_add(ttmp1,ttmp0,ttmp1);

if(pbcext_element_G1_cmp(ttmp1,y[1])==IERROR) {printf("Error!"); printf("Error!"); } // Wrong


pbcext_element_G1_mul(ttmp0,g[2],x[1]);

pbcext_element_G1_mul(ttmp1,g[3],x[2]);

pbcext_element_G1_add(ttmp1,ttmp0,ttmp1);

if(pbcext_element_G1_cmp(ttmp1,y[2])==IERROR) {printf("Error!"); printf("Error!"); } // works


pbcext_element_G1_mul(ttmp0,g[3],x[3]);

if(pbcext_element_G1_cmp(ttmp0,y[3])==IERROR) {printf("Error!"); printf("Error!"); }
//////////////////////////////////////////////////////////////////////
  /* 调用底层 libgroupsig 的 SPK 签名接口 */
  if(spk_rep_sign(scsl25_sig->pi,
                  y, 4,
                  g, 5,
                  x, 4,
                  i, 6,
                  prods,
                  (byte_t *) msg_msg, strlen(msg_msg)) == IERROR) {
    GOTOENDRC(IERROR, scsl25_sign);
  }

  /* 4. 计算顺序信息 seq */
  if(!(seq = (scsl25_seqinfo_t *) mem_malloc(sizeof(scsl25_seqinfo_t)))) GOTOENDRC(IERROR, scsl25_sign);
  if (_scsl25_compute_seq(scsl25_memkey, seq, state) == IERROR) GOTOENDRC(IERROR, scsl25_sign);
  scsl25_sig->seq = seq;

 scsl25_sign_end:
  if (hc) { hash_free(hc); hc = NULL; }
  if(r) { pbcext_element_Fr_free(r); r = NULL; }
  if(r1) { pbcext_element_Fr_free(r1); r1 = NULL; }
  if(r2) { pbcext_element_Fr_free(r2); r2 = NULL; }
  if(r3) { pbcext_element_Fr_free(r3); r3 = NULL; }
  if(ftmp1) { pbcext_element_Fr_free(ftmp1); ftmp1 = NULL; }
  if(ftmp2) { pbcext_element_G1_free(ftmp2); ftmp2 = NULL; }
  if(r2_) { pbcext_element_Fr_free(r2_); r2_ = NULL; }
  if(_r2) { pbcext_element_Fr_free(_r2); _r2 = NULL; }
  if(r2_r1) { pbcext_element_Fr_free(r2_r1); r2_r1 = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }
  if(s1) { pbcext_element_G1_free(s1); s1 = NULL; }
  if(s2) { pbcext_element_G1_free(s2); s2 = NULL; }
  if(s3) { pbcext_element_G1_free(s3); s3 = NULL; }
  if(tmp1) { pbcext_element_G1_free(tmp1); tmp1 = NULL; }
  if(tmp2) { pbcext_element_G1_free(tmp2); tmp2 = NULL; }
  if (rc == IERROR) {
    if(scsl25_sig->psd) { pbcext_element_G1_free(scsl25_sig->psd); scsl25_sig->psd = NULL; }
    if(scsl25_sig->w1) { pbcext_element_G1_free(scsl25_sig->w1); scsl25_sig->w1 = NULL; }
    if(scsl25_sig->w2) { pbcext_element_G1_free(scsl25_sig->w2); scsl25_sig->w2 = NULL; }
    if(scsl25_sig->pi) { spk_rep_free(scsl25_sig->pi); scsl25_sig->pi = NULL; }
  }
  return rc;
}

/* sign.c ends here */
