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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "bap24.h"
#include "groupsig/bap24/signature.h"

groupsig_signature_t* bap24_signature_init() {

  groupsig_signature_t *sig;
  bap24_signature_t *bap24_sig;

  bap24_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bap24_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(bap24_sig = (bap24_signature_t *) mem_malloc(sizeof(bap24_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bap24_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_BAP24_CODE;
  sig->sig = bap24_sig;

  return sig;

}

int bap24_signature_free(groupsig_signature_t *sig) {

  bap24_signature_t *bap24_sig;

  if(!sig || sig->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bap24_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    bap24_sig = sig->sig;
    if(bap24_sig->sigma1) {
      pbcext_element_G1_free(bap24_sig->sigma1);
      bap24_sig->sigma1 = NULL;
    }
    if(bap24_sig->sigma2) {
      pbcext_element_G1_free(bap24_sig->sigma2);
      bap24_sig->sigma2 = NULL;
    }
    if(bap24_sig->c) {
      pbcext_element_Fr_free(bap24_sig->c);
      bap24_sig->c = NULL;
    }
    if(bap24_sig->s) {
      pbcext_element_Fr_free(bap24_sig->s);
      bap24_sig->s = NULL;
    }
    if(bap24_sig->z_zeta1){
      pbcext_element_Fr_free(bap24_sig->z_zeta1);
      bap24_sig->z_zeta1 = NULL;
    }
    if(bap24_sig->z_zeta2){
      pbcext_element_Fr_free(bap24_sig->z_zeta2);
      bap24_sig->z_zeta2 = NULL;
    }
    if(bap24_sig->z_theta1){
      pbcext_element_Fr_free(bap24_sig->z_theta1);
      bap24_sig->z_theta1 = NULL;
    }
    if(bap24_sig->z_theta2){
      pbcext_element_Fr_free(bap24_sig->z_theta2);
      bap24_sig->z_theta2 = NULL;
    }
    if(bap24_sig->z_sk){
      pbcext_element_Fr_free(bap24_sig->z_sk);
      bap24_sig->z_sk = NULL;
    }
    if(bap24_sig->z_uid){
      pbcext_element_Fr_free(bap24_sig->z_uid);
      bap24_sig->z_uid = NULL;
    }
    if(bap24_sig->z_w){
      pbcext_element_Fr_free(bap24_sig->z_w);
      bap24_sig->z_w = NULL;
    }
    if(bap24_sig->z_alpha){
      pbcext_element_Fr_free(bap24_sig->z_alpha);
      bap24_sig->z_alpha = NULL;
    }
    if(bap24_sig->B1){
      pbcext_element_G1_free(bap24_sig->B1);
      bap24_sig->B1 = NULL;
    }
    if(bap24_sig->B2){
      pbcext_element_G1_free(bap24_sig->B2);
      bap24_sig->B2 = NULL;
    }
    if(bap24_sig->hscp){
      pbcext_element_G2_free(bap24_sig->hscp);
      bap24_sig->hscp = NULL;
    }
    if(bap24_sig->cnym1){
      pbcext_element_G2_free(bap24_sig->cnym1);
      bap24_sig->cnym1 = NULL;
    }
    if(bap24_sig->cnym2){
      pbcext_element_GT_free(bap24_sig->cnym2);
      bap24_sig->cnym2 = NULL;
    }
    if(bap24_sig->D1){
      pbcext_element_G1_free(bap24_sig->D1);
      bap24_sig->D1 = NULL;
    }
    if(bap24_sig->D2){
      pbcext_element_G1_free(bap24_sig->D2);
      bap24_sig->D2 = NULL;
    }
    if(bap24_sig->D3){
      pbcext_element_GT_free(bap24_sig->D3);
      bap24_sig->D3 = NULL;
    }
    if(bap24_sig->D4){  
      pbcext_element_GT_free(bap24_sig->D4);
      bap24_sig->D4 = NULL;
    }
    if(bap24_sig->D5){
      pbcext_element_G2_free(bap24_sig->D5);
      bap24_sig->D5 = NULL;
    }
    if(bap24_sig->D6){
      pbcext_element_GT_free(bap24_sig->D6);
      bap24_sig->D6 = NULL;
    }
    mem_free(bap24_sig); bap24_sig = NULL;
  }
  
  mem_free(sig); sig = NULL;

  return IOK;

}

int bap24_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  bap24_signature_t *bap24_dst, *bap24_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_BAP24_CODE ||
     !src || src->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_dst = dst->sig;
  bap24_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(bap24_dst->sigma1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G1_set(bap24_dst->sigma1, bap24_src->sigma1) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->sigma2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);    
  if(pbcext_element_G1_set(bap24_dst->sigma2, bap24_src->sigma2) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);    
  if(pbcext_element_Fr_set(bap24_dst->c, bap24_src->c) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);  
  if(!(bap24_dst->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->s, bap24_src->s) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_zeta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_zeta1, bap24_src->z_zeta1) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_zeta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_zeta2, bap24_src->z_zeta2) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_theta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_theta1, bap24_src->z_theta1) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_theta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_theta2, bap24_src->z_theta2) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_sk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_sk, bap24_src->z_sk) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_uid = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_uid, bap24_src->z_uid) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_w = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_w, bap24_src->z_w) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->z_alpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_Fr_set(bap24_dst->z_alpha, bap24_src->z_alpha) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);  
  if(!(bap24_dst->B1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G1_set(bap24_dst->B1, bap24_src->B1) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->B2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G1_set(bap24_dst->B2, bap24_src->B2) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->hscp = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G2_set(bap24_dst->hscp, bap24_src->hscp) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->cnym1 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G2_set(bap24_dst->cnym1, bap24_src->cnym1) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->cnym2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_GT_set(bap24_dst->cnym2, bap24_src->cnym2) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->D1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G1_set(bap24_dst->D1, bap24_src->D1) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->D2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G1_set(bap24_dst->D2, bap24_src->D2) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->D3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_GT_set(bap24_dst->D3, bap24_src->D3) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->D4 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_GT_set(bap24_dst->D4, bap24_src->D4) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->D5 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_G2_set(bap24_dst->D5, bap24_src->D5) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(!(bap24_dst->D6 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_signature_copy);
  if(pbcext_element_GT_set(bap24_dst->D6, bap24_src->D6) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_copy);
 bap24_signature_copy_end:

  if(rc == IERROR) {
    if(bap24_dst->sigma1) {
      pbcext_element_G1_free(bap24_dst->sigma1);
      bap24_dst->sigma1 = NULL;
    }
    if(bap24_dst->sigma2) {
      pbcext_element_G1_free(bap24_dst->sigma2);
      bap24_dst->sigma2 = NULL;
    }
    if(bap24_dst->c) {
      pbcext_element_Fr_free(bap24_dst->c);
      bap24_dst->c = NULL;
    }
    if(bap24_dst->s) {
      pbcext_element_Fr_free(bap24_dst->s);
      bap24_dst->s = NULL;
    }
    if(bap24_dst->z_zeta1){
      pbcext_element_Fr_free(bap24_dst->z_zeta1);
      bap24_dst->z_zeta1 = NULL;
    }
    if(bap24_dst->z_zeta2){
      pbcext_element_Fr_free(bap24_dst->z_zeta2);
      bap24_dst->z_zeta2 = NULL;
    }
    if(bap24_dst->z_theta1){
      pbcext_element_Fr_free(bap24_dst->z_theta1);
      bap24_dst->z_theta1 = NULL;
    }
    if(bap24_dst->z_theta2){
      pbcext_element_Fr_free(bap24_dst->z_theta2);
      bap24_dst->z_theta2 = NULL;
    }
    if(bap24_dst->z_sk){
      pbcext_element_Fr_free(bap24_dst->z_sk);
      bap24_dst->z_sk = NULL;
    }
    if(bap24_dst->z_uid){
      pbcext_element_Fr_free(bap24_dst->z_uid);
      bap24_dst->z_uid = NULL;
    }
    if(bap24_dst->z_w){
      pbcext_element_Fr_free(bap24_dst->z_w);
      bap24_dst->z_w = NULL;
    }
    if(bap24_dst->z_alpha){
      pbcext_element_Fr_free(bap24_dst->z_alpha);
      bap24_dst->z_alpha = NULL;
    }
    if(bap24_dst->B1){
      pbcext_element_G1_free(bap24_dst->B1);
      bap24_dst->B1 = NULL;
    }
    if(bap24_dst->B2){
      pbcext_element_G1_free(bap24_dst->B2);
      bap24_dst->B2 = NULL;
    }
    if(bap24_dst->hscp){
      pbcext_element_G2_free(bap24_dst->hscp);
      bap24_dst->hscp = NULL;
    }
    if(bap24_dst->cnym1){
      pbcext_element_G2_free(bap24_dst->cnym1);
      bap24_dst->cnym1 = NULL;
    }
    if(bap24_dst->cnym2){
      pbcext_element_GT_free(bap24_dst->cnym2);
      bap24_dst->cnym2 = NULL;
    }
    if (bap24_dst->D1){
      pbcext_element_G1_free(bap24_dst->D1);
      bap24_dst->D1 = NULL;
    }
    if (bap24_dst->D2){
      pbcext_element_G1_free(bap24_dst->D2);
      bap24_dst->D2 = NULL;
    }
    if (bap24_dst->D3){
      pbcext_element_GT_free(bap24_dst->D3);
      bap24_dst->D3 = NULL;
    }
    if (bap24_dst->D4){
      pbcext_element_GT_free(bap24_dst->D4);
      bap24_dst->D4 = NULL;
    }
    if (bap24_dst->D5){
      pbcext_element_G2_free(bap24_dst->D5);
      bap24_dst->D5 = NULL;
    }
    if (bap24_dst->D6){
      pbcext_element_GT_free(bap24_dst->D6);
      bap24_dst->D6 = NULL;
    }
      mem_free(bap24_dst); bap24_dst = NULL;
  }
  
  return rc;

}

int bap24_signature_get_size(groupsig_signature_t *sig) {

  bap24_signature_t *bap24_sig;
  uint64_t size64, ssigma1, ssigma2, sc, ss, sz_zeta1, sz_zeta2, sz_theta1, sz_theta2, sz_sk, sz_uid, sz_w, sz_alpha, sB1, sB2, shscp, scnym1, scnym2, sD1, sD2, sD3, sD4, sD5, sD6;
  
  if(!sig || sig->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  bap24_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&ssigma1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&ssigma2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ss) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_zeta1) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_zeta2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_theta1) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_theta2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_sk) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_uid) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_w) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sz_alpha) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sB1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sB2) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&shscp) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&scnym1) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&scnym2) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&sD1) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&sD2) == IERROR) return -1;
  if (pbcext_element_GT_byte_size(&sD3) == IERROR) return -1;
  if (pbcext_element_GT_byte_size(&sD4) == IERROR) return -1;
  if (pbcext_element_G2_byte_size(&sD5) == IERROR) return -1;
  if (pbcext_element_GT_byte_size(&sD6) == IERROR) return -1;
  size64 = sizeof(uint8_t) + sizeof(int)*23 + ssigma1 + ssigma2 +  sc + ss + sz_zeta1 + sz_zeta2 + sz_theta1 + sz_theta2 + sz_sk + sz_uid + sz_w + sz_alpha + sB1 + sB2 + shscp + scnym1 + scnym2 + sD1 + sD2 + sD3 + sD4 + sD5 + sD6;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int bap24_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *sig) {

  bap24_signature_t *bap24_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  uint8_t code;
  
  if(!sig || sig->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  bap24_sig = sig->sig;

  if ((_size = bap24_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
  /* Dump GROUPSIG_BAP24_CODE */
  code = GROUPSIG_BAP24_CODE;
  _bytes[ctr++] = code;

  /* Dump sigma1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_sig->sigma1) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;  

  /* Dump sigma2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_sig->sigma2) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;  

  /* Dump c */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->c) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump s */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->s) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len; 
  
  /* Dump zeta1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_zeta1) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump zeta2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_zeta2) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump theta1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_theta1) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump theta2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_theta2) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump sk */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_sk) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump uid */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_uid) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump w */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_w) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump alpha */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_sig->z_alpha) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump B1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_sig->B1) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump B2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_sig->B2) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump hscp */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_sig->hscp) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump cnym1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_sig->cnym1) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump cnym2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, bap24_sig->cnym2) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump D1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_sig->D1) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump D2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_sig->D2) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len; 

  /* Dump D3 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, bap24_sig->D3) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump D4 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, bap24_sig->D4) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump D5 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_sig->D5) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;

  /* Dump D6 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, bap24_sig->D6) == IERROR) 
    GOTOENDRC(IERROR, bap24_signature_export);
  ctr += len;


  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_signature_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, bap24_signature_export);
  }
  
  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = ctr;  

 bap24_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;  

}

groupsig_signature_t* bap24_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  bap24_signature_t *bap24_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "bap24_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = bap24_signature_init())) {
    return NULL;
  }
  
  bap24_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, bap24_signature_import);
  }

  /* Get sigma1 */
  if(!(bap24_sig->sigma1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G1_bytes(bap24_sig->sigma1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get sigma2 */
  if(!(bap24_sig->sigma2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G1_bytes(bap24_sig->sigma2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;  

  /* Get c */
  if(!(bap24_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get s */
  if(!(bap24_sig->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get zeta1 */
  if(!(bap24_sig->z_zeta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_zeta1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get zeta2 */
  if(!(bap24_sig->z_zeta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_zeta2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get theta1 */
  if(!(bap24_sig->z_theta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_theta1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get theta2 */
  if(!(bap24_sig->z_theta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_theta2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get sk */
  if(!(bap24_sig->z_sk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_sk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get uid */
  if(!(bap24_sig->z_uid = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_uid, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get w */
  if(!(bap24_sig->z_w = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_w, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get alpha */
  if(!(bap24_sig->z_alpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_Fr_bytes(bap24_sig->z_alpha, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get B1 */
  if(!(bap24_sig->B1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G1_bytes(bap24_sig->B1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get B2 */
  if(!(bap24_sig->B2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G1_bytes(bap24_sig->B2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get hscp */
  if(!(bap24_sig->hscp = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G2_bytes(bap24_sig->hscp, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get cnym1 */
  if(!(bap24_sig->cnym1 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G2_bytes(bap24_sig->cnym1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get cnym2 */
  if(!(bap24_sig->cnym2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_GT_bytes(bap24_sig->cnym2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get D1 */
  if(!(bap24_sig->D1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G1_bytes(bap24_sig->D1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len; 

  /* Get D2 */
  if(!(bap24_sig->D2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G1_bytes(bap24_sig->D2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get D3 */
  if(!(bap24_sig->D3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_GT_bytes(bap24_sig->D3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get D4 */
  if(!(bap24_sig->D4 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_GT_bytes(bap24_sig->D4, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get D5 */
  if(!(bap24_sig->D5 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_G2_bytes(bap24_sig->D5, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

  /* Get D6 */
  if(!(bap24_sig->D6 = pbcext_element_GT_init())) 
    GOTOENDRC(IERROR, bap24_signature_import);
  if(pbcext_get_element_GT_bytes(bap24_sig->D6, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_signature_import);
  ctr += len;

 bap24_signature_import_end:

  if(rc == IERROR && sig) { bap24_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* bap24_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(bap24_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;
}

/* signature.c ends here */
