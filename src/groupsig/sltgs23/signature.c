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
#include "sltgs23.h"
#include "groupsig/sltgs23/signature.h"

/* Public functions */
groupsig_signature_t* sltgs23_signature_init() {

  groupsig_signature_t *sig;
  sltgs23_signature_t *sltgs23_sig;

  sltgs23_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sltgs23_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(sltgs23_sig = (sltgs23_signature_t *) mem_malloc(sizeof(sltgs23_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sltgs23_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_SLTGS23_CODE;
  sig->sig = sltgs23_sig;

  return sig;

}

int sltgs23_signature_free(groupsig_signature_t *sig) {

  sltgs23_signature_t *sltgs23_sig;

  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sltgs23_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    sltgs23_sig = sig->sig;
    if(sltgs23_sig->T1) { pbcext_element_G1_free(sltgs23_sig->T1); sltgs23_sig->T1 = NULL; }
    if(sltgs23_sig->T2) { pbcext_element_G1_free(sltgs23_sig->T2); sltgs23_sig->T2 = NULL; }
    if(sltgs23_sig->T3) { pbcext_element_G1_free(sltgs23_sig->T3); sltgs23_sig->T3 = NULL; }
    if(sltgs23_sig->c) { pbcext_element_Fr_free(sltgs23_sig->c); sltgs23_sig->c = NULL; }
    if(sltgs23_sig->salpha) { pbcext_element_Fr_free(sltgs23_sig->salpha); sltgs23_sig->salpha = NULL; }
    if(sltgs23_sig->sbeta) { pbcext_element_Fr_free(sltgs23_sig->sbeta); sltgs23_sig->sbeta = NULL; }
    if(sltgs23_sig->sx) { pbcext_element_Fr_free(sltgs23_sig->sx); sltgs23_sig->sx = NULL; }
    if(sltgs23_sig->sdelta1) { pbcext_element_Fr_free(sltgs23_sig->sdelta1); sltgs23_sig->sdelta1 = NULL; }
    if(sltgs23_sig->sdelta2) { pbcext_element_Fr_free(sltgs23_sig->sdelta2); sltgs23_sig->sdelta2 = NULL; }
    mem_free(sltgs23_sig); sltgs23_sig = NULL;
  }
  
  mem_free(sig); sig = NULL;

  return IOK;

}

int sltgs23_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  sltgs23_signature_t *sltgs23_dst, *sltgs23_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_SLTGS23_CODE ||
     !src || src->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_dst = dst->sig;
  sltgs23_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(sltgs23_dst->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_G1_set(sltgs23_dst->T1, sltgs23_src->T1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(!(sltgs23_dst->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);    
  if(pbcext_element_G1_set(sltgs23_dst->T2, sltgs23_src->T2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(!(sltgs23_dst->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_G1_set(sltgs23_dst->T3, sltgs23_src->T3) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);  
  if(!(sltgs23_dst->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);    
  if(pbcext_element_Fr_set(sltgs23_dst->c, sltgs23_src->c) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);  
  if(!(sltgs23_dst->salpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->salpha, sltgs23_src->salpha) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);  
  if(!(sltgs23_dst->sbeta = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);    
  if(pbcext_element_Fr_set(sltgs23_dst->sbeta, sltgs23_src->sbeta) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);  
  if(!(sltgs23_dst->sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);    
  if(pbcext_element_Fr_set(sltgs23_dst->sx, sltgs23_src->sx) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);  
  if(!(sltgs23_dst->sdelta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);    
  if(pbcext_element_Fr_set(sltgs23_dst->sdelta1, sltgs23_src->sdelta1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);  
  if(!(sltgs23_dst->sdelta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);    
  if(pbcext_element_Fr_set(sltgs23_dst->sdelta2, sltgs23_src->sdelta2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);  

 sltgs23_signature_copy_end:

  if(rc == IERROR) {
    if(sltgs23_dst->T1) { pbcext_element_G1_free(sltgs23_dst->T1); sltgs23_dst->T1 = NULL; }
    if(sltgs23_dst->T2) { pbcext_element_G1_free(sltgs23_dst->T2); sltgs23_dst->T2 = NULL; }
    if(sltgs23_dst->T3) { pbcext_element_G1_free(sltgs23_dst->T3); sltgs23_dst->T3 = NULL; }
    if(sltgs23_dst->c) { pbcext_element_Fr_free(sltgs23_dst->c); sltgs23_dst->c = NULL; }
    if(sltgs23_dst->salpha) { pbcext_element_Fr_free(sltgs23_dst->salpha); sltgs23_dst->salpha = NULL; }
    if(sltgs23_dst->sbeta) { pbcext_element_Fr_free(sltgs23_dst->sbeta); sltgs23_dst->sbeta = NULL; }
    if(sltgs23_dst->sx) { pbcext_element_Fr_free(sltgs23_dst->sx); sltgs23_dst->sx = NULL; }
    if(sltgs23_dst->sdelta1) { pbcext_element_Fr_free(sltgs23_dst->sdelta1); sltgs23_dst->sdelta1 = NULL; }
    if(sltgs23_dst->sdelta2) { pbcext_element_Fr_free(sltgs23_dst->sdelta2); sltgs23_dst->sdelta2 = NULL; }
  }
  
  return rc;

}

int sltgs23_signature_get_size(groupsig_signature_t *sig) {

  sltgs23_signature_t *sltgs23_sig;
  uint64_t size64, sT1, sT2, sT3, sc, ssalpha, ssbeta, ssx, ssdelta1, ssdelta2;
  
  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  sltgs23_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&sT1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sT2) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sT3) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssalpha) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssbeta) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssx) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssdelta1) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssdelta2) == IERROR) return -1;
      
  size64 = sizeof(uint8_t)+sizeof(int)*9+
    sT1 + sT2 + sT3 + sc + ssalpha + ssbeta + ssx + ssdelta1 + ssdelta2;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int sltgs23_signature_export(byte_t **bytes,
			   uint32_t *size,
			   groupsig_signature_t *sig) {

  sltgs23_signature_t *sltgs23_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  uint8_t code;
  
  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  sltgs23_sig = sig->sig;

  if ((_size = sltgs23_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
  /* Dump GROUPSIG_SLTGS23_CODE */
  code = GROUPSIG_SLTGS23_CODE;
  _bytes[ctr++] = code;

  /* Dump T1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_sig->T1) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;  

  /* Dump T2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_sig->T2) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;  

  /* Dump T3 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_sig->T3) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;  

  /* Dump c */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->c) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;

  /* Dump salpha */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->salpha) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;  

  /* Dump sbeta */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->sbeta) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;

  /* Dump sx */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->sx) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;

  /* Dump sdelta1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->sdelta1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;

  /* Dump sdelta2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->sdelta2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_export);
  ctr += len;

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_signature_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_signature_export);
  }

  *size = ctr;  

 sltgs23_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;  

}

groupsig_signature_t* sltgs23_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  sltgs23_signature_t *sltgs23_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = sltgs23_signature_init())) {
    return NULL;
  }
  
  sltgs23_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_signature_import);
  }

  /* Get T1 */
  if(!(sltgs23_sig->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_G1_bytes(sltgs23_sig->T1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get T2 */
  if(!(sltgs23_sig->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_G1_bytes(sltgs23_sig->T2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;  

  /* Get T3 */
  if(!(sltgs23_sig->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_G1_bytes(sltgs23_sig->T3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get c */
  if(!(sltgs23_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get salpha */
  if(!(sltgs23_sig->salpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->salpha, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get sbeta */
  if(!(sltgs23_sig->sbeta = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->sbeta, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get sx */
  if(!(sltgs23_sig->sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->sx, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get sdelta1 */
  if(!(sltgs23_sig->sdelta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->sdelta1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get sdelta2 */
  if(!(sltgs23_sig->sdelta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->sdelta2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

 sltgs23_signature_import_end:

  if(rc == IERROR && sig) { sltgs23_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* sltgs23_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(sltgs23_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1); // master had unsigned...
  mem_free(bytes); bytes = NULL;

  return str;
}

/* signature.c ends here */
