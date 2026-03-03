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

#include "types.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/pbc_ext.h"
#include "groupsig/scsl25/identity.h"

identity_t* scsl25_identity_init() {

  identity_t *id;
  scsl25_identity_t *scsl25_id;

  if(!(id = (identity_t *) mem_malloc(sizeof(identity_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "scsl25_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* scsl25_identity_t 在 header 中定义为 pbcext_element_G1_t 指针 */
  if(!(scsl25_id = (scsl25_identity_t *) mem_malloc(sizeof(scsl25_identity_t)))) {
    mem_free(id); id = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "scsl25_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  id->scheme = GROUPSIG_SCSL25_CODE;
  id->id = scsl25_id;
  
  return id;

}

int scsl25_identity_free(identity_t *id) {

  scsl25_identity_t *scsl25_id;

  if(!id) {
    LOG_EINVAL_MSG(&logger, __FILE__, "scsl25_identity_free", __LINE__,
           "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(id->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_identity_free", __LINE__, LOGERROR);
    return IERROR;
  }

  scsl25_id = id->id;
  pbcext_element_G1_free(scsl25_id); scsl25_id = NULL;
  mem_free(id);

  return IOK;

}

int scsl25_identity_copy(identity_t *dst, identity_t *src) {

  scsl25_identity_t *scsl25_srcid, *scsl25_dstid;
  
  if(!dst || dst->scheme != GROUPSIG_SCSL25_CODE ||
     !src || src->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  scsl25_srcid = src->id;
  scsl25_dstid = dst->id;
  
  /* 如果目标 id 尚未初始化大数对象，则初始化 */

  if(!(scsl25_dstid = pbcext_element_G1_init())) return IERROR;


  if(pbcext_element_G1_set(scsl25_dstid, scsl25_srcid) == IERROR) return IERROR;
  
  return IOK;

}

uint8_t scsl25_identity_cmp(identity_t *id1, identity_t *id2) {

  scsl25_identity_t *scsl25_id1, *scsl25_id2;
  
  if(!id1 || !id2 || id1->scheme != id2->scheme || 
     id1->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_identity_cmp", __LINE__, LOGERROR);
    return UINT8_MAX; 
  }

  scsl25_id1 = id1->id;
  scsl25_id2 = id2->id;

  /* 返回 0 为相同 */
  return pbcext_element_G1_cmp(scsl25_id1, scsl25_id2);

}

char* scsl25_identity_to_string(identity_t *id) {

  scsl25_identity_t *scsl25_id;
  char *s;
  
  if(!id || id->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_identity_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  scsl25_id = id->id;
  s = pbcext_element_G1_to_b64(scsl25_id);

  return s;

}

identity_t* scsl25_identity_from_string(char *sid) {

  identity_t *id;

  if(!sid) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_identity_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(id = scsl25_identity_init())) return NULL;

  if(pbcext_element_G1_from_b64(id->id, sid) == IERROR) {
    scsl25_identity_free(id);
    return NULL;
  }

  return id;

}

/* identity.c ends here */
