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
#include "groupsig/sltgs23/identity.h"

identity_t* sltgs23_identity_init() {

  identity_t *id;
  sltgs23_identity_t *sltgs23_id;

  if(!(id = (identity_t *) mem_malloc(sizeof(identity_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sltgs23_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(sltgs23_id = (sltgs23_identity_t *) mem_malloc(sizeof(sltgs23_identity_t)))) {
    mem_free(id); id = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "sltgs23_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  id->scheme = GROUPSIG_SLTGS23_CODE;
  id->id = sltgs23_id;
  
  return id;

}

int sltgs23_identity_free(identity_t *id) {

  sltgs23_identity_t *sltgs23_id;

  if(!id) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sltgs23_identity_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(id->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_identity_free", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_id = id->id;
  pbcext_element_G1_free(sltgs23_id); sltgs23_id = NULL;
  mem_free(id);

  return IOK;

}

int sltgs23_identity_copy(identity_t *dst, identity_t *src) {

  sltgs23_identity_t *sltgs23_srcid, *sltgs23_dstid;
  
  if(!dst || dst->scheme != GROUPSIG_SLTGS23_CODE ||
     !src || src->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_srcid = src->id;
  sltgs23_dstid = dst->id;
  
  if(!(sltgs23_dstid = pbcext_element_G1_init())) return IERROR;
  if(pbcext_element_G1_set(sltgs23_dstid, sltgs23_srcid) == IERROR) return IERROR;
  
  return IOK;

}

uint8_t sltgs23_identity_cmp(identity_t *id1, identity_t *id2) {

  sltgs23_identity_t *sltgs23_id1, *sltgs23_id2;
  
  if(!id1 || !id2 || id1->scheme != id2->scheme || 
     id1->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_identity_cmp", __LINE__, LOGERROR);
    return UINT8_MAX;
  }

  sltgs23_id1 = id1->id;
  sltgs23_id2 = id2->id;

  return pbcext_element_G1_cmp(sltgs23_id1, sltgs23_id2);

}

char* sltgs23_identity_to_string(identity_t *id) {

  sltgs23_identity_t *sltgs23_id;
  char *s;
  
  if(!id || id->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_identity_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sltgs23_id = id->id;
  s = pbcext_element_G1_to_b64(sltgs23_id);

  return s;

}

identity_t* sltgs23_identity_from_string(char *sid) {

  if(!sid) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_identity_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* identity.c ends here */
