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

#include "bap24.h"
#include "logger.h"
#include "groupsig/bap24/grp_key.h"
#include "groupsig/bap24/mgr_key.h"
#include "groupsig/bap24/gml.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"

int bap24_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }  

  return IOK;

}

int bap24_clear() {  
  return IOK;
}

int bap24_setup(groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml) {

  bap24_grp_key_t *gkey;
  bap24_mgr_key_t *mkey;
  pbcext_element_Fr_t *inv;
  int rc;

  if(!grpkey || grpkey->scheme != GROUPSIG_BAP24_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_BAP24_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "bap24_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;

  /* Set manager key */
  if(!(mkey->x = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_Fr_random(mkey->x) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);
  if(!(mkey->y = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_Fr_random(mkey->y) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);

  /* Set group key */
  if(!(gkey->g = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_G1_random(gkey->g) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);  
  if(!(gkey->h = pbcext_element_G1_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_G1_random(gkey->h) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);  
  if(!(gkey->gg = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_G2_random(gkey->gg) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);
  if(!(gkey->hh = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_G2_random(gkey->hh) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);
  if(!(gkey->X = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_G2_mul(gkey->X, gkey->gg, mkey->x) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);
  if(!(gkey->Y = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_G2_mul(gkey->Y, gkey->gg, mkey->y) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);  
  if(!(gkey->YY = pbcext_element_G2_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_G2_mul(gkey->YY, gkey->gg, mkey->yy) == IERROR)
    GOTOENDRC(IERROR, bap24_setup); 


    /* Set acc key pair */

  if(!(mkey->ask = pbcext_element_Fr_init())) GOTOENDRC(IERROR,bap24_setup);
  if(pbcext_element_Fr_random(mkey->ask) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);

  if(!(gkey->apk = pbcext_element_G2_init())) GOTOENDRC(IERROR,bap24_setup);
  if(pbcext_element_G2_mul(gkey->apk,gkey->hh,mkey->ask) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);

  if(!(gkey->acc = pbcext_element_G2_init())) GOTOENDRC(IERROR,bap24_setup);
  if(pbcext_element_G2_set(gkey->acc,gkey->h) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);

    /* Set DP key pair */
  if(!(mkey->dsk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bap24_setup);
  if(pbcext_element_Fr_random(mkey->dsk) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);

  if(!(gkey->dpk = pbcext_element_G2_init())) GOTOENDRC(IERROR,bap24_setup);
  if(pbcext_element_G2_mul(gkey->dpk,gkey->hh,mkey->dsk) == IERROR)
    GOTOENDRC(IERROR, bap24_setup);
  



    
  
 bap24_setup_end:

  if (rc == IERROR) {
    if (mkey->x) { pbcext_element_Fr_free(mkey->x); mkey->x = NULL; }
    if (mkey->y) { pbcext_element_Fr_free(mkey->y); mkey->y = NULL; }
    if (gkey->g) { pbcext_element_G1_free(gkey->g); gkey->g = NULL; }
    if (gkey->h) { pbcext_element_G1_free(gkey->h); gkey->h = NULL; }
    if (gkey->g) { pbcext_element_G2_free(gkey->gg); gkey->gg = NULL; }
    if (gkey->hh) { pbcext_element_G2_free(gkey->hh); gkey->hh = NULL; }
    if (gkey->X) { pbcext_element_G2_free(gkey->X); gkey->X = NULL; }
    if (gkey->Y) { pbcext_element_G2_free(gkey->Y); gkey->Y = NULL; }    
    if (mkey->ask) { pbcext_element_Fr_free(mkey->ask); mkey->ask = NULL; }
    if (gkey->apk) { pbcext_element_G2_free(gkey->apk); gkey->apk = NULL; }
    if (gkey->acc) { pbcext_element_G2_free(gkey->acc); gkey->acc = NULL; }
  }

  return rc;

}

/* setup.c ends here */
