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

#include <iostream>
#include <limits.h>

#include "gtest/gtest.h"

#include "groupsig.h"
#include "scsl25.h"
#include "message.h"

using namespace std;
  
namespace groupsig {

  // The fixture for testing SCSL25 scheme.
  class SCSL25Test : public ::testing::Test {
  protected:
    groupsig_key_t *isskey;
    groupsig_key_t *grpkey;
    groupsig_key_t **memkey;
    uint32_t n;

    SCSL25Test() {

      int rc;

      rc = groupsig_init(GROUPSIG_SCSL25_CODE, time(NULL));
      EXPECT_EQ(rc, IOK);
  
      isskey = groupsig_mgr_key_init(GROUPSIG_SCSL25_CODE);
      EXPECT_NE(isskey, nullptr);

      grpkey = groupsig_grp_key_init(GROUPSIG_SCSL25_CODE);
      EXPECT_NE(grpkey, nullptr);

      memkey = nullptr;
      n = 0;

    }
    
    ~SCSL25Test() override {
      groupsig_mgr_key_free(isskey); isskey = NULL;
      groupsig_grp_key_free(grpkey); grpkey = NULL;
      if (memkey) {
        for (uint32_t i=0; i<n; i++) {
          groupsig_mem_key_free(memkey[i]); memkey[i] = NULL;
        }
        free(memkey); memkey = NULL;
      }
      groupsig_clear(GROUPSIG_SCSL25_CODE);      
    }

    void addMembers(uint32_t n) {

      message_t *m0, *m1, *m2, *m3, *m4;
      int rc;
      uint32_t i;

      memkey = (groupsig_key_t **) malloc(sizeof(groupsig_key_t *)*n);
      ASSERT_NE(memkey, nullptr);

      m0 = m1 = m2 = m3 = m4 = nullptr;
      for (i=0; i<n; i++) {

        memkey[i] = groupsig_mem_key_init(grpkey->scheme);
        ASSERT_NE(memkey[i], nullptr);

        m1 = message_init();
        ASSERT_NE(m1, nullptr);

        rc = groupsig_join_mgr(&m1, NULL, isskey, 0, m0, grpkey);
        ASSERT_EQ(rc, IOK);

        m2 = message_init();
        ASSERT_NE(m2, nullptr);

        rc = groupsig_join_mem(&m2, memkey[i], 1, m1, grpkey);
        ASSERT_EQ(rc, IOK); 

        m3 = message_init();
        ASSERT_NE(m3, nullptr);

        rc = groupsig_join_mgr(&m3, NULL, isskey, 2, m2, grpkey);
        ASSERT_EQ(rc, IOK);

        rc = groupsig_join_mem(&m4, memkey[i], 3, m3, grpkey);
        ASSERT_EQ(rc, IOK);

        if(m0) { message_free(m0); m0 = NULL; }
        if(m1) { message_free(m1); m1 = NULL; }
        if(m2) { message_free(m2); m2 = NULL; }
        if(m3) { message_free(m3); m3 = NULL; }
        if(m4) { message_free(m4); m4 = NULL; }
  
      }
      
      this->n = n;
      
    }
    
    void SetUp() override {}
    void TearDown() override {}
  };


  TEST_F(SCSL25Test, GetCodeFromStr) {

    int rc;
    uint8_t scheme;

    rc = groupsig_get_code_from_str(&scheme, (char *) GROUPSIG_SCSL25_NAME);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(scheme, GROUPSIG_SCSL25_CODE);

  }

  TEST_F(SCSL25Test, CreatesGrpAndMgrKeys) {

    EXPECT_EQ(grpkey->scheme, GROUPSIG_SCSL25_CODE);
    EXPECT_EQ(isskey->scheme, GROUPSIG_SCSL25_CODE);
    
  }

  TEST_F(SCSL25Test, CheckJoinStart) {

    int rc;
    uint8_t start;
    
    rc = groupsig_get_joinstart(GROUPSIG_SCSL25_CODE, &start);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(start, 0);
    
  }

  TEST_F(SCSL25Test, CheckJoinSeq) {

    int rc;
    uint8_t seq;
    
    rc = groupsig_get_joinseq(GROUPSIG_SCSL25_CODE, &seq);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(seq, 3);    

  }  

  TEST_F(SCSL25Test, AddsNewMember) {

    int rc;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    addMembers(1);

    EXPECT_EQ(memkey[0]->scheme, GROUPSIG_SCSL25_CODE);    

  }

  TEST_F(SCSL25Test, InitializeSignature) {

    groupsig_signature_t *sig;
    int rc;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);
    EXPECT_EQ(sig->scheme, GROUPSIG_SCSL25_CODE);

    groupsig_signature_free(sig);

  }

  TEST_F(SCSL25Test, SignVerifyValid) {

    groupsig_signature_t *sig;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify(&b, sig, msg, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    groupsig_signature_free(sig);
    message_free(msg);

  }

  TEST_F(SCSL25Test, SignVerifyWrongMessage) {

    groupsig_signature_t *sig;
    message_t *msg, *msg2;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    msg2 = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, Worlds!\" }");
    EXPECT_NE(msg2, nullptr);

    rc = groupsig_verify(&b, sig, msg2, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    groupsig_signature_free(sig);
    message_free(msg);
    message_free(msg2);    

  }

  TEST_F(SCSL25Test, SuccessfullyLinkSigsSameUser) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig1 = groupsig_signature_init(grpkey->scheme);
    sig2 = groupsig_signature_init(grpkey->scheme);

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);    

    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    sigs[0] = sig1;
    sigs[1] = sig2;
    
    rc = groupsig_link(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_link(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);
    
    groupsig_signature_free(sig1);
    groupsig_signature_free(sig2);
    groupsig_proof_free(proof);
    message_free(msg);

    free(msgs);
    free(sigs);

  }

  TEST_F(SCSL25Test, FailsLinkSigsDifferentUsers) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig1 = groupsig_signature_init(grpkey->scheme);
    sig2 = groupsig_signature_init(grpkey->scheme);

    addMembers(2);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig2, msg, memkey[1], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);    

    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    sigs[0] = sig1;
    sigs[1] = sig2;
    
    rc = groupsig_link(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IFAIL);
    
    groupsig_signature_free(sig1);
    groupsig_signature_free(sig2);
    groupsig_proof_free(proof);
    message_free(msg);

    free(msgs);
    free(sigs);

  }    

  TEST_F(SCSL25Test, SuccessfullySeqLinkSigsSameUser) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig1 = groupsig_signature_init(grpkey->scheme);
    sig2 = groupsig_signature_init(grpkey->scheme);

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, 2);
    EXPECT_EQ(rc, IOK);    

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    sigs[0] = sig1;
    sigs[1] = sig2;

    proof = nullptr;
    rc = groupsig_seqlink(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_seqlink(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    groupsig_signature_free(sig1);
    groupsig_signature_free(sig2);
    groupsig_proof_free(proof);
    message_free(msg);

    free(msgs);
    free(sigs);

  }

  TEST_F(SCSL25Test, FailsSeqLinkSigsDifferentUsers) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig1 = groupsig_signature_init(grpkey->scheme);
    sig2 = groupsig_signature_init(grpkey->scheme);

    addMembers(2);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig2, msg, memkey[1], grpkey, 2);
    EXPECT_EQ(rc, IOK);    

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    sigs[0] = sig1;
    sigs[1] = sig2;

    proof = NULL;
    rc = groupsig_link(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IFAIL);
    
    groupsig_signature_free(sig1);
    groupsig_signature_free(sig2);
    groupsig_proof_free(proof);
    message_free(msg);

    free(msgs);
    free(sigs);

  }

  TEST_F(SCSL25Test, RejectsSeqLinkProofWrongOrderSwap) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig1 = groupsig_signature_init(grpkey->scheme);
    sig2 = groupsig_signature_init(grpkey->scheme);

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, 2);
    EXPECT_EQ(rc, IOK);    

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    sigs[0] = sig2;
    sigs[1] = sig1;

    proof = nullptr;
    rc = groupsig_seqlink(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_seqlink(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    groupsig_signature_free(sig1);
    groupsig_signature_free(sig2);
    groupsig_proof_free(proof);
    message_free(msg);

    free(msgs);
    free(sigs);

  }

  TEST_F(SCSL25Test, RejectsSeqLinkProofWrongOrderSkip) {

    groupsig_signature_t *sig1, *sig2, *sig3, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig1 = groupsig_signature_init(grpkey->scheme);
    sig2 = groupsig_signature_init(grpkey->scheme);
    sig3 = groupsig_signature_init(grpkey->scheme);    

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig3, msg, memkey[0], grpkey, 3);
    EXPECT_EQ(rc, IOK);    

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    sigs[0] = sig1;
    sigs[1] = sig3;

    proof = nullptr;
    rc = groupsig_seqlink(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_seqlink(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    groupsig_signature_free(sig1);
    groupsig_signature_free(sig2);
    groupsig_signature_free(sig3);
    groupsig_proof_free(proof);
    message_free(msg);

    free(msgs);
    free(sigs);

  }  

  /** Group key tests **/

  TEST_F(SCSL25Test, GrpKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    len = groupsig_grp_key_get_size(grpkey);
    EXPECT_NE(len, -1);
    
    bytes = nullptr;
    rc = groupsig_grp_key_export(&bytes, &size, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, (int)size);

    dst = groupsig_grp_key_import(GROUPSIG_SCSL25_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    groupsig_grp_key_free(dst);
    free(bytes); 
    
  }

  TEST_F(SCSL25Test, GrpKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    dst = groupsig_grp_key_init(GROUPSIG_SCSL25_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_grp_key_copy(dst, grpkey);
    EXPECT_EQ(rc, IOK);

    groupsig_grp_key_free(dst);    
    
  }

  /** Manager key tests **/

  TEST_F(SCSL25Test, IssKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);
    
    len = groupsig_mgr_key_get_size(isskey);
    EXPECT_NE(len, -1);
    
    bytes = nullptr;
    rc = groupsig_mgr_key_export(&bytes, &size, isskey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, (int)size);

    dst = groupsig_mgr_key_import(GROUPSIG_SCSL25_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    groupsig_mgr_key_free(dst);
    free(bytes);
    
  }

  TEST_F(SCSL25Test, IssKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    dst = groupsig_mgr_key_init(GROUPSIG_SCSL25_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_copy(dst, isskey);
    EXPECT_EQ(rc, IOK);

    groupsig_mgr_key_free(dst);
    
  }

  /** Member key tests **/

  TEST_F(SCSL25Test, MemKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    addMembers(1);

    len = groupsig_mem_key_get_size(memkey[0]);
    EXPECT_NE(len, -1);
    
    bytes = nullptr;
    rc = groupsig_mem_key_export(&bytes, &size, memkey[0]);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, (int)size);

    dst = groupsig_mem_key_import(GROUPSIG_SCSL25_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    groupsig_mem_key_free(dst);
    free(bytes);
    
  }

  TEST_F(SCSL25Test, MemKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    addMembers(1);    

    dst = groupsig_mem_key_init(GROUPSIG_SCSL25_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mem_key_copy(dst, memkey[0]);
    EXPECT_EQ(rc, IOK);

    groupsig_mem_key_free(dst);    
    
  }

  /** Signature object tests **/

  TEST_F(SCSL25Test, SignatureToString) {

    groupsig_signature_t *sig;
    message_t *msg;
    char *str;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);  

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_verify(&b, sig, msg, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);    
    
    str = groupsig_signature_to_string(sig);
    EXPECT_NE(str, nullptr);

    groupsig_signature_free(sig);
    message_free(msg);
    free(str);
    
  }

  TEST_F(SCSL25Test, SignatureCopy) {

    groupsig_signature_t *src, *dst;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    src = groupsig_signature_init(grpkey->scheme);
    dst = groupsig_signature_init(grpkey->scheme);    

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(src, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_verify(&b, src, msg, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);    
    
    rc = groupsig_signature_copy(dst, src);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify(&b, dst, msg, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    groupsig_signature_free(dst);
    groupsig_signature_free(src);
    message_free(msg);
    
  }

  TEST_F(SCSL25Test, SignatureExportImport) {

    groupsig_signature_t *sig, *imported;
    message_t *msg;
    byte_t *bytes;
    uint32_t size;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_SCSL25_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    addMembers(1);

    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    bytes = nullptr;
    rc = groupsig_signature_export(&bytes, &size, sig);
    EXPECT_EQ(rc, IOK);

    imported = groupsig_signature_import(sig->scheme, bytes, size);
    EXPECT_NE(imported, nullptr);    
    
    rc = groupsig_verify(&b, imported, msg, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    groupsig_signature_free(imported);
    groupsig_signature_free(sig);
    message_free(msg);
    free(bytes);
    
  }

}  // namespace groupsig


