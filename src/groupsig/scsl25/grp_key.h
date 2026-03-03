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

#ifndef _scsl25_GRP_KEY_H
#define _scsl25_GRP_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "scsl25.h"
#include "include/grp_key.h"
#include "shim/pbc_ext.h"

/**
 * @struct scsl25_grp_key_t
 * @brief Structure for SCSL25 group keys.
 *
 * For convenience, we set a public key of SCSL25 to contain the instance parameters 
 * as well as the public keys of Issuer and Converter. @TODO We may want to 
 * redesign this at some point...
 */
typedef struct {
  pbcext_element_G1_t *n;   /**< 合数模数 n = p*q */
  pbcext_element_G1_t *g;   /**< 随机生成元 g \in G */
  pbcext_element_G1_t *g1;  /**< 随机生成元 g1 \in G */
  pbcext_element_G1_t *Y;   /**< TA 的公钥 Y = g^isk */

  /* 安全参数 (通常作为公共常数或包含在 key 中以确保验证一致性) */
  uint32_t lambda;          /**< 安全参数 lambda */
  uint32_t lambda1;         /**< 区间证明参数 lambda1 */
  uint32_t lambda2;         /**< 区间证明参数 lambda2 */
  //uint32_t epsilon;         /**< 统计安全参数 iota */

} scsl25_grp_key_t;

/**
 * @def SCSL25_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing SCSL25 group keys
 */
#define SCSL25_GRP_KEY_BEGIN_MSG "BEGIN SCSL25 GROUPKEY"

/**
 * @def scsl25_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing SCSL25 group keys
 */
#define SCSL25_GRP_KEY_END_MSG "END SCSL25 GROUPKEY"

/** 
 * @fn groupsig_key_t* scsl25_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* scsl25_grp_key_init();

/** 
 * @fn int scsl25_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int scsl25_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int scsl25_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies a group key.
 *
 * Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int scsl25_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int scsl25_grp_key_get_size_in_format(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int scsl25_grp_key_get_size(groupsig_key_t *key);

/** 
 * @fn int scsl25_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Exports the given group key to a bytearray with the following format:
 *
 *  | SCSL25_CODE | KEYTYPE | size_g1 | g1 | size_g2 | g2 |
 *    size_h1 | h1 | size_h2 | h2 | size_ipk | ipk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  group key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The group key to export.
 * 
 * @return IOK or IERROR.
 */
int scsl25_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* scsl25_grp_key_import(byte_t *source, uint32_t size)
 * @brief Imports a group key.
 *
 * Imports a SCSL25 group key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* scsl25_grp_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* scsl25_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* scsl25_grp_key_to_string(groupsig_key_t *key);

/**
 * @var scsl25_grp_key_handle
 * @brief The set of functions to manage SCSL25 group keys.
 */
static const grp_key_handle_t scsl25_grp_key_handle = {
  .code = GROUPSIG_SCSL25_CODE, /**< Scheme. */
  .init = &scsl25_grp_key_init, /**< Initialize group keys. */
  .free = &scsl25_grp_key_free, /**< Free group keys. */
  .copy = &scsl25_grp_key_copy, /**< Copy group keys. */
  .gexport = &scsl25_grp_key_export, /**< Export group keys. */
  .gimport = &scsl25_grp_key_import, /**< Import group keys. */
  .to_string = &scsl25_grp_key_to_string, /**< Convert to printable strings. */
  .get_size = &scsl25_grp_key_get_size, /**< Get size of key, in bytes */
};

#endif

/* grp_key.h ends here */
