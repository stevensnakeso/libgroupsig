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

#ifndef _SCSL25_MEM_KEY_H
#define _SCSL25_MEM_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "scsl25.h"
#include "include/mem_key.h"
#include "crypto/spk.h"
#include "crypto/prf.h"

/**
 * @def SCSL25_MEM_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing SCSL25 member keys
 */
#define SCSL25_MEM_KEY_BEGIN_MSG "BEGIN DSCSL25 MEMBERKEY"

/**
 * @def SCSL25_MEM_KEY_END_MSG
 * @brief End string to prepend to headers of files containing SCSL25 member keys
 */
#define SCSL25_MEM_KEY_END_MSG "END SCSL25 MEMBERKEY"

/**
 * @struct scsl25_mem_key_t
 * @brief SCSL25 member keys.
 */
typedef struct {
  pbcext_element_Fr_t *u; /**< u = e * x */
  pbcext_element_G1_t *v; /**< v = U^(1/isk) mod n */
  pbcext_element_Fr_t *x; /**< 秘密指数 x (Secret exponent) */
  pbcext_element_Fr_t *e; /**< 秘密指数 e (Secret exponent) */
  prf_key_t *y;
  prf_key_t *yy; /**< PRF 密钥，用于生成假名序列 (Secret PRF key) */
  /* 预计算或辅助参数 */
  pbcext_element_G1_t *U; /**< 成员公钥部分 U = g1^e mod n */
} scsl25_mem_key_t;

/** 
 * @fn groupsig_key_t* scsl25_mem_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* scsl25_mem_key_init();

/** 
 * @fn int scsl25_mem_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given member key.
 *
 * @param[in,out] key The member key to initialize.
 * 
 * @return IOK or IERROR
 */
int scsl25_mem_key_free(groupsig_key_t *key);

/** 
 * @fn int scsl25_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized 
 *  by the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int scsl25_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int scsl25_mem_key_get_size_in_format(groupsig_key_t *key)
 * @brief Returns the size that the given key would require in order to be 
 *  represented as an array of bytes.
 *
 * @param[in] key The key.
 * 
 * @return The required number of bytes, or -1 if error.
 */
int scsl25_mem_key_get_size(groupsig_key_t *key);

/** 
 * @fn int scsl25_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given member key to an array
 *  with format:
 *
 *  | SCSL25_CODE | KEYTYPE | size_A | A | size_x | x | 
 *    size_y | y | size_s | s | size_H | H | size_h2s | h2s |
 *    size_k | k | size_kk | kk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  member key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The member key to export.
 * 
 * @return IOK or IERROR. 
 */
int scsl25_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* scsl25_mem_key_import(byte_t *source, uint32_t size)
 * @brief Imports a member key.
 *
 * Imports a SCSL25 member key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported member key, or NULL if error.
 */
groupsig_key_t* scsl25_mem_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* scsl25_mem_key_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* scsl25_mem_key_to_string(groupsig_key_t *key);

/**
 * @var scsl25_mem_key_handle
 * @brief Set of functions for managing SCSL25 member keys.
 */
static const mem_key_handle_t scsl25_mem_key_handle = {
  .code = GROUPSIG_SCSL25_CODE, /**< The scheme code. */
  .init = &scsl25_mem_key_init, /**< Initializes member keys. */
  .free = &scsl25_mem_key_free, /**< Frees member keys. */
  .copy = &scsl25_mem_key_copy, /**< Copies member keys. */
  .get_size = &scsl25_mem_key_get_size, /**< Gets the size of the key, in bytes. */
  .gexport = &scsl25_mem_key_export, /**< Exports member keys. */
  .gimport = &scsl25_mem_key_import, /**< Imports member keys. */
  .to_string = &scsl25_mem_key_to_string, /**< Converts member keys to printable strings. */
};

#endif /* _SCSL25_MEM_KEY_H */

/* mem_key.h ends here */
