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

#ifndef _BAP24_MGR_KEY_H
#define _BAP24_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "bap24.h"
#include "include/mgr_key.h"
#include "shim/pbc_ext.h"

/**
 * @def BAP24_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing BAP24 group keys
 */
#define BAP24_MGR_KEY_BEGIN_MSG "BEGIN BAP24 MANAGERKEY"

/**
 * @def BAP24_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing BAP24 group keys
 */
#define BAP24_MGR_KEY_END_MSG "END BAP24 MANAGERKEY"

/**
 * @struct bap24_mgr_key_t
 * @brief BAP24 manager key. 
 */
typedef struct {
  pbcext_element_Fr_t *x; 
  pbcext_element_Fr_t *y; //y1
  pbcext_element_Fr_t *yy; //y2
  pbcext_element_Fr_t *ask;  /*accumulator key pair |sk|*/
  pbcext_element_Fr_t *dsk;  /*Data Processor key pair |sk|*/
} bap24_mgr_key_t;

/** 
 * @fn groupsig_key_t* bap24_mgr_key_init()
 * @brief Creates a new BAP24 manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* bap24_mgr_key_init();

/** 
 * @fn int bap24_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int bap24_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int bap24_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int bap24_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int bap24_mgr_key_get_size(groupsig_key_t *key)
 * @brief Returns the size that the given key would require in order to be
 *  stored in an array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int bap24_mgr_key_get_size(groupsig_key_t *key);

/**
 * @fn int bap24_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given key, with format:
 *
 *  | BAP24_CODE | KEYTYPE | size_x | x | size_y | y |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  manager key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The manager key to export.
 *
 * @return IOK or IERROR
 */
int bap24_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* bap24_mgr_key_import(byte_t *source, uint32_t size)
 * @brief Imports a manager key.
 *
 * Imports a BAP24 manager key from the specified array of bytes.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* bap24_mgr_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* bap24_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* bap24_mgr_key_to_string(groupsig_key_t *key);

/**
 * @var bap24_mgr_key_handle
 * @brief Set of functions for BAP24 manager keys management.
 */
static const mgr_key_handle_t bap24_mgr_key_handle = {
  .code = GROUPSIG_BAP24_CODE, /**< The scheme code. */
  .init = &bap24_mgr_key_init, /**< Initializes manager keys. */
  .free = &bap24_mgr_key_free, /**< Frees manager keys. */
  .copy = &bap24_mgr_key_copy, /**< Copies manager keys. */
  .gexport = &bap24_mgr_key_export, /**< Exports manager keys. */
  .gimport = &bap24_mgr_key_import, /**< Imports manager keys. */
  .to_string = &bap24_mgr_key_to_string, /**< Converts manager keys to printable strings. */
  .get_size = &bap24_mgr_key_get_size,
};

#endif

/* mgr_key.h ends here */
