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

#ifndef _SLTGS23_MGR_KEY_H
#define _SLTGS23_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "sltgs23.h"
#include "include/mgr_key.h"
#include "shim/pbc_ext.h"

/**
 * @def SLTGS23_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing SLTGS23 group keys
 */
#define SLTGS23_MGR_KEY_BEGIN_MSG "BEGIN SLTGS23 MANAGERKEY"

/**
 * @def SLTGS23_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing SLTGS23 group keys
 */
#define SLTGS23_MGR_KEY_END_MSG "END SLTGS23 MANAGERKEY"

/**
 * @struct sltgs23_mgr_key_t
 * @brief SLTGS23 Manager key.
 * 
 * The secret key for the issuing authority.
 */
typedef struct {
  pbcext_element_Fr_t *isk; /**< Issuer secret key. */
  pbcext_element_Fr_t *csk; /**< Converter secret key. */
} sltgs23_mgr_key_t;

/** 
 * @fn groupsig_key_t* sltgs23_mgr_key_init()
 * @brief Creates a new SLTGS23 manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* sltgs23_mgr_key_init();

/** 
 * @fn int sltgs23_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int sltgs23_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int sltgs23_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int sltgs23_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int sltgs23_mgr_key_get_size_in_format(groupsig_key_t *key)
 * @brief Returns the size that the given key would require as an array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int sltgs23_mgr_key_get_size(groupsig_key_t *key);

/** 
 * @fn int sltgs23_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given manager key to an array
 *  with format:
 *
 *  | SLTGS23_CODE | KEYTYPE | size_isk | isk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  manager key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The manager key to export.
 * 
 * @return IOK or IERROR.
 */
int sltgs23_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* sltgs23_mgr_key_import(byte_t *source, uint32_t size)
 * @brief Imports a SLTGS23 manager key from the specified source.
 *
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported manager key, or NULL if error.
 */
groupsig_key_t* sltgs23_mgr_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* sltgs23_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* sltgs23_mgr_key_to_string(groupsig_key_t *key);

/**
 * @var sltgs23_mgr_key_handle
 * @brief Set of functions for SLTGS23 manager keys management.
 */
static const mgr_key_handle_t sltgs23_mgr_key_handle = {
 .code = GROUPSIG_SLTGS23_CODE, /**< The scheme code. */
 .init = &sltgs23_mgr_key_init, /**< Initializes manager keys. */
 .free = &sltgs23_mgr_key_free, /**< Frees manager keys. */
 .copy =  &sltgs23_mgr_key_copy, /**< Copies manager keys. */
 .gexport =  &sltgs23_mgr_key_export, /**< Exports manager keys. */
 .gimport = &sltgs23_mgr_key_import, /**< Imports manager keys. */
 .to_string = &sltgs23_mgr_key_to_string, /**< Converts manager keys to printable strings. */
 .get_size = &sltgs23_mgr_key_get_size /**< Gets the size of the key as a byte array. */
};

#endif

/* mgr_key.h ends here */
