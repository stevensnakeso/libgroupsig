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

#ifndef _SCSL25_PROOF_H
#define _SCSL25_PROOF_H

#include <stdint.h>
#include "include/proof.h"
#include "crypto/spk.h"
#include "scsl25.h"

/**
 * @struct scsl25_proof_t
 * @brief SCSL25 的通用 NIZK 知识证明。
 * 主要用于 SLink 阶段，证明多个签名之间的顺序链接性。
 */
typedef struct {
  spk_dlog_t *spk; /**< 链接证明 (Linking proof)，证明假名的一致性。 */
  byte_t **x; /**< 序列证明分量 (Sequence proof components)。 */
  uint64_t *xlen; /* x 中每个元素的字节长度。 */
  uint64_t n; /**< x 和 xlen 中的元素数量。 */
} scsl25_proof_t;

/** * @fn struct groupsig_proof_t* scsl25_proof_init()
 * @brief 初始化 SCSL25 证明的各个字段。
 *
 * @return 指向已分配证明的指针，出错时返回 NULL。
 */
groupsig_proof_t* scsl25_proof_init();

/** * @fn int scsl25_proof_free(groupsig_proof_t *proof)
 * @brief 释放给定 SCSL25 证明分配的字段。
 *
 * @param[in,out] proof 要释放的证明。
 * * @return IOK 或 IERROR
 */
int scsl25_proof_free(groupsig_proof_t *proof);

/** * @fn int scsl25_proof_to_string
 * @brief 返回代表当前证明的可打印字符串。
 *
 * @param[in] proof 要打印的证明。
 * * @return IOK 或 IERROR
 */
char* scsl25_proof_to_string(groupsig_proof_t *proof);

/** * @fn int scsl25_proof_get_size(groupsig_proof_t *proof)
 * @brief 返回证明转换为字节数组后的大小。
 *
 * @param[in] proof 证明。
 * * @return 出错时返回 -1，否则返回字节数组所需的长度。
 */
int scsl25_proof_get_size(groupsig_proof_t *proof);

/** * @fn int scsl25_proof_copy(groupsig_proof_t *dst, 
 * groupsig_proof_t *src)
 * @brief 将给定的源证明拷贝到目标证明中。
 *
 * @param[in,out] dst 目标证明（由调用者初始化）。
 * @param[in] src 要拷贝的源证明。 
 * * @return IOK 或 IERROR。
 */
int scsl25_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src);


/** * @fn int scsl25_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
 * @brief 将指定的证明导出为字节数组，格式如下：
 * | SCSL25CODE | size_spk | spk | n (uint64_t) | size_x1 | x1 | ... | 
 * size_xn | xn |
 *
 * @param[in,out] bytes 指向字节数组的指针。
 * @param[in,out] size 写入 *bytes 的字节数。
 * @param[in] proof 要导出的证明。
 * * @return IOK 或 IERROR，并更新 errno。
 */
int scsl25_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
  
/** * @fn int scsl25_proof_import(byte_t *source, uint32_t size)
 * @brief 导入 SCSL25 链接证明。
 *
 * @param[in] source 包含要导入证明的字节数组。
 * @param[in] size source 中的字节数。
 * * @return 指向导入证明的指针，出错时返回 NULL。
 */
groupsig_proof_t* scsl25_proof_import(byte_t *source, uint32_t size);

/**
 * @var scsl25_proof_handle
 * @brief SCSL25 证明管理函数句柄。
 */
static const groupsig_proof_handle_t scsl25_proof_handle = {
  .scheme = GROUPSIG_SCSL25_CODE, /**< 方案代码。 */
  .init = &scsl25_proof_init, /**< 初始化证明。 */
  .free = &scsl25_proof_free, /**< 释放证明。 */
  .get_size = &scsl25_proof_get_size, /**< 获取证明字节大小。 */
  .copy = &scsl25_proof_copy, /**< 拷贝证明。 */
  .gexport = &scsl25_proof_export, /**< 导出证明。 */
  .gimport = &scsl25_proof_import, /**< 导入证明。 */
  .to_string = &scsl25_proof_to_string /**< 获取证明的可打印表示。 */
};

#endif /* _SCSL25_PROOF_H */
