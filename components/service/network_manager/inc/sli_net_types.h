/***************************************************************************/ /**
 * @file
 * @brief Networking Types
 *******************************************************************************
 * # License
 * <b>Copyright 2025 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * SPDX-License-Identifier: Zlib
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 ******************************************************************************/
#pragma once
#include "sl_net_constants.h"

/**
 * @brief Network Manager Message structure.
 * 
 * @details
 * This structure is used for communication with the network manager thread.
 * It encapsulates details about the network interface, event flags.
 * 
 */
typedef struct {
  sl_net_interface_t interface; ///< Identifier for the network interface
  uint32_t event_flags;         ///< Event flags for the network manager
} sli_network_manager_message_t;