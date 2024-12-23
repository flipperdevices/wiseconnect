/*******************************************************************************
* @file  si91x_sntp_client_types.h
* @brief 
*******************************************************************************
* # License
* <b>Copyright 2023 Silicon Laboratories Inc. www.silabs.com</b>
*******************************************************************************
*
* The licensor of this software is Silicon Laboratories Inc. Your use of this
* software is governed by the terms of Silicon Labs Master Software License
* Agreement (MSLA) available at
* www.silabs.com/about-us/legal/master-software-license-agreement. This
* software is distributed to you in Source Code format and is governed by the
* sections of the MSLA applicable to Source Code.
*
******************************************************************************/
#pragma once
#include "stdint.h"

/******************************************************
 * *                      Macros
 * ******************************************************/
//SNTP client feature
#define SI91X_SNTP_CLIENT_CREATE            1
#define SI91X_SNTP_CLIENT_GETTIME           2
#define SI91X_SNTP_CLIENT_GETTIME_DATE      3
#define SI91X_SNTP_CLIENT_GETSERVER_ADDRESS 4
#define SI91X_SNTP_CLIENT_DELETE            5
#define SI91X_SNTP_CLIENT_GET_SERVER_INFO   6
#define SI91X_SNTP_CLIENT_SERVER_ASYNC_RSP  7

/******************************************************
 * *                 Type Definitions
 * ******************************************************/

// Define for SNTP client initialization
typedef struct {
  uint8_t command_type;
  uint8_t ip_version;
  union {
    uint8_t ipv4_address[4];
    uint8_t ipv6_address[16];
  } server_ip_address;
  uint8_t sntp_method;
  uint8_t sntp_timeout[2];
} si91x_sntp_client_t;

typedef struct {
  uint8_t command_type;
  uint8_t ip_version;
  union {
    uint8_t ipv4_address[4];
    uint8_t ipv6_address[16];
  } server_ip_address;
  uint8_t sntp_method;
} si91x_sntp_server_info_rsp_t;

typedef struct {
  uint8_t ip_version;
  union {
    uint8_t ipv4_address[4];
    uint8_t ipv6_address[16];
  } server_ip_address;
  uint8_t sntp_method;
} si91x_sntp_server_rsp_t;