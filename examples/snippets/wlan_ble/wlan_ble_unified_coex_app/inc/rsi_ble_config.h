/*******************************************************************************
* @file  rsi_ble_config.h
* @brief 
*******************************************************************************
* # License
* <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
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
/**
 * @file     rsi_ble_config.h
 * @version  0.1  
 * @date     03 Sep 2015
 *
 *
 *
 *  @brief : This file contain definitions and declarations of BLE APIs.
 *
 *  @section Description  This file contains definitions and declarations required to
 *  configure BLE module.
 *
 *
 */

#ifndef SAPIS_EXAMPLES_RSI_DEMO_APPS_INC_RSI_BLE_CONFIG_DEF_H_
#define SAPIS_EXAMPLES_RSI_DEMO_APPS_INC_RSI_BLE_CONFIG_DEF_H_
#include <rsi_common_app.h>

#if BLE_ADV_BT_SPP_THROUGHPUT
#include "rsi_ble_config_DEMO_8.h"
#elif BT_EIR_SNIFF_SPP_PERIPHERAL
#include "rsi_ble_config_DEMO_7.h"
#elif BLE_PERIPHERAL
#include "rsi_ble_config_DEMO_1.h"
#elif BLE_CENTRAL
#include "rsi_ble_config_DEMO_2.h"
#elif BLE_DUAL_ROLE
#include "rsi_ble_config_DEMO_3.h"
#elif BLE_POWERSAVE
#include "rsi_ble_config_DEMO_4.h"
#elif BLE_DUAL_MODE_BT_A2DP_SOURCE_WIFI_HTTP_S_RX
#include "rsi_ble_config_DEMO_20.h"
#elif BLE_DUAL_MODE_BT_SPP_PERIPHERAL
#include "rsi_ble_config_DEMO_21.h"
#elif BLE_ADV
#include "rsi_ble_config_DEMO_23.h"
#elif BLE_IDLE_POWERSAVE
#include "rsi_ble_config_DEMO_24.h"
#elif BLE_SCAN
#include "rsi_ble_config_DEMO_25.h"
#elif BT_SNIFF
#include "rsi_ble_config_DEMO_26.h"
#elif BT_PAGE_INQUIRY
#include "rsi_ble_config_DEMO_27.h"
#elif BT_PER
#include "rsi_ble_config_DEMO_28.h"
#elif BLE_PER
#include "rsi_ble_config_DEMO_31.h"
#elif BT_SPP_RX_TX
#include "rsi_ble_config_DEMO_29.h"
#elif BT_BLE_IDLE_POWERSAVE
#include "rsi_ble_config_DEMO_30.h"
#elif BT_INQUIRY_SCAN
#include "rsi_ble_config_DEMO_32.h"
#elif BT_PAGE_SCAN
#include "rsi_ble_config_DEMO_33.h"
#elif BT_SPP_CENTRAL_SNIFF
#include "rsi_ble_config_DEMO_34.h"
#elif BT_SPP_PERIPHERAL_SNIFF
#include "rsi_ble_config_DEMO_35.h"
#elif BLE_DATA_TRANSFER
#include "rsi_ble_config_DEMO_37.h"
#elif BLE_PRIVACY
#include "rsi_ble_config_DEMO_38.h"
#elif BLE_LONG_READ
#include "rsi_ble_config_DEMO_39.h"
#elif BLE_L2CAP_CBFC
#include "rsi_ble_config_DEMO_40.h"
#elif BLE_GATT_TEST_ASYNC
#include "rsi_ble_config_DEMO_41.h"
#elif BLE_GATT_INDICATION_STATUS
#include "rsi_ble_config_DEMO_55.h"
#elif BLE_SIMPLE_GATT
#include "rsi_ble_config_DEMO_44.h"
#elif BLE_MULTI_PERIPHERAL_CENTRAL
#include "rsi_ble_config_DEMO_47.h"
#elif BLE_OVERLAPPING_PROCEDURES
#include "rsi_ble_config_DEMO_53.h"
#elif BLE_INDICATION
#include "rsi_ble_config_DEMO_50.h"
#elif BLE_MULTI_PERIPHERAL_CENTRAL_BT_A2DP
#include "rsi_ble_config_DEMO_51.h"
#elif BLE_MULTI_PERIPHERAL_CENTRAL_BT_A2DP_WIFI_HTTP_S_RX
#include "rsi_ble_config_DEMO_52.h"
#elif UNIFIED_PROTOCOL
#include "rsi_ble_config_DEMO_54.h"
#elif COEX_MAX_APP
#include "rsi_ble_config_DEMO_57.h"
#elif ANT_APP
#include "rsi_ble_config_ANT.h"
#elif ANT_APP_POWERSAVE
#include "rsi_ble_config_ANT_APP_PWRSAVE.h"
#elif BLE_CENTRAL_ANT_APP
#include "rsi_ble_config_BLE_CENTRAL_ANT_APP.h"
#elif BLE_PERIPHERAL_ANT_APP
#include "rsi_ble_config_BLE_PERIPHERAL_ANT_APP.h"
#elif ANT_BLE_PERI_BT_A2DP_SRC_APP
#include "rsi_ble_config_ANT_BLE_PERI_A2DP_SRC.h"
#elif ANT_BLE_CENT_BT_A2DP_SRC_APP
#include "rsi_ble_config_ANT_BLE_CENT_A2DP_SRC.h"
#elif ANT_BLE_DUAL_ROLE_BT_A2DP_SRC_APP
#include "rsi_ble_config_ANT_BLE_DUAL_ROLE_BT_A2DP_SRC.h"
#elif WLAN_STANDBY_WITH_ANT
#include "rsi_ble_wlan_ant_config.h"
#elif WIFI_ANT_HTTP_S_5MB_RX_WITH_STANDBY
#include "rsi_ble_wlan_http_s_ant_config.h"
#elif BT_CW_MODE
#include "rsi_ble_config_DEMO_61.h"
#elif BLE_CW_MODE
#include "rsi_ble_config_DEMO_62.h"
#elif ANT_CW_MODE
#include "rsi_ant_config_DEMO_66.h"
#elif COEX_THROUGHPUT
#include "rsi_ble_config_DEMO_67.h"
#elif BT_BLE_UPDATE_GAIN_TABLE
#include "rsi_ble_config_DEMO_68.h"
#elif (1)
#include "ble_config.h"

#else
#include <rsi_data_types.h>
/******************************************************
 * *                      Macros
 * ******************************************************/

#define RSI_BLE_SET_RAND_ADDR "00:23:A7:12:34:56"

#define CLEAR_ACCEPTLIST              0x00
#define ADD_DEVICE_TO_ACCEPTLIST      0x01
#define DELETE_DEVICE_FROM_ACCEPTLIST 0x02

#define ALL_PHYS 0x00

#define RSI_BLE_DEV_ADDR_RESOLUTION_ENABLE 0

#define RSI_OPERMODE_WLAN_BLE 13

#define RSI_BLE_MAX_NBR_ATT_REC  80
#define RSI_BLE_MAX_NBR_ATT_SERV 10

#define RSI_BLE_MAX_NBR_PERIPHERALS 8
#define RSI_BLE_MAX_NBR_CENTRALS    2

#define RSI_BLE_GATT_ASYNC_ENABLE 0

/* Number of BLE notifications */
#define RSI_BLE_NUM_CONN_EVENTS   20

/* Number of BLE GATT RECORD SIZE IN (n*16 BYTES), eg:(0x40*16)=1024 bytes */
#define RSI_BLE_NUM_REC_BYTES     0x40

#define RSI_BLE_INDICATE_CONFIRMATION_FROM_HOST 0

/*=======================================================================*/
//! Advertising command parameters
/*=======================================================================*/

#define RSI_BLE_ADV_TYPE          UNDIR_CONN
#define RSI_BLE_ADV_FILTER_TYPE   ALLOW_SCAN_REQ_ANY_CONN_REQ_ANY
#define RSI_BLE_ADV_DIR_ADDR_TYPE LE_PUBLIC_ADDRESS
#define RSI_BLE_ADV_DIR_ADDR      "00:15:83:6A:64:17"

#define RSI_BLE_ADV_INT_MIN                             0x100
#define RSI_BLE_ADV_INT_MAX                             0x200
#define RSI_BLE_ADV_CHANNEL_MAP                         0x07

//!Advertise status
//! Start the advertising process
#define RSI_BLE_START_ADV                               0x01
//! Stop the advertising process
#define RSI_BLE_STOP_ADV                                0x00

//! BLE Tx Power Index On Air
#define RSI_BLE_PWR_INX                                 30

//! BLE Active H/w Pwr Features
#define BLE_DISABLE_DUTY_CYCLING                        0
#define BLE_DUTY_CYCLING                                1
#define BLR_DUTY_CYCLING                                2
#define BLE_4X_PWR_SAVE_MODE                            4
#define RSI_BLE_PWR_SAVE_OPTIONS                        BLE_DISABLE_DUTY_CYCLING

//!Advertise types

/* Advertising will be visible(discoverable) to all the devices.
 * Scanning/Connection is also accepted from all devices
 * */
#define UNDIR_CONN                                      0x80

/* Advertising will be visible(discoverable) to the particular device 
 * mentioned in RSI_BLE_ADV_DIR_ADDR only. 
 * Scanning and Connection will be accepted from that device only.
 * */
#define DIR_CONN                                        0x81

/* Advertising will be visible(discoverable) to all the devices.
 * Scanning will be accepted from all the devices.
 * Connection will be not be accepted from any device.
 * */
#define UNDIR_SCAN                                      0x82

/* Advertising will be visible(discoverable) to all the devices.
 * Scanning and Connection will not be accepted from any device
 * */
#define UNDIR_NON_CONN                                  0x83

/* Advertising will be visible(discoverable) to the particular device 
 * mentioned in RSI_BLE_ADV_DIR_ADDR only. 
 * Scanning and Connection will be accepted from that device only.
 * */
#define DIR_CONN_LOW_DUTY_CYCLE                         0x84

//!Advertising flags
#define LE_LIMITED_DISCOVERABLE                         0x01
#define LE_GENERAL_DISCOVERABLE                         0x02
#define LE_BR_EDR_NOT_SUPPORTED                         0x04

//!Advertise filters
#define ALLOW_SCAN_REQ_ANY_CONN_REQ_ANY                 0x00
#define ALLOW_SCAN_REQ_ACCEPT_LIST_CONN_REQ_ANY         0x01
#define ALLOW_SCAN_REQ_ANY_CONN_REQ_ACCEPT_LIST         0x02
#define ALLOW_SCAN_REQ_ACCEPT_LIST_CONN_REQ_ACCEPT_LIST 0x03

//! Address types
#define LE_PUBLIC_ADDRESS                               0x00
#define LE_RANDOM_ADDRESS                               0x01
#define LE_RESOLVABLE_PUBLIC_ADDRESS                    0x02
#define LE_RESOLVABLE_RANDOM_ADDRESS                    0x03

/*=======================================================================*/

/*=======================================================================*/
//! Connection parameters
/*=======================================================================*/
#define LE_SCAN_INTERVAL                                0x0050
#define LE_SCAN_WINDOW                                  0x0030

#define CONNECTION_INTERVAL_MIN 0x00A0
#define CONNECTION_INTERVAL_MAX 0x00A0

#define CONNECTION_LATENCY  0x0000
#define SUPERVISION_TIMEOUT 0x07D0 //2000

/*=======================================================================*/

/*=======================================================================*/
//! Scan command parameters
/*=======================================================================*/

#define RSI_BLE_SCAN_TYPE                  SCAN_TYPE_ACTIVE
#define RSI_BLE_SCAN_FILTER_TYPE           SCAN_FILTER_TYPE_ALL

//!Scan status
#define RSI_BLE_START_SCAN                 0x01
#define RSI_BLE_STOP_SCAN                  0x00

//!Scan types
#define SCAN_TYPE_ACTIVE                   0x01
#define SCAN_TYPE_PASSIVE                  0x00

//!Scan filters
#define SCAN_FILTER_TYPE_ALL               0x00
#define SCAN_FILTER_TYPE_ONLY_ACCEPT_LISTT 0x01

#define RSI_SEL_INTERNAL_ANTENNA 0x00
#define RSI_SEL_EXTERNAL_ANTENNA 0x01

#include "rsi_ble_common_config.h"
#endif
#endif /* RSI_BLE_CONFIG_DEF_H */
