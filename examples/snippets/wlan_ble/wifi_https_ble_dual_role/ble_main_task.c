/*******************************************************************************
* @file  ble_main_task.c
* @brief 
*******************************************************************************
* # License
* <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
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
 *
 *  @section Licenseremote_name
 *  This program should be used on your own responsibility.
 *  Silicon Labs assumes no responsibility for any losses
 *  incurred by customers or third parties arising from the use of this file.
 *
 *  @brief : This file contains code to create multiple task instances and handling of ble events
 *
 *  @section Description  This file contains code to create multiple task instances and handling of ble events
 */

/*=======================================================================*/
//   ! INCLUDES
/*=======================================================================*/

#include <stdio.h>
#include <string.h>

#include "ble_device_info.h"
#include <rsi_ble.h>
#include "app_common_config.h"
#include "ble_config.h"
#include "ble_device_info.h"
#include "wifi_app_config.h"
#include "rsi_ble_apis.h"
#include "rsi_bt_common_apis.h"
#include "sl_constants.h"
#include "rsi_common_apis.h"

#if RSI_ENABLE_BLE_TEST
/*=======================================================================*/
//   ! MACROS
/*=======================================================================*/

#define RSI_BT_LE_SC_JUST_WORKS 0x01
#define RSI_BT_LE_SC_PASSKEY    0x02

/*=======================================================================*/
//   ! GLOBAL VARIABLES
/*=======================================================================*/
osThreadId_t ble_app_task_handle[TOTAL_CONNECTIONS] = { NULL };
uint8_t ble_conn_id = 0xFF, peripheral_connection_in_prgs = 0, peripheral_con_req_pending = 0;
uint16_t rsi_scan_in_progress;
uint32_t ble_main_app_event_task_map;
uint32_t ble_app_event_task_map[TOTAL_CONNECTIONS];
uint32_t ble_app_event_task_map1[TOTAL_CONNECTIONS];
uint8_t remote_device_role     = 0;
uint8_t central_task_instances = 0, peripheral_task_instances = 0;
volatile uint16_t rsi_disconnect_reason[TOTAL_CONNECTIONS] = { 0 };
volatile uint8_t ix, conn_done, conn_update_done, conn_update_central_done, num_of_conn_centrals = 0,
                                                                            num_of_conn_peripherals = 0;
volatile uint16_t rsi_ble_att1_val_hndl;
volatile uint16_t rsi_ble_att2_val_hndl;
volatile uint16_t rsi_ble_att3_val_hndl;
static uint8_t remote_dev_addr[RSI_REM_DEV_ADDR_LEN]      = { 0 };
static uint8_t remote_dev_addr_conn[RSI_REM_DEV_ADDR_LEN] = { 0 };
static volatile uint32_t ble_app_event_map;
static volatile uint32_t ble_app_event_map1;
static uint8_t central_conn_id                             = 0xff;
static uint8_t peripheral_conn_id                          = 0xff;
static uint8_t rsi_app_resp_get_dev_addr[RSI_DEV_ADDR_LEN] = { 0 };

#if ENABLE_NWP_POWER_SAVE
extern osMutexId_t power_cmd_mutex;
extern bool powersave_cmd_given;
#endif

#if (CONNECT_OPTION == CONN_BY_NAME)
static uint8_t remote_name[RSI_REM_DEV_NAME_LEN];
#endif
rsi_ble_t att_list;
rsi_ble_req_adv_t change_adv_param;
rsi_ble_req_scan_t change_scan_param;
osSemaphoreId_t ble_conn_sem[TOTAL_CONNECTIONS];

/*=======================================================================*/
//   ! EXTERN VARIABLES
/*=======================================================================*/
extern rsi_ble_conn_info_t rsi_ble_conn_info[];
extern rsi_parsed_conf_t rsi_parsed_conf;
extern osSemaphoreId_t ble_main_task_sem, ble_peripheral_conn_sem;
#if WLAN_SYNC_REQ
extern osSemaphoreId_t sync_coex_ble_sem;
#endif
extern bool rsi_wlan_running;

/*========================================================================*/
//!  CALLBACK FUNCTIONS
/*=======================================================================*/

/*=======================================================================*/
//   ! EXTERN FUNCTIONS
/*=======================================================================*/

/*=======================================================================*/
//   ! PROCEDURES
/*=======================================================================*/

/*==============================================*/
/**
 * @fn         rsi_ble_app_set_task_event
 * @brief      set the specific event.
 * @param[in]  event_num, specific event number.
 * @return     none.
 * @section description
 * This function is used to set/raise the specific event.
 */
void rsi_ble_app_set_task_event(uint8_t conn_id, uint32_t event_num)
{
  if (event_num < 32) {
    ble_app_event_task_map[conn_id] |= BIT(event_num);
  } else {
    ble_app_event_task_map1[conn_id] |= BIT((event_num - 32));
  }
  osSemaphoreRelease(ble_conn_sem[conn_id]);
}

/*==============================================*/
/**
 * @fn         rsi_ble_app_init_events
 * @brief      initializes the event parameter.
 * @param[in]  none.
 * @return     none.
 * @section description
 * This function is used during BLE initialization.
 */
static void rsi_ble_app_init_events()
{
  ble_app_event_map  = 0;
  ble_app_event_map1 = 0;
  return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_app_set_event
 * @brief      set the specific event.
 * @param[in]  event_num, specific event number.
 * @return     none.
 * @section description
 * This function is used to set/raise the specific event.
 */
void rsi_ble_app_set_event(uint32_t event_num)
{
  if (event_num < 32) {
    ble_app_event_map |= BIT(event_num);
  } else {
    ble_app_event_map1 |= BIT((event_num - 32));
  }
  osSemaphoreRelease(ble_main_task_sem);
  return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_app_clear_event
 * @brief      clears the specific event.
 * @param[in]  event_num, specific event number.
 * @return     none.
 * @section description
 * This function is used to clear the specific event.
 */
static void rsi_ble_app_clear_event(uint32_t event_num)
{
  if (event_num < 32) {
    ble_app_event_map &= ~BIT(event_num);
  } else {
    ble_app_event_map1 &= ~BIT((event_num - 32));
  }
  return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_app_get_event
 * @brief      returns the first set event based on priority
 * @param[in]  none.
 * @return     int32_t
 *             > 0  = event number
 *             -1   = not received any event
 * @section description
 * This function returns the highest priority event among all the set events
 */
static int32_t rsi_ble_app_get_event(void)
{
  uint32_t ix;

  for (ix = 0; ix < 64; ix++) {
    if (ix < 32) {
      if (ble_app_event_map & (1 << ix)) {
        return ix;
      }
    } else {
      if (ble_app_event_map1 & (1 << (ix - 32))) {
        return ix;
      }
    }
  }
  return (-1);
}

uint8_t rsi_check_dev_central_list(uint8_t *rem_dev_addr)
{
  uint8_t i                    = 0;
  uint8_t central_device_found = NO_DEV_FOUND;

  //! check if central device is already connected
  for (i = 0; i < TOTAL_CONNECTIONS; i++) {
    if (!memcmp(rsi_ble_conn_info[i].remote_dev_addr, rem_dev_addr, RSI_REM_DEV_ADDR_LEN)) {
      central_device_found = DEV_CONNECTED;
      break;
    }
  }

  if (i == TOTAL_CONNECTIONS) {
    central_device_found = DEV_NOT_CONNECTED;
  }
  return central_device_found;
}
/*==============================================*/
/**
 * @fn         rsi_check_dev_list
 * @brief      returns the status of peripheral devices state
 * @param[in]  remote_dev_name - remote device name.
 * 				adv_dev_addr - remote device address
 * @return     uint8_t
 *             NO_PERIPHERAL_FOUND - peripheral address/name doesn't match
 *             PERIPHERAL_FOUND   - peripheral address/name matches
 *             PERIPHERAL_NOT_CONNECTED - peripheral address/name matches and peripheral not yet connected
 *             PERIPHERAL_CONNECTED - peripheral address/name matches and peripheral already connected
 *
 * @section description
 * This function is called when advertise report received and when received checks the address/name with configured names
 */
uint8_t rsi_check_dev_list(uint8_t *remote_dev_name, uint8_t *adv_dev_addr)
{
  uint8_t i                       = 0;
  uint8_t peripheral_device_found = NO_DEV_FOUND;

#if (CONNECT_OPTION == CONN_BY_NAME)
  UNUSED_PARAMETER(adv_dev_addr); //This statement is added only to resolve compilation warning, value is unchanged
#else
  UNUSED_PARAMETER(remote_dev_name); //This statement is added only to resolve compilation warning, value is unchanged
#endif

#if (CONNECT_OPTION == CONN_BY_NAME)
  if (((strcmp((const char *)remote_dev_name, RSI_REMOTE_DEVICE_NAME1)) == 0)
      || ((strcmp((const char *)remote_dev_name, RSI_REMOTE_DEVICE_NAME2)) == 0)) {
    peripheral_device_found = DEV_FOUND;
  } else
    return peripheral_device_found;

  //! check if remote device already connected or advertise report received- TODO .  Can check efficiently?
  if (peripheral_device_found == DEV_FOUND) {
    for (i = 0; i < TOTAL_CONNECTIONS; i++) {
      if ((const char *)rsi_ble_conn_info[i].rsi_remote_name != NULL) {
        if (!(strcmp((const char *)rsi_ble_conn_info[i].rsi_remote_name, (const char *)remote_dev_name))) {
          peripheral_device_found = DEV_CONNECTED;
#if RSI_DEBUG_EN
          LOG_PRINT("\r\nDevice %s already connected!!!\r\n", adv_dev_addr);
#endif
          break;
        }
      }
    }
  }
#else
  if ((!strcmp(RSI_BLE_DEV_1_ADDR, (char *)adv_dev_addr)) || (!strcmp(RSI_BLE_DEV_2_ADDR, (char *)adv_dev_addr))) {
    peripheral_device_found = DEV_FOUND;
  } else {
    return peripheral_device_found;
  }

  //! check if remote device already connected
  if (peripheral_device_found == DEV_FOUND) {
    for (i = 0; i < TOTAL_CONNECTIONS; i++) {
      if (!memcmp(rsi_ble_conn_info[i].remote_dev_addr, adv_dev_addr, RSI_REM_DEV_ADDR_LEN)) {
        peripheral_device_found = DEV_CONNECTED;
#if RSI_DEBUG_EN
        LOG_PRINT("\r\nDevice %s already connected!!!\r\n", adv_dev_addr);
#endif
        break;
      }
    }
  }
#endif
  if (i == TOTAL_CONNECTIONS) {
    peripheral_device_found = DEV_NOT_CONNECTED;
  }

  return peripheral_device_found;
}

/*==============================================*/
/**
 * @fn         rsi_ble_add_char_serv_att
 * @brief      this function is used to add characteristic service attribute..
 * @param[in]  serv_handler, service handler.
 * @param[in]  handle, characteristic service attribute handle.
 * @param[in]  val_prop, characteristic value property.
 * @param[in]  att_val_handle, characteristic value handle
 * @param[in]  att_val_uuid, characteristic value uuid
 * @return     none.
 * @section description
 * This function is used at application to add characteristic attribute
 */
static void rsi_ble_add_char_serv_att(void *serv_handler,
                                      uint16_t handle,
                                      uint8_t val_prop,
                                      uint16_t att_val_handle,
                                      uuid_t att_val_uuid)
{
  rsi_ble_req_add_att_t new_att = { 0 };

  //! preparing the attribute service structure
  new_att.serv_handler       = serv_handler;
  new_att.handle             = handle;
  new_att.att_uuid.size      = 2;
  new_att.att_uuid.val.val16 = RSI_BLE_CHAR_SERV_UUID;
  new_att.property           = RSI_BLE_ATT_PROPERTY_READ;

  //! preparing the characteristic attribute value
  new_att.data_len = att_val_uuid.size + 4;
  new_att.data[0]  = val_prop;
  rsi_uint16_to_2bytes(&new_att.data[2], att_val_handle);
  if (new_att.data_len == 6) {
    rsi_uint16_to_2bytes(&new_att.data[4], att_val_uuid.val.val16);
  } else if (new_att.data_len == 8) {
    rsi_uint32_to_4bytes(&new_att.data[4], att_val_uuid.val.val32);
  } else if (new_att.data_len == 20) {
    memcpy(&new_att.data[4], &att_val_uuid.val.val128, att_val_uuid.size);
  }
  //! Add attribute to the service
  rsi_ble_add_attribute(&new_att);

  return;
}

/*==============================================*/
/**
 * @fn         rsi_gatt_add_attribute_to_list
 * @brief      This function is used to store characteristic service attribute.
 * @param[in]  p_val, pointer to homekit structure
 * @param[in]  handle, characteristic service attribute handle.
 * @param[in]  data_len, characteristic value length
 * @param[in]  data, characteristic value pointer
 * @param[in]  uuid, characteristic value uuid
 * @return     none.
 * @section description
 * This function is used to store all attribute records
 */
void rsi_gatt_add_attribute_to_list(rsi_ble_t *p_val,
                                    uint16_t handle,
                                    uint16_t data_len,
                                    uint8_t *data,
                                    uuid_t uuid,
                                    uint8_t char_prop)
{
  if ((p_val->DATA_ix + data_len) >= BLE_ATT_REC_SIZE) { //! Check for max data length for the characteristic value
    LOG_PRINT("\r\n no data memory for att rec values \r\n");
    return;
  }

  p_val->att_rec_list[p_val->att_rec_list_count].char_uuid     = uuid;
  p_val->att_rec_list[p_val->att_rec_list_count].handle        = handle;
  p_val->att_rec_list[p_val->att_rec_list_count].value_len     = data_len;
  p_val->att_rec_list[p_val->att_rec_list_count].max_value_len = data_len;
  p_val->att_rec_list[p_val->att_rec_list_count].char_val_prop = char_prop;
  memcpy(p_val->DATA + p_val->DATA_ix, data, data_len);
  p_val->att_rec_list[p_val->att_rec_list_count].value = p_val->DATA + p_val->DATA_ix;
  p_val->att_rec_list_count++;
  p_val->DATA_ix += p_val->att_rec_list[p_val->att_rec_list_count].max_value_len;

  return;
}

/*==============================================*/
/**
 * @fn         rsi_gatt_get_attribute_from_list
 * @brief      This function is used to retrieve attribute from list based on handle.
 * @param[in]  p_val, pointer to characteristic structure
 * @param[in]  handle, characteristic service attribute handle.
 * @return     pointer to the attribute
 * @section description
 * This function is used to store all attribute records
 */
rsi_ble_att_list_t *rsi_gatt_get_attribute_from_list(rsi_ble_t *p_val, uint16_t handle)
{
  uint16_t i;
  for (i = 0; i < p_val->att_rec_list_count; i++) {
    if (p_val->att_rec_list[i].handle == handle) {
      //*val_prop = p_val.att_rec_list[i].char_val_prop;
      //*length = p_val.att_rec_list[i].value_len;
      //*max_data_len = p_val.att_rec_list[i].max_value_len;
      return &(p_val->att_rec_list[i]);
    }
  }
  return 0;
}

/*==============================================*/
/**
 * @fn         rsi_ble_add_char_val_att
 * @brief      this function is used to add characteristic value attribute.
 * @param[in]  serv_handler, new service handler.
 * @param[in]  handle, characteristic value attribute handle.
 * @param[in]  att_type_uuid, attribute uuid value.
 * @param[in]  val_prop, characteristic value property.
 * @param[in]  data, characteristic value data pointer.
 * @param[in]  data_len, characteristic value length.
 * @return     none.
 * @section description
 * This function is used at application to create new service.
 */

static void rsi_ble_add_char_val_att(void *serv_handler,
                                     uint16_t handle,
                                     uuid_t att_type_uuid,
                                     uint8_t val_prop,
                                     uint8_t *data,
                                     uint8_t data_len,
                                     uint8_t auth_read)
{
  rsi_ble_req_add_att_t new_att = { 0 };

  //! preparing the attributes
  new_att.serv_handler  = serv_handler;
  new_att.handle        = handle;
  new_att.config_bitmap = auth_read;
  memcpy(&new_att.att_uuid, &att_type_uuid, sizeof(uuid_t));
  new_att.property = val_prop;

  if (data != NULL)
    memcpy(new_att.data, data, RSI_MIN(sizeof(new_att.data), data_len));

  //! preparing the attribute value
  new_att.data_len = data_len;

  //! add attribute to the service
  rsi_ble_add_attribute(&new_att);

  if ((auth_read == ATT_REC_MAINTAIN_IN_HOST) || (data_len > 20)) {
    if (data != NULL) {
      rsi_gatt_add_attribute_to_list(&att_list, handle, data_len, data, att_type_uuid, val_prop);
    }
  }

  //! check the attribute property with notification/Indication
  if ((val_prop & RSI_BLE_ATT_PROPERTY_NOTIFY) || (val_prop & RSI_BLE_ATT_PROPERTY_INDICATE)) {
    //! if notification/indication property supports then we need to add client characteristic service.

    //! preparing the client characteristic attribute & values
    memset(&new_att, 0, sizeof(rsi_ble_req_add_att_t));
    new_att.serv_handler       = serv_handler;
    new_att.handle             = handle + 1;
    new_att.att_uuid.size      = 2;
    new_att.att_uuid.val.val16 = RSI_BLE_CLIENT_CHAR_UUID;
    new_att.property           = RSI_BLE_ATT_PROPERTY_READ | RSI_BLE_ATT_PROPERTY_WRITE;
    new_att.data_len           = 2;

    //! add attribute to the service
    rsi_ble_add_attribute(&new_att);
  }

  return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_add_simple_chat_serv
 * @brief      this function is used to add new servcie i.e.., simple chat service.
 * @param[in]  none.
 * @return     int32_t
 *             0  =  success
 *             !0 = failure
 * @section description
 * This function is used at application to create new service.
 */

static uint32_t rsi_ble_add_simple_chat_serv(void)
{
  uuid_t new_uuid                       = { 0 };
  rsi_ble_resp_add_serv_t new_serv_resp = { 0 };
  uint8_t data[230]                     = { 1, 0 };

  //! adding new service
  new_uuid.size      = 2;
  new_uuid.val.val16 = RSI_BLE_NEW_SERVICE_UUID;
  rsi_ble_add_service(new_uuid, &new_serv_resp);

  //! adding characteristic service attribute to the service
  new_uuid.size      = 2;
  new_uuid.val.val16 = RSI_BLE_ATTRIBUTE_1_UUID;
  rsi_ble_add_char_serv_att(new_serv_resp.serv_handler,
                            new_serv_resp.start_handle + 1,
                            RSI_BLE_ATT_PROPERTY_READ | RSI_BLE_ATT_PROPERTY_NOTIFY | RSI_BLE_ATT_PROPERTY_WRITE,
                            new_serv_resp.start_handle + 2,
                            new_uuid);

  //! adding characteristic value attribute to the service
  rsi_ble_att1_val_hndl = new_serv_resp.start_handle + 2;
  new_uuid.size         = 2;
  new_uuid.val.val16    = RSI_BLE_ATTRIBUTE_1_UUID;
  rsi_ble_add_char_val_att(new_serv_resp.serv_handler,
                           new_serv_resp.start_handle + 2,
                           new_uuid,
                           RSI_BLE_ATT_PROPERTY_READ | RSI_BLE_ATT_PROPERTY_NOTIFY | RSI_BLE_ATT_PROPERTY_WRITE,
                           data,
                           sizeof(data),
                           1);

  return 0;
}

/*==============================================*/
/**
 * @fn         rsi_ble_add_simple_chat_serv3
 * @brief      this function is used to add new servcie i.e.., simple chat service.
 * @param[in]  none.
 * @return     int32_t
 *             0  =  success
 *             !0 = failure
 * @section description
 * This function is used at application to create new service.
 */
static uint32_t rsi_ble_add_simple_chat_serv3(void)
{
  //! adding the custom service
  // 0x6A4E3300-667B-11E3-949A-0800200C9A66
  uint8_t data1[231]                 = { 1, 0 };
  static const uuid_t custom_service = { .size             = 16,
                                         .reserved         = { 0x00, 0x00, 0x00 },
                                         .val.val128.data1 = 0x6A4E3300,
                                         .val.val128.data2 = 0x667B,
                                         .val.val128.data3 = 0x11E3,
                                         .val.val128.data4 = { 0x9A, 0x94, 0x00, 0x08, 0x66, 0x9A, 0x0C, 0x20 } };

  // 0x6A4E3304-667B-11E3-949A-0800200C9A66
  static const uuid_t custom_characteristic = {
    .size             = 16,
    .reserved         = { 0x00, 0x00, 0x00 },
    .val.val128.data1 = 0x6A4E3304,
    .val.val128.data2 = 0x667B,
    .val.val128.data3 = 0x11E3,
    .val.val128.data4 = { 0x9A, 0x94, 0x00, 0x08, 0x66, 0x9A, 0x0C, 0x20 }
  };

  rsi_ble_resp_add_serv_t new_serv_resp = { 0 };
  rsi_ble_add_service(custom_service, &new_serv_resp);

  //! adding custom characteristic declaration to the custom service
  rsi_ble_add_char_serv_att(new_serv_resp.serv_handler,
                            new_serv_resp.start_handle + 1,
                            RSI_BLE_ATT_PROPERTY_WRITE_NO_RESPONSE, //Set read, write, write without response
                            new_serv_resp.start_handle + 2,
                            custom_characteristic);

  //! adding characteristic value attribute to the service
  rsi_ble_att2_val_hndl = new_serv_resp.start_handle + 2;
  rsi_ble_add_char_val_att(new_serv_resp.serv_handler,
                           new_serv_resp.start_handle + 2,
                           custom_characteristic,
                           RSI_BLE_ATT_PROPERTY_WRITE_NO_RESPONSE, //Set read, write, write without response
                           data1,
                           sizeof(data1),
                           1);
  return 0;
}

/*==============================================*/
/**
 * @fn         rsi_ble_add_custom_service_serv
 * @brief      this function is used to add new servcie i.e.., custom service
 * @param[in]  none.
 * @return     int32_t
 *             0  =  success
 *             !0 = failure
 * @section description
 * This function is used at application to create new service.
 */

static uint32_t rsi_ble_add_custom_service_serv(void)
{
  uuid_t new_uuid                       = { 0 };
  rsi_ble_resp_add_serv_t new_serv_resp = { 0 };
  uint8_t data[1]                       = { 90 };
  rsi_ble_pesentation_format_t presentation_format;
  uint8_t format_data[7];

  //!adding descriptor fileds
  format_data[0] = presentation_format.format = RSI_BLE_UINT8_FORMAT;
  format_data[1] = presentation_format.exponent = RSI_BLE_EXPONENT;
  presentation_format.unit                      = RSI_BLE_PERCENTAGE_UNITS_UUID;
  memcpy(&format_data[2], &presentation_format.unit, sizeof(presentation_format.unit));
  format_data[4] = presentation_format.name_space = RSI_BLE_NAME_SPACE;
  presentation_format.description                 = RSI_BLE_DESCRIPTION;
  memcpy(&format_data[5], &presentation_format.description, sizeof(presentation_format.description));

  //! adding new service
  new_uuid.size      = 2;
  new_uuid.val.val16 = RSI_BLE_CUSTOM_SERVICE_UUID;
  rsi_ble_add_service(new_uuid, &new_serv_resp);

  //! adding characteristic service attribute to the service
  new_uuid.size      = 2;
  new_uuid.val.val16 = RSI_BLE_CUSTOM_LEVEL_UUID;
  rsi_ble_add_char_serv_att(new_serv_resp.serv_handler,
                            new_serv_resp.start_handle + 1,
                            RSI_BLE_ATT_PROPERTY_READ | RSI_BLE_ATT_PROPERTY_INDICATE,
                            new_serv_resp.start_handle + 2,
                            new_uuid);
  //! adding characteristic value attribute to the service
  rsi_ble_att3_val_hndl = new_serv_resp.start_handle + 2;
  new_uuid.size         = 2;
  new_uuid.val.val16    = RSI_BLE_CUSTOM_LEVEL_UUID;
  rsi_ble_add_char_val_att(new_serv_resp.serv_handler,
                           new_serv_resp.start_handle + 2,
                           new_uuid,
                           RSI_BLE_ATT_PROPERTY_READ | RSI_BLE_ATT_PROPERTY_INDICATE,
                           data,
                           sizeof(data),
                           1);

  new_uuid.size      = 2;
  new_uuid.val.val16 = RSI_BLE_CHAR_PRESENTATION_FORMATE_UUID;
  rsi_ble_add_char_val_att(new_serv_resp.serv_handler,
                           new_serv_resp.start_handle + 4,
                           new_uuid,
                           RSI_BLE_ATT_PROPERTY_READ,
                           format_data,
                           sizeof(format_data),
                           1);

  return 0;
}

/*==============================================*/
/**
 * @fn         rsi_ble_simple_peripheral_on_remote_features_event
 * @brief      invoked when LE remote features event is received.
 * @param[in] resp_conn, connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection
 */
void rsi_ble_simple_peripheral_on_remote_features_event(rsi_ble_event_remote_features_t *rsi_ble_event_remote_features)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_remote_features->dev_addr);

  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].remote_dev_feature,
         rsi_ble_event_remote_features,
         sizeof(rsi_ble_event_remote_features_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_RECEIVE_REMOTE_FEATURES);
}

/*==============================================*/
/**
 * @fn         rsi_ble_simple_central_on_adv_report_event
 * @brief      invoked when advertise report event is received
 * @param[in]  adv_report, pointer to the received advertising report
 * @return     none.
 * @section description
 * This callback function updates the scanned remote devices list
 */
void rsi_ble_simple_central_on_adv_report_event(rsi_ble_event_adv_report_t *adv_report)
{
  uint8_t device_already_connected = 0;

  if (adv_report->report_type == 0x02) {
    return; // return for NON CONN ADV PACKETS
  }

  //! Need to ignore advertising reports until one peripheral connection is completed successfully
  if ((peripheral_connection_in_prgs) || (peripheral_con_req_pending)) {
    return;
  }

  //! Need to ignore advertising reports when the max peripheral connections is reached
  if (peripheral_task_instances >= RSI_BLE_MAX_NBR_PERIPHERALS) {
    return;
  }

  rsi_6byte_dev_address_to_ascii(remote_dev_addr, (uint8_t *)adv_report->dev_addr);

#if (CONNECT_OPTION == CONN_BY_NAME)
  memset(remote_name, 0, sizeof(remote_name));

  BT_LE_ADPacketExtract(remote_name, adv_report->adv_data, adv_report->adv_data_len);
#if RSI_DEBUG_EN
  //LOG_PRINT("\r\n advertised details remote_name = %s, dev_addr = %s \r\n",remote_name,(int8_t *) remote_dev_addr);
#endif

  device_already_connected = rsi_check_dev_list(remote_name, remote_dev_addr);
#else
  device_already_connected = rsi_check_dev_list(NULL, remote_dev_addr);
#endif

  if (device_already_connected == DEV_NOT_CONNECTED) {
    //! convert to ascii
    rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, adv_report->dev_addr);

    //! get conn_id
#if (CONNECT_OPTION == CONN_BY_NAME)
    ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, remote_name, strlen((char *)remote_name));
#else
    ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);
#endif
    //! check if conn_id is valid
    if (ble_conn_id < TOTAL_CONNECTIONS) {
      rsi_ble_conn_info[ble_conn_id].remote_device_role = PERIPHERAL_ROLE; //! remote device is peripheral
      memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_app_adv_reports_to_app,
             adv_report,
             sizeof(rsi_ble_event_adv_report_t));
      peripheral_con_req_pending = 1;
      peripheral_conn_id         = ble_conn_id;
      //! set common event
      rsi_ble_app_set_event(RSI_APP_EVENT_ADV_REPORT);
    } else {
      //! wrong state
      LOG_PRINT("Connection identifier is wrong\r\n");
      while (1)
        ;
    }
  }
  return;
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_connect_event
 * @brief      invoked when connection complete event is received
 * @param[out] resp_conn, connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection
 */
static void rsi_ble_on_connect_event(rsi_ble_event_conn_status_t *resp_conn)
{
  uint8_t central_dev_found = NO_DEV_FOUND;
#if RSI_DEBUG_EN
  LOG_PRINT("In on conn cb\r\n");
#endif
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, resp_conn->dev_addr);

  //! Check whether the received connected event came from remote peripheral or central
  remote_device_role = rsi_get_remote_device_role(remote_dev_addr_conn);

  if (resp_conn->status != 0) {
    //LOG_PRINT("\r\n On connect event status report : %d", resp_conn->status);
    if (remote_device_role == PERIPHERAL_ROLE) {
      peripheral_connection_in_prgs = 0;
    }
    //! Restarting scan
    rsi_ble_app_set_event(RSI_BLE_SCAN_RESTART_EVENT);
    return;
  }

  if (remote_device_role == PERIPHERAL_ROLE) //check for the connection is from peripheral or central
  {
    //! get conn_id
    ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

    //! copy to conn specific buffer
    memcpy(&rsi_ble_conn_info[ble_conn_id].conn_event_to_app, resp_conn, sizeof(rsi_ble_event_conn_status_t));
    peripheral_connection_in_prgs = 0;

    //! set conn specific event
    rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_CONN_EVENT);

    //! unblock connection semaphore
    osSemaphoreRelease(ble_peripheral_conn_sem);
  } else if (remote_device_role == CENTRAL_ROLE) {
    central_dev_found = rsi_check_dev_central_list(remote_dev_addr_conn);
    if (central_dev_found == DEV_NOT_CONNECTED) {
      ble_conn_id = rsi_add_ble_conn_id(remote_dev_addr_conn, NULL, 0);

      //! check if conn_id is valid
      if (ble_conn_id < TOTAL_CONNECTIONS) {
        rsi_ble_conn_info[ble_conn_id].remote_device_role = CENTRAL_ROLE; //! remote device is peripheral
        memcpy(&rsi_ble_conn_info[ble_conn_id].conn_event_to_app, resp_conn, sizeof(rsi_ble_event_conn_status_t));
        rsi_ble_conn_info[ble_conn_id].is_enhanced_conn = false;
        central_conn_id                                 = ble_conn_id;
        //! set common event
        rsi_ble_app_set_event(RSI_BLE_CONN_EVENT);
      } else {
        //! wrong state
        LOG_PRINT("\nConnection identifier is wrong\r\n");
        while (1)
          ;
      }
    } else {
      LOG_PRINT("\nDevice already connected \r\n");
    }
  } else {
    LOG_PRINT("\nCHECK WHY THIS STATE OCCURS IN CONNECTION \r\n");
    while (1)
      ;
  }
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_enhance_conn_status_event
 * @brief      invoked when enhanced connection complete event is received
 * @param[out] resp_conn, connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection
 */
void rsi_ble_on_enhance_conn_status_event(rsi_ble_event_enhance_conn_status_t *resp_enh_conn)
{
  uint8_t central_dev_found = NO_DEV_FOUND;
#if RSI_DEBUG_EN
  LOG_PRINT("\nIn on_enhance_conn cb\r\n");
#endif
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, resp_enh_conn->dev_addr);

  //! Check whether the received connected event came from remote peripheral or central
  remote_device_role = rsi_get_remote_device_role(remote_dev_addr_conn);

  if (resp_enh_conn->status != 0 && resp_enh_conn->status != 63) {
    LOG_PRINT("\nOn enhanced connect event\r\n");
    if (remote_device_role == PERIPHERAL_ROLE) {
      peripheral_connection_in_prgs = 0;
    }
    rsi_ble_app_set_event(RSI_BLE_SCAN_RESTART_EVENT);
    return;
  }

  if (remote_device_role == PERIPHERAL_ROLE) //check for the connection is from peripheral or central
  {
    ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);
    //! copy to conn specific buffer
    memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_enhc_conn_status,
           resp_enh_conn,
           sizeof(rsi_ble_event_enhance_conn_status_t));

    peripheral_connection_in_prgs = 0;

    //! set conn specific event
    rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_ENHC_CONN_EVENT);

    //! unblock connection semaphore
    osSemaphoreRelease(ble_peripheral_conn_sem);
  } else if (remote_device_role == CENTRAL_ROLE) {
    central_dev_found = rsi_check_dev_central_list(remote_dev_addr_conn);
    if (central_dev_found == DEV_NOT_CONNECTED) {
      ble_conn_id = rsi_add_ble_conn_id(remote_dev_addr_conn, NULL, 0);

      //! check if conn_id is valid
      if (ble_conn_id < TOTAL_CONNECTIONS) {
        rsi_ble_conn_info[ble_conn_id].remote_device_role = CENTRAL_ROLE; //! remote device is peripheral
        memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_enhc_conn_status,
               resp_enh_conn,
               sizeof(rsi_ble_event_enhance_conn_status_t));
        rsi_ble_conn_info[ble_conn_id].is_enhanced_conn = true;
        central_conn_id                                 = ble_conn_id;
        //! set common event
        rsi_ble_app_set_event(RSI_BLE_ENHC_CONN_EVENT);
      } else {
        //! wrong state
        LOG_PRINT("\nConnection identifier is wrong \r\n");
        while (1)
          ;
      }
    } else {
      LOG_PRINT("\nDevice already connected\r\n");
    }
  } else {
    LOG_PRINT("\nCHECK WHY THIS STATE OCCURS IN CONNECTION \r\n");
    while (1)
      ;
  }
}
/*==============================================*/
/**
 * @fn         ble_on_conn_update_complete_event
 * @brief      invoked when connection update complete event is received
 * @param[out] resp_conn, connected remote device information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection
 */
static void ble_on_conn_update_complete_event(rsi_ble_event_conn_update_t *resp_conn_update, uint16_t resp_status)
{
#if RSI_DEBUG_EN
  LOG_PRINT("\r\nIn conn update cb\r\n");
#endif
  if (resp_status != 0) {
    LOG_PRINT("\r\nRSI_BLE_CONN_UPDATE_EVENT FAILED\r\n");
    return;
  } else {
    //! convert to ascii
    rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, resp_conn_update->dev_addr);

    //! get conn_id
    ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

    //! copy to conn specific buffer
    memcpy(&rsi_ble_conn_info[ble_conn_id].conn_update_resp, resp_conn_update, sizeof(rsi_ble_event_conn_update_t));

    //! set conn specific event
    rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_CONN_UPDATE_COMPLETE_EVENT);
  }
}
/*==============================================*/
/**
 * @fn         rsi_ble_on_remote_conn_params_request_event
 * @brief      invoked when remote conn params request is received
 * @param[out] remote_conn_param, emote conn params request information
 * @return     none.
 * @section description
 * This callback function indicates the status of the connection
 */
static void rsi_ble_on_remote_conn_params_request_event(rsi_ble_event_remote_conn_param_req_t *remote_conn_param,
                                                        uint16_t status)
{
  UNUSED_PARAMETER(status); //This statement is added only to resolve compilation warning, value is unchanged
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, remote_conn_param->dev_addr);
  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_app_remote_device_conn_params,
         remote_conn_param,
         sizeof(rsi_ble_event_remote_conn_param_req_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_APP_EVENT_REMOTE_CONN_PARAM_REQ);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_disconnect_event
 * @brief      invoked when disconnection event is received
 * @param[in]  resp_disconnect, disconnected remote device information
 * @param[in]  reason, reason for disconnection.
 * @return     none.
 * @section description
 * This callback function indicates disconnected device information and status
 */
static void rsi_ble_on_disconnect_event(rsi_ble_event_disconnect_t *resp_disconnect, uint16_t reason)
{

  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, resp_disconnect->dev_addr);

  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_disconn_resp, resp_disconnect, sizeof(rsi_ble_event_disconnect_t));

  rsi_disconnect_reason[ble_conn_id] = reason;

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_DISCONN_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_write_resp
 * @brief      its invoked when write response received.
 * @param[in]  event_id, it indicates read event id.
 * @param[in]  rsi_ble_read_req, write respsonse event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when read events are received
 */
static void rsi_ble_on_event_write_resp(uint16_t event_status, rsi_ble_set_att_resp_t *rsi_ble_event_set_att_rs)
{
  //! convert to ascii
#if RSI_DEBUG_EN
  LOG_PRINT("\r\nIn write resp event\r\n");
#endif
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_set_att_rs->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_write_resp_event,
         rsi_ble_event_set_att_rs,
         sizeof(rsi_ble_set_att_resp_t));

  if (event_status != RSI_SUCCESS) {
    LOG_PRINT("\r\n write event response failed\r\n");
  } else {
    //! set conn specific event
    rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_WRITE_EVENT_RESP);
  }
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_event_indication_confirmation
 * @brief      this function will invoke when received indication confirmation event
 * @param[out] resp_id, response id
 * @param[out] status, status of the response
 * @return     none
 * @section description
 */
static void rsi_ble_on_event_indication_confirmation(uint16_t resp_status,
                                                     rsi_ble_set_att_resp_t *rsi_ble_event_set_att_rsp)
{
  UNUSED_PARAMETER(resp_status);

  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_set_att_rsp->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_INDICATION_CONFIRMATION);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_gatt_write_event
 * @brief      its invoked when write/notify/indication events are received.
 * @param[in]  event_id, it indicates write/notification event id.
 * @param[in]  rsi_ble_write, write event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when write/notify/indication events are received
 */
static void rsi_ble_on_gatt_write_event(uint16_t event_id, rsi_ble_event_write_t *rsi_ble_write)
{
  UNUSED_PARAMETER(event_id);
#if RSI_DEBUG_EN
  LOG_PRINT("\r\nIn write event \r\n");
#endif
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_write->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].app_ble_write_event, rsi_ble_write, sizeof(rsi_ble_event_write_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_WRITE_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_gatt_prepare_write_event
 * @brief      its invoked when prepared write events are received.
 * @param[in]  event_id, it indicates write/notification event id.
 * @param[in]  rsi_ble_write, write event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when write/notify/indication events are received
 */
static void rsi_ble_on_gatt_prepare_write_event(uint16_t event_id,
                                                rsi_ble_event_prepare_write_t *rsi_app_ble_prepared_write_event)
{
  UNUSED_PARAMETER(event_id); //This statement is added only to resolve compilation warning, value is unchanged
#if RSI_DEBUG_EN
  LOG_PRINT("\r\nIn rsi_ble_on_gatt_prepare_write_event \r\n");
#endif
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_app_ble_prepared_write_event->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].app_ble_prepared_write_event,
         rsi_app_ble_prepared_write_event,
         sizeof(rsi_ble_event_prepare_write_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_PREPARE_WRITE_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_gatt_execute_write_event
 * @brief      its invoked when prepared write events are received.
 * @param[in]  event_id, it indicates write/notification event id.
 * @param[in]  rsi_ble_write, write event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when write/notify/indication events are received
 */
static void rsi_ble_on_execute_write_event(uint16_t event_id, rsi_ble_execute_write_t *rsi_app_ble_execute_write_event)
{
  UNUSED_PARAMETER(event_id); //This statement is added only to resolve compilation warning, value is unchanged
#if RSI_DEBUG_EN
  LOG_PRINT("\r\nIn rsi_ble_on_execute_write_event \r\n");
#endif
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_app_ble_execute_write_event->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].app_ble_execute_write_event,
         rsi_app_ble_execute_write_event,
         sizeof(rsi_ble_execute_write_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_EXECUTE_WRITE_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_read_req_event
 * @brief      its invoked when read events are received.
 * @param[in]  event_id, it indicates read event id.
 * @param[in]  rsi_ble_read_req, read respsonse event parameters.
 * @return     none.
 * @section description
 * This callback function is invoked when read events are received
 */
static void rsi_ble_on_read_req_event(uint16_t event_id, rsi_ble_read_req_t *rsi_ble_read_req)
{
  UNUSED_PARAMETER(event_id); //This statement is added only to resolve compilation warning, value is unchanged
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_read_req->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].app_ble_read_event, rsi_ble_read_req, sizeof(rsi_ble_read_req_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_READ_REQ_EVENT);
}

static void rsi_ble_on_event_mtu_exchange_info(
  rsi_ble_event_mtu_exchange_information_t *rsi_ble_event_mtu_exchange_info)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_mtu_exchange_info->dev_addr);
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);
  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].mtu_exchange_info,
         rsi_ble_event_mtu_exchange_info,
         sizeof(rsi_ble_event_mtu_exchange_information_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_MTU_EXCHANGE_INFORMATION);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_mtu_event
 * @brief      its invoked when mtu exhange event is received.
 * @param[in]  rsi_ble_mtu, mtu event paramaters.
 * @return     none.
 * @section description
 * This callback function is invoked when  mtu exhange event is received
 */
static void rsi_ble_on_mtu_event(rsi_ble_event_mtu_t *rsi_ble_mtu)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_mtu->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].app_ble_mtu_event, rsi_ble_mtu, sizeof(rsi_ble_event_mtu_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_MTU_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_profiles_list_event
 * @brief      invoked when response is received for get list of services.
 * @param[out] p_ble_resp_profiles, profiles list details
 * @return     none
 * @section description
 */
static void rsi_ble_profiles_list_event(uint16_t resp_status, rsi_ble_event_profiles_list_t *rsi_ble_event_profiles)
{
  if (resp_status == 0x4A0A) {
    return;
  }
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_profiles->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].get_allprofiles,
         rsi_ble_event_profiles,
         sizeof(rsi_ble_event_profiles_list_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_PROFILES);
}

/*==============================================*/
/**
 * @fn         rsi_ble_profile_event
 * @brief      invoked when the specific service details are received for
 *             supported specific services.
 * @param[out] rsi_ble_event_profile, specific profile details
 * @return     none
 * @section description
 * This is a callback function
 */
static void rsi_ble_profile_event(uint16_t resp_status, rsi_ble_event_profile_by_uuid_t *rsi_ble_event_profile)
{
  UNUSED_PARAMETER(resp_status); //This statement is added only to resolve compilation warning, value is unchanged
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_profile->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].get_profile, rsi_ble_event_profile, sizeof(rsi_ble_event_profile_by_uuid_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_PROFILE);
}

/*==============================================*/
/**
 * @fn         rsi_ble_char_services_event
 * @brief      invoked when response is received for characteristic services details
 * @param[out] rsi_ble_event_char_services, list of characteristic services.
 * @return     none
 * @section description
 */
static void rsi_ble_char_services_event(uint16_t resp_status,
                                        rsi_ble_event_read_by_type1_t *rsi_ble_event_char_services)
{
  UNUSED_PARAMETER(resp_status); //This statement is added only to resolve compilation warning, value is unchanged
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_char_services->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].get_char_services,
         rsi_ble_event_char_services,
         sizeof(rsi_ble_event_read_by_type1_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_CHAR_SERVICES);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_read_resp_event
 * @brief      invoked when response is received for the characteristic descriptors details
 * @param[out] rsi_ble_event_att_value_t, list of descriptors response
 * @return     none
 * @section description
 */
static void rsi_ble_on_read_resp_event(uint16_t event_status, rsi_ble_event_att_value_t *rsi_ble_event_att_val)
{
  UNUSED_PARAMETER(event_status); //This statement is added only to resolve compilation warning, value is unchanged
#if RSI_DEBUG_EN
  LOG_PRINT("\n In GATT descriptor response event\r\n");
#endif

  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_att_val->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_char_descriptors,
         rsi_ble_event_att_val,
         sizeof(rsi_ble_event_att_value_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_DESC_SERVICES);
}

/*==============================================*/
/**
 * @fn         rsi_ble_phy_update_complete_event
 * @brief      invoked when disconnection event is received
 * @param[in]  resp_disconnect, disconnected remote device information
 * @param[in]  reason, reason for disconnection.
 * @return     none.
 * @section description
 * This Callback function indicates disconnected device information and status
 */
void rsi_ble_phy_update_complete_event(rsi_ble_event_phy_update_t *rsi_ble_event_phy_update_complete)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_event_phy_update_complete->dev_addr);
  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_APP_EVENT_PHY_UPDATE_COMPLETE);
}

#if SMP_ENABLE
/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_request
 * @brief      its invoked when smp request event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when an SMP request event is received(we are in Central mode)
 * Note: Peripheral requested to start SMP request, we have to send SMP request command
 */
static void rsi_ble_on_smp_request(rsi_bt_event_smp_req_t *remote_smp)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, remote_smp->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_event_smp_req, remote_smp, sizeof(rsi_bt_event_smp_req_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_SMP_REQ_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_response
 * @brief      its invoked when smp response event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when an SMP response event is received(we are in peripheral mode)
 * Note: Central initiated SMP protocol, we have to send SMP response command
 */
void rsi_ble_on_smp_response(rsi_bt_event_smp_resp_t *remote_smp)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, remote_smp->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_event_smp_resp, remote_smp, sizeof(rsi_bt_event_smp_resp_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_SMP_RESP_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_passkey
 * @brief      its invoked when smp passkey event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP passkey events is received
 * Note: We have to send SMP passkey command
 */
static void rsi_ble_on_smp_passkey(rsi_bt_event_smp_passkey_t *smp_pass_key)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, smp_pass_key->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_event_smp_passkey, smp_pass_key, sizeof(rsi_bt_event_smp_passkey_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_SMP_PASSKEY_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_passkey_display
 * @brief      its invoked when smp passkey event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP passkey events is received
 * Note: We have to send SMP passkey command
 */
static void rsi_ble_on_smp_passkey_display(rsi_bt_event_smp_passkey_display_t *smp_passkey_display)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, smp_passkey_display->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_smp_passkey_display,
         smp_passkey_display,
         sizeof(rsi_bt_event_smp_passkey_display_t));

  //! set connection specific event
  //! signal connection specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_SMP_PASSKEY_DISPLAY_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_sc_passkey
 * @brief      its invoked when smp passkey event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP passkey events is received
 * Note: We have to send SMP passkey command
 */
static void rsi_ble_on_sc_passkey(rsi_bt_event_sc_passkey_t *sc_passkey)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, sc_passkey->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_event_sc_passkey, sc_passkey, sizeof(rsi_bt_event_sc_passkey_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_SC_PASSKEY_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_smp_failed
 * @brief      its invoked when smp failed event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when SMP failed events is received
 */
static void rsi_ble_on_smp_failed(uint16_t status, rsi_bt_event_smp_failed_t *remote_dev_address)
{
  UNUSED_PARAMETER(status);
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, remote_dev_address->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_smp_failed, remote_dev_address, sizeof(rsi_bt_event_smp_failed_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_SMP_FAILED_EVENT);
}
#endif
/*==============================================*/
/**
 * @fn         rsi_ble_on_encrypt_started
 * @brief      its invoked when encryption started event is received.
 * @param[in]  remote_dev_address, it indicates remote bd address.
 * @return     none.
 * @section description
 * This callback function is invoked when encryption started events is received
 */
static void rsi_ble_on_encrypt_started(uint16_t status, rsi_bt_event_encryption_enabled_t *enc_enabled)
{
  UNUSED_PARAMETER(status); //This statement is added only to resolve compilation warning, value is unchanged
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, enc_enabled->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_encryption_enabled,
         enc_enabled,
         sizeof(rsi_bt_event_encryption_enabled_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_ENCRYPT_STARTED_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_le_ltk_req_event
 * @brief      invoked when disconnection event is received
 * @param[in]  resp_disconnect, disconnected remote device information
 * @param[in]  reason, reason for disconnection.
 * @return     none.
 * @section description
 * This callback function indicates disconnected device information and status
 */
static void rsi_ble_on_le_ltk_req_event(rsi_bt_event_le_ltk_request_t *le_ltk_req)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, le_ltk_req->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_le_ltk_resp, le_ltk_req, sizeof(rsi_bt_event_le_ltk_request_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_LTK_REQ_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_on_le_security_keys_event
 * @brief      invoked when security keys event is received
 * @param[in]  rsi_bt_event_le_security_keys_t, security keys information
 * @return     none.
 * @section description
 * This callback function indicates security keys information
 */
static void rsi_ble_on_le_security_keys_event(rsi_bt_event_le_security_keys_t *le_sec_keys)
{
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, le_sec_keys->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_le_security_keys, le_sec_keys, sizeof(rsi_bt_event_le_security_keys_t));

  //! set conn specific event
  //! signal conn specific task
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_SECURITY_KEYS_EVENT);
}

/*==============================================*/
/**
 * @fn         rsi_ble_gatt_error_event
 * @brief      this function will invoke when set the attribute value complete
 * @param[out] rsi_ble_gatt_error, event structure
 * @param[out] status, status of the response
 * @return     none
 * @section description
 */
static void rsi_ble_gatt_error_event(uint16_t resp_status, rsi_ble_event_error_resp_t *rsi_ble_gatt_error)
{
  UNUSED_PARAMETER(resp_status); //This statement is added only to resolve compilation warning, value is unchanged
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_gatt_error->dev_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_gatt_err_resp, rsi_ble_gatt_error, sizeof(rsi_ble_event_error_resp_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_GATT_ERROR);
}

static void rsi_ble_more_data_req_event(rsi_ble_event_le_dev_buf_ind_t *rsi_ble_more_data_evt)
{
#if RSI_DEBUG_EN
  LOG_PRINT("\nReceived more data event in main task\r\n");
#endif
  //! convert to ascii
  rsi_6byte_dev_address_to_ascii(remote_dev_addr_conn, rsi_ble_more_data_evt->remote_dev_bd_addr);

  //! get conn_id
  ble_conn_id = rsi_get_ble_conn_id(remote_dev_addr_conn, NULL, 0);

  //! copy to conn specific buffer
  //memcpy(&rsi_ble_conn_info[ble_conn_id].rsi_ble_more_data_evt, rsi_ble_more_data_evt, sizeof(rsi_ble_event_le_dev_buf_ind_t));

  //! set conn specific event
  rsi_ble_app_set_task_event(ble_conn_id, RSI_BLE_MORE_DATA_REQ_EVT);

  return;
}

#if SIG_VUL
/*==============================================*/
/**
 * @fn         rsi_ble_on_sc_method
 * @brief      its invoked when security method event is received.
 * @param[in]  scmethod, 1 means Justworks and 2 means Passkey.
 * @return     none.
 * @section description
 * This callback function is invoked when SC Method events is received
 */
void rsi_ble_on_sc_method(rsi_bt_event_sc_method_t *scmethod)
{
  if (scmethod->sc_method == RSI_BT_LE_SC_JUST_WORKS) {
    LOG_PRINT("\nOur Security method is Just works, hence compare the 6 digit numeric value on both devices\r\n");
  } else if (scmethod->sc_method == RSI_BT_LE_SC_PASSKEY) {
    LOG_PRINT(
      "\nOur Security method is Passkey_Entry, hence same 6 digit Numeric value to be entered on both devices using "
      "keyboard, do not enter the numeric value displayed on one device into another device using keyboard \r\n");
  } else {
  }
}
#endif
/*==============================================*/
/**
 * @fn         rsi_ble_dual_role
 * @brief      this is the application of ble GATT client api's test cases.
 * @param[in]  none.
 * @return     none.
 * @section description
 * This function is used at application.
 */
static int32_t rsi_ble_dual_role(void)
{
  int32_t status  = 0;
  uint8_t adv[31] = { 2, 1, 6 };

  //! This should be vary from one device to other, Present RSI dont have a support of FIXED IRK on every Reset
  uint8_t local_irk[16] = { 0x4d, 0xd7, 0xbd, 0x3e, 0xec, 0x10, 0xda, 0xab,
                            0x1f, 0x85, 0x56, 0xee, 0xa5, 0xc8, 0xe6, 0x93 };

  rsi_ble_add_simple_chat_serv();
  rsi_ble_add_simple_chat_serv3();
  //! adding BLE Custom  Service service
  rsi_ble_add_custom_service_serv();

  //! registering the GAP call back functions
  rsi_ble_gap_register_callbacks(rsi_ble_simple_central_on_adv_report_event,
                                 rsi_ble_on_connect_event,
                                 rsi_ble_on_disconnect_event,
                                 NULL,
                                 NULL, /*rsi_ble_phy_update_complete_event*/
                                 NULL, /*rsi_ble_data_length_change_event*/
                                 rsi_ble_on_enhance_conn_status_event,
                                 NULL,
                                 ble_on_conn_update_complete_event,
                                 rsi_ble_on_remote_conn_params_request_event);
  //! registering the GATT call back functions
  rsi_ble_gatt_register_callbacks(NULL,
                                  NULL, /*rsi_ble_profile*/
                                  NULL, /*rsi_ble_char_services*/
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  rsi_ble_on_gatt_write_event,
                                  rsi_ble_on_gatt_prepare_write_event,
                                  rsi_ble_on_execute_write_event,
                                  rsi_ble_on_read_req_event,
                                  rsi_ble_on_mtu_event,
                                  rsi_ble_gatt_error_event,
                                  NULL,
                                  rsi_ble_profiles_list_event,
                                  rsi_ble_profile_event,
                                  rsi_ble_char_services_event,
                                  NULL,
                                  NULL,
                                  rsi_ble_on_read_resp_event,
                                  rsi_ble_on_event_write_resp,
                                  rsi_ble_on_event_indication_confirmation,
                                  NULL);

  rsi_ble_gatt_extended_register_callbacks(rsi_ble_on_event_mtu_exchange_info);

  rsi_ble_gap_extended_register_callbacks(rsi_ble_simple_peripheral_on_remote_features_event,
                                          rsi_ble_more_data_req_event);

#if SMP_ENABLE
  //! registering the SMP callback functions
  rsi_ble_smp_register_callbacks(rsi_ble_on_smp_request,
                                 rsi_ble_on_smp_response,
                                 rsi_ble_on_smp_passkey,
                                 rsi_ble_on_smp_failed,
                                 rsi_ble_on_encrypt_started,
                                 rsi_ble_on_smp_passkey_display,
                                 rsi_ble_on_sc_passkey,
                                 rsi_ble_on_le_ltk_req_event,
                                 rsi_ble_on_le_security_keys_event,
                                 NULL,
#if SIG_VUL
                                 rsi_ble_on_sc_method
#else
                                 NULL
#endif
  );
#endif

  //! initializing the application events map
  rsi_ble_app_init_events();

  //! Set local name
  rsi_bt_set_local_name((uint8_t *)RSI_BLE_APP_GATT_TEST);

  //! Set local IRK Value
  //! This value should be fixed on every reset
  LOG_PRINT("\r\nSetting the Local IRK Value\r\n");
  status = rsi_ble_set_local_irk_value(local_irk);
  if (status != RSI_SUCCESS) {
    LOG_PRINT("\r\nSetting the Local IRK Value Failed = %lx\r\n", status);
    return status;
  }

  //! get the local device address(MAC address).
  status = rsi_bt_get_local_device_address(rsi_app_resp_get_dev_addr);
  if (status != RSI_SUCCESS) {
    return status;
  }

  LOG_PRINT("Get local device address: %x:%x:%x:%x:%x:%x\n",
            rsi_app_resp_get_dev_addr[5],
            rsi_app_resp_get_dev_addr[4],
            rsi_app_resp_get_dev_addr[3],
            rsi_app_resp_get_dev_addr[2],
            rsi_app_resp_get_dev_addr[1],
            rsi_app_resp_get_dev_addr[0]);

  //! TO-Do: this initialization should be taken care in parsing itself
  //! assign the remote data transfer service and characteristic UUID's to local buffer
  for (uint8_t i = 0; i < TOTAL_CONNECTIONS; i++) {
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].tx_write_clientservice_uuid =
      RSI_BLE_CLIENT_WRITE_SERVICE_UUID_C1;
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].tx_write_client_char_uuid = RSI_BLE_CLIENT_WRITE_CHAR_UUID_C1;
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].tx_wnr_client_service_uuid =
      RSI_BLE_CLIENT_WRITE_NO_RESP_SERVICE_UUID_C1;
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].tx_wnr_client_char_uuid =
      RSI_BLE_CLIENT_WRITE_NO_RESP_CHAR_UUID_C1;
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].rx_indi_client_service_uuid =
      RSI_BLE_CLIENT_INIDCATIONS_SERVICE_UUID_C1;
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].rx_indi_client_char_uuid =
      RSI_BLE_CLIENT_INIDCATIONS_CHAR_UUID_C1;
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].rx_notif_client_service_uuid =
      RSI_BLE_CLIENT_NOTIFICATIONS_SERVICE_UUID_C1;
    rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[i].rx_notif_client_char_uuid =
      RSI_BLE_CLIENT_NOTIFICATIONS_CHAR_UUID_C1;
  }

  //! Module advertises if central connections are configured
  if (RSI_BLE_MAX_NBR_CENTRALS > 0) {
    //! prepare advertise data //local/device name
    adv[3] = strlen(RSI_BLE_APP_GATT_TEST) + 1;
    adv[4] = 9;
    strcpy((char *)&adv[5], RSI_BLE_APP_GATT_TEST);

    //! set advertise data
    rsi_ble_set_advertise_data(adv, strlen(RSI_BLE_APP_GATT_TEST) + 5);

    //! set device in advertising mode.
    status = rsi_ble_start_advertising();
    if (status != RSI_SUCCESS) {
      LOG_PRINT("\r\nAdvertising failed\r\n");
    }
    LOG_PRINT("\r\nAdvertising started, local device name : %s\r\n", (char *)RSI_BLE_APP_GATT_TEST);
  }

  //! Module scans if peripheral connections are configured
  if (RSI_BLE_MAX_NBR_PERIPHERALS > 0) {
    //! start scanning
    status = rsi_ble_start_scanning();
    if (status != RSI_SUCCESS) {
      return status;
    }
    LOG_PRINT("\r\nScanning started\r\n");
  }

  // update the new scan and advertise parameters
  memset(&change_adv_param, 0, sizeof(rsi_ble_req_adv_t));
  memset(&change_scan_param, 0, sizeof(rsi_ble_req_scan_t));

  //! advertise parameters
  change_adv_param.status           = RSI_BLE_START_ADV;
  change_adv_param.adv_type         = UNDIR_NON_CONN; //! non connectable advertising
  change_adv_param.filter_type      = RSI_BLE_ADV_FILTER_TYPE;
  change_adv_param.direct_addr_type = RSI_BLE_ADV_DIR_ADDR_TYPE;
  change_adv_param.adv_int_min      = RSI_BLE_ADV_INT_MIN; //advertising interval - 211.25ms
  change_adv_param.adv_int_max      = RSI_BLE_ADV_INT_MAX;
  change_adv_param.own_addr_type    = LE_PUBLIC_ADDRESS;
  change_adv_param.adv_channel_map  = RSI_BLE_ADV_CHANNEL_MAP;
  rsi_ascii_dev_address_to_6bytes_rev(change_adv_param.direct_addr, (int8_t *)RSI_BLE_ADV_DIR_ADDR);

  //! scan paramaters
  change_scan_param.status        = RSI_BLE_START_SCAN;
  change_scan_param.scan_type     = SCAN_TYPE_PASSIVE;
  change_scan_param.filter_type   = RSI_BLE_SCAN_FILTER_TYPE;
  change_scan_param.scan_int      = LE_SCAN_INTERVAL; //! scan interval 33.125ms
  change_scan_param.scan_win      = LE_SCAN_WINDOW;   //! scan window 13.375ms
  change_scan_param.own_addr_type = LE_PUBLIC_ADDRESS;

#if ENABLE_NWP_POWER_SAVE
  osMutexAcquire(power_cmd_mutex, 0xFFFFFFFFUL);
  if (!powersave_cmd_given) {
    status = rsi_initiate_power_save();
    if (status != RSI_SUCCESS) {
      LOG_PRINT("\nFailed to keep module in power save\r\n");
      return status;
    }
    powersave_cmd_given = true;
  }
  osMutexRelease(power_cmd_mutex);
#endif
  return 0;
}

void rsi_ble_main_app_task()
{

  int32_t status   = RSI_SUCCESS;
  int32_t event_id = 0;

#if WLAN_SYNC_REQ
  //! FIXME: Workaround
  osDelay(50);
  if (rsi_wlan_running) {
    LOG_PRINT("\r\nWaiting BLE, WLAN to unblock \r\n");
    osSemaphoreAcquire(sync_coex_ble_sem, osWaitForever);
  }
#endif

  //! BLE dual role Initialization
  LOG_PRINT("\r\nInitiating BLE \r\n");
  status = rsi_ble_dual_role();
  if (status != RSI_SUCCESS) {
    LOG_PRINT("\nBLE DUAL role init failed \r\n");
  }

  while (1) {
    //! checking for events list
    event_id = rsi_ble_app_get_event();
    if (event_id == -1) {
      //! wait on events
      osSemaphoreAcquire(ble_main_task_sem, osWaitForever);
      continue;
    }

    switch (event_id) {
      case RSI_APP_EVENT_ADV_REPORT: {
        //! clear the advertise report event.
        rsi_ble_app_clear_event(RSI_APP_EVENT_ADV_REPORT);
        //! create task if max peripheral connections not reached
        if (peripheral_task_instances < RSI_BLE_MAX_NBR_PERIPHERALS) {
          //! check for valid connection id
          if ((peripheral_conn_id < TOTAL_CONNECTIONS) && (peripheral_con_req_pending == 1)) {
            //! store the connection identifier in individual connection specific buffer
            rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[peripheral_task_instances].conn_id = peripheral_conn_id;

            //! create task for processing new peripheral connection
            const osThreadAttr_t ble_peripheral_attr = {
              .name       = "ble_peripheral_task",
              .priority   = osPriorityBelowNormal7,
              .stack_mem  = 0,
              .stack_size = 2048,
              .cb_mem     = 0,
              .cb_size    = 0,
              .attr_bits  = 0u,
              .tz_module  = 0u,
            };
            ble_app_task_handle[peripheral_conn_id] =
              osThreadNew(rsi_ble_task_on_conn,
                          (void *)&rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[peripheral_task_instances],
                          &ble_peripheral_attr);
            if (ble_app_task_handle[peripheral_task_instances] == NULL) {
              LOG_PRINT("\r\ntask%d failed to create, reason = %ld\r\n", peripheral_conn_id, status);
              peripheral_con_req_pending = 0;
              rsi_remove_ble_conn_id(rsi_ble_conn_info[peripheral_conn_id].remote_dev_addr);
              memset(&rsi_ble_conn_info[ble_conn_id].rsi_app_adv_reports_to_app, 0, sizeof(rsi_ble_event_adv_report_t));
              break;
            }
            peripheral_task_instances++;
          } else {
            LOG_PRINT("\nIn wrong state \r\n");
            while (1)
              ;
          }
        } else {
          LOG_PRINT("\r\nMaximum peripheral connections reached\r\n");
        }
      } break;
      case RSI_BLE_CONN_EVENT: {
        //! event invokes when connection was completed
#if RSI_DEBUG_EN
        LOG_PRINT("\r\nIn on comm-conn evt\r\n");
#endif
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_CONN_EVENT);
        if (remote_device_role == CENTRAL_ROLE) {
          if (central_task_instances < RSI_BLE_MAX_NBR_CENTRALS) {
            //! check for valid connection id
            if (central_conn_id < TOTAL_CONNECTIONS) {
              //! store the connection identifier in individual connection specific buffer
              rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[RSI_BLE_MAX_NBR_PERIPHERALS + central_task_instances]
                .conn_id = central_conn_id;

              //! create task for processing new central connection
              const osThreadAttr_t ble_central_attr = {
                .name       = "ble_central_task",
                .priority   = osPriorityBelowNormal7,
                .stack_mem  = 0,
                .stack_size = 2048,
                .cb_mem     = 0,
                .cb_size    = 0,
                .attr_bits  = 0u,
                .tz_module  = 0u,
              };
              ble_app_task_handle[central_conn_id] =
                osThreadNew(rsi_ble_task_on_conn,
                            (void *)&rsi_parsed_conf.rsi_ble_config
                              .rsi_ble_conn_config[RSI_BLE_MAX_NBR_PERIPHERALS + central_task_instances],
                            &ble_central_attr);
              if (ble_app_task_handle[central_conn_id] == NULL) {
                LOG_PRINT("\r\ntask%d failed to create\r\n", central_conn_id);
                //! remove device from local list
                rsi_remove_ble_conn_id(rsi_ble_conn_info[central_conn_id].remote_dev_addr);
                memset(&rsi_ble_conn_info[ble_conn_id].conn_event_to_app, 0, sizeof(rsi_ble_event_conn_status_t));
                break;
              }

              //! clear the connection id as it is already used in creating task
              central_conn_id = 0xff;
              central_task_instances++;
            } else {
              //! unexpected state
              LOG_PRINT("\nInvalid conn identifier \r\n");
              while (1)
                ;
            }
          } else {
            LOG_PRINT("\nMax central connections reached\r\n");
          }
        } else {
          LOG_PRINT("\nCheck why this state occurred?\r\n");
          while (1)
            ;
        }
      } break;
      case RSI_BLE_ENHC_CONN_EVENT: {
#if RSI_DEBUG_EN
        LOG_PRINT("\nIn on_enhance_conn evt\r\n");
#endif
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_ENHC_CONN_EVENT);
        if (remote_device_role == CENTRAL_ROLE) {
          if (central_task_instances < RSI_BLE_MAX_NBR_CENTRALS) {
            //! check for valid connection id
            if (central_conn_id < TOTAL_CONNECTIONS) {
              //! store the connection identifier in individual connection specific buffer
              rsi_parsed_conf.rsi_ble_config.rsi_ble_conn_config[RSI_BLE_MAX_NBR_PERIPHERALS + central_task_instances]
                .conn_id = central_conn_id;
              //LOG_PRINT("free bytes remaining before connection1 - %ld \r\n",xPortGetFreeHeapSize());

              //! create task for processing new central connection
              const osThreadAttr_t ble_central_attr = {
                .name       = "ble_central_task",
                .priority   = osPriorityBelowNormal7,
                .stack_mem  = 0,
                .stack_size = 2048,
                .cb_mem     = 0,
                .cb_size    = 0,
                .attr_bits  = 0u,
                .tz_module  = 0u,
              };
              ble_app_task_handle[central_conn_id] =
                osThreadNew(rsi_ble_task_on_conn,
                            (void *)&rsi_parsed_conf.rsi_ble_config
                              .rsi_ble_conn_config[RSI_BLE_MAX_NBR_PERIPHERALS + central_task_instances],
                            &ble_central_attr);
              if (ble_app_task_handle[central_conn_id] == NULL) {
                LOG_PRINT("\r\ntask%d failed to create\r\n", central_conn_id);
                //! remove device from local list
                rsi_remove_ble_conn_id(rsi_ble_conn_info[central_conn_id].remote_dev_addr);
                memset(&rsi_ble_conn_info[ble_conn_id].rsi_enhc_conn_status,
                       0,
                       sizeof(rsi_ble_event_enhance_conn_status_t));
                break;
              }

              //! clear the connection id as it is already used in creating task
              central_conn_id = 0xff;
              central_task_instances++;
            } else {
              //! unexpected state
              LOG_PRINT("\nInvalid conn identifier\r\n");
              while (1)
                ;
            }
          } else {
            LOG_PRINT("\nMax central connections reached\r\n");
          }
        } else {
          LOG_PRINT("\nCheck why this state occurred?\r\n");
          while (1)
            ;
        }
      } break;
      case RSI_BLE_GATT_PROFILES: {
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_GATT_PROFILES);
        LOG_PRINT("\r\nIn GATT test:rsi_ble_gatt_profiles \r\n");
      } break;

      case RSI_BLE_GATT_PROFILE: {
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_GATT_PROFILE);
      } break;

      case RSI_BLE_GATT_CHAR_SERVICES: {
        rsi_ble_app_clear_event(RSI_BLE_GATT_CHAR_SERVICES);
      } break;

      case RSI_BLE_GATT_DESC_SERVICES: {
        rsi_ble_app_clear_event(RSI_BLE_GATT_DESC_SERVICES);
      } break;

      case RSI_BLE_RECEIVE_REMOTE_FEATURES: {

        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_RECEIVE_REMOTE_FEATURES);
      } break;
      case RSI_BLE_CONN_UPDATE_COMPLETE_EVENT: {
#if RSI_DEBUG_EN
        LOG_PRINT("\r\nIn conn update evt\r\n");
#endif

        rsi_ble_app_clear_event(RSI_BLE_CONN_UPDATE_COMPLETE_EVENT);
      } break;
      case RSI_BLE_DISCONN_EVENT: {

        LOG_PRINT("\r\nIn dis-conn evt\r\n");
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_DISCONN_EVENT);
      } break;
      case RSI_BLE_GATT_WRITE_EVENT: {
        //! event invokes when write event received
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_GATT_WRITE_EVENT);

      } break;
      case RSI_BLE_READ_REQ_EVENT: {
#if RSI_DEBUG_EN
        //! event invokes when read event received
        LOG_PRINT("\r\nIn on GATT rd evt\r\n");
#endif
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_READ_REQ_EVENT);
      } break;
      case RSI_BLE_MTU_EVENT: {
#if RSI_DEBUG_EN
        //! event invokes when MTU event received
        LOG_PRINT("\r\nIn on mtu evt\r\n");
#endif
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_MTU_EVENT);
      } break;
      case RSI_BLE_SCAN_RESTART_EVENT: {
        //! clear the served event
        rsi_ble_app_clear_event(RSI_BLE_SCAN_RESTART_EVENT);

        status = rsi_ble_stop_scanning();
        if (status != RSI_SUCCESS) {
          LOG_PRINT("\r\nScanning stop cmd status = %lx\r\n", status);
          //return status;	//! TODO
        } else {
          rsi_scan_in_progress = 0;
        }
        LOG_PRINT("\r\nRestarting scanning\r\n");

        status = rsi_ble_start_scanning();
        if (status != RSI_SUCCESS) {
          LOG_PRINT("\r\n scanning start cmd status = %lx\r\n", status);
          //return status;	//! TODO
        } else {
          rsi_scan_in_progress = 1;
        }

        if (status != RSI_SUCCESS) {
          LOG_PRINT("\r\nRestart_scanning\r\n");
          rsi_ble_app_set_event(RSI_BLE_SCAN_RESTART_EVENT);
        }
      } break;
      case RSI_APP_EVENT_REMOTE_CONN_PARAM_REQ: {
#if RSI_DEBUG_EN
        LOG_PRINT("\r\nIn conn params req evt\r\n");
#endif
        //! remote device conn params request
        //! clear the conn params request event.
        rsi_ble_app_clear_event(RSI_APP_EVENT_REMOTE_CONN_PARAM_REQ);
      } break;
      case RSI_BLE_CONN_UPDATE_REQ: {
        rsi_ble_app_clear_event(RSI_BLE_CONN_UPDATE_REQ);
      } break;
      default:
        break;
    }
  }
}
#endif
