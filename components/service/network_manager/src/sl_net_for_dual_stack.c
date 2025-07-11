/***************************************************************************/ /**
 * @file
 * @brief
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
#include "sl_status.h"
#include "sl_wifi_types.h"
#include "sl_net.h"
#include "stddef.h"
#include "sl_status.h"
#include "sl_utility.h"
#include "sl_net.h"
#include "sl_wifi.h"
#include "sl_net_wifi_types.h"
#include "sl_net_si91x.h"
#include "sl_si91x_host_interface.h"
#include "sl_si91x_driver.h"
#include "sl_rsi_utility.h"
#include "sli_net_utility.h"
#include "sl_si91x_core_utilities.h"
#include "sli_net_common_utility.h"
#include <stdbool.h>
#include <string.h>
#include "sl_wifi_callback_framework.h"
#include "sl_net_dns.h"
#include "sli_wifi_constants.h"
#include "sl_net_for_lwip.h"
#include "lwip/tcpip.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/ethip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/timeouts.h"

#define NETIF_IPV4_ADDRESS(X, Y) (uint8_t)(((X) >> (8 * Y)) & 0xFF)
#define MAC_48_BIT_SET           (1)
#define LWIP_FRAME_ALIGNMENT     60
#define STRUCT_PBUF              ((struct pbuf *)0)
#define INTERFACE_NAME_0         'w' ///< Network interface name 0
#define INTERFACE_NAME_1         'l' ///< Network interface name 1
#define MAX_TRANSFER_UNIT        1500
#define get_netif(i)             ((i & SL_WIFI_CLIENT_INTERFACE) ? &wifi_client_context->netif : &wifi_ap_context->netif)

typedef enum { SLI_SI91X_CLIENT = 0, SLI_SI91X_AP = 1, SLI_SI91X_MAX_INTERFACES } sli_si91x_interfaces_t;

sl_net_wifi_lwip_context_t *wifi_client_context = NULL;
sl_net_wifi_lwip_context_t *wifi_ap_context     = NULL;
uint32_t gOverrunCount                          = 0;

static sl_status_t sli_si91x_send_multicast_request(sl_wifi_interface_t interface,
                                                    const sl_ip_address_t *ip_address,
                                                    uint8_t command_type);
sl_status_t sl_net_dns_resolve_hostname(const char *host_name,
                                        const uint32_t timeout,
                                        const sl_net_dns_resolution_ip_type_t dns_resolution_ip,
                                        sl_ip_address_t *sl_ip_address);

extern bool device_initialized;

static sl_ip_management_t dhcp_type[SLI_SI91X_MAX_INTERFACES] = { 0 };

static void low_level_init(struct netif *netif)
{
  uint32_t status = 0;
  sl_mac_address_t mac_addr;

  // set netif MAC hardware address length
  netif->hwaddr_len = ETH_HWADDR_LEN;

  // Request MAC address
  status = sl_wifi_get_mac_address(SL_WIFI_CLIENT_INTERFACE, &mac_addr);
  if (status != SL_STATUS_OK) {
    SL_DEBUG_LOG("\r\n MAC address failed \r\n");
    return;
  }

  // set netif MAC hardware address
  netif->hwaddr[0] = mac_addr.octet[0];
  netif->hwaddr[1] = mac_addr.octet[1];
  netif->hwaddr[2] = mac_addr.octet[2];
  netif->hwaddr[3] = mac_addr.octet[3];
  netif->hwaddr[4] = mac_addr.octet[4];
  netif->hwaddr[5] = mac_addr.octet[5];

  // set netif maximum transfer unit
  netif->mtu = MAX_TRANSFER_UNIT;

  // Accept broadcast address and ARP traffic
  netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

  // Set netif link flag
  // netif->flags |= NETIF_FLAG_LINK_UP;

#if LWIP_IPV6_MLD
  netif->flags |= NETIF_FLAG_MLD6;
#endif /* LWIP_IPV6_MLD */
}

static void low_level_input(struct netif *netif, uint8_t *b, uint16_t len)
{
  struct pbuf *p, *q;
  uint32_t bufferoffset;

  if (len <= 0) {
    return;
  }

  if (len < LWIP_FRAME_ALIGNMENT) { /* 60 : LWIP frame alignment */
    len = LWIP_FRAME_ALIGNMENT;
  }

  // Drop packets originated from the same interface and is not destined for the said interface
  const uint8_t *src_mac = b + netif->hwaddr_len;
  const uint8_t *dst_mac = b;

#if LWIP_IPV6
  if (!(ip6_addr_ispreferred(netif_ip6_addr_state(netif, 0)))
      && (memcmp(netif->hwaddr, src_mac, netif->hwaddr_len) == 0)
      && (memcmp(netif->hwaddr, dst_mac, netif->hwaddr_len) != 0)) {
    SL_DEBUG_LOG("%s: DROP, [%02x:%02x:%02x:%02x:%02x:%02x]<-[%02x:%02x:%02x:%02x:%02x:%02x] type=%02x%02x",
                 __func__,
                 dst_mac[0],
                 dst_mac[1],
                 dst_mac[2],
                 dst_mac[3],
                 dst_mac[4],
                 dst_mac[5],
                 src_mac[0],
                 src_mac[1],
                 src_mac[2],
                 src_mac[3],
                 src_mac[4],
                 src_mac[5],
                 b[12],
                 b[13]);
    return;
  }
#endif

  /* We allocate a pbuf chain of pbufs from the Lwip buffer pool
   * and copy the data to the pbuf chain
   */
  if ((p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL)) != STRUCT_PBUF) {
    for (q = p, bufferoffset = 0; q != NULL; q = q->next) {
      memcpy((uint8_t *)q->payload, (uint8_t *)b + bufferoffset, q->len);
      bufferoffset += q->len;
    }

    SL_DEBUG_LOG("%s: ACCEPT %d, [%02x:%02x:%02x:%02x:%02x:%02x]<-[%02x:%02x:%02x:%02x:%02x:%02x] type=%02x%02x",
                 __func__,
                 bufferoffset,
                 dst_mac[0],
                 dst_mac[1],
                 dst_mac[2],
                 dst_mac[3],
                 dst_mac[4],
                 dst_mac[5],
                 src_mac[0],
                 src_mac[1],
                 src_mac[2],
                 src_mac[3],
                 src_mac[4],
                 src_mac[5],
                 b[12],
                 b[13]);

    if (netif->input(p, netif) != ERR_OK) {
      gOverrunCount++;
      pbuf_free(p);
    }
  } else {
    gOverrunCount++;
  }

  return;
}

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
  UNUSED_PARAMETER(netif);
  sl_status_t status;

  status = sl_wifi_send_raw_data_frame(SL_WIFI_CLIENT_INTERFACE, (uint8_t *)p->payload, p->len);
  if (status != SL_STATUS_OK) {
    return ERR_IF;
  }
  return ERR_OK;
}

static err_t sta_ethernetif_init(struct netif *netif)
{
  LWIP_ASSERT("netif != NULL", (netif != NULL));

#if LWIP_NETIF_HOSTNAME
  /* Initialize interface hostname */
  netif->hostname = "lwip_sta";
#endif /* LWIP_NETIF_HOSTNAME */
  //! Set the netif name to identify the interface
  netif->name[0] = INTERFACE_NAME_0;
  netif->name[1] = INTERFACE_NAME_1;

  //! Assign handler/function for the interface
  // netif->input      = tcpip_input;
#if LWIP_IPV4 && LWIP_ARP
  netif->output = etharp_output;
#endif /* #if LWIP_IPV4 && LWIP_ARP */
#if LWIP_IPV6 && LWIP_ETHERNET
  netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 && LWIP_ETHERNET */
  netif->linkoutput = low_level_output;

  //! initialize the hardware
  low_level_init(netif);
  //  sta_netif = *netif;

  return ERR_OK;
}

static void sta_netif_config(void)
{
#if LWIP_IPV4
  ip_addr_t sta_ipaddr;
  ip_addr_t sta_netmask;
  ip_addr_t sta_gw;

  /* Initialize the Station information */
  ip_addr_set_zero_ip4(&sta_ipaddr);
  ip_addr_set_zero_ip4(&sta_netmask);
  ip_addr_set_zero_ip4(&sta_gw);
#endif /* LWIP_IPV4 */

  /* Add station interfaces */
  netif_add(&(wifi_client_context->netif),
#if LWIP_IPV4
            (const ip4_addr_t *)&sta_ipaddr,
            (const ip4_addr_t *)&sta_netmask,
            (const ip4_addr_t *)&sta_gw,
#endif /* LWIP_IPV4 */
            NULL,
            &sta_ethernetif_init,
            &tcpip_input);

  /* Registers the default network interface */
  netif_set_default(&(wifi_client_context->netif));
}

/* In dual stack mode, assign the IP received from offloaded stack to LWIP interface */
static void set_sta_link_up(sl_net_wifi_client_profile_t *profile)
{
  ip4_addr_t ipaddr  = { 0 };
  ip4_addr_t gateway = { 0 };
  ip4_addr_t netmask = { 0 };
  uint8_t *address   = &(profile->ip.ip.v4.ip_address.bytes[0]);

  IP4_ADDR(&ipaddr, address[0], address[1], address[2], address[3]);
  address = &(profile->ip.ip.v4.gateway.bytes[0]);
  IP4_ADDR(&gateway, address[0], address[1], address[2], address[3]);
  address = &(profile->ip.ip.v4.netmask.bytes[0]);
  IP4_ADDR(&netmask, address[0], address[1], address[2], address[3]);

  netifapi_netif_set_addr(&(wifi_client_context->netif), &ipaddr, &netmask, &gateway);

  netifapi_netif_set_up(&(wifi_client_context->netif));
  netifapi_netif_set_link_up(&(wifi_client_context->netif));

#if LWIP_IPV4
  uint64_t addr = wifi_client_context->netif.ip_addr.addr;
#endif
#if LWIP_IPV6
  uint64_t addr = wifi_client_context->netif.ip_addr.u_addr.ip4.addr;
#endif
  SL_DEBUG_LOG("DHCP IP: %u.%u.%u.%u\n",
               NETIF_IPV4_ADDRESS(addr, 0),
               NETIF_IPV4_ADDRESS(addr, 1),
               NETIF_IPV4_ADDRESS(addr, 2),
               NETIF_IPV4_ADDRESS(addr, 3));

#if LWIP_IPV6
#if LWIP_IPV6_AUTOCONFIG
  wifi_client_context->netif.ip6_autoconfig_enabled = 1;
#endif /* LWIP_IPV6_AUTOCONFIG */
  netif_create_ip6_linklocal_address(&(wifi_client_context->netif), MAC_48_BIT_SET);
#endif
  return;
}

static void set_sta_link_down(void)
{
  netifapi_netif_set_link_down(&(wifi_client_context->netif));
  netifapi_netif_set_down(&(wifi_client_context->netif));
}

sl_status_t sl_net_wifi_client_init(sl_net_interface_t interface,
                                    const void *configuration,
                                    void *context,
                                    sl_net_event_handler_t event_handler)
{
  UNUSED_PARAMETER(interface);
  UNUSED_PARAMETER(context);
  sl_status_t status = SL_STATUS_FAIL;

  // Set the user-defined event handler for client mode
  sl_si91x_register_event_handler(event_handler);

  status = sl_wifi_init(configuration, NULL, sl_wifi_default_event_handler);
  if (status != SL_STATUS_OK) {
    return status;
  }

  wifi_client_context = context;
  tcpip_init(NULL, NULL);
  sta_netif_config();

  return SL_STATUS_OK;
}

sl_status_t sl_net_wifi_client_deinit(sl_net_interface_t interface)
{
  UNUSED_PARAMETER(interface);
  struct sys_timeo **list_head = NULL;

  //! Free all timers
  for (int i = 0; i < lwip_num_cyclic_timers; i++) {
    list_head = sys_timeouts_get_next_timeout();
    if (*list_head != NULL)
      sys_untimeout((*list_head)->h, (*list_head)->arg);
  }

  return sl_wifi_deinit();
}

sl_status_t sl_net_wifi_client_up(sl_net_interface_t interface, sl_net_profile_id_t profile_id)
{
  UNUSED_PARAMETER(interface);
  sl_status_t status;
  sl_net_wifi_client_profile_t profile;

  // Connect to the Wi-Fi network
  if (profile_id == SL_NET_AUTO_JOIN) {
    return sli_handle_auto_join(interface, &profile);
  }

  // Get the client profile using the provided profile_id
  status = sl_net_get_profile(SL_NET_WIFI_CLIENT_INTERFACE, profile_id, &profile);
  VERIFY_STATUS_AND_RETURN(status);

  // Connect to the Wi-Fi network
  status = sl_wifi_connect(SL_WIFI_CLIENT_INTERFACE, &profile.config, SLI_WIFI_CONNECT_TIMEOUT);
  VERIFY_STATUS_AND_RETURN(status);

  // Configure the IP address settings
  status = sl_si91x_configure_ip_address(&profile.ip, SL_SI91X_WIFI_CLIENT_VAP_ID);
  VERIFY_STATUS_AND_RETURN(status);
  dhcp_type[SLI_SI91X_CLIENT] = profile.ip.mode;

  // Assign the IP address received from offload stack to LWIP interface */
  set_sta_link_up(&profile);

  // Set the client profile
  status = sl_net_set_profile(SL_NET_WIFI_CLIENT_INTERFACE, profile_id, &profile);
  return status;
}

sl_status_t sl_net_wifi_client_down(sl_net_interface_t interface)
{
  UNUSED_PARAMETER(interface);

  set_sta_link_down();

  // Disconnect from the Wi-Fi network
  return sl_wifi_disconnect(SL_WIFI_CLIENT_INTERFACE);
}

sl_status_t sl_net_wifi_ap_init(sl_net_interface_t interface,
                                const void *configuration,
                                const void *workspace,
                                sl_net_event_handler_t event_handler)
{
  UNUSED_PARAMETER(interface);
  UNUSED_PARAMETER(workspace);
  sl_status_t status = SL_STATUS_FAIL;

  // Set the user-defined event handler for AP mode
  sl_si91x_register_event_handler(event_handler);

  status = sl_wifi_init(configuration, NULL, sl_wifi_default_event_handler);
  VERIFY_STATUS_AND_RETURN(status);
  return status;
}

sl_status_t sl_net_wifi_ap_deinit(sl_net_interface_t interface)
{
  UNUSED_PARAMETER(interface);
  return sl_wifi_deinit();
}

sl_status_t sl_net_wifi_ap_up(sl_net_interface_t interface, sl_net_profile_id_t profile_id)
{
  UNUSED_PARAMETER(interface);
  sl_status_t status;
  sl_net_wifi_ap_profile_t profile;

  status = sl_net_get_profile(SL_NET_WIFI_AP_INTERFACE, profile_id, &profile);
  VERIFY_STATUS_AND_RETURN(status);

  // Validate if profile configuration is valid
  // AP + DHCP client not supported
  // AP + link local not supported
  if (profile.ip.mode != SL_IP_MANAGEMENT_STATIC_IP) {
    return SL_STATUS_INVALID_CONFIGURATION;
  }
  status = sl_si91x_configure_ip_address(&profile.ip, SL_SI91X_WIFI_AP_VAP_ID);
  VERIFY_STATUS_AND_RETURN(status);
  dhcp_type[SLI_SI91X_AP] = profile.ip.mode;

  // Set the AP profile
  status = sl_net_set_profile(SL_NET_WIFI_AP_INTERFACE, profile_id, &profile);
  VERIFY_STATUS_AND_RETURN(status);

  status = sl_wifi_start_ap(SL_WIFI_AP_2_4GHZ_INTERFACE, &profile.config);
  VERIFY_STATUS_AND_RETURN(status);

  return status;
}

sl_status_t sl_net_wifi_ap_down(sl_net_interface_t interface)
{
  UNUSED_PARAMETER(interface);
  return sl_wifi_stop_ap(SL_WIFI_AP_INTERFACE);
}

sl_status_t sl_net_join_multicast_address(sl_net_interface_t interface, const sl_ip_address_t *ip_address)
{
  return sli_si91x_send_multicast_request((sl_wifi_interface_t)interface, ip_address, SL_WIFI_MULTICAST_JOIN);
}

sl_status_t sl_net_leave_multicast_address(sl_net_interface_t interface, const sl_ip_address_t *ip_address)
{
  return sli_si91x_send_multicast_request((sl_wifi_interface_t)interface, ip_address, SL_WIFI_MULTICAST_LEAVE);
}

static sl_status_t sli_si91x_send_multicast_request(sl_wifi_interface_t interface,
                                                    const sl_ip_address_t *ip_address,
                                                    uint8_t command_type)
{
  UNUSED_PARAMETER(interface);
  sli_si91x_req_multicast_t multicast = { 0 };
  sl_status_t status                  = SL_STATUS_OK;

  if (!device_initialized) {
    return SL_STATUS_NOT_INITIALIZED;
  }

  //Fill IP version and IP address
  if (ip_address->type == SL_IPV6) {
    multicast.ip_version[0] = 6;
    memcpy(multicast.multicast_address.ipv6_address, ip_address->ip.v6.bytes, SLI_IP_ADDRESS_LEN * 4);
  } else {
    multicast.ip_version[0] = 4;
    memcpy(multicast.multicast_address.ipv4_address, ip_address->ip.v4.bytes, SLI_IP_ADDRESS_LEN);
  }
  multicast.type[0] = command_type;

  status = sli_si91x_driver_send_command(SLI_WLAN_REQ_MULTICAST,
                                         SLI_SI91X_NETWORK_CMD,
                                         &multicast,
                                         sizeof(multicast),
                                         SLI_SI91X_WAIT_FOR_COMMAND_SUCCESS,
                                         NULL,
                                         NULL);

  VERIFY_STATUS_AND_RETURN(status);
  return SL_STATUS_OK;
}

// Resolve a host name to an IP address using DNS
sl_status_t sl_net_dns_resolve_hostname(const char *host_name,
                                        const uint32_t timeout,
                                        const sl_net_dns_resolution_ip_type_t dns_resolution_ip,
                                        sl_ip_address_t *sl_ip_address)
{
  // Check for a NULL pointer for sl_ip_address
  SL_WIFI_ARGS_CHECK_NULL_POINTER(sl_ip_address);

  sl_status_t status;
  sl_si91x_packet_t *packet;
  sl_wifi_buffer_t *buffer                        = NULL;
  const sli_si91x_dns_response_t *dns_response    = { 0 };
  sli_si91x_dns_query_request_t dns_query_request = { 0 };

  // Determine the wait period based on the timeout value
  sli_si91x_wait_period_t wait_period = timeout == 0 ? SLI_SI91X_RETURN_IMMEDIATELY
                                                     : SL_SI91X_WAIT_FOR_RESPONSE(timeout);
  // Determine the IP version to be used (IPv4 or IPv6)
  dns_query_request.ip_version[0] = (dns_resolution_ip == SL_NET_DNS_TYPE_IPV4) ? 4 : 6;
  memcpy(dns_query_request.url_name, host_name, sizeof(dns_query_request.url_name));

  status = sli_si91x_driver_send_command(SLI_WLAN_REQ_DNS_QUERY,
                                         SLI_SI91X_NETWORK_CMD,
                                         &dns_query_request,
                                         sizeof(dns_query_request),
                                         wait_period,
                                         NULL,
                                         &buffer);

  // Check if the command failed and free the buffer if it was allocated
  if ((status != SL_STATUS_OK) && (buffer != NULL)) {
    sli_si91x_host_free_buffer(buffer);
  }
  VERIFY_STATUS_AND_RETURN(status);

  // Extract the DNS response from the SI91X packet buffer
  packet       = sl_si91x_host_get_buffer_data(buffer, 0, NULL);
  dns_response = (sli_si91x_dns_response_t *)packet->data;

  // Convert the SI91X DNS response to the sl_ip_address format
  sli_convert_si91x_dns_response(sl_ip_address, dns_response);
  sli_si91x_host_free_buffer(buffer);
  return SL_STATUS_OK;
}

sl_status_t sl_net_set_dns_server(sl_net_interface_t interface, const sl_net_dns_address_t *address)
{
  UNUSED_PARAMETER(interface);
  sl_status_t status                                  = 0;
  sli_dns_server_add_request_t dns_server_add_request = { 0 };

  if (!device_initialized) {
    return SL_STATUS_NOT_INITIALIZED;
  }

  //! Check for invalid parameters
  if ((address->primary_server_address && address->primary_server_address->type != SL_IPV4
       && address->primary_server_address->type != SL_IPV6)
      || (address->secondary_server_address && address->secondary_server_address->type != SL_IPV4
          && address->secondary_server_address->type != SL_IPV6)) {
    //! Throw error in case of invalid parameters
    return SL_STATUS_INVALID_PARAMETER;
  }

  //! Set DNS mode
  dns_server_add_request.dns_mode[0] =
    (address->primary_server_address == NULL && address->secondary_server_address == NULL) ? 1 /*dhcp*/ : 0 /*static*/;

  if (address->primary_server_address && address->primary_server_address->type == SL_IPV4) {
    dns_server_add_request.ip_version[0] = SL_IPV4_VERSION;
    //! Fill Primary IP address
    memcpy(dns_server_add_request.sli_ip_address1.primary_dns_ipv4,
           address->primary_server_address->ip.v4.bytes,
           SL_IPV4_ADDRESS_LENGTH);
  } else if (address->primary_server_address && address->primary_server_address->type == SL_IPV6) {
    dns_server_add_request.ip_version[0] = SL_IPV6_VERSION;
    //! Fill Primary IP address
    memcpy(dns_server_add_request.sli_ip_address1.primary_dns_ipv6,
           address->primary_server_address->ip.v6.bytes,
           SL_IPV6_ADDRESS_LENGTH);
  }

  if (address->secondary_server_address && address->secondary_server_address->type == SL_IPV4) {
    dns_server_add_request.ip_version[0] = SL_IPV4_VERSION;
    //! Fill Secondary IP address
    memcpy(dns_server_add_request.sli_ip_address2.secondary_dns_ipv4,
           address->secondary_server_address->ip.v4.bytes,
           SL_IPV4_ADDRESS_LENGTH);
  } else if (address->secondary_server_address && address->secondary_server_address->type == SL_IPV6) {
    dns_server_add_request.ip_version[0] = SL_IPV6_VERSION;
    //! Fill Secondary IP address
    memcpy(dns_server_add_request.sli_ip_address2.secondary_dns_ipv6,
           address->secondary_server_address->ip.v6.bytes,
           SL_IPV6_ADDRESS_LENGTH);
  }

  status = sli_si91x_driver_send_command(SLI_WLAN_REQ_DNS_SERVER_ADD,
                                         SLI_SI91X_NETWORK_CMD,
                                         &dns_server_add_request,
                                         sizeof(dns_server_add_request),
                                         SLI_SI91X_WAIT_FOR_COMMAND_SUCCESS,
                                         NULL,
                                         NULL);

  return status;
}

sl_status_t sl_net_configure_ip(sl_net_interface_t interface,
                                const sl_net_ip_configuration_t *ip_config,
                                uint32_t timeout)
{
  uint8_t vap_id                   = 0;
  sl_net_ip_configuration_t config = { 0 };

  if (SL_NET_WIFI_CLIENT_INTERFACE == SL_NET_INTERFACE_TYPE(interface)) {
    vap_id                      = SL_SI91X_WIFI_CLIENT_VAP_ID;
    dhcp_type[SLI_SI91X_CLIENT] = ip_config->mode;
  } else if (SL_NET_WIFI_AP_INTERFACE == SL_NET_INTERFACE_TYPE(interface)) {
    vap_id                  = SL_SI91X_WIFI_AP_VAP_ID;
    dhcp_type[SLI_SI91X_AP] = ip_config->mode;
  } else {
    return SL_STATUS_WIFI_UNSUPPORTED;
  }

  memcpy(&config, ip_config, sizeof(sl_net_ip_configuration_t));
  return sli_si91x_configure_ip_address(&config, vap_id, timeout);
}

sl_status_t sl_net_get_ip_address(sl_net_interface_t interface, sl_net_ip_address_t *ip_address, uint32_t timeout)
{
  uint8_t vap_id                      = 0;
  sl_status_t status                  = 0;
  sl_net_ip_configuration_t ip_config = { 0 };

  if (SL_NET_WIFI_CLIENT_INTERFACE == SL_NET_INTERFACE_TYPE(interface)) {
    vap_id           = SL_SI91X_WIFI_CLIENT_VAP_ID;
    ip_address->mode = dhcp_type[SLI_SI91X_CLIENT];
  } else if (SL_NET_WIFI_AP_INTERFACE == SL_NET_INTERFACE_TYPE(interface)) {
    vap_id           = SL_SI91X_WIFI_AP_VAP_ID;
    ip_address->mode = dhcp_type[SLI_SI91X_AP];
    return SL_STATUS_OK;
  } else {
    return SL_STATUS_WIFI_UNSUPPORTED;
  }

  ip_config.mode = SL_IP_MANAGEMENT_DHCP;
#ifdef SLI_SI91X_ENABLE_IPV6
  ip_config.type = SL_IPV6;
#else
  ip_config.type = SL_IPV4;
#endif
  status = sli_si91x_configure_ip_address(&ip_config, vap_id, timeout);
  if (status != SL_STATUS_OK) {
    return status;
  }

  ip_address->type = ip_config.type;
  // Copy the IPv4 addresses to the address structure
  memcpy(ip_address->v4.ip_address.bytes, (const uint8_t *)ip_config.ip.v4.ip_address.bytes, sizeof(sl_ipv4_address_t));
  memcpy(ip_address->v4.netmask.bytes, (const uint8_t *)ip_config.ip.v4.netmask.bytes, sizeof(sl_ipv4_address_t));
  memcpy(ip_address->v4.gateway.bytes, (const uint8_t *)ip_config.ip.v4.gateway.bytes, sizeof(sl_ipv4_address_t));

  // Copy the IPv6 addresses to the address structure
  memcpy(&ip_address->v6.link_local_address.bytes,
         (const uint8_t *)ip_config.ip.v6.link_local_address.bytes,
         sizeof(sl_ipv6_address_t));
  memcpy(&ip_address->v6.global_address.bytes,
         (const uint8_t *)ip_config.ip.v6.global_address.bytes,
         sizeof(sl_ipv6_address_t));
  memcpy(&ip_address->v6.gateway.bytes, (const uint8_t *)ip_config.ip.v6.gateway.bytes, sizeof(sl_ipv6_address_t));

  return SL_STATUS_OK;
}

sl_status_t sl_si91x_host_process_data_frame(sl_wifi_interface_t interface, sl_wifi_buffer_t *buffer)
{
  void *packet;
  struct netif *ifp;
  sl_si91x_packet_t *rsi_pkt;
  packet  = sl_si91x_host_get_buffer_data(buffer, 0, NULL);
  rsi_pkt = (sl_si91x_packet_t *)packet;
  SL_DEBUG_LOG("\nRX len : %d\n", rsi_pkt->length);

  /* get the network interface for STATION interface,
   * and forward the received frame buffer to LWIP
   */
  if ((ifp = get_netif(interface)) != NULL) {
    low_level_input(ifp, rsi_pkt->data, rsi_pkt->length);
  }

  return SL_STATUS_OK;
}
