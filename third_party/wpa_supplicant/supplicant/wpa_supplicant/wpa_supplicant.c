/*
 * WPA Supplicant
 * Copyright (c) 2003-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements functions for registering and unregistering
 * %wpa_supplicant interfaces. In addition, this file contains number of
 * functions for managing network connections.
 */

#include "includes.h"
#ifdef CONFIG_MATCH_IFACE
#include <net/if.h>
#include <fnmatch.h>
#endif /* CONFIG_MATCH_IFACE */

#include "common.h"
#include "crypto/random.h"
#include "crypto/sha1.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "eap_peer/eap.h"
#ifdef CONFIG_EAP_PROXY
#include "eap_peer/eap_proxy.h"
#endif
#include "eap_server/eap_methods.h"
#include "rsn_supp/wpa.h"
#include "eloop.h"
#include "config.h"
#include "utils/ext_password.h"
#include "l2_packet/l2_packet.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#ifdef CTRL_IFACE
#include "ctrl_iface.h"
#endif
#include "pcsc_funcs.h"
#include "common/version.h"
#include "rsn_supp/preauth.h"
#include "rsn_supp/pmksa_cache.h"
#include "common/wpa_ctrl.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#if UNUSED_FEAT_IN_SUPP_29
#include "common/hw_features_common.h"
#endif
#ifdef CONFIG_GAS_SERVER
#include "common/gas_server.h"
#endif
#ifdef CONFIG_GAS
#include "gas_query.h"
#endif
#ifdef CONFIG_DPP
#include "common/dpp.h"
#include "dpp_supplicant.h"
#endif
#ifdef CONFIG_P2P
#include "p2p/p2p.h"
#include "p2p_supplicant.h"
#endif
#ifdef CONFIG_FST
#include "fst/fst.h"
#endif
#include "blacklist.h"
#include "wpas_glue.h"
#include "wps_supplicant.h"
#ifdef CONFIG_IBSS_RSN
#include "ibss_rsn.h"
#endif
#include "sme.h"
#include "ap.h"
#include "wifi_display.h"
#include "notify.h"
#include "bgscan.h"
#include "autoscan.h"
#include "bss.h"
#include "scan.h"
#include "offchannel.h"
#ifdef CONFIG_HS20
#include "hs20_supplicant.h"
#endif
#include "wnm_sta.h"
#include "wpas_kay.h"
#ifdef CONFIG_MESH
#include "mesh.h"
#include "ap/ap_config.h"
#include "ap/hostapd.h"
#endif /* CONFIG_MESH */
#ifdef RSI_ENABLE_CCX
#include "rsn_supp/wpa_i.h"
#endif
#ifdef ENABLE_UMAC_ROM_PTR
#include "supplicant_rom_image.h"
#include "umac_rom_image.h"
#endif /*ENABLE_UMAC_ROM_PTR*/

void send_ap_join_fail_response(void);

const char *const wpa_supplicant_version =
"wpa_supplicant v" VERSION_STR "\n"
"Copyright (c) 2003-2019, Jouni Malinen <j@w1.fi> and contributors";

const char *const wpa_supplicant_license =
"This software may be distributed under the terms of the BSD license.\n"
"See README for more details.\n"
#ifdef EAP_TLS_OPENSSL
"\nThis product includes software developed by the OpenSSL Project\n"
"for use in the OpenSSL Toolkit (http://www.openssl.org/)\n"
#endif /* EAP_TLS_OPENSSL */
;

#ifndef CONFIG_NO_STDOUT_DEBUG
/* Long text divided into parts in order to fit in C89 strings size limits. */
const char *const wpa_supplicant_full_license1 =
"";
const char *const wpa_supplicant_full_license2 =
"This software may be distributed under the terms of the BSD license.\n"
"\n"
"Redistribution and use in source and binary forms, with or without\n"
"modification, are permitted provided that the following conditions are\n"
"met:\n"
"\n";
const char *const wpa_supplicant_full_license3 =
"1. Redistributions of source code must retain the above copyright\n"
"   notice, this list of conditions and the following disclaimer.\n"
"\n"
"2. Redistributions in binary form must reproduce the above copyright\n"
"   notice, this list of conditions and the following disclaimer in the\n"
"   documentation and/or other materials provided with the distribution.\n"
"\n";
const char *const wpa_supplicant_full_license4 =
"3. Neither the name(s) of the above-listed copyright holder(s) nor the\n"
"   names of its contributors may be used to endorse or promote products\n"
"   derived from this software without specific prior written permission.\n"
"\n"
"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n";
const char *const wpa_supplicant_full_license5 =
"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
"\n";
#endif /* CONFIG_NO_STDOUT_DEBUG */

#if UNUSED_FEAT_IN_SUPP_29
static void wpa_bss_tmp_disallow_timeout(void *eloop_ctx, void *timeout_ctx);
#endif
#if defined(CONFIG_FILS) && defined(IEEE8021X_EAPOL)
static void wpas_update_fils_connect_params(struct wpa_supplicant *wpa_s);
#endif /* CONFIG_FILS && IEEE8021X_EAPOL */

#ifndef CONFIG_NO_WEP
/* Configure default/group WEP keys for static WEP */
int wpa_set_wep_keys(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	int i, set = 0;

	for (i = 0; i < NUM_WEP_KEYS; i++) {
		if (ssid->wep_key_len[i] == 0)
			continue;

		set = 1;
		wpa_drv_set_key(wpa_s, WPA_ALG_WEP, NULL,
				i, i == ssid->wep_tx_keyidx, NULL, 0,
				ssid->wep_key[i], ssid->wep_key_len[i]);
	}

	return set;
}
#endif

int wpa_supplicant_set_wpa_none_key(struct wpa_supplicant *wpa_s,
				    struct wpa_ssid *ssid)
{
	u8 key[32];
	size_t keylen;
	enum wpa_alg alg;
	u8 seq[6] = { 0 };
	int ret;

	/* IBSS/WPA-None uses only one key (Group) for both receiving and
	 * sending unicast and multicast packets. */

	if (ssid->mode != WPAS_MODE_IBSS) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Invalid mode %d (not "
			"IBSS/ad-hoc) for WPA-None", ssid->mode);
		return -1;
	}

	if (!ssid->psk_set) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: No PSK configured for "
			"WPA-None");
		return -1;
	}

	switch (wpa_s->group_cipher) {
	case WPA_CIPHER_CCMP:
		os_memcpy(key, ssid->psk, 16);
		keylen = 16;
		alg = WPA_ALG_CCMP;
		break;
	case WPA_CIPHER_GCMP:
		os_memcpy(key, ssid->psk, 16);
		keylen = 16;
		alg = WPA_ALG_GCMP;
		break;
	case WPA_CIPHER_TKIP:
		/* WPA-None uses the same Michael MIC key for both TX and RX */
		os_memcpy(key, ssid->psk, 16 + 8);
		os_memcpy(key + 16 + 8, ssid->psk + 16, 8);
		keylen = 32;
		alg = WPA_ALG_TKIP;
		break;
	default:
		wpa_msg(wpa_s, MSG_INFO, "WPA: Invalid group cipher %d for "
			"WPA-None", wpa_s->group_cipher);
		return -1;
	}

	/* TODO: should actually remember the previously used seq#, both for TX
	 * and RX from each STA.. */

	ret = wpa_drv_set_key(wpa_s, alg, NULL, 0, 1, seq, 6, key, keylen);
	os_memset(key, 0, sizeof(key));
	return ret;
}

STATIC void wpa_supplicant_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	const u8 *bssid = wpa_s->bssid;
#ifdef ENABLE_DRAEGER_CUSTOMIZATION
	int is_rejoin_going_on = 0;
#endif
	if (!is_zero_ether_addr(wpa_s->pending_bssid) &&
	    (wpa_s->wpa_state == WPA_AUTHENTICATING ||
	     wpa_s->wpa_state == WPA_ASSOCIATING))
		bssid = wpa_s->pending_bssid;
	wpa_msg(wpa_s, MSG_INFO, "Authentication with " MACSTR " timed out.",
		MAC2STR(bssid));
	wpa_blacklist_add(wpa_s, bssid);
	wpa_sm_notify_disassoc(wpa_s->wpa);
	wpa_supplicant_deauthenticate(wpa_s, WLAN_REASON_DEAUTH_LEAVING);
	wpa_s->reassociate = 1;

	/*
	 * If we timed out, the AP or the local radio may be busy.
	 * So, wait a second until scanning again.
	 */
#ifdef ENABLE_DRAEGER_CUSTOMIZATION
	sl_wpa_driver_wrapper(wpa_s, WPA_DRV_CHK_REJOIN, &is_rejoin_going_on);

	if (is_rejoin_going_on) {	 
		wpa_supplicant_req_scan(wpa_s, 1, 0);
	}
#endif	
}


/**
 * wpa_supplicant_req_auth_timeout - Schedule a timeout for authentication
 * @wpa_s: Pointer to wpa_supplicant data
 * @sec: Number of seconds after which to time out authentication
 * @usec: Number of microseconds after which to time out authentication
 *
 * This function is used to schedule a timeout for the current authentication
 * attempt.
 */
void wpa_supplicant_req_auth_timeout(struct wpa_supplicant *wpa_s,
				     int sec, int usec)
{
	if (wpa_s->conf->ap_scan == 0 &&
	    (wpa_s->drv_flags & WPA_DRIVER_FLAGS_WIRED))
		return;

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Setting authentication timeout: %d sec "
		"%d usec", sec, usec);
#endif
	SL_PRINTF(WLAN_SUPP_SETTING_AUTHENTICATION_TIMEOUT, WLAN_UMAC, LOG_INFO, "%d sec %d usec", sec, usec);
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
	wpa_s->last_auth_timeout_sec = sec;
	eloop_register_timeout(sec, usec, wpa_supplicant_timeout, wpa_s, NULL);
}


/*
 * wpas_auth_timeout_restart - Restart and change timeout for authentication
 * @wpa_s: Pointer to wpa_supplicant data
 * @sec_diff: difference in seconds applied to original timeout value
 */
#if UNUSED_FEAT_IN_SUPP_29
void wpas_auth_timeout_restart(struct wpa_supplicant *wpa_s, int sec_diff)
{
	int new_sec = wpa_s->last_auth_timeout_sec + sec_diff;

	if (eloop_is_timeout_registered(wpa_supplicant_timeout, wpa_s, NULL)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"Authentication timeout restart: %d sec", new_sec);
#endif
		SL_PRINTF(WLAN_SUPP_AUTHENTICATION_TIMEOUT_RESTART, WLAN_UMAC, LOG_INFO, "%d sec", new_sec);
		eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
		eloop_register_timeout(new_sec, 0, wpa_supplicant_timeout,
				       wpa_s, NULL);
	}
}
#endif


/**
 * wpa_supplicant_cancel_auth_timeout - Cancel authentication timeout
 * @wpa_s: Pointer to wpa_supplicant data
 *
 * This function is used to cancel authentication timeout scheduled with
 * wpa_supplicant_req_auth_timeout() and it is called when authentication has
 * been completed.
 */
void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s)
{
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Cancelling authentication timeout");
#endif
	SL_PRINTF(WLAN_SUPP_CANCELLING_AUTHENTICATION_TIMEOUT, WLAN_UMAC, LOG_INFO);
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
	wpa_blacklist_del(wpa_s, wpa_s->bssid);
	os_free(wpa_s->last_con_fail_realm);
	wpa_s->last_con_fail_realm = NULL;
	wpa_s->last_con_fail_realm_len = 0;
}


/**
 * wpa_supplicant_initiate_eapol - Configure EAPOL state machine
 * @wpa_s: Pointer to wpa_supplicant data
 *
 * This function is used to configure EAPOL state machine based on the selected
 * authentication mode.
 */
void wpa_supplicant_initiate_eapol(struct wpa_supplicant *wpa_s)
{
#ifdef IEEE8021X_EAPOL
	struct eapol_config eapol_conf;
	struct wpa_ssid *ssid = wpa_s->current_ssid;

#ifdef CONFIG_IBSS_RSN
	if (ssid->mode == WPAS_MODE_IBSS &&
	    wpa_s->key_mgmt != WPA_KEY_MGMT_NONE &&
	    wpa_s->key_mgmt != WPA_KEY_MGMT_WPA_NONE) {
		/*
		 * RSN IBSS authentication is per-STA and we can disable the
		 * per-BSSID EAPOL authentication.
		 */
		eapol_sm_notify_portControl(wpa_s->eapol, ForceAuthorized);
		eapol_sm_notify_eap_success(wpa_s->eapol, TRUE);
		eapol_sm_notify_eap_fail(wpa_s->eapol, FALSE);
		return;
	}
#endif /* CONFIG_IBSS_RSN */

	eapol_sm_notify_eap_success(wpa_s->eapol, FALSE);
	eapol_sm_notify_eap_fail(wpa_s->eapol, FALSE);

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE)
		eapol_sm_notify_portControl(wpa_s->eapol, ForceAuthorized);
	else
		eapol_sm_notify_portControl(wpa_s->eapol, Auto);

	os_memset(&eapol_conf, 0, sizeof(eapol_conf));
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		eapol_conf.accept_802_1x_keys = 1;
		eapol_conf.required_keys = 0;
		if (ssid->eapol_flags & EAPOL_FLAG_REQUIRE_KEY_UNICAST) {
			eapol_conf.required_keys |= EAPOL_REQUIRE_KEY_UNICAST;
		}
		if (ssid->eapol_flags & EAPOL_FLAG_REQUIRE_KEY_BROADCAST) {
			eapol_conf.required_keys |=
				EAPOL_REQUIRE_KEY_BROADCAST;
		}

		if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_WIRED)
			eapol_conf.required_keys = 0;
	}
	eapol_conf.fast_reauth = wpa_s->conf->fast_reauth;
	eapol_conf.workaround = ssid->eap_workaround;
	eapol_conf.eap_disabled =
		!wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt) &&
		wpa_s->key_mgmt != WPA_KEY_MGMT_IEEE8021X_NO_WPA &&
		wpa_s->key_mgmt != WPA_KEY_MGMT_WPS;
	eapol_conf.external_sim = wpa_s->conf->external_sim;

#ifdef CONFIG_WPS
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPS) {
		eapol_conf.wps |= EAPOL_LOCAL_WPS_IN_USE;
		if (wpa_s->current_bss) {
			struct wpabuf *ie;
			ie = wpa_bss_get_vendor_ie_multi(wpa_s->current_bss,
							 WPS_IE_VENDOR_TYPE);
			if (ie) {
				if (wps_is_20(ie))
					eapol_conf.wps |=
						EAPOL_PEER_IS_WPS20_AP;
				wpabuf_free(ie);
			}
		}
	}
#endif /* CONFIG_WPS */

	eapol_sm_notify_config(wpa_s->eapol, &ssid->eap, &eapol_conf);

#ifdef CONFIG_MACSEC
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE && ssid->mka_psk_set)
		ieee802_1x_create_preshared_mka(wpa_s, ssid);
	else
		ieee802_1x_alloc_kay_sm(wpa_s, ssid);
#endif /* CONFIG_MACSEC */
#endif /* IEEE8021X_EAPOL */
}


/**
 * wpa_supplicant_set_non_wpa_policy - Set WPA parameters to non-WPA mode
 * @wpa_s: Pointer to wpa_supplicant data
 * @ssid: Configuration data for the network
 *
 * This function is used to configure WPA state machine and related parameters
 * to a mode where WPA is not enabled. This is called as part of the
 * authentication configuration when the selected network does not use WPA.
 */
void wpa_supplicant_set_non_wpa_policy(struct wpa_supplicant *wpa_s,
				       struct wpa_ssid *ssid)
{
	int i;

	if (ssid->key_mgmt & WPA_KEY_MGMT_WPS)
		wpa_s->key_mgmt = WPA_KEY_MGMT_WPS;
	else if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA)
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X_NO_WPA;
	else
		wpa_s->key_mgmt = WPA_KEY_MGMT_NONE;
	wpa_sm_set_ap_wpa_ie(wpa_s->wpa, NULL, 0);
	wpa_sm_set_ap_rsn_ie(wpa_s->wpa, NULL, 0);
	wpa_sm_set_ap_rsnxe(wpa_s->wpa, NULL, 0);
	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
	wpa_sm_set_assoc_rsnxe(wpa_s->wpa, NULL, 0);
	wpa_s->rsnxe_len = 0;
	wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
	wpa_s->group_cipher = WPA_CIPHER_NONE;
	wpa_s->mgmt_group_cipher = 0;

	for (i = 0; i < NUM_WEP_KEYS; i++) {
		if (ssid->wep_key_len[i] > 5) {
			wpa_s->pairwise_cipher = WPA_CIPHER_WEP104;
			wpa_s->group_cipher = WPA_CIPHER_WEP104;
			break;
		} else if (ssid->wep_key_len[i] > 0) {
			wpa_s->pairwise_cipher = WPA_CIPHER_WEP40;
			wpa_s->group_cipher = WPA_CIPHER_WEP40;
			break;
		}
	}

	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_ENABLED, 0);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_KEY_MGMT, wpa_s->key_mgmt);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PAIRWISE,
			 wpa_s->pairwise_cipher);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_GROUP, wpa_s->group_cipher);
#ifdef CONFIG_IEEE80211W
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_MGMT_GROUP,
			 wpa_s->mgmt_group_cipher);
#endif /* CONFIG_IEEE80211W */

	pmksa_cache_clear_current(wpa_s->wpa);
}


void free_hw_features(struct wpa_supplicant *wpa_s)
{
	int i;
	if (wpa_s->hw.modes == NULL)
		return;

	for (i = 0; i < wpa_s->hw.num_modes; i++) {
		os_free(wpa_s->hw.modes[i].channels);
		os_free(wpa_s->hw.modes[i].rates);
	}

	os_free(wpa_s->hw.modes);
	wpa_s->hw.modes = NULL;
}


#if UNUSED_FEAT_IN_SUPP_29
void free_bss_tmp_disallowed(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss_tmp_disallowed *bss, *prev;

	dl_list_for_each_safe(bss, prev, &wpa_s->bss_tmp_disallowed,
			      struct wpa_bss_tmp_disallowed, list) {
		eloop_cancel_timeout(wpa_bss_tmp_disallow_timeout, wpa_s, bss);
		dl_list_del(&bss->list);
		os_free(bss);
	}
}
#endif


#ifdef CONFIG_FILS
void wpas_flush_fils_hlp_req(struct wpa_supplicant *wpa_s)
{
	struct fils_hlp_req *req;

	while ((req = dl_list_first(&wpa_s->fils_hlp_req, struct fils_hlp_req,
				    list)) != NULL) {
		dl_list_del(&req->list);
		wpabuf_free(req->pkt);
		os_free(req);
	}
}
#endif
void sme_clear_on_disassoc(struct wpa_supplicant *wpa_s)
{
	wpabuf_free(wpa_s->sme.sae_token);  
	wpa_s->sme.sae_token = NULL;
	sae_clear_data(&wpa_s->sme.sae);
}                                                                                                                                                                                           
void sme_deinit(struct wpa_supplicant *wpa_s)
{
	sme_clear_on_disassoc(wpa_s);   
}
static void wpa_supplicant_cleanup(struct wpa_supplicant *wpa_s)
{
	int i;

	bgscan_deinit(wpa_s);
	autoscan_deinit(wpa_s);
	scard_deinit(wpa_s->scard);
	wpa_s->scard = NULL;
	wpa_sm_set_scard_ctx(wpa_s->wpa, NULL);
	eapol_sm_register_scard_ctx(wpa_s->eapol, NULL);
	l2_packet_deinit(wpa_s->l2);
	wpa_s->l2 = NULL;
	if (wpa_s->l2_br) {
		l2_packet_deinit(wpa_s->l2_br);
		wpa_s->l2_br = NULL;
	}
#ifdef CONFIG_TESTING_OPTIONS
	l2_packet_deinit(wpa_s->l2_test);
	wpa_s->l2_test = NULL;
	os_free(wpa_s->get_pref_freq_list_override);
	wpa_s->get_pref_freq_list_override = NULL;
	wpabuf_free(wpa_s->last_assoc_req_wpa_ie);
	wpa_s->last_assoc_req_wpa_ie = NULL;
#endif /* CONFIG_TESTING_OPTIONS */

	if (wpa_s->conf != NULL) {
		struct wpa_ssid *ssid;
		for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next)
			wpas_notify_network_removed(wpa_s, ssid);
	}

	os_free(wpa_s->confname);
	wpa_s->confname = NULL;

	os_free(wpa_s->confanother);
	wpa_s->confanother = NULL;

	os_free(wpa_s->last_con_fail_realm);
	wpa_s->last_con_fail_realm = NULL;
	wpa_s->last_con_fail_realm_len = 0;

	wpa_sm_set_eapol(wpa_s->wpa, NULL);
	eapol_sm_deinit(wpa_s->eapol);
	wpa_s->eapol = NULL;

	rsn_preauth_deinit(wpa_s->wpa);

#ifdef CONFIG_TDLS
	wpa_tdls_deinit(wpa_s->wpa);
#endif /* CONFIG_TDLS */
#if UNUSED_FEAT_IN_SUPP_29
	wmm_ac_clear_saved_tspecs(wpa_s);
#endif	
	pmksa_candidate_free(wpa_s->wpa);
	wpa_sm_deinit(wpa_s->wpa);
	wpa_s->wpa = NULL;
	wpa_blacklist_clear(wpa_s);

	wpa_bss_deinit(wpa_s);

	wpa_supplicant_cancel_delayed_sched_scan(wpa_s);
	wpa_supplicant_cancel_scan(wpa_s);
	wpa_supplicant_cancel_auth_timeout(wpa_s);
	eloop_cancel_timeout(wpa_supplicant_stop_countermeasures, wpa_s, NULL);
#ifdef CONFIG_DELAYED_MIC_ERROR_REPORT
	eloop_cancel_timeout(wpa_supplicant_delayed_mic_error_report,
			     wpa_s, NULL);
#endif /* CONFIG_DELAYED_MIC_ERROR_REPORT */

#if UNUSED_FEAT_IN_SUPP_29
	eloop_cancel_timeout(wpas_network_reenabled, wpa_s, NULL);
#endif
	wpas_wps_deinit(wpa_s);

	wpabuf_free(wpa_s->pending_eapol_rx);
	wpa_s->pending_eapol_rx = NULL;

#ifdef CONFIG_IBSS_RSN
	ibss_rsn_deinit(wpa_s->ibss_rsn);
	wpa_s->ibss_rsn = NULL;
#endif /* CONFIG_IBSS_RSN */

	sme_deinit(wpa_s);

#ifdef CONFIG_AP
	wpa_supplicant_ap_deinit(wpa_s);
#endif /* CONFIG_AP */
#ifdef CONFIG_P2P
	wpas_p2p_deinit(wpa_s);
#endif
#ifdef CONFIG_OFFCHANNEL
	offchannel_deinit(wpa_s);
#endif /* CONFIG_OFFCHANNEL */

	wpa_supplicant_cancel_sched_scan(wpa_s);

	os_free(wpa_s->next_scan_freqs);
	wpa_s->next_scan_freqs = NULL;

	os_free(wpa_s->manual_scan_freqs);
	wpa_s->manual_scan_freqs = NULL;
	os_free(wpa_s->select_network_scan_freqs);
	wpa_s->select_network_scan_freqs = NULL;

	os_free(wpa_s->manual_sched_scan_freqs);
	wpa_s->manual_sched_scan_freqs = NULL;

#if UNUSED_FEAT_IN_SUPP_29
	wpas_mac_addr_rand_scan_clear(wpa_s, MAC_ADDR_RAND_ALL);
#endif

	/*
	 * Need to remove any pending gas-query radio work before the
	 * gas_query_deinit() call because gas_query::work has not yet been set
	 * for works that have not been started. gas_query_free() will be unable
	 * to cancel such pending radio works and once the pending gas-query
	 * radio work eventually gets removed, the deinit notification call to
	 * gas_query_start_cb() would result in dereferencing freed memory.
	 */
#ifdef ENABLE_RRM 
	if (wpa_s->radio)
		radio_remove_works(wpa_s, "gas-query", 0);
#endif
#ifdef CONFIG_GAS
	gas_query_deinit(wpa_s->gas);
	wpa_s->gas = NULL;
	gas_server_deinit(wpa_s->gas_server);
	wpa_s->gas_server = NULL;
#endif

	free_hw_features(wpa_s);

	ieee802_1x_dealloc_kay_sm(wpa_s);

	os_free(wpa_s->bssid_filter);
	wpa_s->bssid_filter = NULL;

	os_free(wpa_s->disallow_aps_bssid);
	wpa_s->disallow_aps_bssid = NULL;
	os_free(wpa_s->disallow_aps_ssid);
	wpa_s->disallow_aps_ssid = NULL;

#ifdef CONFIG_WNM
	wnm_bss_keep_alive_deinit(wpa_s);
	wnm_deallocate_memory(wpa_s);
#endif /* CONFIG_WNM */

	ext_password_deinit(wpa_s->ext_pw);
	wpa_s->ext_pw = NULL;

	wpabuf_free(wpa_s->last_gas_resp);
	wpa_s->last_gas_resp = NULL;
	wpabuf_free(wpa_s->prev_gas_resp);
	wpa_s->prev_gas_resp = NULL;

	os_free(wpa_s->last_scan_res);
	wpa_s->last_scan_res = NULL;

#ifdef CONFIG_HS20
	if (wpa_s->drv_priv)
		wpa_drv_configure_frame_filters(wpa_s, 0);
	hs20_deinit(wpa_s);
#endif /* CONFIG_HS20 */

	for (i = 0; i < NUM_VENDOR_ELEM_FRAMES; i++) {
		wpabuf_free(wpa_s->vendor_elem[i]);
		wpa_s->vendor_elem[i] = NULL;
	}
#if UNUSED_FEAT_IN_SUPP_29
	wmm_ac_notify_disassoc(wpa_s);
#endif
	wpa_s->sched_scan_plans_num = 0;
	os_free(wpa_s->sched_scan_plans);
	wpa_s->sched_scan_plans = NULL;

#ifdef CONFIG_MBO_STA
	wpa_s->non_pref_chan_num = 0;
	os_free(wpa_s->non_pref_chan);
	wpa_s->non_pref_chan = NULL;
#endif /* CONFIG_MBO_STA */

#if UNUSED_FEAT_IN_SUPP_29
	free_bss_tmp_disallowed(wpa_s);
#endif

	wpabuf_free(wpa_s->lci);
	wpa_s->lci = NULL;
#ifdef CHIP_9117
	wpas_clear_beacon_rep_data(wpa_s);
#endif
#ifdef CONFIG_PMKSA_CACHE_EXTERNAL
#ifdef CONFIG_MESH
	{
		struct external_pmksa_cache *entry;

		while ((entry = dl_list_last(&wpa_s->mesh_external_pmksa_cache,
					     struct external_pmksa_cache,
					     list)) != NULL) {
			dl_list_del(&entry->list);
			os_free(entry->pmksa_cache);
			os_free(entry);
		}
	}
#endif /* CONFIG_MESH */
#endif /* CONFIG_PMKSA_CACHE_EXTERNAL */

#ifdef CONFIG_FILS
	wpas_flush_fils_hlp_req(wpa_s);
#endif

	wpabuf_free(wpa_s->ric_ies);
	wpa_s->ric_ies = NULL;

#ifdef CONFIG_DPP
	wpas_dpp_deinit(wpa_s);
	dpp_global_deinit(wpa_s->dpp);
	wpa_s->dpp = NULL;
#endif /* CONFIG_DPP */
}


/**
 * wpa_clear_keys - Clear keys configured for the driver
 * @wpa_s: Pointer to wpa_supplicant data
 * @addr: Previously used BSSID or %NULL if not available
 *
 * This function clears the encryption keys that has been previously configured
 * for the driver.
 */
void wpa_clear_keys(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	int i, max;

#ifdef CONFIG_IEEE80211W
	max = 6;
#else /* CONFIG_IEEE80211W */
	max = 4;
#endif /* CONFIG_IEEE80211W */

	/* MLME-DELETEKEYS.request */
	for (i = 0; i < max; i++) {
		if (wpa_s->keys_cleared & BIT(i))
			continue;
		wpa_drv_set_key(wpa_s, WPA_ALG_NONE, NULL, i, 0, NULL, 0,
				NULL, 0);
	}
	if (!(wpa_s->keys_cleared & BIT(0)) && addr &&
	    !is_zero_ether_addr(addr)) {
		wpa_drv_set_key(wpa_s, WPA_ALG_NONE, addr, 0, 0, NULL, 0, NULL,
				0);
		/* MLME-SETPROTECTION.request(None) */
		wpa_drv_mlme_setprotection(
			wpa_s, addr,
			MLME_SETPROTECTION_PROTECT_TYPE_NONE,
			MLME_SETPROTECTION_KEY_TYPE_PAIRWISE);
	}
	wpa_s->keys_cleared = (u32) -1;
}


/**
 * wpa_supplicant_state_txt - Get the connection state name as a text string
 * @state: State (wpa_state; WPA_*)
 * Returns: The state name as a printable text string
 */
const char * wpa_supplicant_state_txt(enum wpa_states state)
{
	switch (state) {
	case WPA_DISCONNECTED:
		return "DISCONNECTED";
	case WPA_INACTIVE:
		return "INACTIVE";
	case WPA_INTERFACE_DISABLED:
		return "INTERFACE_DISABLED";
	case WPA_SCANNING:
		return "SCANNING";
	case WPA_AUTHENTICATING:
		return "AUTHENTICATING";
	case WPA_ASSOCIATING:
		return "ASSOCIATING";
	case WPA_ASSOCIATED:
		return "ASSOCIATED";
	case WPA_4WAY_HANDSHAKE:
		return "4WAY_HANDSHAKE";
	case WPA_GROUP_HANDSHAKE:
		return "GROUP_HANDSHAKE";
	case WPA_COMPLETED:
		return "COMPLETED";
	default:
		return "UNKNOWN";
	}
}


#ifdef CONFIG_BGSCAN

static void wpa_supplicant_start_bgscan(struct wpa_supplicant *wpa_s)
{
	const char *name;

	if (wpa_s->current_ssid && wpa_s->current_ssid->bgscan)
		name = wpa_s->current_ssid->bgscan;
	else
		name = wpa_s->conf->bgscan;
	if (name == NULL || name[0] == '\0')
		return;
	if (wpas_driver_bss_selection(wpa_s))
		return;
	if (wpa_s->current_ssid == wpa_s->bgscan_ssid)
		return;
#ifdef CONFIG_P2P
	if (wpa_s->p2p_group_interface != NOT_P2P_GROUP_INTERFACE)
		return;
#endif /* CONFIG_P2P */

	bgscan_deinit(wpa_s);
	if (wpa_s->current_ssid) {
		if (bgscan_init(wpa_s, wpa_s->current_ssid, name)) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "Failed to initialize "
				"bgscan");
#endif
			SL_PRINTF(WLAN_SUPP_FAILED_TO_INITIALIZE_BGSCAN, WLAN_UMAC, LOG_INFO);
			/*
			 * Live without bgscan; it is only used as a roaming
			 * optimization, so the initial connection is not
			 * affected.
			 */
		} else {
			struct wpa_scan_results *scan_res;
			wpa_s->bgscan_ssid = wpa_s->current_ssid;
			scan_res = wpa_supplicant_get_scan_results(wpa_s, NULL,
								   0);
			if (scan_res) {
				bgscan_notify_scan(wpa_s, scan_res);
				wpa_scan_results_free(scan_res);
			}
		}
	} else
		wpa_s->bgscan_ssid = NULL;
}


static void wpa_supplicant_stop_bgscan(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->bgscan_ssid != NULL) {
		bgscan_deinit(wpa_s);
		wpa_s->bgscan_ssid = NULL;
	}
}

#endif /* CONFIG_BGSCAN */


static void wpa_supplicant_start_autoscan(struct wpa_supplicant *wpa_s)
{
	if (autoscan_init(wpa_s, 0))
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Failed to initialize autoscan");
#endif
		SL_PRINTF(WLAN_SUPP_FAILED_TO_INITIALIZE_AUTOSCAN, WLAN_UMAC, LOG_INFO);
}


static void wpa_supplicant_stop_autoscan(struct wpa_supplicant *wpa_s)
{
	autoscan_deinit(wpa_s);
}


void wpa_supplicant_reinit_autoscan(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->wpa_state == WPA_DISCONNECTED ||
	    wpa_s->wpa_state == WPA_SCANNING) {
		autoscan_deinit(wpa_s);
		wpa_supplicant_start_autoscan(wpa_s);
	}
}


/**
 * wpa_supplicant_set_state - Set current connection state
 * @wpa_s: Pointer to wpa_supplicant data
 * @state: The new connection state
 *
 * This function is called whenever the connection state changes, e.g.,
 * association is completed for WPA/WPA2 4-Way Handshake is started.
 */
void wpa_supplicant_set_state(struct wpa_supplicant *wpa_s,
			      enum wpa_states state)
{
#if 0 
	enum wpa_states old_state = wpa_s->wpa_state;

	wpa_dbg(wpa_s, MSG_DEBUG, "State: %s -> %s",
		wpa_supplicant_state_txt(wpa_s->wpa_state),
		wpa_supplicant_state_txt(state));

	if (state == WPA_COMPLETED &&
	    os_reltime_initialized(&wpa_s->roam_start)) {
		os_reltime_age(&wpa_s->roam_start, &wpa_s->roam_time);
		wpa_s->roam_start.sec = 0;
		wpa_s->roam_start.usec = 0;
		wpas_notify_auth_changed(wpa_s);
		wpas_notify_roam_time(wpa_s);
		wpas_notify_roam_complete(wpa_s);
	} else if (state == WPA_DISCONNECTED &&
		   os_reltime_initialized(&wpa_s->roam_start)) {
		wpa_s->roam_start.sec = 0;
		wpa_s->roam_start.usec = 0;
		wpa_s->roam_time.sec = 0;
		wpa_s->roam_time.usec = 0;
		wpas_notify_roam_complete(wpa_s);
	}

	if (state == WPA_INTERFACE_DISABLED) {
		/* Assure normal scan when interface is restored */
		wpa_s->normal_scans = 0;
	}

	if (state == WPA_COMPLETED) {
		wpas_connect_work_done(wpa_s);
		/* Reinitialize normal_scan counter */
		wpa_s->normal_scans = 0;
	}

#ifdef CONFIG_P2P
	/*
	 * P2PS client has to reply to Probe Request frames received on the
	 * group operating channel. Enable Probe Request frame reporting for
	 * P2P connected client in case p2p_cli_probe configuration property is
	 * set to 1.
	 */
	if (wpa_s->conf->p2p_cli_probe && wpa_s->current_ssid &&
	    wpa_s->current_ssid->mode == WPAS_MODE_INFRA &&
	    wpa_s->current_ssid->p2p_group) {
		if (state == WPA_COMPLETED && !wpa_s->p2p_cli_probe) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG,
				"P2P: Enable CLI Probe Request RX reporting");
#endif
			SL_PRINTF(WLAN_SUPP_P2P_ENABLE_CLI_PROBE_REQUEST_RX_REPORTING, WLAN_UMAC, LOG_INFO);
			wpa_s->p2p_cli_probe =
				wpa_drv_probe_req_report(wpa_s, 1) >= 0;
		} else if (state != WPA_COMPLETED && wpa_s->p2p_cli_probe) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG,
				"P2P: Disable CLI Probe Request RX reporting");
#endif
			SL_PRINTF(WLAN_SUPP_P2P_DISABLE_CLI_PROBE_REQUEST_RX_REPORTING, WLAN_UMAC, LOG_INFO);
			wpa_s->p2p_cli_probe = 0;
			wpa_drv_probe_req_report(wpa_s, 0);
		}
	}
#endif /* CONFIG_P2P */

	if (state != WPA_SCANNING)
		wpa_supplicant_notify_scanning(wpa_s, 0);

	if (state == WPA_COMPLETED && wpa_s->new_connection) {
		struct wpa_ssid *ssid = wpa_s->current_ssid;
		int fils_hlp_sent = 0;

#ifdef CONFIG_SME
		if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) &&
		    wpa_auth_alg_fils(wpa_s->sme.auth_alg))
			fils_hlp_sent = 1;
#endif /* CONFIG_SME */
		if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) &&
		    wpa_auth_alg_fils(wpa_s->auth_alg))
			fils_hlp_sent = 1;

#if defined(CONFIG_CTRL_IFACE) || !defined(CONFIG_NO_STDOUT_DEBUG)
		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_CONNECTED "- Connection to "
			MACSTR " completed [id=%d id_str=%s%s]",
			MAC2STR(wpa_s->bssid),
			ssid ? ssid->id : -1,
			ssid && ssid->id_str ? ssid->id_str : "",
			fils_hlp_sent ? " FILS_HLP_SENT" : "");
#endif /* CONFIG_CTRL_IFACE || !CONFIG_NO_STDOUT_DEBUG */
		wpas_clear_temp_disabled(wpa_s, ssid, 1);
		wpa_blacklist_clear(wpa_s);
		wpa_s->extra_blacklist_count = 0;
		wpa_s->new_connection = 0;
		wpa_drv_set_operstate(wpa_s, 1);
#ifndef IEEE8021X_EAPOL
		wpa_drv_set_supp_port(wpa_s, 1);
#endif /* IEEE8021X_EAPOL */
		wpa_s->after_wps = 0;
		wpa_s->known_wps_freq = 0;
		wpas_p2p_completed(wpa_s);

		sme_sched_obss_scan(wpa_s, 1);

#if defined(CONFIG_FILS) && defined(IEEE8021X_EAPOL)
		if (!fils_hlp_sent && ssid && ssid->eap.erp)
			wpas_update_fils_connect_params(wpa_s);
#endif /* CONFIG_FILS && IEEE8021X_EAPOL */
	} else if (state == WPA_DISCONNECTED || state == WPA_ASSOCIATING ||
		   state == WPA_ASSOCIATED) {
		wpa_s->new_connection = 1;
		wpa_drv_set_operstate(wpa_s, 0);
#ifndef IEEE8021X_EAPOL
		wpa_drv_set_supp_port(wpa_s, 0);
#endif /* IEEE8021X_EAPOL */
		sme_sched_obss_scan(wpa_s, 0);
	}
	wpa_s->wpa_state = state;

#ifdef CONFIG_BGSCAN
	if (state == WPA_COMPLETED)
		wpa_supplicant_start_bgscan(wpa_s);
	else if (state < WPA_ASSOCIATED)
		wpa_supplicant_stop_bgscan(wpa_s);
#endif /* CONFIG_BGSCAN */

	if (state > WPA_SCANNING)
		wpa_supplicant_stop_autoscan(wpa_s);

	if (state == WPA_DISCONNECTED || state == WPA_INACTIVE)
		wpa_supplicant_start_autoscan(wpa_s);

	if (old_state >= WPA_ASSOCIATED && wpa_s->wpa_state < WPA_ASSOCIATED)
		wmm_ac_notify_disassoc(wpa_s);

	if (wpa_s->wpa_state != old_state) {
		wpas_notify_state_changed(wpa_s, wpa_s->wpa_state, old_state);

		/*
		 * Notify the P2P Device interface about a state change in one
		 * of the interfaces.
		 */
		wpas_p2p_indicate_state_change(wpa_s);

		if (wpa_s->wpa_state == WPA_COMPLETED ||
		    old_state == WPA_COMPLETED)
			wpas_notify_auth_changed(wpa_s);
	}
#endif

	enum wpa_states old_state = wpa_s->wpa_state;

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "State: %s -> %s",
		wpa_supplicant_state_txt(wpa_s->wpa_state),
		wpa_supplicant_state_txt(state));
#endif
	SL_PRINTF(WLAN_SUPP_STATE, WLAN_UMAC, LOG_INFO, "State: %s -> %s", wpa_supplicant_state_txt(wpa_s->wpa_state), wpa_supplicant_state_txt(state));

	if (state != WPA_SCANNING)
		wpa_supplicant_notify_scanning(wpa_s, 0);

	if (state == WPA_COMPLETED && wpa_s->new_connection) {
		struct wpa_ssid *ssid = wpa_s->current_ssid; /* K60_PORTING moved this from below define*/
#if defined(CONFIG_CTRL_IFACE) || !defined(CONFIG_NO_STDOUT_DEBUG)		
		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_CONNECTED "- Connection to "
			MACSTR " completed [id=%d id_str=%s]",
			MAC2STR(wpa_s->bssid),
			ssid ? ssid->id : -1,
			ssid && ssid->id_str ? ssid->id_str : "");
#endif /* CONFIG_CTRL_IFACE || !CONFIG_NO_STDOUT_DEBUG */
		wpas_clear_temp_disabled(wpa_s, ssid, 1);
		wpa_s->extra_blacklist_count = 0;
		wpa_s->new_connection = 0;
		wpa_drv_set_operstate(wpa_s, 1);
#ifndef IEEE8021X_EAPOL
		wpa_drv_set_supp_port(wpa_s, 1);
#endif /* IEEE8021X_EAPOL */
		wpa_s->after_wps = 0;
		wpa_s->known_wps_freq = 0;
#ifdef CONFIG_P2P
		WPAS_P2P_COMPLETED(wpa_s);
#endif /* CONFIG_P2P */

		sme_sched_obss_scan(wpa_s, 1);
	} else if (state == WPA_DISCONNECTED || state == WPA_ASSOCIATING ||
		   state == WPA_ASSOCIATED) {
		wpa_s->new_connection = 1;
		wpa_drv_set_operstate(wpa_s, 0);
#ifndef IEEE8021X_EAPOL
		wpa_drv_set_supp_port(wpa_s, 0);
#endif /* IEEE8021X_EAPOL */
		sme_sched_obss_scan(wpa_s, 0);
	}
	wpa_s->wpa_state = state;

#ifdef CONFIG_BGSCAN
	if (state == WPA_COMPLETED)
		wpa_supplicant_start_bgscan(wpa_s);
	else
		wpa_supplicant_stop_bgscan(wpa_s);
#endif /* CONFIG_BGSCAN */

	if (state == WPA_AUTHENTICATING)
		wpa_supplicant_stop_autoscan(wpa_s);

	if (state == WPA_DISCONNECTED || state == WPA_INACTIVE)
		wpa_supplicant_start_autoscan(wpa_s);

	if (wpa_s->wpa_state != old_state) {
#ifdef ENABLE_UMAC_ROM_PTR
		WPAS_NOTIFY_STATE_CHANGED(wpa_s, wpa_s->wpa_state, old_state);
#else
		wpas_notify_state_changed(wpa_s, wpa_s->wpa_state, old_state);
#endif /* ENABLE_UMAC_ROM_PTR */
		if (wpa_s->wpa_state == WPA_COMPLETED ||
		    old_state == WPA_COMPLETED)
			wpas_notify_auth_changed(wpa_s);
	}
}

#if UNUSED_FEAT_IN_SUPP_29
void wpa_supplicant_terminate_proc(struct wpa_global *global)
{
	int pending = 0;
#ifdef CONFIG_WPS
	struct wpa_supplicant *wpa_s = global->ifaces;
	while (wpa_s) {
		struct wpa_supplicant *next = wpa_s->next;
		if (wpas_wps_terminate_pending(wpa_s) == 1)
			pending = 1;
#ifdef CONFIG_P2P
		if (wpa_s->p2p_group_interface != NOT_P2P_GROUP_INTERFACE ||
		    (wpa_s->current_ssid && wpa_s->current_ssid->p2p_group))
			wpas_p2p_disconnect(wpa_s);
#endif /* CONFIG_P2P */
		wpa_s = next;
	}
#endif /* CONFIG_WPS */
	if (pending)
		return;
	eloop_terminate();
}


static void wpa_supplicant_terminate(int sig, void *signal_ctx)
{
	struct wpa_global *global = signal_ctx;
	wpa_supplicant_terminate_proc(global);
}
#endif


void wpa_supplicant_clear_status(struct wpa_supplicant *wpa_s)
{
	enum wpa_states old_state = wpa_s->wpa_state;

	wpa_s->pairwise_cipher = 0;
	wpa_s->group_cipher = 0;
	wpa_s->mgmt_group_cipher = 0;
	wpa_s->key_mgmt = 0;
	if (wpa_s->wpa_state != WPA_INTERFACE_DISABLED)
		wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);

	if (wpa_s->wpa_state != old_state)
		wpas_notify_state_changed(wpa_s, wpa_s->wpa_state, old_state);
}


/**
 * wpa_supplicant_reload_configuration - Reload configuration data
 * @wpa_s: Pointer to wpa_supplicant data
 * Returns: 0 on success or -1 if configuration parsing failed
 *
 * This function can be used to request that the configuration data is reloaded
 * (e.g., after configuration file change). This function is reloading
 * configuration only for one interface, so this may need to be called multiple
 * times if %wpa_supplicant is controlling multiple interfaces and all
 * interfaces need reconfiguration.
 */
#if UNUSED_FEAT_IN_SUPP_29
int wpa_supplicant_reload_configuration(struct wpa_supplicant *wpa_s)
{
	struct wpa_config *conf;
	int reconf_ctrl;
	int old_ap_scan;

	if (wpa_s->confname == NULL)
		return -1;
	conf = wpa_config_read(wpa_s->confname, NULL);
	if (conf == NULL) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Failed to parse the configuration "
			"file '%s' - exiting", wpa_s->confname);
#endif
		SL_PRINTF(WLAN_SUPP_FAILED_TO_PARSE_THE_CONFIGURATION_FILE_2, WLAN_UMAC, LOG_ERROR, "%s", wpa_s->confname);
		return -1;
	}
	if (wpa_s->confanother &&
	    !wpa_config_read(wpa_s->confanother, conf)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR,
			"Failed to parse the configuration file '%s' - exiting",
			wpa_s->confanother);
#endif
		SL_PRINTF(WLAN_SUPP_FAILED_TO_PARSE_THE_CONFIGURATION_FILE, WLAN_UMAC, LOG_ERROR, "%s", wpa_s->confanother);
		return -1;
	}

	conf->changed_parameters = (unsigned int) -1;

	reconf_ctrl = !!conf->ctrl_interface != !!wpa_s->conf->ctrl_interface
		|| (conf->ctrl_interface && wpa_s->conf->ctrl_interface &&
		    os_strcmp(conf->ctrl_interface,
			      wpa_s->conf->ctrl_interface) != 0);

	if (reconf_ctrl && wpa_s->ctrl_iface) {
		wpa_supplicant_ctrl_iface_deinit(wpa_s->ctrl_iface);
		wpa_s->ctrl_iface = NULL;
	}

	eapol_sm_invalidate_cached_session(wpa_s->eapol);
	if (wpa_s->current_ssid) {
		if (wpa_s->wpa_state >= WPA_AUTHENTICATING)
			wpa_s->own_disconnect_req = 1;
		wpa_supplicant_deauthenticate(wpa_s,
					      WLAN_REASON_DEAUTH_LEAVING);
	}

	/*
	 * TODO: should notify EAPOL SM about changes in opensc_engine_path,
	 * pkcs11_engine_path, pkcs11_module_path, openssl_ciphers.
	 */
	if (wpa_key_mgmt_wpa_psk(wpa_s->key_mgmt) ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_OWE ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_DPP) {
		/*
		 * Clear forced success to clear EAP state for next
		 * authentication.
		 */
		eapol_sm_notify_eap_success(wpa_s->eapol, FALSE);
	}
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	wpa_sm_set_config(wpa_s->wpa, NULL);
	wpa_sm_pmksa_cache_flush(wpa_s->wpa, NULL);
	wpa_sm_set_fast_reauth(wpa_s->wpa, wpa_s->conf->fast_reauth);
	rsn_preauth_deinit(wpa_s->wpa);

	old_ap_scan = wpa_s->conf->ap_scan;
	wpa_config_free(wpa_s->conf);
	wpa_s->conf = conf;
	if (old_ap_scan != wpa_s->conf->ap_scan)
		wpas_notify_ap_scan_changed(wpa_s);

	if (reconf_ctrl)
		wpa_s->ctrl_iface = wpa_supplicant_ctrl_iface_init(wpa_s);

	wpa_supplicant_update_config(wpa_s);

	wpa_supplicant_clear_status(wpa_s);
	if (wpa_supplicant_enabled_networks(wpa_s)) {
		wpa_s->reassociate = 1;
		wpa_supplicant_req_scan(wpa_s, 0, 0);
	}
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Reconfiguration completed");
#endif
	SL_PRINTF(WLAN_SUPP_RECONFIGURATION_COMPLETED, WLAN_UMAC, LOG_INFO);
	return 0;
}


static void wpa_supplicant_reconfig(int sig, void *signal_ctx)
{
	struct wpa_global *global = signal_ctx;
	struct wpa_supplicant *wpa_s;
	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Signal %d received - reconfiguring",
			sig);
#endif
		SL_PRINTF(WLAN_SUPP_SIGNAL_RECEIVED, WLAN_UMAC, LOG_INFO, "Signal %d received - reconfiguring", sig);
		if (wpa_supplicant_reload_configuration(wpa_s) < 0) {
			wpa_supplicant_terminate_proc(global);
		}
	}

	if (wpa_debug_reopen_file() < 0) {
		/* Ignore errors since we cannot really do much to fix this */
		wpa_printf(MSG_DEBUG, "Could not reopen debug log file");
	}
}
#endif

//#ifdef SUPPLICANT_ROM
enum wpa_cipher cipher_suite2driver(int cipher)
{
	switch (cipher) {
		case WPA_CIPHER_NONE:
			return CIPHER_NONE;
		case WPA_CIPHER_WEP40:
			return CIPHER_WEP40;
		case WPA_CIPHER_WEP104:
			return CIPHER_WEP104;
		case WPA_CIPHER_CCMP:
			return CIPHER_CCMP;
		case WPA_CIPHER_GCMP:
			return CIPHER_GCMP;
		case WPA_CIPHER_TKIP:
		default:
			return CIPHER_TKIP;
	}
}


enum wpa_key_mgmt key_mgmt2driver(int key_mgmt)
{
	switch (key_mgmt) {
		case WPA_KEY_MGMT_NONE:                                                    return KEY_MGMT_NONE;
		case WPA_KEY_MGMT_IEEE8021X_NO_WPA:
											   return KEY_MGMT_802_1X_NO_WPA;
		case WPA_KEY_MGMT_IEEE8021X:
											   return KEY_MGMT_802_1X;
		case WPA_KEY_MGMT_WPA_NONE:
											   return KEY_MGMT_WPA_NONE;
		case WPA_KEY_MGMT_FT_IEEE8021X:
											   return KEY_MGMT_FT_802_1X;
		case WPA_KEY_MGMT_FT_PSK:
											   return KEY_MGMT_FT_PSK;
		case WPA_KEY_MGMT_IEEE8021X_SHA256:
											   return KEY_MGMT_802_1X_SHA256;
		case WPA_KEY_MGMT_PSK_SHA256:
											   return KEY_MGMT_PSK_SHA256;
		case WPA_KEY_MGMT_WPS:
											   return KEY_MGMT_WPS;
#ifdef RSI_ENABLE_CCX
		case WPA_KEY_MGMT_CCKM:
											   return WPA_KEY_MGMT_CCKM;
#endif
		case WPA_KEY_MGMT_PSK:
		default:
											   return KEY_MGMT_PSK;
	}
}
//#endif


STATIC int wpa_supplicant_suites_from_ai(struct wpa_supplicant *wpa_s,
					 struct wpa_ssid *ssid,
					 struct wpa_ie_data *ie)
{
	int ret = wpa_sm_parse_own_wpa_ie(wpa_s->wpa, ie);
	if (ret) {
		if (ret == -2) {
			wpa_msg(wpa_s, MSG_INFO, "WPA: Failed to parse WPA IE "
				"from association info");
		}
		return -1;
	}

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "WPA: Using WPA IE from AssocReq to set "
		"cipher suites");
#endif
	SL_PRINTF(WLAN_SUPP_WPA_USING_WPA_IE_FROM_ASSOCREQ_TO_SET_CIPHER_SUITES, WLAN_UMAC, LOG_INFO);
	if (!(ie->group_cipher & ssid->group_cipher)) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Driver used disabled group "
			"cipher 0x%x (mask 0x%x) - reject",
			ie->group_cipher, ssid->group_cipher);
		return -1;
	}
	if (!(ie->pairwise_cipher & ssid->pairwise_cipher)) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Driver used disabled pairwise "
			"cipher 0x%x (mask 0x%x) - reject",
			ie->pairwise_cipher, ssid->pairwise_cipher);
		return -1;
	}
	if (!(ie->key_mgmt & ssid->key_mgmt)) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Driver used disabled key "
			"management 0x%x (mask 0x%x) - reject",
			ie->key_mgmt, ssid->key_mgmt);
		return -1;
	}

#ifdef CONFIG_IEEE80211W
	if (!(ie->capabilities & WPA_CAPABILITY_MFPC) &&
	    wpas_get_ssid_pmf(wpa_s, ssid) == MGMT_FRAME_PROTECTION_REQUIRED) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Driver associated with an AP "
			"that does not support management frame protection - "
			"reject");
		return -1;
	}
#endif /* CONFIG_IEEE80211W */

	return 0;
}


static int matching_ciphers(struct wpa_ssid *ssid, struct wpa_ie_data *ie,
			    int freq)
{
	if (!ie->has_group)
		ie->group_cipher = wpa_default_rsn_cipher(freq);
	if (!ie->has_pairwise)
		ie->pairwise_cipher = wpa_default_rsn_cipher(freq);
	return (ie->group_cipher & ssid->group_cipher) &&
		(ie->pairwise_cipher & ssid->pairwise_cipher);
}


/**
 * wpa_supplicant_set_suites - Set authentication and encryption parameters
 * @wpa_s: Pointer to wpa_supplicant data
 * @bss: Scan results for the selected BSS, or %NULL if not available
 * @ssid: Configuration data for the selected network
 * @wpa_ie: Buffer for the WPA/RSN IE
 * @wpa_ie_len: Maximum wpa_ie buffer size on input. This is changed to be the
 * used buffer length in case the functions returns success.
 * Returns: 0 on success or -1 on failure
 *
 * This function is used to configure authentication and encryption parameters
 * based on the network configuration and scan result for the selected BSS (if
 * available).
 */
int wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
			      struct wpa_bss *bss, struct wpa_ssid *ssid,
			      u8 *wpa_ie, size_t *wpa_ie_len)
{
	struct wpa_ie_data ie;
	struct wpa_driver_auth_params params;
	int sel, proto, sae_pwe;
	const u8 *bss_wpa, *bss_rsn, *bss_rsnx, *bss_osen;

	if (bss) {
		bss_wpa = wpa_bss_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE);
		bss_rsn = wpa_bss_get_ie(bss, WLAN_EID_RSN);
		bss_rsnx = wpa_bss_get_ie(bss, WLAN_EID_RSNX);
		bss_osen = wpa_bss_get_vendor_ie(bss, OSEN_IE_VENDOR_TYPE);
	} else {
		bss_wpa = bss_rsn = bss_rsnx = bss_osen = NULL;
	}

	if (bss_rsn && (ssid->proto & WPA_PROTO_RSN) &&
	    wpa_parse_wpa_ie(bss_rsn, 2 + bss_rsn[1], &ie) == 0 &&
	    matching_ciphers(ssid, &ie, bss->freq) &&
	    (ie.key_mgmt & ssid->key_mgmt)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "RSN: using IEEE 802.11i/D9.0");
#endif
		SL_PRINTF(WLAN_SUPP_RSN_USING_IEEE_802_11I_D90, WLAN_UMAC, LOG_INFO);
		proto = WPA_PROTO_RSN;
	} else if (bss_wpa && (ssid->proto & WPA_PROTO_WPA) &&
		   wpa_parse_wpa_ie(bss_wpa, 2 + bss_wpa[1], &ie) == 0 &&
		   (ie.group_cipher & ssid->group_cipher) &&
		   (ie.pairwise_cipher & ssid->pairwise_cipher) &&
		   (ie.key_mgmt & ssid->key_mgmt)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using IEEE 802.11i/D3.0");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_IEEE_802_11I_D30, WLAN_UMAC, LOG_INFO);
		proto = WPA_PROTO_WPA;
#ifdef CONFIG_HS20
	} else if (bss_osen && (ssid->proto & WPA_PROTO_OSEN) &&
		   wpa_parse_wpa_ie(bss_osen, 2 + bss_osen[1], &ie) == 0 &&
		   (ie.group_cipher & ssid->group_cipher) &&
		   (ie.pairwise_cipher & ssid->pairwise_cipher) &&
		   (ie.key_mgmt & ssid->key_mgmt)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "HS 2.0: using OSEN");
#endif
		SL_PRINTF(WLAN_SUPP_HS_2_0_USING_OSEN, WLAN_UMAC, LOG_INFO);
		proto = WPA_PROTO_OSEN;
	} else if (bss_rsn && (ssid->proto & WPA_PROTO_OSEN) &&
	    wpa_parse_wpa_ie(bss_rsn, 2 + bss_rsn[1], &ie) == 0 &&
	    (ie.group_cipher & ssid->group_cipher) &&
	    (ie.pairwise_cipher & ssid->pairwise_cipher) &&
	    (ie.key_mgmt & ssid->key_mgmt)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "RSN: using OSEN (within RSN)");
#endif
		SL_PRINTF(WLAN_SUPP_RSN_USING_OSEN_WITHIN_RSN, WLAN_UMAC, LOG_INFO);
		proto = WPA_PROTO_RSN;
#endif /* CONFIG_HS20 */
	} else if (bss) {
		wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to select WPA/RSN");
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"WPA: ssid proto=0x%x pairwise_cipher=0x%x group_cipher=0x%x key_mgmt=0x%x",
			ssid->proto, ssid->pairwise_cipher, ssid->group_cipher,
			ssid->key_mgmt);
#endif
		SL_PRINTF(WLAN_SUPP_WPA_SSID_PROTO, WLAN_UMAC, LOG_INFO, "WPA: ssid proto=%4x pairwise_cipher=%4x group_cipher=%4x", ssid->proto, ssid->pairwise_cipher, ssid->group_cipher);
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: BSS " MACSTR " ssid='%s'%s%s%s",
			MAC2STR(bss->bssid),
			wpa_ssid_txt(bss->ssid, bss->ssid_len),
			bss_wpa ? " WPA" : "",
			bss_rsn ? " RSN" : "",
			bss_osen ? " OSEN" : "");
		if (bss_rsn) {
			wpa_hexdump(MSG_DEBUG, "RSN", bss_rsn, 2 + bss_rsn[1]);
			if (wpa_parse_wpa_ie(bss_rsn, 2 + bss_rsn[1], &ie)) {
#if UNUSED_FEAT_IN_SUPP_29
				wpa_dbg(wpa_s, MSG_DEBUG,
					"Could not parse RSN element");
#endif
				SL_PRINTF(WLAN_SUPP_COULD_NOT_PARSE_RSN_ELEMENT, WLAN_UMAC, LOG_INFO);
			} else {
#if UNUSED_FEAT_IN_SUPP_29
				wpa_dbg(wpa_s, MSG_DEBUG,
					"RSN: pairwise_cipher=0x%x group_cipher=0x%x key_mgmt=0x%x",
					ie.pairwise_cipher, ie.group_cipher,
					ie.key_mgmt);
#endif
				SL_PRINTF(WLAN_SUPP_RSN_PAIRWISE_CIPHER, WLAN_UMAC, LOG_INFO, "RSN: pairwise_cipher=%4x group_cipher=%4x key_mgmt=%4x", ie.pairwise_cipher, ie.group_cipher, ie.key_mgmt);
			}
		}
		if (bss_wpa) {
			wpa_hexdump(MSG_DEBUG, "WPA", bss_wpa, 2 + bss_wpa[1]);
			if (wpa_parse_wpa_ie(bss_wpa, 2 + bss_wpa[1], &ie)) {
#if UNUSED_FEAT_IN_SUPP_29
				wpa_dbg(wpa_s, MSG_DEBUG,
					"Could not parse WPA element");
#endif
				SL_PRINTF(WLAN_SUPP_COULD_NOT_PARSE_WPA_ELEMENT, WLAN_UMAC, LOG_INFO);
			} else {
#if UNUSED_FEAT_IN_SUPP_29
				wpa_dbg(wpa_s, MSG_DEBUG,
					"WPA: pairwise_cipher=0x%x group_cipher=0x%x key_mgmt=0x%x",
					ie.pairwise_cipher, ie.group_cipher,
					ie.key_mgmt);
#endif
				SL_PRINTF(WLAN_SUPP_WPA_PAIRWISE_CIPHER, WLAN_UMAC, LOG_INFO, "WPA: pairwise_cipher=%4x group_cipher=%4x key_mgmt=%4x", ie.pairwise_cipher, ie.group_cipher, ie.key_mgmt);
			}
		}
		return -1;
	} else {
		if (ssid->proto & WPA_PROTO_OSEN)
			proto = WPA_PROTO_OSEN;
		else if (ssid->proto & WPA_PROTO_RSN)
			proto = WPA_PROTO_RSN;
		else
			proto = WPA_PROTO_WPA;
		if (wpa_supplicant_suites_from_ai(wpa_s, ssid, &ie) < 0) {
			os_memset(&ie, 0, sizeof(ie));
			ie.group_cipher = ssid->group_cipher;
			ie.pairwise_cipher = ssid->pairwise_cipher;
			ie.key_mgmt = ssid->key_mgmt;
#ifdef CONFIG_IEEE80211W
			ie.mgmt_group_cipher = 0;
			if (ssid->ieee80211w != NO_MGMT_FRAME_PROTECTION) {
				if (ssid->group_mgmt_cipher &
				    WPA_CIPHER_BIP_GMAC_256)
					ie.mgmt_group_cipher =
						WPA_CIPHER_BIP_GMAC_256;
				else if (ssid->group_mgmt_cipher &
					 WPA_CIPHER_BIP_CMAC_256)
					ie.mgmt_group_cipher =
						WPA_CIPHER_BIP_CMAC_256;
				else if (ssid->group_mgmt_cipher &
					 WPA_CIPHER_BIP_GMAC_128)
					ie.mgmt_group_cipher =
						WPA_CIPHER_BIP_GMAC_128;
				else
					ie.mgmt_group_cipher =
						WPA_CIPHER_AES_128_CMAC;
			}
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_OWE
			if ((ssid->key_mgmt & WPA_KEY_MGMT_OWE) &&
			    !ssid->owe_only &&
			    !bss_wpa && !bss_rsn && !bss_osen) {
				wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
				wpa_s->wpa_proto = 0;
				*wpa_ie_len = 0;
				return 0;
			}
#endif /* CONFIG_OWE */
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "WPA: Set cipher suites "
				"based on configuration");
#endif
			SL_PRINTF(WLAN_SUPP_WPA_SET_CIPHER_SUITES_BASED_ON_CONFIGURATION, WLAN_UMAC, LOG_INFO);
		} else
			proto = ie.proto;
	}

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "WPA: Selected cipher suites: group %d "
		"pairwise %d key_mgmt %d proto %d",
		ie.group_cipher, ie.pairwise_cipher, ie.key_mgmt, proto);
#endif
	SL_PRINTF(WLAN_SUPP_WPA_SELECTED_CIPHER_SUITES, WLAN_UMAC, LOG_INFO, "group %d pairwise %d key_mgmt %d", ie.group_cipher, ie.pairwise_cipher, ie.key_mgmt);
#ifdef CONFIG_IEEE80211W
	if (ssid->ieee80211w) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: Selected mgmt group cipher %d",
			ie.mgmt_group_cipher);
#endif
		SL_PRINTF(WLAN_SUPP_WPA_SELECTED_MGMT_GROUP_CIPHER, WLAN_UMAC, LOG_INFO, "cipher %d", ie.mgmt_group_cipher);
	}
#endif /* CONFIG_IEEE80211W */

	wpa_s->wpa_proto = proto;
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PROTO, proto);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_ENABLED,
			 !!(ssid->proto & (WPA_PROTO_RSN | WPA_PROTO_OSEN)));

	if (bss || !wpa_s->ap_ies_from_associnfo) {
		if (wpa_sm_set_ap_wpa_ie(wpa_s->wpa, bss_wpa,
					 bss_wpa ? 2 + bss_wpa[1] : 0) ||
		    wpa_sm_set_ap_rsn_ie(wpa_s->wpa, bss_rsn,
					 bss_rsn ? 2 + bss_rsn[1] : 0) ||
		    wpa_sm_set_ap_rsnxe(wpa_s->wpa, bss_rsnx,
					bss_rsnx ? 2 + bss_rsnx[1] : 0))
			return -1;
	}

#ifdef CONFIG_NO_WPA
	wpa_s->group_cipher = WPA_CIPHER_NONE;
	wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
#else /* CONFIG_NO_WPA */
	sel = ie.group_cipher & ssid->group_cipher;
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG,
		"WPA: AP group 0x%x network profile group 0x%x; available group 0x%x",
		ie.group_cipher, ssid->group_cipher, sel);
#endif
	SL_PRINTF(WLAN_SUPP_WPA_AP_GROUP, WLAN_UMAC, LOG_INFO, "WPA: AP group %4x network profile group %4x; available group %4x", ie.group_cipher, ssid->group_cipher, sel);
	wpa_s->group_cipher = wpa_pick_group_cipher(sel);
	if (wpa_s->group_cipher < 0) {
		wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to select group "
			"cipher");
		return -1;
	}
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using GTK %s",
		wpa_cipher_txt(wpa_s->group_cipher));
#endif
	SL_PRINTF(WLAN_SUPP_WPA_USING_GTK, WLAN_UMAC, LOG_INFO, "GTK %s", wpa_cipher_txt(wpa_s->group_cipher));

	sel = ie.pairwise_cipher & ssid->pairwise_cipher;
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG,
		"WPA: AP pairwise 0x%x network profile pairwise 0x%x; available pairwise 0x%x",
		ie.pairwise_cipher, ssid->pairwise_cipher, sel);
#endif
	SL_PRINTF(WLAN_SUPP_WPA_AP_PAIRWISE, WLAN_UMAC, LOG_INFO, "WPA: AP pairwise %4x network profile pairwise %4x; available pairwise %4x", ie.pairwise_cipher, ssid->pairwise_cipher, sel);
	wpa_s->pairwise_cipher = wpa_pick_pairwise_cipher(sel, 1);
	if (wpa_s->pairwise_cipher < 0) {
		wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to select pairwise "
			"cipher");
		return -1;
	}
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using PTK %s",
		wpa_cipher_txt(wpa_s->pairwise_cipher));
#endif
	SL_PRINTF(WLAN_SUPP_WPA_USING_PTK, WLAN_UMAC, LOG_INFO, "using PTK %s", wpa_cipher_txt(wpa_s->pairwise_cipher));
#endif /* CONFIG_NO_WPA */

	sel = ie.key_mgmt & ssid->key_mgmt;
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG,
		"WPA: AP key_mgmt 0x%x network profile key_mgmt 0x%x; available key_mgmt 0x%x",
		ie.key_mgmt, ssid->key_mgmt, sel);
#endif
	SL_PRINTF(WLAN_SUPP_WPA_AP_KEY_MGMT, WLAN_UMAC, LOG_INFO, "AP key_mgmt %4x network profile key_mgmt %4x; available key_mgmt %4x", ie.key_mgmt, ssid->key_mgmt, sel);
#ifndef CONFIG_SAE /* TODO: Need to register driver flags and enable this code */
	if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_SAE))
		sel &= ~(WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_FT_SAE);
#endif /* CONFIG_SAE */
	if (0) {
#ifdef CONFIG_IEEE80211R
#ifdef CONFIG_SHA384
	} else if (sel & WPA_KEY_MGMT_FT_IEEE8021X_SHA384) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FT_IEEE8021X_SHA384;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"WPA: using KEY_MGMT FT/802.1X-SHA384");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_FT_802_1X_SHA384, WLAN_UMAC, LOG_INFO);
		if (!ssid->ft_eap_pmksa_caching &&
		    pmksa_cache_get_current(wpa_s->wpa)) {
			/* PMKSA caching with FT may have interoperability
			 * issues, so disable that case by default for now. */
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG,
				"WPA: Disable PMKSA caching for FT/802.1X connection");
#endif
			SL_PRINTF(WLAN_SUPP_WPA_DISABLE_PMKSA_CACHING_FOR_FT_802_1X_CONNECTION_2, WLAN_UMAC, LOG_INFO);
			pmksa_cache_clear_current(wpa_s->wpa);
		}
#endif /* CONFIG_SHA384 */
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_SUITEB192
	} else if (sel & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"WPA: using KEY_MGMT 802.1X with Suite B (192-bit)");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_802_1X_WITH_SUITE_B_192_BIT, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_SUITEB192 */
#ifdef CONFIG_SUITEB
	} else if (sel & WPA_KEY_MGMT_IEEE8021X_SUITE_B) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X_SUITE_B;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"WPA: using KEY_MGMT 802.1X with Suite B");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_802_1X_WITH_SUITE_B, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_SUITEB */
#ifdef CONFIG_FILS
#ifdef CONFIG_IEEE80211R
	} else if (sel & WPA_KEY_MGMT_FT_FILS_SHA384) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FT_FILS_SHA384;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT FT-FILS-SHA384");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_FT_FILS_SHA384, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_KEY_MGMT_FT_FILS_SHA256) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FT_FILS_SHA256;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT FT-FILS-SHA256");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_FT_FILS_SHA256, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_IEEE80211R */
	} else if (sel & WPA_KEY_MGMT_FILS_SHA384) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FILS_SHA384;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT FILS-SHA384");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_FILS_SHA384, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_KEY_MGMT_FILS_SHA256) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FILS_SHA256;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT FILS-SHA256");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_FILS_SHA256, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_FILS */
#ifdef CONFIG_IEEE80211R
	} else if (sel & WPA_KEY_MGMT_FT_IEEE8021X) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FT_IEEE8021X;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT FT/802.1X");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_FT_802_1X, WLAN_UMAC, LOG_INFO);
		if (!ssid->ft_eap_pmksa_caching &&
		    pmksa_cache_get_current(wpa_s->wpa)) {
			/* PMKSA caching with FT may have interoperability
			 * issues, so disable that case by default for now. */
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG,
				"WPA: Disable PMKSA caching for FT/802.1X connection");
#endif
			SL_PRINTF(WLAN_SUPP_WPA_DISABLE_PMKSA_CACHING_FOR_FT_802_1X_CONNECTION, WLAN_UMAC, LOG_INFO);
			pmksa_cache_clear_current(wpa_s->wpa);
		}
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_DPP
	} else if (sel & WPA_KEY_MGMT_DPP) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_DPP;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "RSN: using KEY_MGMT DPP");
#endif
		SL_PRINTF(WLAN_SUPP_RSN_USING_KEY_MGMT_DPP, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_DPP */
#ifdef CONFIG_SAE
	} else if (sel & WPA_KEY_MGMT_FT_SAE) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FT_SAE;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "RSN: using KEY_MGMT FT/SAE");
#endif
		SL_PRINTF(WLAN_SUPP_RSN_USING_KEY_MGMT_FT_SAE, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_KEY_MGMT_SAE) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_SAE;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "RSN: using KEY_MGMT SAE");
#endif
		SL_PRINTF(WLAN_SUPP_RSN_USING_KEY_MGMT_SAE, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_SAE */
#ifdef CONFIG_IEEE80211R
	} else if (sel & WPA_KEY_MGMT_FT_PSK) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_FT_PSK;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT FT/PSK");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_FT_PSK, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
	} else if (sel & WPA_KEY_MGMT_IEEE8021X_SHA256) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X_SHA256;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"WPA: using KEY_MGMT 802.1X with SHA256");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_802_1X_WITH_SHA256, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_KEY_MGMT_PSK_SHA256) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_PSK_SHA256;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"WPA: using KEY_MGMT PSK with SHA256");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_PSK_WITH_SHA256, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_IEEE80211W */
#ifdef RSI_ENABLE_CCX
	} else if (sel & WPA_KEY_MGMT_CCKM) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_CCKM;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
				"WPA: using KEY_MGMT 802.1X with CCKM");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_802_1X_WITH_CCKM, WLAN_UMAC, LOG_INFO);
#endif
	} else if (sel & WPA_KEY_MGMT_IEEE8021X) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT 802.1X");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_802_1X, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_KEY_MGMT_PSK) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_PSK;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT WPA-PSK");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_WPA_PSK, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_KEY_MGMT_WPA_NONE) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_WPA_NONE;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using KEY_MGMT WPA-NONE");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_KEY_MGMT_WPA_NONE, WLAN_UMAC, LOG_INFO);
#ifdef CONFIG_HS20
	} else if (sel & WPA_KEY_MGMT_OSEN) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_OSEN;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "HS 2.0: using KEY_MGMT OSEN");
#endif
		SL_PRINTF(WLAN_SUPP_HS_2_0_USING_KEY_MGMT_OSEN, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_HS20 */
#ifdef CONFIG_OWE
	} else if (sel & WPA_KEY_MGMT_OWE) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_OWE;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "RSN: using KEY_MGMT OWE");
#endif
		SL_PRINTF(WLAN_SUPP_RSN_USING_KEY_MGMT_OWE, WLAN_UMAC, LOG_INFO);
#endif /* CONFIG_OWE */
	} else {
		wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to select "
			"authenticated key management type");
		return -1;
	}

	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_KEY_MGMT, wpa_s->key_mgmt);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PAIRWISE,
			 wpa_s->pairwise_cipher);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_GROUP, wpa_s->group_cipher);

#ifdef CONFIG_IEEE80211W
	sel = ie.mgmt_group_cipher;
	if (ssid->group_mgmt_cipher)
		sel &= ssid->group_mgmt_cipher;
	if (wpas_get_ssid_pmf(wpa_s, ssid) == NO_MGMT_FRAME_PROTECTION ||
	    !(ie.capabilities & WPA_CAPABILITY_MFPC))
		sel = 0;
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG,
		"WPA: AP mgmt_group_cipher 0x%x network profile mgmt_group_cipher 0x%x; available mgmt_group_cipher 0x%x",
		ie.mgmt_group_cipher, ssid->group_mgmt_cipher, sel);
#endif
	SL_PRINTF(WLAN_SUPP_WPA_AP_MGMT_GROUP_CIPHER, WLAN_UMAC, LOG_INFO, "WPA: AP mgmt_group_cipher %4x network profile mgmt_group_cipher %4x; available mgmt_group_cipher %4x", ie.mgmt_group_cipher, ssid->group_mgmt_cipher, sel);
	if (sel & WPA_CIPHER_AES_128_CMAC) {
		wpa_s->mgmt_group_cipher = WPA_CIPHER_AES_128_CMAC;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using MGMT group cipher "
			"AES-128-CMAC");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_MGMT_GROUP_CIPHER_AES_128_CMAC, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_CIPHER_BIP_GMAC_128) {
		wpa_s->mgmt_group_cipher = WPA_CIPHER_BIP_GMAC_128;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using MGMT group cipher "
			"BIP-GMAC-128");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_MGMT_GROUP_CIPHER_BIP_GMAC128, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_CIPHER_BIP_GMAC_256) {
		wpa_s->mgmt_group_cipher = WPA_CIPHER_BIP_GMAC_256;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using MGMT group cipher "
			"BIP-GMAC-256");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_MGMT_GROUP_CIPHER_BIP_GMAC256, WLAN_UMAC, LOG_INFO);
	} else if (sel & WPA_CIPHER_BIP_CMAC_256) {
		wpa_s->mgmt_group_cipher = WPA_CIPHER_BIP_CMAC_256;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: using MGMT group cipher "
			"BIP-CMAC-256");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_USING_MGMT_GROUP_CIPHER_BIP_CMAC256, WLAN_UMAC, LOG_INFO);
	} else {
		wpa_s->mgmt_group_cipher = 0;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "WPA: not using MGMT group cipher");
#endif
		SL_PRINTF(WLAN_SUPP_WPA_NOT_USING_MGMT_GROUP_CIPHER, WLAN_UMAC, LOG_INFO);
	}
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_MGMT_GROUP,
			 wpa_s->mgmt_group_cipher);
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_MFP,
			 wpas_get_ssid_pmf(wpa_s, ssid));
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_OCV
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_OCV, ssid->ocv);
#endif /* CONFIG_OCV */
#ifdef SUPPLICANT_PORTING	
		/*Inclusion or deletion of RSNXE IE is done here in case of Transition mode (WPA3/WAP2)*/
		if(wpa_s->key_mgmt & WPA_KEY_MGMT_SAE)
			wpa_s->conf->sae_pwe = 2;
		else{
			wpa_sm_set_assoc_rsnxe(wpa_s->wpa, NULL, 0);
			wpa_s->conf->sae_pwe = 0;
		}
#endif /*SUPPLICANT_PORTING*/

	sae_pwe = wpa_s->conf->sae_pwe;
	if (ssid->sae_password_id && sae_pwe != 3)
		sae_pwe = 1;
	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_SAE_PWE, sae_pwe);

	if (wpa_sm_set_assoc_wpa_ie_default(wpa_s->wpa, wpa_ie, wpa_ie_len)) {
		wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to generate WPA IE");
		return -1;
	}

	wpa_s->rsnxe_len = sizeof(wpa_s->rsnxe);
	if (wpa_sm_set_assoc_rsnxe_default(wpa_s->wpa, wpa_s->rsnxe,
					   &wpa_s->rsnxe_len)) {
		wpa_msg(wpa_s, MSG_WARNING, "RSN: Failed to generate RSNXE");
		return -1;
	}
#ifdef SUPPLICANT_PORTING	
	/*this is required to include rsnxe ie in Assoc request frame*/
	//os_memcpy(pw_str, wpabuf_head(pw), wpabuf_len(pw));
if (wpa_s->rsnxe_len){
	int ie_counter;
	for(ie_counter=0;ie_counter<wpa_s->rsnxe_len;ie_counter++){
		wpa_ie[*wpa_ie_len+ie_counter]=  wpa_s->rsnxe[ie_counter];
	}
	*wpa_ie_len+=wpa_s->rsnxe_len;
}
#endif /*SUPPLICANT_PORTING*/
	if (0) {
#ifdef CONFIG_DPP
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_DPP) {
		/* Use PMK from DPP network introduction (PMKSA entry) */
		wpa_sm_set_pmk_from_pmksa(wpa_s->wpa);
#endif /* CONFIG_DPP */
	} else if (wpa_key_mgmt_wpa_psk(ssid->key_mgmt)) {
		int psk_set = 0;
		int sae_only;

		sae_only = (ssid->key_mgmt & (WPA_KEY_MGMT_PSK |
					      WPA_KEY_MGMT_FT_PSK |
					      WPA_KEY_MGMT_PSK_SHA256)) == 0;

		if (ssid->psk_set && !sae_only) {
			wpa_hexdump_key(MSG_MSGDUMP, "PSK (set in config)",
					ssid->psk, PMK_LEN);
			wpa_sm_set_pmk(wpa_s->wpa, ssid->psk, PMK_LEN, NULL,
				       NULL);
			psk_set = 1;
		}

		if (wpa_key_mgmt_sae(ssid->key_mgmt) &&
		    (ssid->sae_password || ssid->passphrase)){

#ifdef CONFIG_SAE
	wpa_s->sme.sae_pmksa_caching = 0;
	if (wpa_key_mgmt_sae(ssid->key_mgmt)) {
		const u8 *rsn;
		struct wpa_ie_data ied;
		rsn = wpa_bss_get_ie(bss, WLAN_EID_RSN);
		if (!rsn) {
			wpa_dbg(wpa_s, MSG_DEBUG,
				"SAE enabled, but target BSS does not advertise RSN");
		} else if (wpa_parse_wpa_ie(rsn, 2 + rsn[1], &ied) == 0 &&
			   wpa_key_mgmt_sae(ied.key_mgmt)) {
			wpa_dbg(wpa_s, MSG_DEBUG, "Using SAE auth_alg");
			params.auth_alg = WPA_AUTH_ALG_SAE;
		} else {
			wpa_dbg(wpa_s, MSG_DEBUG,
				"SAE enabled, but target BSS does not advertise SAE AKM for RSN");
		}
	}
	if (params.auth_alg == WPA_AUTH_ALG_SAE &&
	    pmksa_cache_set_current(wpa_s->wpa, NULL, bss->bssid, ssid, 0,
				    NULL,
				    wpa_s->key_mgmt == WPA_KEY_MGMT_FT_SAE ?
				    WPA_KEY_MGMT_FT_SAE :
				    WPA_KEY_MGMT_SAE) == 0) {
		wpa_dbg(wpa_s, MSG_DEBUG,
			"PMKSA cache entry found - try to use PMKSA caching instead of new SAE authentication");
		wpa_sm_set_pmk_from_pmksa(wpa_s->wpa);
		params.auth_alg = WPA_AUTH_ALG_OPEN;
		wpa_s->sme.sae_pmksa_caching = 1;
	}
	SL_PRINTF(WLAN_SUPP_PMKSA_VALUE, WLAN_UMAC, LOG_INFO, "sae_pmksa: %d", wpa_s->sme.sae_pmksa_caching);
#endif /* CONFIG_SAE */
			psk_set = 1;
			}

#ifndef CONFIG_NO_PBKDF2
		if (bss && ssid->bssid_set && ssid->ssid_len == 0 &&
		    ssid->passphrase && !sae_only) {
			u8 psk[PMK_LEN];
		        pbkdf2_sha1(ssid->passphrase, bss->ssid, bss->ssid_len,
				    4096, psk, PMK_LEN);
		        wpa_hexdump_key(MSG_MSGDUMP, "PSK (from passphrase)",
					psk, PMK_LEN);
			wpa_sm_set_pmk(wpa_s->wpa, psk, PMK_LEN, NULL, NULL);
			psk_set = 1;
			os_memset(psk, 0, sizeof(psk));
		}
#endif /* CONFIG_NO_PBKDF2 */
#ifdef CONFIG_EXT_PASSWORD
		if (ssid->ext_psk && !sae_only) {
			struct wpabuf *pw = ext_password_get(wpa_s->ext_pw,
							     ssid->ext_psk);
			char pw_str[64 + 1];
			u8 psk[PMK_LEN];

			if (pw == NULL) {
				wpa_msg(wpa_s, MSG_INFO, "EXT PW: No PSK "
					"found from external storage");
				return -1;
			}

			if (wpabuf_len(pw) < 8 || wpabuf_len(pw) > 64) {
				wpa_msg(wpa_s, MSG_INFO, "EXT PW: Unexpected "
					"PSK length %d in external storage",
					(int) wpabuf_len(pw));
				ext_password_free(pw);
				return -1;
			}

			os_memcpy(pw_str, wpabuf_head(pw), wpabuf_len(pw));
			pw_str[wpabuf_len(pw)] = '\0';

#ifndef CONFIG_NO_PBKDF2
			if (wpabuf_len(pw) >= 8 && wpabuf_len(pw) < 64 && bss)
			{
				pbkdf2_sha1(pw_str, bss->ssid, bss->ssid_len,
					    4096, psk, PMK_LEN);
				os_memset(pw_str, 0, sizeof(pw_str));
				wpa_hexdump_key(MSG_MSGDUMP, "PSK (from "
						"external passphrase)",
						psk, PMK_LEN);
				wpa_sm_set_pmk(wpa_s->wpa, psk, PMK_LEN, NULL,
					       NULL);
				psk_set = 1;
				os_memset(psk, 0, sizeof(psk));
			} else
#endif /* CONFIG_NO_PBKDF2 */
			if (wpabuf_len(pw) == 2 * PMK_LEN) {
				if (hexstr2bin(pw_str, psk, PMK_LEN) < 0) {
					wpa_msg(wpa_s, MSG_INFO, "EXT PW: "
						"Invalid PSK hex string");
					os_memset(pw_str, 0, sizeof(pw_str));
					ext_password_free(pw);
					return -1;
				}
				wpa_hexdump_key(MSG_MSGDUMP,
						"PSK (from external PSK)",
						psk, PMK_LEN);
				wpa_sm_set_pmk(wpa_s->wpa, psk, PMK_LEN, NULL,
					       NULL);
				psk_set = 1;
				os_memset(psk, 0, sizeof(psk));
			} else {
				wpa_msg(wpa_s, MSG_INFO, "EXT PW: No suitable "
					"PSK available");
				os_memset(pw_str, 0, sizeof(pw_str));
				ext_password_free(pw);
				return -1;
			}

			os_memset(pw_str, 0, sizeof(pw_str));
			ext_password_free(pw);
		}
#endif /* CONFIG_EXT_PASSWORD */

		if (!psk_set) {
			wpa_msg(wpa_s, MSG_INFO,
				"No PSK available for association");
			wpas_auth_failed(wpa_s, "NO_PSK_AVAILABLE");
			return -1;
		}
#ifdef CONFIG_OWE
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_OWE) {
		/* OWE Diffie-Hellman exchange in (Re)Association
		 * Request/Response frames set the PMK, so do not override it
		 * here. */
#endif /* CONFIG_OWE */
	} else
		wpa_sm_set_pmk_from_pmksa(wpa_s->wpa);

	return 0;
}


static void wpas_ext_capab_byte(struct wpa_supplicant *wpa_s, u8 *pos, int idx)
{
	*pos = 0x00;

	switch (idx) {
	case 0: /* Bits 0-7 */
		break;
	case 1: /* Bits 8-15 */
		if (wpa_s->conf->coloc_intf_reporting) {
			/* Bit 13 - Collocated Interference Reporting */
			*pos |= 0x20;
		}
		break;
	case 2: /* Bits 16-23 */
#ifdef CONFIG_WNM
		*pos |= 0x02; /* Bit 17 - WNM-Sleep Mode */
		if (!wpa_s->disable_mbo_oce && !wpa_s->conf->disable_btm)
			*pos |= 0x08; /* Bit 19 - BSS Transition */
#endif /* CONFIG_WNM */
		break;
	case 3: /* Bits 24-31 */
#ifdef CONFIG_WNM
		*pos |= 0x02; /* Bit 25 - SSID List */
#endif /* CONFIG_WNM */
#ifdef CONFIG_INTERWORKING
		if (wpa_s->conf->interworking)
			*pos |= 0x80; /* Bit 31 - Interworking */
#endif /* CONFIG_INTERWORKING */
		break;
	case 4: /* Bits 32-39 */
#ifdef CONFIG_INTERWORKING
		if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_QOS_MAPPING)
			*pos |= 0x01; /* Bit 32 - QoS Map */
#endif /* CONFIG_INTERWORKING */
		break;
	case 5: /* Bits 40-47 */
#ifdef CONFIG_HS20
		if (wpa_s->conf->hs20)
			*pos |= 0x40; /* Bit 46 - WNM-Notification */
#endif /* CONFIG_HS20 */
#ifdef CONFIG_MBO_STA
		*pos |= 0x40; /* Bit 46 - WNM-Notification */
#endif /* CONFIG_MBO_STA */
		break;
	case 6: /* Bits 48-55 */
		break;
	case 7: /* Bits 56-63 */
		break;
	case 8: /* Bits 64-71 */
		if (wpa_s->conf->ftm_responder)
			*pos |= 0x40; /* Bit 70 - FTM responder */
		if (wpa_s->conf->ftm_initiator)
			*pos |= 0x80; /* Bit 71 - FTM initiator */
		break;
	case 9: /* Bits 72-79 */
#ifdef CONFIG_FILS
		if (!wpa_s->disable_fils)
			*pos |= 0x01;
#endif /* CONFIG_FILS */
		break;
	}
}


int wpas_build_ext_capab(struct wpa_supplicant *wpa_s, u8 *buf, size_t buflen)
{
	u8 *pos = buf;
	u8 len = 10, i;

	if (len < wpa_s->extended_capa_len)
		len = wpa_s->extended_capa_len;
	if (buflen < (size_t) len + 2) {
		wpa_printf(MSG_INFO,
			   "Not enough room for building extended capabilities element");
		return -1;
	}

	*pos++ = WLAN_EID_EXT_CAPAB;
	*pos++ = len;
	for (i = 0; i < len; i++, pos++) {
		wpas_ext_capab_byte(wpa_s, pos, i);

		if (i < wpa_s->extended_capa_len) {
			*pos &= ~wpa_s->extended_capa_mask[i];
			*pos |= wpa_s->extended_capa[i];
		}
	}

	while (len > 0 && buf[1 + len] == 0) {
		len--;
		buf[1] = len;
	}
	if (len == 0)
		return 0;

	return 2 + len;
}


#if UNUSED_FEAT_IN_SUPP_29
static int wpas_valid_bss(struct wpa_supplicant *wpa_s,
			  struct wpa_bss *test_bss)
{
	struct wpa_bss *bss;

	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		if (bss == test_bss)
			return 1;
	}

	return 0;
}


static int wpas_valid_ssid(struct wpa_supplicant *wpa_s,
			   struct wpa_ssid *test_ssid)
{
	struct wpa_ssid *ssid;

	for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next) {
		if (ssid == test_ssid)
			return 1;
	}

	return 0;
}


int wpas_valid_bss_ssid(struct wpa_supplicant *wpa_s, struct wpa_bss *test_bss,
			struct wpa_ssid *test_ssid)
{
	if (test_bss && !wpas_valid_bss(wpa_s, test_bss))
		return 0;

	return test_ssid == NULL || wpas_valid_ssid(wpa_s, test_ssid);
}

void wpas_connect_work_free(struct wpa_connect_work *cwork)
{
	if (cwork == NULL)
		return;
	os_free(cwork);
}


void wpas_connect_work_done(struct wpa_supplicant *wpa_s)
{
	struct wpa_connect_work *cwork;
	struct wpa_radio_work *work = wpa_s->connect_work;

	if (!work)
		return;

	wpa_s->connect_work = NULL;
	cwork = work->ctx;
	work->ctx = NULL;
	wpas_connect_work_free(cwork);
	radio_work_done(work);
}


int wpas_update_random_addr(struct wpa_supplicant *wpa_s, int style)
{
	struct os_reltime now;
	u8 addr[ETH_ALEN];

	os_get_reltime(&now);
	if (wpa_s->last_mac_addr_style == style &&
	    wpa_s->last_mac_addr_change.sec != 0 &&
	    !os_reltime_expired(&now, &wpa_s->last_mac_addr_change,
				wpa_s->conf->rand_addr_lifetime)) {
		wpa_msg(wpa_s, MSG_DEBUG,
			"Previously selected random MAC address has not yet expired");
		return 0;
	}

	switch (style) {
	case 1:
		if (random_mac_addr(addr) < 0)
			return -1;
		break;
	case 2:
		os_memcpy(addr, wpa_s->perm_addr, ETH_ALEN);
		if (random_mac_addr_keep_oui(addr) < 0)
			return -1;
		break;
	default:
		return -1;
	}

	if (wpa_drv_set_mac_addr(wpa_s, addr) < 0) {
		wpa_msg(wpa_s, MSG_INFO,
			"Failed to set random MAC address");
		return -1;
	}

	os_get_reltime(&wpa_s->last_mac_addr_change);
	wpa_s->mac_addr_changed = 1;
	wpa_s->last_mac_addr_style = style;

	if (wpa_supplicant_update_mac_addr(wpa_s) < 0) {
		wpa_msg(wpa_s, MSG_INFO,
			"Could not update MAC address information");
		return -1;
	}

	wpa_msg(wpa_s, MSG_DEBUG, "Using random MAC address " MACSTR,
		MAC2STR(addr));

	return 0;
}


int wpas_update_random_addr_disassoc(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->wpa_state >= WPA_AUTHENTICATING ||
	    !wpa_s->conf->preassoc_mac_addr)
		return 0;

	return wpas_update_random_addr(wpa_s, wpa_s->conf->preassoc_mac_addr);
}


static void wpas_start_assoc_cb(struct wpa_radio_work *work, int deinit);
#endif

/**
 * wpa_supplicant_associate - Request association
 * @wpa_s: Pointer to wpa_supplicant data
 * @bss: Scan results for the selected BSS, or %NULL if not available
 * @ssid: Configuration data for the selected network
 *
 * This function is used to request %wpa_supplicant to associate with a BSS.
 */
Boolean sae_pk_valid_password(const char *pw)
{
       return FALSE;
}

static void wpa_s_setup_sae_pt(struct wpa_config *conf, struct wpa_ssid *ssid)
{
#ifdef CONFIG_SAE
       int *groups = conf->sae_groups;
	int default_groups[] = { 19, 20, 21, 0 };
       const char *password;

       if (!groups || groups[0] <= 0)
               groups = default_groups;

       password = ssid->sae_password;
       if (!password)
               password = ssid->passphrase;

	   if (!password ||
           (conf->sae_pwe == 0 && !ssid->sae_password_id &&
            !sae_pk_valid_password(password)) ||
           conf->sae_pwe == 3) {
               /* PT derivation not needed */
               sae_deinit_pt(ssid->pt);
               ssid->pt = NULL;
               return;
       }

       if (ssid->pt)
               return; /* PT already derived */
       ssid->pt = sae_derive_pt(groups, ssid->ssid, ssid->ssid_len,
                                (const u8 *) password, os_strlen(password),
                                ssid->sae_password_id);
#endif /* CONFIG_SAE */
}

#if UNUSED_FEAT_IN_SUPP_29
static void wpa_s_clear_sae_rejected(struct wpa_supplicant *wpa_s)
{
#if defined(CONFIG_SAE) && defined(CONFIG_SME)
       os_free(wpa_s->sme.sae_rejected_groups);
       wpa_s->sme.sae_rejected_groups = NULL;
#ifdef CONFIG_TESTING_OPTIONS
       if (wpa_s->extra_sae_rejected_groups) {
               int i, *groups = wpa_s->extra_sae_rejected_groups;

               for (i = 0; groups[i]; i++) {
                       wpa_printf(MSG_DEBUG,
                                  "TESTING: Indicate rejection of an extra SAE group %d",
                                  groups[i]);
                       int_array_add_unique(&wpa_s->sme.sae_rejected_groups,
                                            groups[i]);
               }
       }
#endif /* CONFIG_TESTING_OPTIONS */
#endif /* CONFIG_SAE && CONFIG_SME */
}
#endif

void wpa_supplicant_associate(struct wpa_supplicant *wpa_s,
			      struct wpa_bss *bss, struct wpa_ssid *ssid)
{

#if UNUSED_FEAT_IN_SUPP_29
	struct wpa_connect_work *cwork;
	int rand_style;

	wpa_s->own_disconnect_req = 0;

	/*
	 * If we are starting a new connection, any previously pending EAPOL
	 * RX cannot be valid anymore.
	 */
	wpabuf_free(wpa_s->pending_eapol_rx);
	wpa_s->pending_eapol_rx = NULL;

	if (ssid->mac_addr == -1)
		rand_style = wpa_s->conf->mac_addr;
	else
		rand_style = ssid->mac_addr;

	//wmm_ac_clear_saved_tspecs(wpa_s);
	wpa_s->reassoc_same_bss = 0;
	wpa_s->reassoc_same_ess = 0;
#ifdef CONFIG_TESTING_OPTIONS
	wpa_s->testing_resend_assoc = 0;
#endif /* CONFIG_TESTING_OPTIONS */

	if (wpa_s->last_ssid == ssid) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Re-association to the same ESS");
#endif
		SL_PRINTF(WLAN_SUPP_RE_ASSOCIATION_TO_THE_SAME_ESS, WLAN_UMAC, LOG_INFO);
		wpa_s->reassoc_same_ess = 1;
		if (wpa_s->current_bss && wpa_s->current_bss == bss) {
		//	wmm_ac_save_tspecs(wpa_s);
			wpa_s->reassoc_same_bss = 1;
		} else if (wpa_s->current_bss && wpa_s->current_bss != bss) {
			os_get_reltime(&wpa_s->roam_start);
		}
	}

	if (rand_style > 0 && !wpa_s->reassoc_same_ess) {
		if (wpas_update_random_addr(wpa_s, rand_style) < 0)
			return;
		wpa_sm_pmksa_cache_flush(wpa_s->wpa, ssid);
	} else if (rand_style == 0 && wpa_s->mac_addr_changed) {
		if (wpa_drv_set_mac_addr(wpa_s, NULL) < 0) {
			wpa_msg(wpa_s, MSG_INFO,
				"Could not restore permanent MAC address");
			return;
		}
		wpa_s->mac_addr_changed = 0;
		if (wpa_supplicant_update_mac_addr(wpa_s) < 0) {
			wpa_msg(wpa_s, MSG_INFO,
				"Could not update MAC address information");
			return;
		}
		wpa_msg(wpa_s, MSG_DEBUG, "Using permanent MAC address");
	}
	wpa_s->last_ssid = ssid;

#ifdef CONFIG_IBSS_RSN
	ibss_rsn_deinit(wpa_s->ibss_rsn);
	wpa_s->ibss_rsn = NULL;
#else /* CONFIG_IBSS_RSN */
	if (ssid->mode == WPAS_MODE_IBSS &&
	    !(ssid->key_mgmt & (WPA_KEY_MGMT_NONE | WPA_KEY_MGMT_WPA_NONE))) {
		wpa_msg(wpa_s, MSG_INFO,
			"IBSS RSN not supported in the build");
		return;
	}
#endif /* CONFIG_IBSS_RSN */

	if (ssid->mode == WPAS_MODE_AP || ssid->mode == WPAS_MODE_P2P_GO ||
	    ssid->mode == WPAS_MODE_P2P_GROUP_FORMATION) {
#ifdef CONFIG_AP
		if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_AP)) {
			wpa_msg(wpa_s, MSG_INFO, "Driver does not support AP "
				"mode");
			return;
		}
		if (wpa_supplicant_create_ap(wpa_s, ssid) < 0) {
			wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
#ifdef ENABLE_UMAC_ROM_PTR
			SEND_AP_JOIN_FAIL_RESPONSE(); /* K60_PORTING */
#else
			send_ap_join_fail_response();
#endif /* ENABLE_UMAC_ROM_PTR */
			if (ssid->mode == WPAS_MODE_P2P_GROUP_FORMATION)
				wpas_p2p_ap_setup_failed(wpa_s);
			return;
		}
		wpa_s->current_bss = bss;
#else /* CONFIG_AP */
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "AP mode support not included in "
			"the build");
#endif
		SL_PRINTF(WLAN_SUPP_AP_MODE_SUPPORT_NOT_INCLUDED_IN_THE_BUILD_2, WLAN_UMAC, LOG_ERROR);
#endif /* CONFIG_AP */
		return;
	}

	if (ssid->mode == WPAS_MODE_MESH) {
#ifdef CONFIG_MESH
		if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_MESH)) {
			wpa_msg(wpa_s, MSG_INFO,
				"Driver does not support mesh mode");
			return;
		}
		if (bss)
			ssid->frequency = bss->freq;
		if (wpa_supplicant_join_mesh(wpa_s, ssid) < 0) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_msg(wpa_s, MSG_ERROR, "Could not join mesh");
#endif
			SL_PRINTF(WLAN_SUPP_COULD_NOT_JOIN_MESH, WLAN_UMAC, LOG_ERROR);
			return;
		}
		wpa_s->current_bss = bss;
		wpa_msg(wpa_s, MSG_INFO, MESH_GROUP_STARTED "ssid=\"%s\" id=%d",
			wpa_ssid_txt(ssid->ssid, ssid->ssid_len),
			ssid->id);
		wpas_notify_mesh_group_started(wpa_s, ssid);
#else /* CONFIG_MESH */
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR,
			"mesh mode support not included in the build");
#endif
		SL_PRINTF(WLAN_SUPP_MESH_MODE_SUPPORT_NOT_INCLUDED_IN_THE_BUILD, WLAN_UMAC, LOG_ERROR);
#endif /* CONFIG_MESH */
		return;
	}

	/*
	 * Set WPA state machine configuration to match the selected network now
	 * so that the information is available before wpas_start_assoc_cb()
	 * gets called. This is needed at least for RSN pre-authentication where
	 * candidate APs are added to a list based on scan result processing
	 * before completion of the first association.
	 */
	wpa_supplicant_rsn_supp_set_config(wpa_s, ssid);

#ifdef CONFIG_DPP
	if (wpas_dpp_check_connect(wpa_s, ssid, bss) != 0)
		return;
#endif /* CONFIG_DPP */

#ifdef CONFIG_TDLS
	if (bss)
		wpa_tdls_ap_ies(wpa_s->wpa, (const u8 *) (bss + 1),
				bss->ie_len);
#endif /* CONFIG_TDLS */

	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) &&
	    ssid->mode == WPAS_MODE_INFRA) {
		sme_authenticate(wpa_s, bss, ssid);
		return;
	}

	if (wpa_s->connect_work) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Reject wpa_supplicant_associate() call since connect_work exist");
#endif
		SL_PRINTF(WLAN_SUPP_REJECT_WPA_SUPPLICANT_ASSOCIATE_CALL_SINCE_CONNECT_WORK_EXIST, WLAN_UMAC, LOG_INFO);
		return;
	}

	if (radio_work_pending(wpa_s, "connect")) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Reject wpa_supplicant_associate() call since pending work exist");
#endif
		SL_PRINTF(WLAN_SUPP_REJECT_WPA_SUPPLICANT_ASSOCIATE_CALL_SINCE_PENDING_WORK_EXIST, WLAN_UMAC, LOG_INFO);
		return;
	}

#ifdef CONFIG_SME
	if (ssid->mode == WPAS_MODE_IBSS || ssid->mode == WPAS_MODE_MESH) {
		/* Clear possibly set auth_alg, if any, from last attempt. */
		wpa_s->sme.auth_alg = WPA_AUTH_ALG_OPEN;
	}
#endif /* CONFIG_SME */

	wpas_abort_ongoing_scan(wpa_s);

	cwork = os_zalloc(sizeof(*cwork));
	if (cwork == NULL)
		return;

	cwork->bss = bss;
	cwork->ssid = ssid;

	if (radio_add_work(wpa_s, bss ? bss->freq : 0, "connect", 1,
			   wpas_start_assoc_cb, cwork) < 0) {
		os_free(cwork);
	}
#endif
#if 1
#ifdef CONFIG_MBO_STA
	u8 wpa_ie[400];
#else
	u8 wpa_ie[200];
#endif
	size_t wpa_ie_len;
	int use_crypt, ret, i, bssid_changed;
	int algs = WPA_AUTH_ALG_OPEN;
#ifdef CONFIG_MBO_STA
	const u8 *mbo_ie = NULL;
    size_t max_wpa_ie_len = sizeof(wpa_ie);
#endif
	wpa_s->own_disconnect_req = 0;
	/*
	 * If we are starting a new connection, any previously pending EAPOL
	 * RX cannot be valid anymore.
	 */
	wpabuf_free(wpa_s->pending_eapol_rx);
	wpa_s->pending_eapol_rx = NULL;

	enum wpa_cipher cipher_pairwise, cipher_group;
	struct wpa_driver_associate_params *params;
	int wep_keys_set = 0;
	struct wpa_driver_capa capa;
	int assoc_failed = 0;
	struct wpa_ssid *old_ssid;
#ifdef CONFIG_HT_OVERRIDES
	struct ieee80211_ht_capabilities htcaps;
	struct ieee80211_ht_capabilities htcaps_mask;
#endif /* CONFIG_HT_OVERRIDES */


#ifdef CONFIG_IBSS_RSN
	ibss_rsn_deinit(wpa_s->ibss_rsn);
	wpa_s->ibss_rsn = NULL;
#endif /* CONFIG_IBSS_RSN */

	if (ssid->mode == WPAS_MODE_AP || ssid->mode == WPAS_MODE_P2P_GO ||
	    ssid->mode == WPAS_MODE_P2P_GROUP_FORMATION) {
#ifdef CONFIG_AP
		if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_AP)) {
			wpa_msg(wpa_s, MSG_INFO, "Driver does not support AP "
				"mode");
			return;
		}
#ifdef ENABLE_UMAC_ROM_PTR
		if (WPA_SUPPLICANT_CREATE_AP(wpa_s, ssid) < 0)
#else
		if (wpa_supplicant_create_ap(wpa_s, ssid) < 0)
#endif
		{
			wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
#ifdef ENABLE_UMAC_ROM_PTR
			SEND_AP_JOIN_FAIL_RESPONSE(); /* K60_PORTING */
#else
			send_ap_join_fail_response();
#endif /* ENABLE_UMAC_ROM_PTR */
			return;
		}
		wpa_s->current_bss = bss;
#else /* CONFIG_AP */
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "AP mode support not included in "
			"the build");
#endif
		SL_PRINTF(WLAN_SUPP_AP_MODE_SUPPORT_NOT_INCLUDED_IN_THE_BUILD, WLAN_UMAC, LOG_ERROR);
#endif /* CONFIG_AP */
		return;
	}

#ifdef CONFIG_TDLS
	if (bss)
		wpa_tdls_ap_ies(wpa_s->wpa, (const u8 *) (bss + 1),
				bss->ie_len);
#endif /* CONFIG_TDLS */

#ifdef CONFIG_MBO_STA
    wpas_mbo_check_pmf(wpa_s, bss, ssid);
#endif /*  CONFIG_MBO_STA */

	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) &&
	    ssid->mode == IEEE80211_MODE_INFRA) {
		sme_authenticate(wpa_s, bss, ssid);
		return;
	}
#ifdef ENABLE_UMAC_ROM_PTR
  params = OS_MALLOC(sizeof(struct wpa_driver_associate_params));
#else
  params = os_malloc(sizeof(struct wpa_driver_associate_params));
#endif /* ENABLE_UMAC_ROM_PTR */
  if(params == NULL)
  {
   SLI_WLAN_MGMT_ASSERT(UMAC_ASSERT_OS_MALLOC_FAILED_DURING_ASSOCIATION);
   return;
  }
#ifdef RSI_ENABLE_CCX
	struct wpa_sm *wpa_sm = wpa_s->wpa;
	uint8_t roam =0;
#endif
	os_memset(params, 0, sizeof(struct wpa_driver_associate_params));
	wpa_s->reassociate = 0;
	if (bss && !wpas_driver_bss_selection(wpa_s)) {
#ifdef CONFIG_IEEE80211R
		const u8 *ie, *md = NULL;
#endif /* CONFIG_IEEE80211R */
		wpa_msg(wpa_s, MSG_INFO, "Trying to associate with " MACSTR
			" (SSID='%s' freq=%d MHz)", MAC2STR(bss->bssid),
			wpa_ssid_txt(bss->ssid, bss->ssid_len), bss->freq);
		bssid_changed = !is_zero_ether_addr(wpa_s->bssid);
		os_memset(wpa_s->bssid, 0, ETH_ALEN);
		os_memcpy(wpa_s->pending_bssid, bss->bssid, ETH_ALEN);
		if (bssid_changed)
			wpas_notify_bssid_changed(wpa_s);
#ifdef CONFIG_IEEE80211R
		ie = wpa_bss_get_ie(bss, WLAN_EID_MOBILITY_DOMAIN);
		if (ie && ie[1] >= MOBILITY_DOMAIN_ID_LEN)
			md = ie + 2;
#ifdef ENABLE_UMAC_ROM_PTR
			WPA_SM_SET_FT_PARAMS(wpa_s->wpa, ie, ie ? 2 + ie[1] : 0);
#else
			wpa_sm_set_ft_params(wpa_s->wpa, ie, ie ? 2 + ie[1] : 0);
#endif /* ENABLE_UMAC_ROM_PTR */
		if (md) {
			/* Prepare for the next transition */
#ifdef ENABLE_UMAC_ROM_PTR
			WPA_FT_PREPARE_AUTH_REQUEST(wpa_s->wpa, ie);
#else
			wpa_ft_prepare_auth_request(wpa_s->wpa, ie);
#endif /* ENABLE_UMAC_ROM_PTR */
		}
#endif /* CONFIG_IEEE80211R */

#ifdef RSI_ENABLE_CCX
	if(bss) {
		wpa_printf(MSG_DEBUG, "bss->Bssid %02x %02x %02x %02x %02x %02x freq %d ssid %s \n", bss->bssid[0],
				bss->bssid[1],bss->bssid[2],bss->bssid[3],bss->bssid[4],bss->bssid[5], bss->freq, bss->ssid);
	}
#endif
#ifdef CONFIG_WPS
	} else if ((ssid->ssid == NULL || ssid->ssid_len == 0) &&
		   wpa_s->conf->ap_scan == 2 &&
		   (ssid->key_mgmt & WPA_KEY_MGMT_WPS)) {
		/* Use ap_scan==1 style network selection to find the network
		 */
		wpa_s->scan_req = MANUAL_SCAN_REQ;
		wpa_s->reassociate = 1;
#ifdef ENABLE_UMAC_ROM_PTR
		WPA_SUPPLICANT_REQ_SCAN(wpa_s, 0, 0);
#else
		wpa_supplicant_req_scan(wpa_s, 0, 0);
#endif /* ENABLE_UMAC_ROM_PTR */
		os_free(params);
		return;
#endif /* CONFIG_WPS */
	} else {
		wpa_msg(wpa_s, MSG_INFO, "Trying to associate with SSID '%s'",
			wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
		os_memset(wpa_s->pending_bssid, 0, ETH_ALEN);
	}
#ifdef ENABLE_UMAC_ROM_PTR
	WPA_SUPPLICANT_CANCEL_SCHED_SCAN(wpa_s);
#else
	wpa_supplicant_cancel_sched_scan(wpa_s);
#endif /* ENABLE_UMAC_ROM_PTR */

#ifdef ENABLE_UMAC_ROM_PTR
	WPA_SUPPLICANT_CANCEL_SCAN(wpa_s);
#else
	wpa_supplicant_cancel_scan(wpa_s);
#endif
	/* Starting new association, so clear the possibly used WPA IE from the
	 * previous association. */
#ifdef ENABLE_UMAC_ROM_PTR
	WPA_SM_SET_ASSOC_WPA_IE(wpa_s->wpa, NULL, 0);
#else
	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
#endif /* ENABLE_UMAC_ROM_PTR */


#ifdef IEEE8021X_EAPOL
	if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if (ssid->leap) {
			if (ssid->non_leap == 0)
				algs = WPA_AUTH_ALG_LEAP;
			else
				algs |= WPA_AUTH_ALG_LEAP;
		}
	}
#endif /* IEEE8021X_EAPOL */
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Automatic auth_alg selection: 0x%x", algs);
#endif
	SL_PRINTF(WLAN_SUPP_AUTOMATIC_AUTH_ALG_SELECTION_2, WLAN_UMAC, LOG_INFO, "alg: %4x", algs);
	if (ssid->auth_alg) {
		algs = ssid->auth_alg;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Overriding auth_alg selection: "
			"0x%x", algs);
#endif
		SL_PRINTF(WLAN_SUPP_OVERRIDING_AUTH_ALG_SELECTION_2, WLAN_UMAC, LOG_INFO, "alg: %4x", algs);
	}

	if (bss && (wpa_bss_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE) ||
		    wpa_bss_get_ie(bss, WLAN_EID_RSN)) &&
	    wpa_key_mgmt_wpa(ssid->key_mgmt)) {
#ifdef RSI_ENABLE_CCX
		if (ssid->key_mgmt != WPA_KEY_MGMT_CCKM)
#endif
		{
		int try_opportunistic;
		try_opportunistic = (ssid->proactive_key_caching < 0 ?
				     wpa_s->conf->okc :
				     ssid->proactive_key_caching) &&
			(ssid->proto & WPA_PROTO_RSN);
		if (pmksa_cache_set_current(wpa_s->wpa, NULL, bss->bssid,
					    ssid, try_opportunistic, NULL,0) == 0)   // changed during version28 porting
		//	EAPOL_SM_NOTIFY_PMKID_ATTEMPT(wpa_s->eapol, 1);  // changed during version28 porting
		//EAPOL_SM_NOTIFY_PMKID_ATTEMPT(wpa_s->eapol);
		eapol_sm_notify_pmkid_attempt(wpa_s->eapol);

}
		wpa_ie_len = sizeof(wpa_ie);
		if (wpa_supplicant_set_suites(wpa_s, bss, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to set WPA "
				"key management and encryption suites");
		    os_free(params);
			return;
		}
	} else if ((ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA) && bss &&
		   wpa_key_mgmt_wpa_ieee8021x(ssid->key_mgmt)) {
		/*
		 * Both WPA and non-WPA IEEE 802.1X enabled in configuration -
		 * use non-WPA since the scan results did not indicate that the
		 * AP is using WPA or WPA2.
		 */
#ifdef ENABLE_UMAC_ROM_PTR
		WPA_SUPPLICANT_SET_NON_WPA_POLICY(wpa_s, ssid);
#else
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
#endif /* ENABLE_UMAC_ROM_PTR */
		wpa_ie_len = 0;
		wpa_s->wpa_proto = 0;
	} else if (wpa_key_mgmt_wpa_any(ssid->key_mgmt)) {
		wpa_ie_len = sizeof(wpa_ie);
		if (wpa_supplicant_set_suites(wpa_s, NULL, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to set WPA "
				"key management and encryption suites (no "
				"scan results)");
			 os_free(params);	
			return;
		}
#ifdef CONFIG_WPS
	} else if (ssid->key_mgmt & WPA_KEY_MGMT_WPS) {
		struct wpabuf *wps_ie;
#ifdef ENABLE_UMAC_ROM_PTR
		wps_ie = WPS_BUILD_ASSOC_REQ_IE(WPAS_WPS_GET_REQ_TYPE(ssid));
#else
		wps_ie = wps_build_assoc_req_ie(wpas_wps_get_req_type(ssid));
#endif /* ENABLE_UMAC_ROM_PTR */
		if (wps_ie && wpabuf_len(wps_ie) <= sizeof(wpa_ie)) {
			wpa_ie_len = wpabuf_len(wps_ie);
			os_memcpy(wpa_ie, wpabuf_head(wps_ie), wpa_ie_len);
		} else
			wpa_ie_len = 0;
		wpabuf_free(wps_ie);
#ifdef ENABLE_UMAC_ROM_PTR
		WPA_SUPPLICANT_SET_NON_WPA_POLICY(wpa_s, ssid);
#else
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
#endif /* ENABLE_UMAC_ROM_PTR */
		if (!bss || (bss->caps & IEEE80211_CAP_PRIVACY))
			params->wps = WPS_MODE_PRIVACY;
		else
			params->wps = WPS_MODE_OPEN;
		wpa_s->wpa_proto = 0;
#endif /* CONFIG_WPS */
	} else {
#ifdef ENABLE_UMAC_ROM_PTR
		WPA_SUPPLICANT_SET_NON_WPA_POLICY(wpa_s, ssid);
#else
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
#endif /* ENABLE_UMAC_ROM_PTR */
		wpa_ie_len = 0;
		wpa_s->wpa_proto = 0;
	}

#ifdef CONFIG_P2P
	if (wpa_s->global->p2p) {
		u8 *pos;
		size_t len;
		int res;
		pos = wpa_ie + wpa_ie_len;
		len = sizeof(wpa_ie) - wpa_ie_len;
		res = WPAS_P2P_ASSOC_REQ_IE(wpa_s, bss, pos, len,
					    ssid->p2p_group);
		if (res >= 0)
			wpa_ie_len += res;
	}

	wpa_s->cross_connect_disallowed = 0;
	if (bss) {
		struct wpabuf *p2p;
		p2p = wpa_bss_get_vendor_ie_multi(bss, P2P_IE_VENDOR_TYPE);
		if (p2p) {
			wpa_s->cross_connect_disallowed =
				P2P_GET_CROSS_CONNECT_DISALLOWED(p2p);
			wpabuf_free(p2p);
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "P2P: WLAN AP %s cross "
				"connection",
				wpa_s->cross_connect_disallowed ?
				"disallows" : "allows");
#endif
			char* tmpstr = (wpa_s->cross_connect_disallowed ? "disallowed" : "allowed");
			SL_PRINTF(WLAN_SUPP_P2P_WLAN_AP_CROSS_CONNECTION_2, WLAN_UMAC, LOG_INFO, "cross connection %s", tmpstr);
		}
	}
#endif /* CONFIG_P2P */

#ifdef SUPPLICANT_PORTING
#ifdef CONFIG_MBO_STA
	if (bss) {
		wpa_ie_len += wpas_supp_op_class_ie(wpa_s, ssid, bss->freq,
						    wpa_ie + wpa_ie_len,
						    max_wpa_ie_len -
						    wpa_ie_len);
	}

	mbo_ie = bss ? wpa_bss_get_vendor_ie(bss, MBO_IE_VENDOR_TYPE) : NULL;
	if (!wpa_s->disable_mbo_oce && mbo_ie) {
		int len;

		len = wpas_mbo_ie(wpa_s, wpa_ie + wpa_ie_len,
				  max_wpa_ie_len - wpa_ie_len,
				  !!mbo_attr_from_mbo_ie(mbo_ie,
							 OCE_ATTR_ID_CAPA_IND));
		if (len >= 0)
			wpa_ie_len += len;
	}
#endif /* CONFIG_MBO_STA */
#endif

#ifdef CONFIG_HS20
	if (wpa_s->conf->hs20) {
		struct wpabuf *hs20;
		hs20 = wpabuf_alloc(20);
		if (hs20) {
			wpas_hs20_add_indication(hs20);
			os_memcpy(wpa_ie + wpa_ie_len, wpabuf_head(hs20),
				  wpabuf_len(hs20));
			wpa_ie_len += wpabuf_len(hs20);
			wpabuf_free(hs20);
		}
	}
#endif /* CONFIG_HS20 */

	if (!bss || wpa_bss_get_ie(bss, WLAN_EID_EXT_CAPAB)) {
		u8 ext_capab[18];
		int ext_capab_len;
	    ext_capab_len = wpas_build_ext_capab(wpa_s, ext_capab,sizeof(ext_capab));
		if (ext_capab_len > 0) {
			u8 *pos = wpa_ie;
			if (wpa_ie_len > 0 && pos[0] == WLAN_EID_RSN)
				pos += 2 + pos[1];
			os_memmove(pos + ext_capab_len, pos,
				   wpa_ie_len - (pos - wpa_ie));
			wpa_ie_len += ext_capab_len;
			os_memcpy(pos, ext_capab, ext_capab_len);
		}
	}

	wpa_clear_keys(wpa_s, bss ? bss->bssid : NULL);
	use_crypt = 1;
	cipher_pairwise = cipher_suite2driver(wpa_s->pairwise_cipher);
	cipher_group = cipher_suite2driver(wpa_s->group_cipher);
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE)
			use_crypt = 0;
#ifndef CONFIG_NO_WEP
		if (wpa_set_wep_keys(wpa_s, ssid)) {
			use_crypt = 1;
			wep_keys_set = 1;
		}
#endif
	}
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPS)
		use_crypt = 0;

#ifdef IEEE8021X_EAPOL
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if ((ssid->eapol_flags &
		     (EAPOL_FLAG_REQUIRE_KEY_UNICAST |
		      EAPOL_FLAG_REQUIRE_KEY_BROADCAST)) == 0 &&
		    !wep_keys_set) {
			use_crypt = 0;
		} else {
			/* Assume that dynamic WEP-104 keys will be used and
			 * set cipher suites in order for drivers to expect
			 * encryption. */
			cipher_pairwise = cipher_group = CIPHER_WEP104;
		}
	}
#endif /* IEEE8021X_EAPOL */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		/* Set the key before (and later after) association */
#ifdef ENABLE_UMAC_ROM_PTR
		WPA_SUPPLICANT_SET_WPA_NONE_KEY(wpa_s, ssid);
#else
		wpa_supplicant_set_wpa_none_key(wpa_s, ssid);
#endif /* ENABLE_UMAC_ROM_PTR */
	}
#ifdef RSI_ENABLE_CCX
	if(wpa_s->wpa_state == WPA_COMPLETED)
		roam =1;	
#endif
	wpa_supplicant_set_state(wpa_s, WPA_ASSOCIATING);

	if (bss) {
		params->ssid = bss->ssid;
		params->ssid_len = bss->ssid_len;
		if (!wpas_driver_bss_selection(wpa_s) || ssid->bssid_set) {
			wpa_printf(MSG_DEBUG, "Limit connection to BSSID "
				   MACSTR " freq=%u MHz based on scan results "
				   "(bssid_set=%d)",
				   MAC2STR(bss->bssid), bss->freq,
				   ssid->bssid_set);
			params->bssid = bss->bssid;
			params->freq.freq = bss->freq;
		}
	} else {
		params->ssid = ssid->ssid;
		params->ssid_len = ssid->ssid_len;
	}

	if (ssid->mode == WPAS_MODE_IBSS && ssid->bssid_set &&
	    wpa_s->conf->ap_scan == 2) {
		params->bssid = ssid->bssid;
		params->fixed_bssid = 1;
	}

	if (ssid->mode == WPAS_MODE_IBSS && ssid->frequency > 0 &&
	   ( params->freq.freq == 0))
		params->freq.freq = ssid->frequency; /* Initial channel for IBSS */
	params->wpa_ie = wpa_ie;
	params->wpa_ie_len = wpa_ie_len;
	params->pairwise_suite = cipher_pairwise;
	params->group_suite = cipher_group;
	params->key_mgmt_suite = key_mgmt2driver(wpa_s->key_mgmt);
	params->wpa_proto = wpa_s->wpa_proto;
	params->auth_alg = algs;
	params->mode = ssid->mode;
	params->bg_scan_period = ssid->bg_scan_period;
#ifdef RSI_ENABLE_CCX
	params->ccx_capable = bss->ccx_capable;	
	wpa_sm->wpa_cckm_completed = 0 ; // commented in version258 porting

#endif
	for (i = 0; i < NUM_WEP_KEYS; i++) {
		if (ssid->wep_key_len[i])
			params->wep_key[i] = ssid->wep_key[i];
		params->wep_key_len[i] = ssid->wep_key_len[i];
	}
	params->wep_tx_keyidx = ssid->wep_tx_keyidx;

	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_8021X) &&
	    (params->key_mgmt_suite == KEY_MGMT_PSK ||
	     params->key_mgmt_suite == KEY_MGMT_FT_PSK)) {
		params->passphrase = ssid->passphrase;
		if (ssid->psk_set)
			params->psk = ssid->psk;
	}

	params->drop_unencrypted = use_crypt;

#ifdef CONFIG_IEEE80211W
	params->mgmt_frame_protection =
		ssid->ieee80211w == MGMT_FRAME_PROTECTION_DEFAULT ?
		wpa_s->conf->pmf : ssid->ieee80211w;
	if (params->mgmt_frame_protection != NO_MGMT_FRAME_PROTECTION && bss) {
		const u8 *rsn = wpa_bss_get_ie(bss, WLAN_EID_RSN);
		struct wpa_ie_data ie;
		if (rsn && wpa_parse_wpa_ie(rsn, 2 + rsn[1], &ie) == 0 &&
		    ie.capabilities &
		    (WPA_CAPABILITY_MFPC | WPA_CAPABILITY_MFPR)) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "WPA: Selected AP supports "
				"MFP: require MFP");
#endif
			SL_PRINTF(WLAN_SUPP_WPA_SELECTED_AP_SUPPORTS_MFP_REQUIRE_MFP_2, WLAN_UMAC, LOG_INFO);
			params->mgmt_frame_protection =
				MGMT_FRAME_PROTECTION_REQUIRED;
		}
	}
#endif /* CONFIG_IEEE80211W */

	params->p2p = ssid->p2p_group;

	if (wpa_s->parent->set_sta_uapsd)
		params->uapsd = wpa_s->parent->sta_uapsd;
	else
		params->uapsd = -1;

#ifdef CONFIG_HT_OVERRIDES
	os_memset(&htcaps, 0, sizeof(htcaps));
	os_memset(&htcaps_mask, 0, sizeof(htcaps_mask));
	params->htcaps = (u8 *) &htcaps;
	params->htcaps_mask = (u8 *) &htcaps_mask;
	wpa_supplicant_apply_ht_overrides(wpa_s, ssid, params);
#endif /* CONFIG_HT_OVERRIDES */

#ifdef RSI_ENABLE_CCX // commented while version28 porting
	if (params->key_mgmt_suite == WPA_KEY_MGMT_CCKM)
	{
		if(roam) {
			struct wpa_sm *wps = wpa_s->wpa;
			/* Advance the rekey number first */
			++wps->rekey_number;  // commented while version28 porting
			wpa_cckm_hmac_calculate(wps, wps->assoc_wpa_ie, wps->assoc_wpa_ie_len, 
					&wps->own_addr[0], bss->bssid, wps->rekey_number, (u8 *)&bss->tsf, wps->mic, 8); 	
			/* Calculate new PTK for the AP */
			cckm_driver_newptk(wps, bss->bssid);
			params->tsf = bss->tsf;
			params->rn = wps->rekey_number;
			memcpy(&params->mic,wps->mic,8);
		}
	}
	params->ccx_capable = bss->ccx_capable;	
	wpa_sm->wpa_cckm_completed = 0;
#endif
#ifdef SUPPLICANT_PORTING
#ifdef CONFIG_SAE
       wpa_s_setup_sae_pt(wpa_s->conf, ssid);
#endif /* CONFIG_SAE */
#endif
	ret = wpa_drv_associate(wpa_s, params);
	if (ret < 0) {
		wpa_msg(wpa_s, MSG_INFO, "Association request to the driver "
			"failed");
		if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SANE_ERROR_CODES) {
			/*
			 * The driver is known to mean what is saying, so we
			 * can stop right here; the association will not
			 * succeed.
			 */
#ifdef ENABLE_UMAC_ROM_PTR
			WPAS_CONNECTION_FAILED(wpa_s, wpa_s->pending_bssid);
#else
			wpas_connection_failed(wpa_s, wpa_s->pending_bssid);
#endif /* ENABLE_UMAC_ROM_PTR */
			wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
			os_memset(wpa_s->pending_bssid, 0, ETH_ALEN);
#ifdef ENABLE_UMAC_ROM_PTR
			OS_FREE(params);
#else
            os_free(params);
#endif /* ENABLE_UMAC_ROM_PTR */
			return;
		}
		/* try to continue anyway; new association will be tried again
		 * after timeout */
		assoc_failed = 1;
	}
#ifdef ENABLE_UMAC_ROM_PTR
  OS_FREE(params);
#else
  os_free(params);
#endif /* ENABLE_UMAC_ROM_PTR */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		/* Set the key after the association just in case association
		 * cleared the previously configured key. */
#ifdef ENABLE_UMAC_ROM_PTR
		WPA_SUPPLICANT_SET_WPA_NONE_KEY(wpa_s, ssid);
#else
		wpa_supplicant_set_wpa_none_key(wpa_s, ssid);
#endif /* ENABLE_UMAC_ROM_PTR */
		/* No need to timeout authentication since there is no key
		 * management. */
		wpa_supplicant_cancel_auth_timeout(wpa_s);
		wpa_supplicant_set_state(wpa_s, WPA_COMPLETED);
#ifdef CONFIG_IBSS_RSN
	} else if (ssid->mode == WPAS_MODE_IBSS &&
		   wpa_s->key_mgmt != WPA_KEY_MGMT_NONE &&
		   wpa_s->key_mgmt != WPA_KEY_MGMT_WPA_NONE) {
		/*
		 * RSN IBSS authentication is per-STA and we can disable the
		 * per-BSSID authentication.
		 */
		wpa_supplicant_cancel_auth_timeout(wpa_s);
#endif /* CONFIG_IBSS_RSN */
	} else {
		/* Timeout for IEEE 802.11 authentication and association */
		int timeout = 60;

		if (assoc_failed) {
			/* give IBSS a bit more time */
			timeout = ssid->mode == WPAS_MODE_IBSS ? 10 : 5;
		} else if (wpa_s->conf->ap_scan == 1) {
			/* give IBSS a bit more time */
			timeout = ssid->mode == WPAS_MODE_IBSS ? 20 : 10;
		}
		wpa_supplicant_req_auth_timeout(wpa_s, timeout, 0);
	}
	
#ifndef CONFIG_NO_WEP
	if (wep_keys_set && wpa_drv_get_capa(wpa_s, &capa) == 0 &&
	    capa.flags & WPA_DRIVER_FLAGS_SET_KEYS_AFTER_ASSOC) {
		/* Set static WEP keys again */
		wpa_set_wep_keys(wpa_s, ssid);
	}
#endif

	if (wpa_s->current_ssid && wpa_s->current_ssid != ssid) {
		/*
		 * Do not allow EAP session resumption between different
		 * network configurations.
		 */
#ifdef ENABLE_UMAC_ROM_PTR
		EAPOL_SM_INVALIDATE_CACHED_SESSION(wpa_s->eapol);
#else
		eapol_sm_invalidate_cached_session(wpa_s->eapol);
#endif /* ENABLE_UMAC_ROM_PTR */
	}
	old_ssid = wpa_s->current_ssid;
	wpa_s->current_ssid = ssid;
	wpa_s->current_bss = bss;
	wpa_supplicant_rsn_supp_set_config(wpa_s, wpa_s->current_ssid);
	wpa_supplicant_initiate_eapol(wpa_s);
	if (old_ssid != wpa_s->current_ssid)
		wpas_notify_network_changed(wpa_s);

#endif


}

#if UNUSED_FEAT_IN_SUPP_29
static int bss_is_ibss(struct wpa_bss *bss)
{
	return (bss->caps & (IEEE80211_CAP_ESS | IEEE80211_CAP_IBSS)) ==
		IEEE80211_CAP_IBSS;
}


static int drv_supports_vht(struct wpa_supplicant *wpa_s,
			    const struct wpa_ssid *ssid)
{
	enum hostapd_hw_mode hw_mode;
	struct hostapd_hw_modes *mode = NULL;
	u8 channel;
	int i;

	hw_mode = ieee80211_freq_to_chan(ssid->frequency, &channel);
	if (hw_mode == NUM_HOSTAPD_MODES)
		return 0;
	for (i = 0; wpa_s->hw.modes && i < wpa_s->hw.num_modes; i++) {
		if (wpa_s->hw.modes[i].mode == hw_mode) {
			mode = &wpa_s->hw.modes[i];
			break;
		}
	}

	if (!mode)
		return 0;

	return mode->vht_capab != 0;
}


void ibss_mesh_setup_freq(struct wpa_supplicant *wpa_s,
			  const struct wpa_ssid *ssid,
			  struct hostapd_freq_params *freq)
{
	int ieee80211_mode = wpas_mode_to_ieee80211_mode(ssid->mode);
	enum hostapd_hw_mode hw_mode;
	struct hostapd_hw_modes *mode = NULL;
	int ht40plus[] = { 36, 44, 52, 60, 100, 108, 116, 124, 132, 149, 157,
			   184, 192 };
	int vht80[] = { 36, 52, 100, 116, 132, 149 };
	struct hostapd_channel_data *pri_chan = NULL, *sec_chan = NULL;
	u8 channel;
	int i, chan_idx, ht40 = -1, res, obss_scan = 1;
	unsigned int j, k;
	struct hostapd_freq_params vht_freq;
	int chwidth, seg0, seg1;
	u32 vht_caps = 0;

	freq->freq = ssid->frequency;

	for (j = 0; j < wpa_s->last_scan_res_used; j++) {
		struct wpa_bss *bss = wpa_s->last_scan_res[j];

		if (ssid->mode != WPAS_MODE_IBSS)
			break;

		/* Don't adjust control freq in case of fixed_freq */
		if (ssid->fixed_freq)
			break;

		if (!bss_is_ibss(bss))
			continue;

		if (ssid->ssid_len == bss->ssid_len &&
		    os_memcmp(ssid->ssid, bss->ssid, bss->ssid_len) == 0) {
			wpa_printf(MSG_DEBUG,
				   "IBSS already found in scan results, adjust control freq: %d",
				   bss->freq);
			freq->freq = bss->freq;
			obss_scan = 0;
			break;
		}
	}

	/* For IBSS check HT_IBSS flag */
	if (ssid->mode == WPAS_MODE_IBSS &&
	    !(wpa_s->drv_flags & WPA_DRIVER_FLAGS_HT_IBSS))
		return;

	if (wpa_s->group_cipher == WPA_CIPHER_WEP40 ||
	    wpa_s->group_cipher == WPA_CIPHER_WEP104 ||
	    wpa_s->pairwise_cipher == WPA_CIPHER_TKIP) {
		wpa_printf(MSG_DEBUG,
			   "IBSS: WEP/TKIP detected, do not try to enable HT");
		return;
	}

	hw_mode = ieee80211_freq_to_chan(freq->freq, &channel);
	for (i = 0; wpa_s->hw.modes && i < wpa_s->hw.num_modes; i++) {
		if (wpa_s->hw.modes[i].mode == hw_mode) {
			mode = &wpa_s->hw.modes[i];
			break;
		}
	}

	if (!mode)
		return;

	/* HE can work without HT + VHT */
	freq->he_enabled = mode->he_capab[ieee80211_mode].he_supported;

#ifdef CONFIG_HT_OVERRIDES
	if (ssid->disable_ht) {
		freq->ht_enabled = 0;
		return;
	}
#endif /* CONFIG_HT_OVERRIDES */

	freq->ht_enabled = ht_supported(mode);
	if (!freq->ht_enabled)
		return;

	/* Setup higher BW only for 5 GHz */
	if (mode->mode != HOSTAPD_MODE_IEEE80211A)
		return;

	for (chan_idx = 0; chan_idx < mode->num_channels; chan_idx++) {
		pri_chan = &mode->channels[chan_idx];
		if (pri_chan->chan == channel)
			break;
		pri_chan = NULL;
	}
	if (!pri_chan)
		return;

	/* Check primary channel flags */
	if (pri_chan->flag & (HOSTAPD_CHAN_DISABLED | HOSTAPD_CHAN_NO_IR))
		return;

	freq->channel = pri_chan->chan;

#ifdef CONFIG_HT_OVERRIDES
	if (ssid->disable_ht40) {
		if (ssid->disable_vht)
			return;
		goto skip_ht40;
	}
#endif /* CONFIG_HT_OVERRIDES */

	/* Check/setup HT40+/HT40- */
	for (j = 0; j < ARRAY_SIZE(ht40plus); j++) {
		if (ht40plus[j] == channel) {
			ht40 = 1;
			break;
		}
	}

	/* Find secondary channel */
	for (i = 0; i < mode->num_channels; i++) {
		sec_chan = &mode->channels[i];
		if (sec_chan->chan == channel + ht40 * 4)
			break;
		sec_chan = NULL;
	}
	if (!sec_chan)
		return;

	/* Check secondary channel flags */
	if (sec_chan->flag & (HOSTAPD_CHAN_DISABLED | HOSTAPD_CHAN_NO_IR))
		return;

	if (ht40 == -1) {
		if (!(pri_chan->flag & HOSTAPD_CHAN_HT40MINUS))
			return;
	} else {
		if (!(pri_chan->flag & HOSTAPD_CHAN_HT40PLUS))
			return;
	}
	freq->sec_channel_offset = ht40;

	if (obss_scan) {
		struct wpa_scan_results *scan_res;

		scan_res = wpa_supplicant_get_scan_results(wpa_s, NULL, 0);
		if (scan_res == NULL) {
			/* Back to HT20 */
			freq->sec_channel_offset = 0;
			return;
		}
#if UNUSED_FEAT_IN_SUPP_29
		res = check_40mhz_5g(mode, scan_res, pri_chan->chan,
				     sec_chan->chan);
#endif		
		switch (res) {
		case 0:
			/* Back to HT20 */
			freq->sec_channel_offset = 0;
			break;
		case 1:
			/* Configuration allowed */
			break;
		case 2:
			/* Switch pri/sec channels */
#if UNUSED_FEAT_IN_SUPP_29	
			freq->freq = hw_get_freq(mode, sec_chan->chan);
#endif		
			freq->sec_channel_offset = -freq->sec_channel_offset;
			freq->channel = sec_chan->chan;
			break;
		default:
			freq->sec_channel_offset = 0;
			break;
		}

		wpa_scan_results_free(scan_res);
	}

#ifdef CONFIG_HT_OVERRIDES
skip_ht40:
#endif /* CONFIG_HT_OVERRIDES */
	wpa_printf(MSG_DEBUG,
		   "IBSS/mesh: setup freq channel %d, sec_channel_offset %d",
		   freq->channel, freq->sec_channel_offset);

	if (!drv_supports_vht(wpa_s, ssid))
		return;

	/* For IBSS check VHT_IBSS flag */
	if (ssid->mode == WPAS_MODE_IBSS &&
	    !(wpa_s->drv_flags & WPA_DRIVER_FLAGS_VHT_IBSS))
		return;

	vht_freq = *freq;

#ifdef CONFIG_VHT_OVERRIDES
	if (ssid->disable_vht) {
		freq->vht_enabled = 0;
		return;
	}
#endif /* CONFIG_VHT_OVERRIDES */

	vht_freq.vht_enabled = vht_supported(mode);
	if (!vht_freq.vht_enabled)
		return;

	/* setup center_freq1, bandwidth */
	for (j = 0; j < ARRAY_SIZE(vht80); j++) {
		if (freq->channel >= vht80[j] &&
		    freq->channel < vht80[j] + 16)
			break;
	}

	if (j == ARRAY_SIZE(vht80))
		return;

	for (i = vht80[j]; i < vht80[j] + 16; i += 4) {
		struct hostapd_channel_data *chan;
#if UNUSED_FEAT_IN_SUPP_29
		chan = hw_get_channel_chan(mode, i, NULL);
		if (!chan)
			return;
#endif
		/* Back to HT configuration if channel not usable */
		if (chan->flag & (HOSTAPD_CHAN_DISABLED | HOSTAPD_CHAN_NO_IR))
			return;
	}

	chwidth = CHANWIDTH_80MHZ;
	seg0 = vht80[j] + 6;
	seg1 = 0;

	if (ssid->max_oper_chwidth == CHANWIDTH_80P80MHZ) {
		/* setup center_freq2, bandwidth */
		for (k = 0; k < ARRAY_SIZE(vht80); k++) {
			/* Only accept 80 MHz segments separated by a gap */
			if (j == k || abs(vht80[j] - vht80[k]) == 16)
				continue;
			for (i = vht80[k]; i < vht80[k] + 16; i += 4) {
				struct hostapd_channel_data *chan;
#if UNUSED_FEAT_IN_SUPP_29
				chan = hw_get_channel_chan(mode, i, NULL);
				if (!chan)
					continue;
#endif
				if (chan->flag & (HOSTAPD_CHAN_DISABLED |
						  HOSTAPD_CHAN_NO_IR |
						  HOSTAPD_CHAN_RADAR))
					continue;

				/* Found a suitable second segment for 80+80 */
				chwidth = CHANWIDTH_80P80MHZ;
				vht_caps |=
					VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
				seg1 = vht80[k] + 6;
			}

			if (chwidth == CHANWIDTH_80P80MHZ)
				break;
		}
	} else if (ssid->max_oper_chwidth == CHANWIDTH_160MHZ) {
		if (freq->freq == 5180) {
			chwidth = CHANWIDTH_160MHZ;
			vht_caps |= VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
			seg0 = 50;
		} else if (freq->freq == 5520) {
			chwidth = CHANWIDTH_160MHZ;
			vht_caps |= VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
			seg0 = 114;
		}
	} else if (ssid->max_oper_chwidth == CHANWIDTH_USE_HT) {
		chwidth = CHANWIDTH_USE_HT;
		seg0 = vht80[j] + 2;
#ifdef CONFIG_HT_OVERRIDES
		if (ssid->disable_ht40)
			seg0 = 0;
#endif /* CONFIG_HT_OVERRIDES */
	}
#if UNUSED_FEAT_IN_SUPP_29 
	if (hostapd_set_freq_params(&vht_freq, mode->mode, freq->freq,
				    freq->channel, freq->ht_enabled,
				    vht_freq.vht_enabled, freq->he_enabled,
				    freq->sec_channel_offset,
				    chwidth, seg0, seg1, vht_caps,
				    &mode->he_capab[ieee80211_mode]) != 0)
		return;
#endif
	*freq = vht_freq;

	wpa_printf(MSG_DEBUG, "IBSS: VHT setup freq cf1 %d, cf2 %d, bw %d",
		   freq->center_freq1, freq->center_freq2, freq->bandwidth);
}
#endif

#ifdef CONFIG_FILS
static size_t wpas_add_fils_hlp_req(struct wpa_supplicant *wpa_s, u8 *ie_buf,
				    size_t ie_buf_len)
{
	struct fils_hlp_req *req;
	size_t rem_len, hdr_len, hlp_len, len, ie_len = 0;
	const u8 *pos;
	u8 *buf = ie_buf;

	dl_list_for_each(req, &wpa_s->fils_hlp_req, struct fils_hlp_req,
			 list) {
		rem_len = ie_buf_len - ie_len;
		pos = wpabuf_head(req->pkt);
		hdr_len = 1 + 2 * ETH_ALEN + 6;
		hlp_len = wpabuf_len(req->pkt);

		if (rem_len < 2 + hdr_len + hlp_len) {
			wpa_printf(MSG_ERROR,
				   "FILS: Cannot fit HLP - rem_len=%lu to_fill=%lu",
				   (unsigned long) rem_len,
				   (unsigned long) (2 + hdr_len + hlp_len));
			break;
		}

		len = (hdr_len + hlp_len) > 255 ? 255 : hdr_len + hlp_len;
		/* Element ID */
		*buf++ = WLAN_EID_EXTENSION;
		/* Length */
		*buf++ = len;
		/* Element ID Extension */
		*buf++ = WLAN_EID_EXT_FILS_HLP_CONTAINER;
		/* Destination MAC address */
		os_memcpy(buf, req->dst, ETH_ALEN);
		buf += ETH_ALEN;
		/* Source MAC address */
		os_memcpy(buf, wpa_s->own_addr, ETH_ALEN);
		buf += ETH_ALEN;
		/* LLC/SNAP Header */
		os_memcpy(buf, "\xaa\xaa\x03\x00\x00\x00", 6);
		buf += 6;
		/* HLP Packet */
		os_memcpy(buf, pos, len - hdr_len);
		buf += len - hdr_len;
		pos += len - hdr_len;

		hlp_len -= len - hdr_len;
		ie_len += 2 + len;
		rem_len -= 2 + len;

		while (hlp_len) {
			len = (hlp_len > 255) ? 255 : hlp_len;
			if (rem_len < 2 + len)
				break;
			*buf++ = WLAN_EID_FRAGMENT;
			*buf++ = len;
			os_memcpy(buf, pos, len);
			buf += len;
			pos += len;

			hlp_len -= len;
			ie_len += 2 + len;
			rem_len -= 2 + len;
		}
	}

	return ie_len;
}


int wpa_is_fils_supported(struct wpa_supplicant *wpa_s)
{
	return (((wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) &&
		 (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SUPPORT_FILS)) ||
		(!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) &&
		 (wpa_s->drv_flags & WPA_DRIVER_FLAGS_FILS_SK_OFFLOAD)));
}


int wpa_is_fils_sk_pfs_supported(struct wpa_supplicant *wpa_s)
{
#ifdef CONFIG_FILS_SK_PFS
	return (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) &&
		(wpa_s->drv_flags & WPA_DRIVER_FLAGS_SUPPORT_FILS);
#else /* CONFIG_FILS_SK_PFS */
	return 0;
#endif /* CONFIG_FILS_SK_PFS */
}

#endif /* CONFIG_FILS */


#if UNUSED_FEAT_IN_SUPP_29
static u8 * wpas_populate_assoc_ies(
	struct wpa_supplicant *wpa_s,
	struct wpa_bss *bss, struct wpa_ssid *ssid,
	struct wpa_driver_associate_params *params,
	enum wpa_drv_update_connect_params_mask *mask)
{
	u8 *wpa_ie;
	size_t max_wpa_ie_len = 500;
	size_t wpa_ie_len;
	int algs = WPA_AUTH_ALG_OPEN;
#ifdef CONFIG_MBO_STA
	const u8 *mbo_ie;
#endif
#ifdef CONFIG_SAE
	int sae_pmksa_cached = 0;
#endif /* CONFIG_SAE */
#ifdef CONFIG_FILS
	const u8 *realm, *username, *rrk;
	size_t realm_len, username_len, rrk_len;
	u16 next_seq_num;
	struct fils_hlp_req *req;

	dl_list_for_each(req, &wpa_s->fils_hlp_req, struct fils_hlp_req,
			 list) {
		max_wpa_ie_len += 3 + 2 * ETH_ALEN + 6 + wpabuf_len(req->pkt) +
				  2 + 2 * wpabuf_len(req->pkt) / 255;
	}
#endif /* CONFIG_FILS */

	wpa_ie = os_malloc(max_wpa_ie_len);
	if (!wpa_ie) {
		wpa_printf(MSG_ERROR,
			   "Failed to allocate connect IE buffer for %lu bytes",
			   (unsigned long) max_wpa_ie_len);
		return NULL;
	}

	if (bss && (wpa_bss_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE) ||
		    wpa_bss_get_ie(bss, WLAN_EID_RSN)) &&
	    wpa_key_mgmt_wpa(ssid->key_mgmt)) {
		int try_opportunistic;
		const u8 *cache_id = NULL;

		try_opportunistic = (ssid->proactive_key_caching < 0 ?
				     wpa_s->conf->okc :
				     ssid->proactive_key_caching) &&
			(ssid->proto & WPA_PROTO_RSN);
#ifdef CONFIG_FILS
		if (wpa_key_mgmt_fils(ssid->key_mgmt))
			cache_id = wpa_bss_get_fils_cache_id(bss);
#endif /* CONFIG_FILS */
		if (pmksa_cache_set_current(wpa_s->wpa, NULL, bss->bssid,
					    ssid, try_opportunistic,
					    cache_id, 0) == 0) {
			//eapol_sm_notify_pmkid_attempt(wpa_s->eapol);
		//	EAPOL_SM_NOTIFY_PMKID_ATTEMPT(wpa_s->eapol);
		eapol_sm_notify_pmkid_attempt(wpa_s->eapol);
#ifdef CONFIG_SAE
			sae_pmksa_cached = 1;
#endif /* CONFIG_SAE */
		}
		wpa_ie_len = max_wpa_ie_len;
		if (wpa_supplicant_set_suites(wpa_s, bss, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to set WPA "
				"key management and encryption suites");
			os_free(wpa_ie);
			return NULL;
		}
#ifdef CONFIG_HS20
	} else if (bss && wpa_bss_get_vendor_ie(bss, OSEN_IE_VENDOR_TYPE) &&
		   (ssid->key_mgmt & WPA_KEY_MGMT_OSEN)) {
		/* No PMKSA caching, but otherwise similar to RSN/WPA */
		wpa_ie_len = max_wpa_ie_len;
		if (wpa_supplicant_set_suites(wpa_s, bss, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to set WPA "
				"key management and encryption suites");
			os_free(wpa_ie);
			return NULL;
		}
#endif /* CONFIG_HS20 */
	} else if ((ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA) && bss &&
		   wpa_key_mgmt_wpa_ieee8021x(ssid->key_mgmt)) {
		/*
		 * Both WPA and non-WPA IEEE 802.1X enabled in configuration -
		 * use non-WPA since the scan results did not indicate that the
		 * AP is using WPA or WPA2.
		 */
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
		wpa_ie_len = 0;
		wpa_s->wpa_proto = 0;
	} else if (wpa_key_mgmt_wpa_any(ssid->key_mgmt)) {
		wpa_ie_len = max_wpa_ie_len;
		if (wpa_supplicant_set_suites(wpa_s, NULL, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to set WPA "
				"key management and encryption suites (no "
				"scan results)");
			os_free(wpa_ie);
			return NULL;
		}
#ifdef CONFIG_WPS
	} else if (ssid->key_mgmt & WPA_KEY_MGMT_WPS) {
		struct wpabuf *wps_ie;
		wps_ie = wps_build_assoc_req_ie(wpas_wps_get_req_type(ssid));
		if (wps_ie && wpabuf_len(wps_ie) <= max_wpa_ie_len) {
			wpa_ie_len = wpabuf_len(wps_ie);
			os_memcpy(wpa_ie, wpabuf_head(wps_ie), wpa_ie_len);
		} else
			wpa_ie_len = 0;
		wpabuf_free(wps_ie);
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
		if (!bss || (bss->caps & IEEE80211_CAP_PRIVACY))
			params->wps = WPS_MODE_PRIVACY;
		else
			params->wps = WPS_MODE_OPEN;
		wpa_s->wpa_proto = 0;
#endif /* CONFIG_WPS */
	} else {
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
		wpa_ie_len = 0;
		wpa_s->wpa_proto = 0;
	}

#ifdef IEEE8021X_EAPOL
	if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if (ssid->leap) {
			if (ssid->non_leap == 0)
				algs = WPA_AUTH_ALG_LEAP;
			else
				algs |= WPA_AUTH_ALG_LEAP;
		}
	}

#ifdef CONFIG_FILS
	/* Clear FILS association */
	wpa_sm_set_reset_fils_completed(wpa_s->wpa, 0);

	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_FILS_SK_OFFLOAD) &&
	    ssid->eap.erp && wpa_key_mgmt_fils(wpa_s->key_mgmt) &&
	    eapol_sm_get_erp_info(wpa_s->eapol, &ssid->eap, &username,
				  &username_len, &realm, &realm_len,
				  &next_seq_num, &rrk, &rrk_len) == 0 &&
	    (!wpa_s->last_con_fail_realm ||
	     wpa_s->last_con_fail_realm_len != realm_len ||
	     os_memcmp(wpa_s->last_con_fail_realm, realm, realm_len) != 0)) {
		algs = WPA_AUTH_ALG_FILS;
		params->fils_erp_username = username;
		params->fils_erp_username_len = username_len;
		params->fils_erp_realm = realm;
		params->fils_erp_realm_len = realm_len;
		params->fils_erp_next_seq_num = next_seq_num;
		params->fils_erp_rrk = rrk;
		params->fils_erp_rrk_len = rrk_len;

		if (mask)
			*mask |= WPA_DRV_UPDATE_FILS_ERP_INFO;
	}
#endif /* CONFIG_FILS */
#endif /* IEEE8021X_EAPOL */
#ifdef CONFIG_SAE
	if (wpa_s->key_mgmt & (WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_FT_SAE))
		algs = WPA_AUTH_ALG_SAE;
#endif /* CONFIG_SAE */

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Automatic auth_alg selection: 0x%x", algs);
#endif
	SL_PRINTF(WLAN_SUPP_AUTOMATIC_AUTH_ALG_SELECTION, WLAN_UMAC, LOG_INFO, "Automatic auth_alg selection: %4x", algs);
	if (ssid->auth_alg) {
		algs = ssid->auth_alg;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"Overriding auth_alg selection: 0x%x", algs);
#endif
		SL_PRINTF(WLAN_SUPP_OVERRIDING_AUTH_ALG_SELECTION, WLAN_UMAC, LOG_INFO, "Overriding auth_alg selection: %4x", algs);
	}

#ifdef CONFIG_SAE
	if (sae_pmksa_cached && algs == WPA_AUTH_ALG_SAE) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"SAE: Use WPA_AUTH_ALG_OPEN for PMKSA caching attempt");
#endif
		SL_PRINTF(WLAN_SUPP_SAE_USE_WPA_AUTH_ALG_OPEN_FOR_PMKSA_CACHING_ATTEMPT, WLAN_UMAC, LOG_INFO, "SAE: Use WPA_AUTH_ALG_OPEN for PMKSA caching attempt");
		algs = WPA_AUTH_ALG_OPEN;
	}
#endif /* CONFIG_SAE */

#ifdef CONFIG_P2P
	if (wpa_s->global->p2p) {
		u8 *pos;
		size_t len;
		int res;
		pos = wpa_ie + wpa_ie_len;
		len = max_wpa_ie_len - wpa_ie_len;
		res = wpas_p2p_assoc_req_ie(wpa_s, bss, pos, len,
					    ssid->p2p_group);
		if (res >= 0)
			wpa_ie_len += res;
	}

	wpa_s->cross_connect_disallowed = 0;
	if (bss) {
		struct wpabuf *p2p;
		p2p = wpa_bss_get_vendor_ie_multi(bss, P2P_IE_VENDOR_TYPE);
		if (p2p) {
			wpa_s->cross_connect_disallowed =
				p2p_get_cross_connect_disallowed(p2p);
			wpabuf_free(p2p);
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "P2P: WLAN AP %s cross "
				"connection",
				wpa_s->cross_connect_disallowed ?
				"disallows" : "allows");
#endif
			char* tmpstr = (wpa_s->cross_connect_disallowed ? "disallowed" : "allowed");
			SL_PRINTF(WLAN_SUPP_P2P_WLAN_AP_CROSS_CONNECTION, WLAN_UMAC, LOG_INFO, "cross connection %s", tmpstr);
		}
	}

	os_memset(wpa_s->p2p_ip_addr_info, 0, sizeof(wpa_s->p2p_ip_addr_info));
#endif /* CONFIG_P2P */
#if UNUSED_FEAT_IN_SUPP_29
	if (bss) {
		wpa_ie_len += wpas_supp_op_class_ie(wpa_s, ssid, bss->freq,
						    wpa_ie + wpa_ie_len,
						    max_wpa_ie_len -
						    wpa_ie_len);
	}
#endif
	/*
	 * Workaround: Add Extended Capabilities element only if the AP
	 * included this element in Beacon/Probe Response frames. Some older
	 * APs seem to have interoperability issues if this element is
	 * included, so while the standard may require us to include the
	 * element in all cases, it is justifiable to skip it to avoid
	 * interoperability issues.
	 */
	if (ssid->p2p_group)
		wpa_drv_get_ext_capa(wpa_s, WPA_IF_P2P_CLIENT);
	else
		wpa_drv_get_ext_capa(wpa_s, WPA_IF_STATION);

	if (!bss || wpa_bss_get_ie(bss, WLAN_EID_EXT_CAPAB)) {
		u8 ext_capab[18];
		int ext_capab_len;
		ext_capab_len = wpas_build_ext_capab(wpa_s, ext_capab,
						     sizeof(ext_capab));
		if (ext_capab_len > 0 &&
		    wpa_ie_len + ext_capab_len <= max_wpa_ie_len) {
			u8 *pos = wpa_ie;
			if (wpa_ie_len > 0 && pos[0] == WLAN_EID_RSN)
				pos += 2 + pos[1];
			os_memmove(pos + ext_capab_len, pos,
				   wpa_ie_len - (pos - wpa_ie));
			wpa_ie_len += ext_capab_len;
			os_memcpy(pos, ext_capab, ext_capab_len);
		}
	}

#ifdef CONFIG_HS20
	if (is_hs20_network(wpa_s, ssid, bss)) {
		struct wpabuf *hs20;

		hs20 = wpabuf_alloc(20 + MAX_ROAMING_CONS_OI_LEN);
		if (hs20) {
			int pps_mo_id = hs20_get_pps_mo_id(wpa_s, ssid);
			size_t len;

			wpas_hs20_add_indication(hs20, pps_mo_id,
						 get_hs20_version(bss));
			wpas_hs20_add_roam_cons_sel(hs20, ssid);
			len = max_wpa_ie_len - wpa_ie_len;
			if (wpabuf_len(hs20) <= len) {
				os_memcpy(wpa_ie + wpa_ie_len,
					  wpabuf_head(hs20), wpabuf_len(hs20));
				wpa_ie_len += wpabuf_len(hs20);
			}
			wpabuf_free(hs20);

			hs20_configure_frame_filters(wpa_s);
		}
	}
#endif /* CONFIG_HS20 */

	if (wpa_s->vendor_elem[VENDOR_ELEM_ASSOC_REQ]) {
		struct wpabuf *buf = wpa_s->vendor_elem[VENDOR_ELEM_ASSOC_REQ];
		size_t len;

		len = max_wpa_ie_len - wpa_ie_len;
		if (wpabuf_len(buf) <= len) {
			os_memcpy(wpa_ie + wpa_ie_len,
				  wpabuf_head(buf), wpabuf_len(buf));
			wpa_ie_len += wpabuf_len(buf);
		}
	}

#ifdef CONFIG_FST
	if (wpa_s->fst_ies) {
		int fst_ies_len = wpabuf_len(wpa_s->fst_ies);

		if (wpa_ie_len + fst_ies_len <= max_wpa_ie_len) {
			os_memcpy(wpa_ie + wpa_ie_len,
				  wpabuf_head(wpa_s->fst_ies), fst_ies_len);
			wpa_ie_len += fst_ies_len;
		}
	}
#endif /* CONFIG_FST */

#ifdef CONFIG_MBO_STA
	mbo_ie = bss ? wpa_bss_get_vendor_ie(bss, MBO_IE_VENDOR_TYPE) : NULL;
	if (!wpa_s->disable_mbo_oce && mbo_ie) {
		int len;

		len = wpas_mbo_ie(wpa_s, wpa_ie + wpa_ie_len,
				  max_wpa_ie_len - wpa_ie_len,
				  !!mbo_attr_from_mbo_ie(mbo_ie,
							 OCE_ATTR_ID_CAPA_IND));
		if (len >= 0)
			wpa_ie_len += len;
	}
#endif /* CONFIG_MBO_STA */

#ifdef CONFIG_FILS
	if (algs == WPA_AUTH_ALG_FILS) {
		size_t len;

		len = wpas_add_fils_hlp_req(wpa_s, wpa_ie + wpa_ie_len,
					    max_wpa_ie_len - wpa_ie_len);
		wpa_ie_len += len;
	}
#endif /* CONFIG_FILS */

#ifdef CONFIG_OWE
#ifdef CONFIG_TESTING_OPTIONS
	if (get_ie_ext(wpa_ie, wpa_ie_len, WLAN_EID_EXT_OWE_DH_PARAM)) {
		wpa_printf(MSG_INFO, "TESTING: Override OWE DH element");
	} else
#endif /* CONFIG_TESTING_OPTIONS */
	if (algs == WPA_AUTH_ALG_OPEN &&
	    ssid->key_mgmt == WPA_KEY_MGMT_OWE) {
		struct wpabuf *owe_ie;
		u16 group;

		if (ssid->owe_group) {
			group = ssid->owe_group;
		} else if (wpa_s->assoc_status_code ==
			   WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED) {
			if (wpa_s->last_owe_group == 19)
				group = 20;
			else if (wpa_s->last_owe_group == 20)
				group = 21;
			else
				group = OWE_DH_GROUP;
		} else {
			group = OWE_DH_GROUP;
		}

		wpa_s->last_owe_group = group;
		wpa_printf(MSG_DEBUG, "OWE: Try to use group %u", group);
		owe_ie = owe_build_assoc_req(wpa_s->wpa, group);
		if (owe_ie &&
		    wpabuf_len(owe_ie) <= max_wpa_ie_len - wpa_ie_len) {
			os_memcpy(wpa_ie + wpa_ie_len,
				  wpabuf_head(owe_ie), wpabuf_len(owe_ie));
			wpa_ie_len += wpabuf_len(owe_ie);
		}
		wpabuf_free(owe_ie);
	}
#endif /* CONFIG_OWE */

#ifdef CONFIG_DPP2
	if (wpa_sm_get_key_mgmt(wpa_s->wpa) == WPA_KEY_MGMT_DPP &&
	    ssid->dpp_netaccesskey) {
		dpp_pfs_free(wpa_s->dpp_pfs);
		wpa_s->dpp_pfs = dpp_pfs_init(ssid->dpp_netaccesskey,
					      ssid->dpp_netaccesskey_len);
		if (!wpa_s->dpp_pfs) {
			wpa_printf(MSG_DEBUG, "DPP: Could not initialize PFS");
			/* Try to continue without PFS */
			goto pfs_fail;
		}
		if (wpabuf_len(wpa_s->dpp_pfs->ie) <=
		    max_wpa_ie_len - wpa_ie_len) {
			os_memcpy(wpa_ie + wpa_ie_len,
				  wpabuf_head(wpa_s->dpp_pfs->ie),
				  wpabuf_len(wpa_s->dpp_pfs->ie));
			wpa_ie_len += wpabuf_len(wpa_s->dpp_pfs->ie);
		}
	}
pfs_fail:
#endif /* CONFIG_DPP2 */

#ifdef CONFIG_IEEE80211R
	/*
	 * Add MDIE under these conditions: the network profile allows FT,
	 * the AP supports FT, and the mobility domain ID matches.
	 */
	if (bss && wpa_key_mgmt_ft(wpa_sm_get_key_mgmt(wpa_s->wpa))) {
		const u8 *mdie = wpa_bss_get_ie(bss, WLAN_EID_MOBILITY_DOMAIN);

		if (mdie && mdie[1] >= MOBILITY_DOMAIN_ID_LEN) {
			size_t len = 0;
			const u8 *md = mdie + 2;
			const u8 *wpa_md = wpa_sm_get_ft_md(wpa_s->wpa);

			if (os_memcmp(md, wpa_md,
				      MOBILITY_DOMAIN_ID_LEN) == 0) {
				/* Add mobility domain IE */
				len = wpa_ft_add_mdie(
					wpa_s->wpa, wpa_ie + wpa_ie_len,
					max_wpa_ie_len - wpa_ie_len, mdie);
				wpa_ie_len += len;
			}
#ifdef CONFIG_SME
			if (len > 0 && wpa_s->sme.ft_used &&
			    wpa_sm_has_ptk(wpa_s->wpa)) {
#if UNUSED_FEAT_IN_SUPP_29
				wpa_dbg(wpa_s, MSG_DEBUG,
					"SME: Trying to use FT over-the-air");
#endif
				SL_PRINTF(WLAN_SUPP_SME_TRYING_TO_USE_FT_OVER_THE_AIR, WLAN_UMAC, LOG_INFO);
				algs |= WPA_AUTH_ALG_FT;
			}
#endif /* CONFIG_SME */
		}
	}
#endif /* CONFIG_IEEE80211R */

	if (wpa_s->rsnxe_len > 0 &&
	    wpa_s->rsnxe_len <= max_wpa_ie_len - wpa_ie_len) {
		os_memcpy(wpa_ie + wpa_ie_len, wpa_s->rsnxe, wpa_s->rsnxe_len);
		wpa_ie_len += wpa_s->rsnxe_len;
	}
	if (ssid->multi_ap_backhaul_sta) {
		size_t multi_ap_ie_len;

		multi_ap_ie_len = add_multi_ap_ie(wpa_ie + wpa_ie_len,
						  max_wpa_ie_len - wpa_ie_len,
						  MULTI_AP_BACKHAUL_STA);
		if (multi_ap_ie_len == 0) {
			wpa_printf(MSG_ERROR,
				   "Multi-AP: Failed to build Multi-AP IE");
			os_free(wpa_ie);
			return NULL;
		}
		wpa_ie_len += multi_ap_ie_len;
	}

	params->wpa_ie = wpa_ie;
	params->wpa_ie_len = wpa_ie_len;
	params->auth_alg = algs;
	if (mask)
		*mask |= WPA_DRV_UPDATE_ASSOC_IES | WPA_DRV_UPDATE_AUTH_TYPE;

	return wpa_ie;
}
#endif


#if defined(CONFIG_FILS) && defined(IEEE8021X_EAPOL)
#if UNUSED_FEAT_IN_SUPP_29
static void wpas_update_fils_connect_params(struct wpa_supplicant *wpa_s)
{
	struct wpa_driver_associate_params params;
	enum wpa_drv_update_connect_params_mask mask = 0;
	u8 *wpa_ie;

	if (wpa_s->auth_alg != WPA_AUTH_ALG_OPEN)
		return; /* nothing to do */

	os_memset(&params, 0, sizeof(params));
	wpa_ie = wpas_populate_assoc_ies(wpa_s, wpa_s->current_bss,
					 wpa_s->current_ssid, &params, &mask);
	if (!wpa_ie)
		return;

	if (params.auth_alg != WPA_AUTH_ALG_FILS) {
		os_free(wpa_ie);
		return;
	}

	wpa_s->auth_alg = params.auth_alg;
	wpa_drv_update_connect_params(wpa_s, &params, mask);
	os_free(wpa_ie);
}
#endif
#endif /* CONFIG_FILS && IEEE8021X_EAPOL */


#ifdef CONFIG_MBO_STA
void wpas_update_mbo_connect_params(struct wpa_supplicant *wpa_s)
{
	struct wpa_driver_associate_params params;
#if UNUSED_FEAT_IN_SUPP_29 
	u8 *wpa_ie;
#endif

	/*
	 * Update MBO connect params only in case of change of MBO attributes
	 * when connected, if the AP support MBO.
	 */

	if (wpa_s->wpa_state != WPA_COMPLETED || !wpa_s->current_ssid ||
	    !wpa_s->current_bss ||
	    !wpa_bss_get_vendor_ie(wpa_s->current_bss, MBO_IE_VENDOR_TYPE))
		return;

	os_memset(&params, 0, sizeof(params));
#if UNUSED_FEAT_IN_SUPP_29 
	wpa_ie = wpas_populate_assoc_ies(wpa_s, wpa_s->current_bss,
					 wpa_s->current_ssid, &params, NULL);
	if (!wpa_ie)
		return;

	wpa_drv_update_connect_params(wpa_s, &params, WPA_DRV_UPDATE_ASSOC_IES);
	os_free(wpa_ie);
#endif
}
#endif /* CONFIG_MBO_STA */


#if UNUSED_FEAT_IN_SUPP_29
static void wpas_start_assoc_cb(struct wpa_radio_work *work, int deinit)
{
	struct wpa_connect_work *cwork = work->ctx;
	struct wpa_bss *bss = cwork->bss;
	struct wpa_ssid *ssid = cwork->ssid;
	struct wpa_supplicant *wpa_s = work->wpa_s;
	u8 *wpa_ie;
	int use_crypt, ret, i, bssid_changed;
	unsigned int cipher_pairwise, cipher_group, cipher_group_mgmt;
	struct wpa_driver_associate_params params;
	int wep_keys_set = 0;
	int assoc_failed = 0;
	struct wpa_ssid *old_ssid;
	u8 prev_bssid[ETH_ALEN];
#ifdef CONFIG_HT_OVERRIDES
	struct ieee80211_ht_capabilities htcaps;
	struct ieee80211_ht_capabilities htcaps_mask;
#endif /* CONFIG_HT_OVERRIDES */
#ifdef CONFIG_VHT_OVERRIDES
       struct ieee80211_vht_capabilities vhtcaps;
       struct ieee80211_vht_capabilities vhtcaps_mask;
#endif /* CONFIG_VHT_OVERRIDES */

	if (deinit) {
		if (work->started) {
			wpa_s->connect_work = NULL;

			/* cancel possible auth. timeout */
			eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s,
					     NULL);
		}
		wpas_connect_work_free(cwork);
		return;
	}

	wpa_s->connect_work = work;

	if (cwork->bss_removed || !wpas_valid_bss_ssid(wpa_s, bss, ssid) ||
	    wpas_network_disabled(wpa_s, ssid)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "BSS/SSID entry for association not valid anymore - drop connection attempt");
#endif
		SL_PRINTF(WLAN_SUPP_BSS_SSID_ENTRY_FOR_ASSOCIATION_NOT_VALID_ANYMORE_DROP_CONNECTION_ATTEMPT, WLAN_UMAC, LOG_INFO);
		wpas_connect_work_done(wpa_s);
		return;
	}

	os_memcpy(prev_bssid, wpa_s->bssid, ETH_ALEN);
	os_memset(&params, 0, sizeof(params));
	wpa_s->reassociate = 0;
	wpa_s->eap_expected_failure = 0;

	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
	wpa_sm_set_assoc_rsnxe(wpa_s->wpa, NULL, 0);
	wpa_s->rsnxe_len = 0;

	wpa_ie = wpas_populate_assoc_ies(wpa_s, bss, ssid, &params, NULL);
	if (!wpa_ie) {
		wpas_connect_work_done(wpa_s);
		return;
	}

	if (bss &&
	    (!wpas_driver_bss_selection(wpa_s) || wpas_wps_searching(wpa_s))) {
#ifdef CONFIG_IEEE80211R
		const u8 *ie, *md = NULL;
#endif /* CONFIG_IEEE80211R */
		wpa_msg(wpa_s, MSG_INFO, "Trying to associate with " MACSTR
			" (SSID='%s' freq=%d MHz)", MAC2STR(bss->bssid),
			wpa_ssid_txt(bss->ssid, bss->ssid_len), bss->freq);
		bssid_changed = !is_zero_ether_addr(wpa_s->bssid);
		os_memset(wpa_s->bssid, 0, ETH_ALEN);
		os_memcpy(wpa_s->pending_bssid, bss->bssid, ETH_ALEN);
		if (bssid_changed)
			wpas_notify_bssid_changed(wpa_s);
#ifdef CONFIG_IEEE80211R
		ie = wpa_bss_get_ie(bss, WLAN_EID_MOBILITY_DOMAIN);
		if (ie && ie[1] >= MOBILITY_DOMAIN_ID_LEN)
			md = ie + 2;
		wpa_sm_set_ft_params(wpa_s->wpa, ie, ie ? 2 + ie[1] : 0);
		if (md) {
			/* Prepare for the next transition */
			wpa_ft_prepare_auth_request(wpa_s->wpa, ie);
		}
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_WPS
	} else if ((ssid->ssid == NULL || ssid->ssid_len == 0) &&
		   wpa_s->conf->ap_scan == 2 &&
		   (ssid->key_mgmt & WPA_KEY_MGMT_WPS)) {
		/* Use ap_scan==1 style network selection to find the network
		 */
		wpas_connect_work_done(wpa_s);
		wpa_s->scan_req = MANUAL_SCAN_REQ;
		wpa_s->reassociate = 1;
		wpa_supplicant_req_scan(wpa_s, 0, 0);
		return;
#endif /* CONFIG_WPS */
	} else {
		wpa_msg(wpa_s, MSG_INFO, "Trying to associate with SSID '%s'",
			wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
		if (bss)
			os_memcpy(wpa_s->pending_bssid, bss->bssid, ETH_ALEN);
		else
			os_memset(wpa_s->pending_bssid, 0, ETH_ALEN);
	}
	if (!wpa_s->pno)
		wpa_supplicant_cancel_sched_scan(wpa_s);

	wpa_supplicant_cancel_scan(wpa_s);

	/* Starting new association, so clear the possibly used WPA IE from the
	 * previous association. */
	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);

	wpa_ie = wpas_populate_assoc_ies(wpa_s, bss, ssid, &params, NULL);
	if (!wpa_ie) {
		wpas_connect_work_done(wpa_s);
		return;
	}

	wpa_clear_keys(wpa_s, bss ? bss->bssid : NULL);
	use_crypt = 1;
	cipher_pairwise = wpa_s->pairwise_cipher;
	cipher_group = wpa_s->group_cipher;
	cipher_group_mgmt = wpa_s->mgmt_group_cipher;
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE)
			use_crypt = 0;
		if (wpa_set_wep_keys(wpa_s, ssid)) {
			use_crypt = 1;
			wep_keys_set = 1;
		}
	}
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPS)
		use_crypt = 0;

#ifdef IEEE8021X_EAPOL
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if ((ssid->eapol_flags &
		     (EAPOL_FLAG_REQUIRE_KEY_UNICAST |
		      EAPOL_FLAG_REQUIRE_KEY_BROADCAST)) == 0 &&
		    !wep_keys_set) {
			use_crypt = 0;
		} else {
			/* Assume that dynamic WEP-104 keys will be used and
			 * set cipher suites in order for drivers to expect
			 * encryption. */
			cipher_pairwise = cipher_group = WPA_CIPHER_WEP104;
		}
	}
#endif /* IEEE8021X_EAPOL */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		/* Set the key before (and later after) association */
		wpa_supplicant_set_wpa_none_key(wpa_s, ssid);
	}

	wpa_supplicant_set_state(wpa_s, WPA_ASSOCIATING);
	if (bss) {
		params.ssid = bss->ssid;
		params.ssid_len = bss->ssid_len;
		if (!wpas_driver_bss_selection(wpa_s) || ssid->bssid_set ||
		    wpa_s->key_mgmt == WPA_KEY_MGMT_WPS) {
			wpa_printf(MSG_DEBUG, "Limit connection to BSSID "
				   MACSTR " freq=%u MHz based on scan results "
				   "(bssid_set=%d wps=%d)",
				   MAC2STR(bss->bssid), bss->freq,
				   ssid->bssid_set,
				   wpa_s->key_mgmt == WPA_KEY_MGMT_WPS);
			params.bssid = bss->bssid;
			params.freq.freq = bss->freq;
		}
		params.bssid_hint = bss->bssid;
		params.freq_hint = bss->freq;
		params.pbss = bss_is_pbss(bss);
	} else {
		if (ssid->bssid_hint_set)
			params.bssid_hint = ssid->bssid_hint;

		params.ssid = ssid->ssid;
		params.ssid_len = ssid->ssid_len;
		params.pbss = (ssid->pbss != 2) ? ssid->pbss : 0;
	}

	if (ssid->mode == WPAS_MODE_IBSS && ssid->bssid_set &&
	    wpa_s->conf->ap_scan == 2) {
		params.bssid = ssid->bssid;
		params.fixed_bssid = 1;
	}

	/* Initial frequency for IBSS/mesh */
	if ((ssid->mode == WPAS_MODE_IBSS || ssid->mode == WPAS_MODE_MESH) &&
	    ssid->frequency > 0 && params.freq.freq == 0)
		ibss_mesh_setup_freq(wpa_s, ssid, &params.freq);

	if (ssid->mode == WPAS_MODE_IBSS) {
		params.fixed_freq = ssid->fixed_freq;
		if (ssid->beacon_int)
			params.beacon_int = ssid->beacon_int;
		else
			params.beacon_int = wpa_s->conf->beacon_int;
	}

	params.pairwise_suite = cipher_pairwise;
	params.group_suite = cipher_group;
	params.mgmt_group_suite = cipher_group_mgmt;
	params.key_mgmt_suite = wpa_s->key_mgmt;
	params.wpa_proto = wpa_s->wpa_proto;
	wpa_s->auth_alg = params.auth_alg;
	params.mode = ssid->mode;
	params.bg_scan_period = ssid->bg_scan_period;
	for (i = 0; i < NUM_WEP_KEYS; i++) {
		if (ssid->wep_key_len[i])
			params.wep_key[i] = ssid->wep_key[i];
		params.wep_key_len[i] = ssid->wep_key_len[i];
	}
	params.wep_tx_keyidx = ssid->wep_tx_keyidx;

	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK) &&
	    (params.key_mgmt_suite == WPA_KEY_MGMT_PSK ||
	     params.key_mgmt_suite == WPA_KEY_MGMT_FT_PSK)) {
		params.passphrase = ssid->passphrase;
		if (ssid->psk_set)
			params.psk = ssid->psk;
	}

	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_8021X) &&
	    (params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X ||
	     params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X_SHA256 ||
	     params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X_SUITE_B ||
	     params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X_SUITE_B_192))
		params.req_handshake_offload = 1;

	if (wpa_s->conf->key_mgmt_offload) {
		if (params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X ||
		    params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X_SHA256 ||
		    params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X_SUITE_B ||
		    params.key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X_SUITE_B_192)
			params.req_key_mgmt_offload =
				ssid->proactive_key_caching < 0 ?
				wpa_s->conf->okc : ssid->proactive_key_caching;
		else
			params.req_key_mgmt_offload = 1;

		if ((params.key_mgmt_suite == WPA_KEY_MGMT_PSK ||
		     params.key_mgmt_suite == WPA_KEY_MGMT_PSK_SHA256 ||
		     params.key_mgmt_suite == WPA_KEY_MGMT_FT_PSK) &&
		    ssid->psk_set)
			params.psk = ssid->psk;
	}

	params.drop_unencrypted = use_crypt;

#ifdef CONFIG_IEEE80211W
	params.mgmt_frame_protection = wpas_get_ssid_pmf(wpa_s, ssid);
	if (params.mgmt_frame_protection != NO_MGMT_FRAME_PROTECTION && bss) {
		const u8 *rsn = wpa_bss_get_ie(bss, WLAN_EID_RSN);
		struct wpa_ie_data ie;
		if (rsn && wpa_parse_wpa_ie(rsn, 2 + rsn[1], &ie) == 0 &&
		    ie.capabilities &
		    (WPA_CAPABILITY_MFPC | WPA_CAPABILITY_MFPR)) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "WPA: Selected AP supports "
				"MFP: require MFP");
#endif
			SL_PRINTF(WLAN_SUPP_WPA_SELECTED_AP_SUPPORTS_MFP_REQUIRE_MFP, WLAN_UMAC, LOG_INFO);
			params.mgmt_frame_protection =
				MGMT_FRAME_PROTECTION_REQUIRED;
#ifdef CONFIG_OWE
		} else if (!rsn && (ssid->key_mgmt & WPA_KEY_MGMT_OWE) &&
			   !ssid->owe_only) {
			params.mgmt_frame_protection = NO_MGMT_FRAME_PROTECTION;
#endif /* CONFIG_OWE */
		}
	}
#endif /* CONFIG_IEEE80211W */

	params.p2p = ssid->p2p_group;

	if (wpa_s->p2pdev->set_sta_uapsd)
		params.uapsd = wpa_s->p2pdev->sta_uapsd;
	else
		params.uapsd = -1;

#ifdef CONFIG_HT_OVERRIDES
	os_memset(&htcaps, 0, sizeof(htcaps));
	os_memset(&htcaps_mask, 0, sizeof(htcaps_mask));
	params.htcaps = (u8 *) &htcaps;
	params.htcaps_mask = (u8 *) &htcaps_mask;
	wpa_supplicant_apply_ht_overrides(wpa_s, ssid, &params);
#endif /* CONFIG_HT_OVERRIDES */
#ifdef CONFIG_VHT_OVERRIDES
	os_memset(&vhtcaps, 0, sizeof(vhtcaps));
	os_memset(&vhtcaps_mask, 0, sizeof(vhtcaps_mask));
	params.vhtcaps = &vhtcaps;
	params.vhtcaps_mask = &vhtcaps_mask;
	wpa_supplicant_apply_vht_overrides(wpa_s, ssid, &params);
#endif /* CONFIG_VHT_OVERRIDES */

#ifdef CONFIG_P2P
	/*
	 * If multi-channel concurrency is not supported, check for any
	 * frequency conflict. In case of any frequency conflict, remove the
	 * least prioritized connection.
	 */
	if (wpa_s->num_multichan_concurrent < 2) {
		int freq, num;
		num = get_shared_radio_freqs(wpa_s, &freq, 1);
		if (num > 0 && freq > 0 && freq != params.freq.freq) {
			wpa_printf(MSG_DEBUG,
				   "Assoc conflicting freq found (%d != %d)",
				   freq, params.freq.freq);
			if (wpas_p2p_handle_frequency_conflicts(
				    wpa_s, params.freq.freq, ssid) < 0) {
				wpas_connect_work_done(wpa_s);
				os_free(wpa_ie);
				return;
			}
		}
	}
#endif /* CONFIG_P2P */

	if (wpa_s->reassoc_same_ess && !is_zero_ether_addr(prev_bssid) &&
	    wpa_s->current_ssid)
		params.prev_bssid = prev_bssid;

#ifdef CONFIG_SAE
	params.sae_pwe = wpa_s->conf->sae_pwe;
#endif /* CONFIG_SAE */

	ret = wpa_drv_associate(wpa_s, &params);
	os_free(wpa_ie);
	if (ret < 0) {
		wpa_msg(wpa_s, MSG_INFO, "Association request to the driver "
			"failed");
		if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SANE_ERROR_CODES) {
			/*
			 * The driver is known to mean what is saying, so we
			 * can stop right here; the association will not
			 * succeed.
			 */
			wpas_connection_failed(wpa_s, wpa_s->pending_bssid);
			wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
			os_memset(wpa_s->pending_bssid, 0, ETH_ALEN);
			return;
		}
		/* try to continue anyway; new association will be tried again
		 * after timeout */
		assoc_failed = 1;
	}

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_WPA_NONE) {
		/* Set the key after the association just in case association
		 * cleared the previously configured key. */
		wpa_supplicant_set_wpa_none_key(wpa_s, ssid);
		/* No need to timeout authentication since there is no key
		 * management. */
		wpa_supplicant_cancel_auth_timeout(wpa_s);
		wpa_supplicant_set_state(wpa_s, WPA_COMPLETED);
#ifdef CONFIG_IBSS_RSN
	} else if (ssid->mode == WPAS_MODE_IBSS &&
		   wpa_s->key_mgmt != WPA_KEY_MGMT_NONE &&
		   wpa_s->key_mgmt != WPA_KEY_MGMT_WPA_NONE) {
		/*
		 * RSN IBSS authentication is per-STA and we can disable the
		 * per-BSSID authentication.
		 */
		wpa_supplicant_cancel_auth_timeout(wpa_s);
#endif /* CONFIG_IBSS_RSN */
	} else {
		/* Timeout for IEEE 802.11 authentication and association */
		int timeout = 60;

		if (assoc_failed) {
			/* give IBSS a bit more time */
			timeout = ssid->mode == WPAS_MODE_IBSS ? 10 : 5;
		} else if (wpa_s->conf->ap_scan == 1) {
			/* give IBSS a bit more time */
			timeout = ssid->mode == WPAS_MODE_IBSS ? 20 : 10;
		}
		wpa_supplicant_req_auth_timeout(wpa_s, timeout, 0);
	}

	if (wep_keys_set &&
	    (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SET_KEYS_AFTER_ASSOC)) {
		/* Set static WEP keys again */
		wpa_set_wep_keys(wpa_s, ssid);
	}

	if (wpa_s->current_ssid && wpa_s->current_ssid != ssid) {
		/*
		 * Do not allow EAP session resumption between different
		 * network configurations.
		 */
		eapol_sm_invalidate_cached_session(wpa_s->eapol);
	}
	old_ssid = wpa_s->current_ssid;
	wpa_s->current_ssid = ssid;

	if (!wpas_driver_bss_selection(wpa_s) || ssid->bssid_set) {
		wpa_s->current_bss = bss;
#ifdef CONFIG_HS20
		hs20_configure_frame_filters(wpa_s);
#endif /* CONFIG_HS20 */
	}

	wpa_supplicant_rsn_supp_set_config(wpa_s, wpa_s->current_ssid);
	wpa_supplicant_initiate_eapol(wpa_s);
	if (old_ssid != wpa_s->current_ssid)
		wpas_notify_network_changed(wpa_s);
}
#endif


static void wpa_supplicant_clear_connection(struct wpa_supplicant *wpa_s,
					    const u8 *addr)
{
	struct wpa_ssid *old_ssid;

#ifdef ENABLE_RRM
	wpas_connect_work_done(wpa_s);
#endif
	wpa_clear_keys(wpa_s, addr);
	old_ssid = wpa_s->current_ssid;
	wpa_supplicant_mark_disassoc(wpa_s);
	wpa_sm_set_config(wpa_s->wpa, NULL);
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	if (old_ssid != wpa_s->current_ssid)
		wpas_notify_network_changed(wpa_s);
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
}


/**
 * wpa_supplicant_deauthenticate - Deauthenticate the current connection
 * @wpa_s: Pointer to wpa_supplicant data
 * @reason_code: IEEE 802.11 reason code for the deauthenticate frame
 *
 * This function is used to request %wpa_supplicant to deauthenticate from the
 * current AP.
 */
void wpa_supplicant_deauthenticate(struct wpa_supplicant *wpa_s,
				   u16 reason_code)
{
	u8 *addr = NULL;
	union wpa_event_data event;
	int zero_addr = 0;

	 wpa_dbg(wpa_s, MSG_DEBUG, "Request to deauthenticate - bssid=" MACSTR
		" pending_bssid=" MACSTR " reason=%d (%s) state=%s",
		MAC2STR(wpa_s->bssid), MAC2STR(wpa_s->pending_bssid),
		reason_code, reason2str(reason_code),
		wpa_supplicant_state_txt(wpa_s->wpa_state)); 

	if (!is_zero_ether_addr(wpa_s->pending_bssid) &&
	    (wpa_s->wpa_state == WPA_AUTHENTICATING ||
	     wpa_s->wpa_state == WPA_ASSOCIATING))
		addr = wpa_s->pending_bssid;
	else if (!is_zero_ether_addr(wpa_s->bssid))
		addr = wpa_s->bssid;
	else if (wpa_s->wpa_state == WPA_ASSOCIATING) {
		/*
		 * When using driver-based BSS selection, we may not know the
		 * BSSID with which we are currently trying to associate. We
		 * need to notify the driver of this disconnection even in such
		 * a case, so use the all zeros address here.
		 */
		addr = wpa_s->bssid;
		zero_addr = 1;
	}

	if (wpa_s->enabled_4addr_mode && wpa_drv_set_4addr_mode(wpa_s, 0) == 0)
		wpa_s->enabled_4addr_mode = 0;

#ifdef CONFIG_TDLS
	wpa_tdls_teardown_peers(wpa_s->wpa);
#endif /* CONFIG_TDLS */

#ifdef CONFIG_MESH
	if (wpa_s->ifmsh) {
		struct mesh_conf *mconf;

		mconf = wpa_s->ifmsh->mconf;
		wpa_msg(wpa_s, MSG_INFO, MESH_GROUP_REMOVED "%s",
			wpa_s->ifname);
		wpas_notify_mesh_group_removed(wpa_s, mconf->meshid,
					       mconf->meshid_len, reason_code);
		wpa_supplicant_leave_mesh(wpa_s);
	}
#endif /* CONFIG_MESH */

	if (addr) {
		wpa_drv_deauthenticate(wpa_s, addr, reason_code);
		os_memset(&event, 0, sizeof(event));
		event.deauth_info.reason_code = reason_code;
		event.deauth_info.locally_generated = 1;
		wpa_supplicant_event(wpa_s, EVENT_DEAUTH, &event);
		if (zero_addr)
			addr = NULL;
	}

	wpa_supplicant_clear_connection(wpa_s, addr);
}
#ifdef RSI_ENABLE_CCX
/**
 * wpa_supplicant_disassociate - Disassociate the current connection
 * @wpa_s: Pointer to wpa_supplicant data
 * @reason_code: IEEE 802.11 reason code for the disassociate frame
 * 
 * This function is used to request %wpa_supplicant to disassociate with the
 * current AP.
 */
#if UNUSED_FEAT_IN_SUPP_29
void wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s,
		int reason_code)
{
	struct wpa_ssid *old_ssid;
	u8 *addr = NULL;

	if (!is_zero_ether_addr(wpa_s->bssid)) {
		if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_USER_SPACE_MLME) {
			//ieee80211_sta_disassociate(wpa_s, reason_code);
		}
		else
			wpa_drv_disassociate(wpa_s, wpa_s->bssid, reason_code);
		addr = wpa_s->bssid;
	}
	wpa_clear_keys(wpa_s, addr);
	wpa_supplicant_mark_disassoc(wpa_s);
	old_ssid = wpa_s->current_ssid;
	wpa_s->current_ssid = NULL;
	wpa_s->current_bss = NULL;
	wpa_sm_set_config(wpa_s->wpa, NULL);
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	if (old_ssid != wpa_s->current_ssid)
		wpas_notify_network_changed(wpa_s);
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
}
#endif
#endif
#if UNUSED_FEAT_IN_SUPP_29
static void wpa_supplicant_enable_one_network(struct wpa_supplicant *wpa_s,
					      struct wpa_ssid *ssid)
{
	if (!ssid || !ssid->disabled || ssid->disabled == 2)
		return;

	ssid->disabled = 0;
	ssid->owe_transition_bss_select_count = 0;
	wpas_clear_temp_disabled(wpa_s, ssid, 1);
	wpas_notify_network_enabled_changed(wpa_s, ssid);

	/*
	 * Try to reassociate since there is no current configuration and a new
	 * network was made available.
	 */
	if (!wpa_s->current_ssid && !wpa_s->disconnected)
		wpa_s->reassociate = 1;
}


/**
 * wpa_supplicant_add_network - Add a new network
 * @wpa_s: wpa_supplicant structure for a network interface
 * Returns: The new network configuration or %NULL if operation failed
 *
 * This function performs the following operations:
 * 1. Adds a new network.
 * 2. Send network addition notification.
 * 3. Marks the network disabled.
 * 4. Set network default parameters.
 */
struct wpa_ssid * wpa_supplicant_add_network(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid;

	ssid = wpa_config_add_network(wpa_s->conf);
	if (!ssid)
		return NULL;
	wpas_notify_network_added(wpa_s, ssid);
	ssid->disabled = 1;
	wpa_config_set_network_defaults(ssid);

	return ssid;
}


/**
 * wpa_supplicant_remove_network - Remove a configured network based on id
 * @wpa_s: wpa_supplicant structure for a network interface
 * @id: Unique network id to search for
 * Returns: 0 on success, or -1 if the network was not found, -2 if the network
 * could not be removed
 *
 * This function performs the following operations:
 * 1. Removes the network.
 * 2. Send network removal notification.
 * 3. Update internal state machines.
 * 4. Stop any running sched scans.
 */
int wpa_supplicant_remove_network(struct wpa_supplicant *wpa_s, int id)
{
	struct wpa_ssid *ssid;
	int was_disabled;

	ssid = wpa_config_get_network(wpa_s->conf, id);
	if (!ssid)
		return -1;
	wpas_notify_network_removed(wpa_s, ssid);

	if (wpa_s->last_ssid == ssid)
		wpa_s->last_ssid = NULL;

	if (ssid == wpa_s->current_ssid || !wpa_s->current_ssid) {
#ifdef CONFIG_SME
		wpa_s->sme.prev_bssid_set = 0;
#endif /* CONFIG_SME */
		/*
		 * Invalidate the EAP session cache if the current or
		 * previously used network is removed.
		 */
		eapol_sm_invalidate_cached_session(wpa_s->eapol);
	}

	if (ssid == wpa_s->current_ssid) {
		wpa_sm_set_config(wpa_s->wpa, NULL);
		eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);

		if (wpa_s->wpa_state >= WPA_AUTHENTICATING)
			wpa_s->own_disconnect_req = 1;
		wpa_supplicant_deauthenticate(wpa_s,
					      WLAN_REASON_DEAUTH_LEAVING);
	}

	was_disabled = ssid->disabled;

	if (wpa_config_remove_network(wpa_s->conf, id) < 0)
		return -2;

	if (!was_disabled && wpa_s->sched_scanning) {
		wpa_printf(MSG_DEBUG,
			   "Stop ongoing sched_scan to remove network from filters");
		wpa_supplicant_cancel_sched_scan(wpa_s);
		wpa_supplicant_req_scan(wpa_s, 0, 0);
	}

	return 0;
}

/**
 * wpa_supplicant_enable_network - Mark a configured network as enabled
 * @wpa_s: wpa_supplicant structure for a network interface
 * @ssid: wpa_ssid structure for a configured network or %NULL
 *
 * Enables the specified network or all networks if no network specified.
 */
void wpa_supplicant_enable_network(struct wpa_supplicant *wpa_s,
				   struct wpa_ssid *ssid)
{
	if (ssid == NULL) {
		for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next)
			wpa_supplicant_enable_one_network(wpa_s, ssid);
	} else
		wpa_supplicant_enable_one_network(wpa_s, ssid);

	if (wpa_s->reassociate && !wpa_s->disconnected &&
	    (!wpa_s->current_ssid ||
	     wpa_s->wpa_state == WPA_DISCONNECTED ||
	     wpa_s->wpa_state == WPA_SCANNING)) {
		if (wpa_s->sched_scanning) {
			wpa_printf(MSG_DEBUG, "Stop ongoing sched_scan to add "
				   "new network to scan filters");
			wpa_supplicant_cancel_sched_scan(wpa_s);
		}

		if (wpa_supplicant_fast_associate(wpa_s) != 1) {
			wpa_s->scan_req = NORMAL_SCAN_REQ;
			wpa_supplicant_req_scan(wpa_s, 0, 0);
		}
	}
}


/**
 * wpa_supplicant_disable_network - Mark a configured network as disabled
 * @wpa_s: wpa_supplicant structure for a network interface
 * @ssid: wpa_ssid structure for a configured network or %NULL
 *
 * Disables the specified network or all networks if no network specified.
 */
void wpa_supplicant_disable_network(struct wpa_supplicant *wpa_s,
				    struct wpa_ssid *ssid)
{
	struct wpa_ssid *other_ssid;
	int was_disabled;

	if (ssid == NULL) {
		if (wpa_s->sched_scanning)
			wpa_supplicant_cancel_sched_scan(wpa_s);

		for (other_ssid = wpa_s->conf->ssid; other_ssid;
		     other_ssid = other_ssid->next) {
			was_disabled = other_ssid->disabled;
			if (was_disabled == 2)
				continue; /* do not change persistent P2P group
					   * data */

			other_ssid->disabled = 1;

			if (was_disabled != other_ssid->disabled)
				wpas_notify_network_enabled_changed(
					wpa_s, other_ssid);
		}
		if (wpa_s->current_ssid) {
			if (wpa_s->wpa_state >= WPA_AUTHENTICATING)
				wpa_s->own_disconnect_req = 1;
			wpa_supplicant_deauthenticate(
				wpa_s, WLAN_REASON_DEAUTH_LEAVING);
		}
	} else if (ssid->disabled != 2) {
		if (ssid == wpa_s->current_ssid) {
			if (wpa_s->wpa_state >= WPA_AUTHENTICATING)
				wpa_s->own_disconnect_req = 1;
			wpa_supplicant_deauthenticate(
				wpa_s, WLAN_REASON_DEAUTH_LEAVING);
		}

		was_disabled = ssid->disabled;

		ssid->disabled = 1;

		if (was_disabled != ssid->disabled) {
			wpas_notify_network_enabled_changed(wpa_s, ssid);
			if (wpa_s->sched_scanning) {
				wpa_printf(MSG_DEBUG, "Stop ongoing sched_scan "
					   "to remove network from filters");
				wpa_supplicant_cancel_sched_scan(wpa_s);
				wpa_supplicant_req_scan(wpa_s, 0, 0);
			}
		}
	}
}


/**
 * wpa_supplicant_select_network - Attempt association with a network
 * @wpa_s: wpa_supplicant structure for a network interface
 * @ssid: wpa_ssid structure for a configured network or %NULL for any network
 */
void wpa_supplicant_select_network(struct wpa_supplicant *wpa_s,
				   struct wpa_ssid *ssid)
{

	struct wpa_ssid *other_ssid;
	int disconnected = 0;

	if (ssid && ssid != wpa_s->current_ssid && wpa_s->current_ssid) {
		if (wpa_s->wpa_state >= WPA_AUTHENTICATING)
			wpa_s->own_disconnect_req = 1;
		wpa_supplicant_deauthenticate(
			wpa_s, WLAN_REASON_DEAUTH_LEAVING);
		disconnected = 1;
	}

	if (ssid)
		wpas_clear_temp_disabled(wpa_s, ssid, 1);

	/*
	 * Mark all other networks disabled or mark all networks enabled if no
	 * network specified.
	 */
	for (other_ssid = wpa_s->conf->ssid; other_ssid;
	     other_ssid = other_ssid->next) {
		int was_disabled = other_ssid->disabled;
		if (was_disabled == 2)
			continue; /* do not change persistent P2P group data */

		other_ssid->disabled = ssid ? (ssid->id != other_ssid->id) : 0;
		if (was_disabled && !other_ssid->disabled)
			wpas_clear_temp_disabled(wpa_s, other_ssid, 0);

		if (was_disabled != other_ssid->disabled)
			wpas_notify_network_enabled_changed(wpa_s, other_ssid);
	}

	if (ssid && ssid == wpa_s->current_ssid && wpa_s->current_ssid &&
	    wpa_s->wpa_state >= WPA_AUTHENTICATING) {
		/* We are already associated with the selected network */
		wpa_printf(MSG_DEBUG, "Already associated with the "
			   "selected network - do nothing");
		return;
	}

	if (ssid) {
		wpa_s->current_ssid = ssid;
		eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
		wpa_s->connect_without_scan =
			(ssid->mode == WPAS_MODE_MESH) ? ssid : NULL;

		/*
		 * Don't optimize next scan freqs since a new ESS has been
		 * selected.
		 */
		os_free(wpa_s->next_scan_freqs);
		wpa_s->next_scan_freqs = NULL;
	} else {
		wpa_s->connect_without_scan = NULL;
	}

	wpa_s->disconnected = 0;
	wpa_s->reassociate = 1;
#if UNUSED_FEAT_IN_SUPP_29
	wpa_s_clear_sae_rejected(wpa_s);
#endif
	wpa_s->last_owe_group = 0;
	if (ssid) {
		ssid->owe_transition_bss_select_count = 0;
		wpa_s_setup_sae_pt(wpa_s->conf, ssid);
	}

	if (wpa_s->connect_without_scan ||
	    wpa_supplicant_fast_associate(wpa_s) != 1) {
		wpa_s->scan_req = NORMAL_SCAN_REQ;
		wpas_scan_reset_sched_scan(wpa_s);
		wpa_supplicant_req_scan(wpa_s, 0, disconnected ? 100000 : 0);
	}

	if (ssid)
		wpas_notify_network_selected(wpa_s, ssid);
}


/**
 * wpas_set_pkcs11_engine_and_module_path - Set PKCS #11 engine and module path
 * @wpa_s: wpa_supplicant structure for a network interface
 * @pkcs11_engine_path: PKCS #11 engine path or NULL
 * @pkcs11_module_path: PKCS #11 module path or NULL
 * Returns: 0 on success; -1 on failure
 *
 * Sets the PKCS #11 engine and module path. Both have to be NULL or a valid
 * path. If resetting the EAPOL state machine with the new PKCS #11 engine and
 * module path fails the paths will be reset to the default value (NULL).
 */
int wpas_set_pkcs11_engine_and_module_path(struct wpa_supplicant *wpa_s,
					   const char *pkcs11_engine_path,
					   const char *pkcs11_module_path)
{
	char *pkcs11_engine_path_copy = NULL;
	char *pkcs11_module_path_copy = NULL;

	if (pkcs11_engine_path != NULL) {
		pkcs11_engine_path_copy = os_strdup(pkcs11_engine_path);
		if (pkcs11_engine_path_copy == NULL)
			return -1;
	}
	if (pkcs11_module_path != NULL) {
		pkcs11_module_path_copy = os_strdup(pkcs11_module_path);
		if (pkcs11_module_path_copy == NULL) {
			os_free(pkcs11_engine_path_copy);
			return -1;
		}
	}

	os_free(wpa_s->conf->pkcs11_engine_path);
	os_free(wpa_s->conf->pkcs11_module_path);
	wpa_s->conf->pkcs11_engine_path = pkcs11_engine_path_copy;
	wpa_s->conf->pkcs11_module_path = pkcs11_module_path_copy;

	wpa_sm_set_eapol(wpa_s->wpa, NULL);
	eapol_sm_deinit(wpa_s->eapol);
	wpa_s->eapol = NULL;
	if (wpa_supplicant_init_eapol(wpa_s)) {
		/* Error -> Reset paths to the default value (NULL) once. */
		if (pkcs11_engine_path != NULL && pkcs11_module_path != NULL)
			wpas_set_pkcs11_engine_and_module_path(wpa_s, NULL,
							       NULL);

		return -1;
	}
	wpa_sm_set_eapol(wpa_s->wpa, wpa_s->eapol);

	return 0;
}

/**
 * wpa_supplicant_set_ap_scan - Set AP scan mode for interface
 * @wpa_s: wpa_supplicant structure for a network interface
 * @ap_scan: AP scan mode
 * Returns: 0 if succeed or -1 if ap_scan has an invalid value
 *
 */
int wpa_supplicant_set_ap_scan(struct wpa_supplicant *wpa_s, int ap_scan)
{

	int old_ap_scan;

	if (ap_scan < 0 || ap_scan > 2)
		return -1;

	if (ap_scan == 2 && os_strcmp(wpa_s->driver->name, "nl80211") == 0) {
		wpa_printf(MSG_INFO,
			   "Note: nl80211 driver interface is not designed to be used with ap_scan=2; this can result in connection failures");
	}

#ifdef ANDROID
	if (ap_scan == 2 && ap_scan != wpa_s->conf->ap_scan &&
	    wpa_s->wpa_state >= WPA_ASSOCIATING &&
	    wpa_s->wpa_state < WPA_COMPLETED) {
		wpa_printf(MSG_ERROR, "ap_scan = %d (%d) rejected while "
			   "associating", wpa_s->conf->ap_scan, ap_scan);
		return 0;
	}
#endif /* ANDROID */

	old_ap_scan = wpa_s->conf->ap_scan;
	wpa_s->conf->ap_scan = ap_scan;

	if (old_ap_scan != wpa_s->conf->ap_scan)
		wpas_notify_ap_scan_changed(wpa_s);

	return 0;
}


/**
 * wpa_supplicant_set_bss_expiration_age - Set BSS entry expiration age
 * @wpa_s: wpa_supplicant structure for a network interface
 * @expire_age: Expiration age in seconds
 * Returns: 0 if succeed or -1 if expire_age has an invalid value
 *
 */
int wpa_supplicant_set_bss_expiration_age(struct wpa_supplicant *wpa_s,
					  unsigned int bss_expire_age)
{
	if (bss_expire_age < 10) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Invalid bss expiration age %u",
			bss_expire_age);
#endif
		SL_PRINTF(WLAN_SUPP_INVALID_BSS_EXPIRATION_AGE, WLAN_UMAC, LOG_ERROR, "age %d", bss_expire_age);
		return -1;
	}
	wpa_msg(wpa_s, MSG_DEBUG, "Setting bss expiration age: %d sec",
		bss_expire_age);
	wpa_s->conf->bss_expiration_age = bss_expire_age;

	return 0;
}


/**
 * wpa_supplicant_set_bss_expiration_count - Set BSS entry expiration scan count
 * @wpa_s: wpa_supplicant structure for a network interface
 * @expire_count: number of scans after which an unseen BSS is reclaimed
 * Returns: 0 if succeed or -1 if expire_count has an invalid value
 *
 */
int wpa_supplicant_set_bss_expiration_count(struct wpa_supplicant *wpa_s,
					    unsigned int bss_expire_count)
{
	if (bss_expire_count < 1) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Invalid bss expiration count %u",
			bss_expire_count);
#endif
		SL_PRINTF(WLAN_SUPP_INVALID_BSS_EXPIRATION_COUNT, WLAN_UMAC, LOG_ERROR, "count %d", bss_expire_count);
		return -1;
	}
	wpa_msg(wpa_s, MSG_DEBUG, "Setting bss expiration scan count: %u",
		bss_expire_count);
	wpa_s->conf->bss_expiration_scan_count = bss_expire_count;

	return 0;
}


/**
 * wpa_supplicant_set_scan_interval - Set scan interval
 * @wpa_s: wpa_supplicant structure for a network interface
 * @scan_interval: scan interval in seconds
 * Returns: 0 if succeed or -1 if scan_interval has an invalid value
 *
 */
int wpa_supplicant_set_scan_interval(struct wpa_supplicant *wpa_s,
				     int scan_interval)
{
	if (scan_interval < 0) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Invalid scan interval %d",
			scan_interval);
#endif
		SL_PRINTF(WLAN_SUPP_INVALID_SCAN_INTERVAL, WLAN_UMAC, LOG_ERROR, "interval %d", scan_interval);
		return -1;
	}
	wpa_msg(wpa_s, MSG_DEBUG, "Setting scan interval: %d sec",
		scan_interval);
	wpa_supplicant_update_scan_int(wpa_s, scan_interval);

	return 0;
}


/**
 * wpa_supplicant_set_debug_params - Set global debug params
 * @global: wpa_global structure
 * @debug_level: debug level
 * @debug_timestamp: determines if show timestamp in debug data
 * @debug_show_keys: determines if show keys in debug data
 * Returns: 0 if succeed or -1 if debug_level has wrong value
 */
int wpa_supplicant_set_debug_params(struct wpa_global *global, int debug_level,
				    int debug_timestamp, int debug_show_keys)
{

	int old_level, old_timestamp, old_show_keys;

	/* check for allowed debuglevels */
	if (debug_level != MSG_EXCESSIVE &&
	    debug_level != MSG_MSGDUMP &&
	    debug_level != MSG_DEBUG &&
	    debug_level != MSG_INFO &&
	    debug_level != MSG_WARNING &&
	    debug_level != MSG_ERROR)
		return -1;

	old_level = wpa_debug_level;
	old_timestamp = wpa_debug_timestamp;
	old_show_keys = wpa_debug_show_keys;

	wpa_debug_level = debug_level;
	wpa_debug_timestamp = debug_timestamp ? 1 : 0;
	wpa_debug_show_keys = debug_show_keys ? 1 : 0;

	if (wpa_debug_level != old_level)
		wpas_notify_debug_level_changed(global);
	if (wpa_debug_timestamp != old_timestamp)
		wpas_notify_debug_timestamp_changed(global);
	if (wpa_debug_show_keys != old_show_keys)
		wpas_notify_debug_show_keys_changed(global);

	return 0;
}
#endif


#ifdef CONFIG_OWE
static int owe_trans_ssid_match(struct wpa_supplicant *wpa_s, const u8 *bssid,
				const u8 *entry_ssid, size_t entry_ssid_len)
{
	const u8 *owe, *pos, *end;
	u8 ssid_len;
	struct wpa_bss *bss;

	/* Check network profile SSID aganst the SSID in the
	 * OWE Transition Mode element. */

	bss = wpa_bss_get_bssid_latest(wpa_s, bssid);
	if (!bss)
		return 0;

	owe = wpa_bss_get_vendor_ie(bss, OWE_IE_VENDOR_TYPE);
	if (!owe)
		return 0;

	pos = owe + 6;
	end = owe + 2 + owe[1];

	if (end - pos < ETH_ALEN + 1)
		return 0;
	pos += ETH_ALEN;
	ssid_len = *pos++;
	if (end - pos < ssid_len || ssid_len > SSID_MAX_LEN)
		return 0;

	return entry_ssid_len == ssid_len &&
		os_memcmp(pos, entry_ssid, ssid_len) == 0;
}
#endif /* CONFIG_OWE */


/**
 * wpa_supplicant_get_ssid - Get a pointer to the current network structure
 * @wpa_s: Pointer to wpa_supplicant data
 * Returns: A pointer to the current network structure or %NULL on failure
 */
struct wpa_ssid * wpa_supplicant_get_ssid(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *entry;
	u8 ssid[SSID_MAX_LEN];
	int res;
	size_t ssid_len;
	u8 bssid[ETH_ALEN];
	int wired;

	res = wpa_drv_get_ssid(wpa_s, ssid);
	if (res < 0) {
		wpa_msg(wpa_s, MSG_WARNING, "Could not read SSID from "
			"driver");
		return NULL;
	}
	ssid_len = res;

	if (wpa_drv_get_bssid(wpa_s, bssid) < 0) {
		wpa_msg(wpa_s, MSG_WARNING, "Could not read BSSID from "
			"driver");
		return NULL;
	}

	wired = wpa_s->conf->ap_scan == 0 &&
		(wpa_s->drv_flags & WPA_DRIVER_FLAGS_WIRED);

	entry = wpa_s->conf->ssid;
	while (entry) {
		if (!wpas_network_disabled(wpa_s, entry) &&
		    ((ssid_len == entry->ssid_len &&
		      (!entry->ssid ||
		       os_memcmp(ssid, entry->ssid, ssid_len) == 0)) ||
		     wired) &&
		    (!entry->bssid_set ||
		     os_memcmp(bssid, entry->bssid, ETH_ALEN) == 0))
			return entry;
#ifdef CONFIG_WPS
		if (!wpas_network_disabled(wpa_s, entry) &&
		    (entry->key_mgmt & WPA_KEY_MGMT_WPS) &&
		    (entry->ssid == NULL || entry->ssid_len == 0) &&
		    (!entry->bssid_set ||
		     os_memcmp(bssid, entry->bssid, ETH_ALEN) == 0))
			return entry;
#endif /* CONFIG_WPS */

#ifdef CONFIG_OWE
		if (!wpas_network_disabled(wpa_s, entry) &&
		    owe_trans_ssid_match(wpa_s, bssid, entry->ssid,
		    entry->ssid_len) &&
		    (!entry->bssid_set ||
		     os_memcmp(bssid, entry->bssid, ETH_ALEN) == 0))
			return entry;
#endif /* CONFIG_OWE */

		if (!wpas_network_disabled(wpa_s, entry) && entry->bssid_set &&
		    entry->ssid_len == 0 &&
		    os_memcmp(bssid, entry->bssid, ETH_ALEN) == 0)
			return entry;

		entry = entry->next;
	}

	return NULL;
}


static int select_driver(struct wpa_supplicant *wpa_s, int i)
{
	struct wpa_global *global = wpa_s->global;

	if (wpa_drivers[i]->global_init && global->drv_priv[i] == NULL) {
		global->drv_priv[i] = wpa_drivers[i]->global_init(global);
		if (global->drv_priv[i] == NULL) {
			wpa_printf(MSG_ERROR, "Failed to initialize driver "
				   "'%s'", wpa_drivers[i]->name);
			return -1;
		}
	}

	wpa_s->driver = wpa_drivers[i];
	wpa_s->global_drv_priv = global->drv_priv[i];

	return 0;
}


static int wpa_supplicant_set_driver(struct wpa_supplicant *wpa_s,
				     const char *name)
{
	int i;
	size_t len;
	const char *pos, *driver = name;

	if (wpa_s == NULL)
		return -1;

	if (wpa_drivers[0] == NULL) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "No driver interfaces build into "
			"wpa_supplicant");
#endif
		SL_PRINTF(WLAN_SUPP_NO_DRIVER_INTERFACES_BUILD_INTO_WPA_SUPPLICANT, WLAN_UMAC, LOG_ERROR);
		return -1;
	}

	if (name == NULL) {
		/* default to first driver in the list */
		return select_driver(wpa_s, 0);
	}

	do {
		pos = os_strchr(driver, ',');
		if (pos)
			len = pos - driver;
		else
			len = os_strlen(driver);

		for (i = 0; wpa_drivers[i]; i++) {
			if (os_strlen(wpa_drivers[i]->name) == len &&
			    os_strncmp(driver, wpa_drivers[i]->name, len) ==
			    0) {
				/* First driver that succeeds wins */
				if (select_driver(wpa_s, i) == 0)
					return 0;
			}
		}

		driver = pos + 1;
	} while (pos);

#if UNUSED_FEAT_IN_SUPP_29
	wpa_msg(wpa_s, MSG_ERROR, "Unsupported driver '%s'", name);
#endif
	SL_PRINTF(WLAN_SUPP_UNSUPPORTED_DRIVER, WLAN_UMAC, LOG_ERROR, "driver %s", (uint32_t)name);
	return -1;
}


/**
 * wpa_supplicant_rx_eapol - Deliver a received EAPOL frame to wpa_supplicant
 * @ctx: Context pointer (wpa_s); this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @src_addr: Source address of the EAPOL frame
 * @buf: EAPOL data starting from the EAPOL header (i.e., no Ethernet header)
 * @len: Length of the EAPOL data
 *
 * This function is called for each received EAPOL frame. Most driver
 * interfaces rely on more generic OS mechanism for receiving frames through
 * l2_packet, but if such a mechanism is not available, the driver wrapper may
 * take care of received EAPOL frames and deliver them to the core supplicant
 * code by calling this function.
 */
void wpa_supplicant_rx_eapol(void *ctx, const u8 *src_addr,
			     const u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "RX EAPOL from " MACSTR, MAC2STR(src_addr));
#endif
	SL_PRINTF(WLAN_SUPP_RX_EAPOL_FROM_SRC, WLAN_UMAC, LOG_INFO);
	wpa_hexdump(MSG_MSGDUMP, "RX EAPOL", buf, len);

#ifdef CONFIG_TESTING_OPTIONS
	if (wpa_s->ignore_auth_resp) {
		wpa_printf(MSG_INFO, "RX EAPOL - ignore_auth_resp active!");
		return;
	}
#endif /* CONFIG_TESTING_OPTIONS */

	if (wpa_s->wpa_state < WPA_ASSOCIATED ||
	    (wpa_s->last_eapol_matches_bssid &&
#ifdef CONFIG_AP
	     !wpa_s->ap_iface &&
#endif /* CONFIG_AP */
	     os_memcmp(src_addr, wpa_s->bssid, ETH_ALEN) != 0)) {
		/*
		 * There is possible race condition between receiving the
		 * association event and the EAPOL frame since they are coming
		 * through different paths from the driver. In order to avoid
		 * issues in trying to process the EAPOL frame before receiving
		 * association information, lets queue it for processing until
		 * the association event is received. This may also be needed in
		 * driver-based roaming case, so also use src_addr != BSSID as a
		 * trigger if we have previously confirmed that the
		 * Authenticator uses BSSID as the src_addr (which is not the
		 * case with wired IEEE 802.1X).
		 */
		 wpa_dbg(wpa_s, MSG_DEBUG, "Not associated - Delay processing "
			"of received EAPOL frame (state=%s bssid=" MACSTR ")",
			wpa_supplicant_state_txt(wpa_s->wpa_state),
			MAC2STR(wpa_s->bssid)); 
		SL_PRINTF(WLAN_SUPP_NOT_ASSOCIATED_DELAY_PROCESSING_OF_RECEIVED_EAPOL_FRAME_STATE, WLAN_UMAC, LOG_INFO, "(state=%s)", wpa_supplicant_state_txt(wpa_s->wpa_state));
		wpabuf_free(wpa_s->pending_eapol_rx);
		wpa_s->pending_eapol_rx = wpabuf_alloc_copy(buf, len);
		if (wpa_s->pending_eapol_rx) {
			os_get_reltime(&wpa_s->pending_eapol_rx_time);
			os_memcpy(wpa_s->pending_eapol_rx_src, src_addr,
				  ETH_ALEN);
		}
		return;
	}

	wpa_s->last_eapol_matches_bssid =
		os_memcmp(src_addr, wpa_s->bssid, ETH_ALEN) == 0;

#ifdef CONFIG_AP
	if (wpa_s->ap_iface) {
		wpa_supplicant_ap_rx_eapol(wpa_s, src_addr, buf, len);
		return;
	}
#endif /* CONFIG_AP */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Ignored received EAPOL frame since "
			"no key management is configured");
#endif
		SL_PRINTF(WLAN_SUPP_IGNORED_RECEIVED_EAPOL_FRAME_SINCE_NO_KEY_MANAGEMENT_IS_CONFIGURED, WLAN_UMAC, LOG_INFO);
		return;
	}

	if (wpa_s->eapol_received == 0 &&
	    (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK) ||
	     !wpa_key_mgmt_wpa_psk(wpa_s->key_mgmt) ||
	     wpa_s->wpa_state != WPA_COMPLETED) &&
	    (wpa_s->current_ssid == NULL ||
	     wpa_s->current_ssid->mode != WPAS_MODE_IBSS)) {
		/* Timeout for completing IEEE 802.1X and WPA authentication */
		int timeout = 10;

		if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt) ||
		    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA ||
		    wpa_s->key_mgmt == WPA_KEY_MGMT_WPS) {
			/* Use longer timeout for IEEE 802.1X/EAP */
			timeout = 70;
		}
		int rsa_4096_support = 0;
		sl_wpa_driver_wrapper(wpa_s, WPA_DRV_CHK_RSA_4096_SUPPORT, &rsa_4096_support);
		if (rsa_4096_support) {
			timeout = 90;
		}

#ifdef CONFIG_WPS
		if (wpa_s->current_ssid && wpa_s->current_bss &&
		    (wpa_s->current_ssid->key_mgmt & WPA_KEY_MGMT_WPS) &&
		    eap_is_wps_pin_enrollee(&wpa_s->current_ssid->eap)) {
			/*
			 * Use shorter timeout if going through WPS AP iteration
			 * for PIN config method with an AP that does not
			 * advertise Selected Registrar.
			 */
			struct wpabuf *wps_ie;

			wps_ie = wpa_bss_get_vendor_ie_multi(
				wpa_s->current_bss, WPS_IE_VENDOR_TYPE);
			if (wps_ie &&
			    !wps_is_addr_authorized(wps_ie, wpa_s->own_addr, 1))
				timeout = 10;
			wpabuf_free(wps_ie);
		}
#endif /* CONFIG_WPS */

		wpa_supplicant_req_auth_timeout(wpa_s, timeout, 0);
	}
	wpa_s->eapol_received++;

	if (wpa_s->countermeasures) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Countermeasures - dropped "
			"EAPOL packet");
		return;
	}

#ifdef CONFIG_IBSS_RSN
	if (wpa_s->current_ssid &&
	    wpa_s->current_ssid->mode == WPAS_MODE_IBSS) {
		ibss_rsn_rx_eapol(wpa_s->ibss_rsn, src_addr, buf, len);
		return;
	}
#endif /* CONFIG_IBSS_RSN */

	/* Source address of the incoming EAPOL frame could be compared to the
	 * current BSSID. However, it is possible that a centralized
	 * Authenticator could be using another MAC address than the BSSID of
	 * an AP, so just allow any address to be used for now. The replies are
	 * still sent to the current BSSID (if available), though. */

	os_memcpy(wpa_s->last_eapol_src, src_addr, ETH_ALEN);
	if (!wpa_key_mgmt_wpa_psk(wpa_s->key_mgmt) &&
	    wpa_s->key_mgmt != WPA_KEY_MGMT_OWE &&
	    wpa_s->key_mgmt != WPA_KEY_MGMT_DPP &&
	    eapol_sm_rx_eapol(wpa_s->eapol, src_addr, buf, len) > 0)
		return;
	wpa_drv_poll(wpa_s);
	if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK))
		wpa_sm_rx_eapol(wpa_s->wpa, src_addr, buf, len);
	else if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt)) {
		/*
		 * Set portValid = TRUE here since we are going to skip 4-way
		 * handshake processing which would normally set portValid. We
		 * need this to allow the EAPOL state machines to be completed
		 * without going through EAPOL-Key handshake.
		 */
		eapol_sm_notify_portValid(wpa_s->eapol, TRUE);
	}
}


int wpa_supplicant_update_mac_addr(struct wpa_supplicant *wpa_s)
{
#if UNUSED_FEAT_IN_SUPP_29
	if ((!wpa_s->p2p_mgmt ||
	     !(wpa_s->drv_flags & WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE)) &&
	    !(wpa_s->drv_flags & WPA_DRIVER_FLAGS_P2P_DEDICATED_INTERFACE)) {
		l2_packet_deinit(wpa_s->l2);
		wpa_s->l2 = l2_packet_init(wpa_s->ifname,
					   wpa_drv_get_mac_addr(wpa_s),
					   ETH_P_EAPOL,
					   wpa_supplicant_rx_eapol, wpa_s, 0);
		if (wpa_s->l2 == NULL)
			return -1;

		if (l2_packet_set_packet_filter(wpa_s->l2,
						L2_PACKET_FILTER_PKTTYPE))
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG,
				"Failed to attach pkt_type filter");
#endif
			SL_PRINTF(WLAN_SUPP_FAILED_TO_ATTACH_PKT_TYPE_FILTER, WLAN_UMAC, LOG_INFO);
	} else {
		const u8 *addr = wpa_drv_get_mac_addr(wpa_s);
		if (addr)
			os_memcpy(wpa_s->own_addr, addr, ETH_ALEN);
	}

	if (wpa_s->l2 && l2_packet_get_own_addr(wpa_s->l2, wpa_s->own_addr)) {
	#if UNUSED_FEAT_IN_SUPP_29
	wpa_msg(wpa_s, MSG_ERROR, "Failed to get own L2 address");
#endif
		SL_PRINTF(WLAN_SUPP_FAILED_TO_GET_OWN_L2_ADDRESS_2, WLAN_UMAC, LOG_ERROR);
		return -1;
	}

	wpa_sm_set_own_addr(wpa_s->wpa, wpa_s->own_addr);

	return 0;
#endif


if (wpa_s->driver->send_eapol) {
	const u8 *addr = wpa_drv_get_mac_addr(wpa_s);
	if (addr)
		os_memcpy(wpa_s->own_addr, addr, ETH_ALEN);
} else if (!(wpa_s->drv_flags &
		 WPA_DRIVER_FLAGS_P2P_DEDICATED_INTERFACE)) {
	l2_packet_deinit(wpa_s->l2);
	wpa_s->l2 = l2_packet_init(wpa_s->ifname,
				   wpa_drv_get_mac_addr(wpa_s),
				   ETH_P_EAPOL,
				   wpa_supplicant_rx_eapol, wpa_s, 0);
	if (wpa_s->l2 == NULL)
		return -1;
} else {
	const u8 *addr = wpa_drv_get_mac_addr(wpa_s);
	if (addr)
		os_memcpy(wpa_s->own_addr, addr, ETH_ALEN);
}

if (wpa_s->l2 && l2_packet_get_own_addr(wpa_s->l2, wpa_s->own_addr)) {
#if UNUSED_FEAT_IN_SUPP_29
	wpa_msg(wpa_s, MSG_ERROR, "Failed to get own L2 address");
#endif
	SL_PRINTF(WLAN_SUPP_FAILED_TO_GET_OWN_L2_ADDRESS, WLAN_UMAC, LOG_ERROR);
	return -1;
}

wpa_dbg(wpa_s, MSG_DEBUG, "Own MAC address: " MACSTR,
	MAC2STR(wpa_s->own_addr));
wpa_sm_set_own_addr(wpa_s->wpa, wpa_s->own_addr);

return 0;


}


static void wpa_supplicant_rx_eapol_bridge(void *ctx, const u8 *src_addr,
					   const u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;
	const struct l2_ethhdr *eth;

	if (len < sizeof(*eth))
		return;
	eth = (const struct l2_ethhdr *) buf;

	if (os_memcmp(eth->h_dest, wpa_s->own_addr, ETH_ALEN) != 0 &&
	    !(eth->h_dest[0] & 0x01)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "RX EAPOL from " MACSTR " to " MACSTR
			" (bridge - not for this interface - ignore)",
			MAC2STR(src_addr), MAC2STR(eth->h_dest));
#endif
		SL_PRINTF(WLAN_SUPP_RX_EAPOL_FROM_SRC_TO_DEST_BRIDGE_NOT_FOR_THIS_INTERFACE_IGNORE, WLAN_UMAC, LOG_INFO);
		return;
	}

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "RX EAPOL from " MACSTR " to " MACSTR
		" (bridge)", MAC2STR(src_addr), MAC2STR(eth->h_dest));
#endif
	SL_PRINTF(WLAN_SUPP_RX_EAPOL_FROM_SRC_TO_DEST_BRIDGE, WLAN_UMAC, LOG_INFO);
	wpa_supplicant_rx_eapol(wpa_s, src_addr, buf + sizeof(*eth),
				len - sizeof(*eth));
}


/**
 * wpa_supplicant_driver_init - Initialize driver interface parameters
 * @wpa_s: Pointer to wpa_supplicant data
 * Returns: 0 on success, -1 on failure
 *
 * This function is called to initialize driver interface parameters.
 * wpa_drv_init() must have been called before this function to initialize the
 * driver interface.
 */
int wpa_supplicant_driver_init(struct wpa_supplicant *wpa_s)
{
	static int interface_count = 0;

	if (wpa_supplicant_update_mac_addr(wpa_s) < 0)
		return -1;

	wpa_dbg(wpa_s, MSG_DEBUG, "Own MAC address: " MACSTR,
		MAC2STR(wpa_s->own_addr));
	os_memcpy(wpa_s->perm_addr, wpa_s->own_addr, ETH_ALEN);
	wpa_sm_set_own_addr(wpa_s->wpa, wpa_s->own_addr);

	if (wpa_s->bridge_ifname[0]) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Receiving packets from bridge "
			"interface '%s'", wpa_s->bridge_ifname);
#endif
		SL_PRINTF(WLAN_SUPP_RECEIVING_PACKETS_FROM_BRIDGE_INTERFACE, WLAN_UMAC, LOG_INFO, "interface %s", wpa_s->bridge_ifname);
		wpa_s->l2_br = l2_packet_init_bridge(
			wpa_s->bridge_ifname, wpa_s->ifname, wpa_s->own_addr,
			ETH_P_EAPOL, wpa_supplicant_rx_eapol_bridge, wpa_s, 1);
		if (wpa_s->l2_br == NULL) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_msg(wpa_s, MSG_ERROR, "Failed to open l2_packet "
				"connection for the bridge interface '%s'",
				wpa_s->bridge_ifname);
#endif
			SL_PRINTF(WLAN_SUPP_FAILED_TO_OPEN_L2_PACKET_CONNECTION_FOR_THE_BRIDGE_INTERFACE, WLAN_UMAC, LOG_ERROR, "interface %s", (uint32_t)wpa_s->bridge_ifname);
			return -1;
		}
	}

	if (wpa_s->conf->ap_scan == 2 &&
	    os_strcmp(wpa_s->driver->name, "nl80211") == 0) {
		wpa_printf(MSG_INFO,
			   "Note: nl80211 driver interface is not designed to be used with ap_scan=2; this can result in connection failures");
	}

	wpa_clear_keys(wpa_s, NULL);

	/* Make sure that TKIP countermeasures are not left enabled (could
	 * happen if wpa_supplicant is killed during countermeasures. */
	wpa_drv_set_countermeasures(wpa_s, 0);

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "RSN: flushing PMKID list in the driver");
#endif
	SL_PRINTF(WLAN_SUPP_RSN_FLUSHING_PMKID_LIST_IN_THE_DRIVER, WLAN_UMAC, LOG_INFO);
	wpa_drv_flush_pmkid(wpa_s);

	wpa_s->prev_scan_ssid = WILDCARD_SSID_SCAN;
	wpa_s->prev_scan_wildcard = 0;

	if (wpa_supplicant_enabled_networks(wpa_s)) {
		if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED) {
			wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
			interface_count = 0;
		}
#ifndef ANDROID
		if (!wpa_s->p2p_mgmt &&
		    wpa_supplicant_delayed_sched_scan(wpa_s,
						      interface_count % 3,
						      100000))
			wpa_supplicant_req_scan(wpa_s, interface_count % 3,
						100000);
#endif /* ANDROID */
		interface_count++;
	} else
		wpa_supplicant_set_state(wpa_s, WPA_INACTIVE);

	return 0;
}


#if UNUSED_FEAT_IN_SUPP_29 
static int wpa_supplicant_daemon(const char *pid_file)
{
	wpa_printf(MSG_DEBUG, "Daemonize..");
	return os_daemonize(pid_file);
}
#endif


static struct wpa_supplicant *
wpa_supplicant_alloc(struct wpa_supplicant *parent)
{
	struct wpa_supplicant *wpa_s;

	wpa_s = os_zalloc(sizeof(*wpa_s));
	if (wpa_s == NULL)
		return NULL;
	wpa_s->scan_req = INITIAL_SCAN_REQ;
	wpa_s->scan_interval = 5;
	wpa_s->new_connection = 1;
	wpa_s->parent = parent ? parent : wpa_s;
	wpa_s->p2pdev = wpa_s->parent;
	wpa_s->sched_scanning = 0;

	dl_list_init(&wpa_s->bss_tmp_disallowed);
#ifdef CONFIG_FILS
	dl_list_init(&wpa_s->fils_hlp_req);
#endif

	return wpa_s;
}


#ifdef CONFIG_HT_OVERRIDES

static int wpa_set_htcap_mcs(struct wpa_supplicant *wpa_s,
			     struct ieee80211_ht_capabilities *htcaps,
			     struct ieee80211_ht_capabilities *htcaps_mask,
			     const char *ht_mcs)
{
	/* parse ht_mcs into hex array */
	int i;
	const char *tmp = ht_mcs;
	char *end = NULL;

	/* If ht_mcs is null, do not set anything */
	if (!ht_mcs)
		return 0;

	/* This is what we are setting in the kernel */
	os_memset(&htcaps->supported_mcs_set, 0, IEEE80211_HT_MCS_MASK_LEN);

	wpa_msg(wpa_s, MSG_DEBUG, "set_htcap, ht_mcs -:%s:-", ht_mcs);

	for (i = 0; i < IEEE80211_HT_MCS_MASK_LEN; i++) {
		long v;

		errno = 0;
		v = strtol(tmp, &end, 16);

		if (errno == 0) {
			wpa_msg(wpa_s, MSG_DEBUG,
				"htcap value[%i]: %ld end: %p  tmp: %p",
				i, v, end, tmp);
			if (end == tmp)
				break;

			htcaps->supported_mcs_set[i] = v;
			tmp = end;
		} else {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_msg(wpa_s, MSG_ERROR,
				"Failed to parse ht-mcs: %s, error: %s\n",
				ht_mcs, strerror(errno));
#endif
			SL_PRINTF(WLAN_SUPP_FAILED_TO_PARSE_HT_MCS, WLAN_UMAC, LOG_ERROR, "ht-mcs: %s, error: %s", ht_mcs, strerror(errno));
			return -1;
		}
	}

	/*
	 * If we were able to parse any values, then set mask for the MCS set.
	 */
	if (i) {
		os_memset(&htcaps_mask->supported_mcs_set, 0xff,
			  IEEE80211_HT_MCS_MASK_LEN - 1);
		/* skip the 3 reserved bits */
		htcaps_mask->supported_mcs_set[IEEE80211_HT_MCS_MASK_LEN - 1] =
			0x1f;
	}

	return 0;
}


static int wpa_disable_max_amsdu(struct wpa_supplicant *wpa_s,
				 struct ieee80211_ht_capabilities *htcaps,
				 struct ieee80211_ht_capabilities *htcaps_mask,
				 int disabled)
{
	le16 msk;

	if (disabled == -1)
		return 0;

	wpa_msg(wpa_s, MSG_DEBUG, "set_disable_max_amsdu: %d", disabled);

	msk = host_to_le16(HT_CAP_INFO_MAX_AMSDU_SIZE);
	htcaps_mask->ht_capabilities_info |= msk;
	if (disabled)
		htcaps->ht_capabilities_info &= msk;
	else
		htcaps->ht_capabilities_info |= msk;

	return 0;
}


static int wpa_set_ampdu_factor(struct wpa_supplicant *wpa_s,
				struct ieee80211_ht_capabilities *htcaps,
				struct ieee80211_ht_capabilities *htcaps_mask,
				int factor)
{
	if (factor == -1)
		return 0;

	wpa_msg(wpa_s, MSG_DEBUG, "set_ampdu_factor: %d", factor);

	if (factor < 0 || factor > 3) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "ampdu_factor: %d out of range. "
			"Must be 0-3 or -1", factor);
#endif
		SL_PRINTF(WLAN_SUPP_AMPDU_FACTOR_OUT_OF_RANGE, WLAN_UMAC, LOG_ERROR, "ampdu_factor: %d", factor);
		return -EINVAL;
	}

	htcaps_mask->a_mpdu_params |= 0x3; /* 2 bits for factor */
	htcaps->a_mpdu_params &= ~0x3;
	htcaps->a_mpdu_params |= factor & 0x3;

	return 0;
}


static int wpa_set_ampdu_density(struct wpa_supplicant *wpa_s,
				 struct ieee80211_ht_capabilities *htcaps,
				 struct ieee80211_ht_capabilities *htcaps_mask,
				 int density)
{
	if (density == -1)
		return 0;

	wpa_msg(wpa_s, MSG_DEBUG, "set_ampdu_density: %d", density);

	if (density < 0 || density > 7) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR,
			"ampdu_density: %d out of range. Must be 0-7 or -1.",
			density);
#endif
		SL_PRINTF(WLAN_SUPP_AMPDU_DENSITY_OUT_OF_RANGE, WLAN_UMAC, LOG_ERROR, "ampdu_density: %d", density);
		return -EINVAL;
	}

	htcaps_mask->a_mpdu_params |= 0x1C;
	htcaps->a_mpdu_params &= ~(0x1C);
	htcaps->a_mpdu_params |= (density << 2) & 0x1C;

	return 0;
}


static int wpa_set_disable_ht40(struct wpa_supplicant *wpa_s,
				struct ieee80211_ht_capabilities *htcaps,
				struct ieee80211_ht_capabilities *htcaps_mask,
				int disabled)
{
	if (disabled)
		wpa_msg(wpa_s, MSG_DEBUG, "set_disable_ht40: %d", disabled);

	set_disable_ht40(htcaps, disabled);
	set_disable_ht40(htcaps_mask, 0);

	return 0;
}


static int wpa_set_disable_sgi(struct wpa_supplicant *wpa_s,
			       struct ieee80211_ht_capabilities *htcaps,
			       struct ieee80211_ht_capabilities *htcaps_mask,
			       int disabled)
{
	/* Masking these out disables SGI */
	le16 msk = host_to_le16(HT_CAP_INFO_SHORT_GI20MHZ |
				HT_CAP_INFO_SHORT_GI40MHZ);

	if (disabled)
		wpa_msg(wpa_s, MSG_DEBUG, "set_disable_sgi: %d", disabled);

	if (disabled)
		htcaps->ht_capabilities_info &= ~msk;
	else
		htcaps->ht_capabilities_info |= msk;

	htcaps_mask->ht_capabilities_info |= msk;

	return 0;
}


static int wpa_set_disable_ldpc(struct wpa_supplicant *wpa_s,
			       struct ieee80211_ht_capabilities *htcaps,
			       struct ieee80211_ht_capabilities *htcaps_mask,
			       int disabled)
{
	/* Masking these out disables LDPC */
	le16 msk = host_to_le16(HT_CAP_INFO_LDPC_CODING_CAP);

	if (disabled)
		wpa_msg(wpa_s, MSG_DEBUG, "set_disable_ldpc: %d", disabled);

	if (disabled)
		htcaps->ht_capabilities_info &= ~msk;
	else
		htcaps->ht_capabilities_info |= msk;

	htcaps_mask->ht_capabilities_info |= msk;

	return 0;
}


static int wpa_set_tx_stbc(struct wpa_supplicant *wpa_s,
			   struct ieee80211_ht_capabilities *htcaps,
			   struct ieee80211_ht_capabilities *htcaps_mask,
			   int tx_stbc)
{
	le16 msk = host_to_le16(HT_CAP_INFO_TX_STBC);

	if (tx_stbc == -1)
		return 0;

	wpa_msg(wpa_s, MSG_DEBUG, "set_tx_stbc: %d", tx_stbc);

	if (tx_stbc < 0 || tx_stbc > 1) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR,
			"tx_stbc: %d out of range. Must be 0-1 or -1", tx_stbc);
#endif
		SL_PRINTF(WLAN_SUPP_TX_STBC_OUT_OF_RANGE, WLAN_UMAC, LOG_ERROR, "tx_stbc: %d", tx_stbc);
		return -EINVAL;
	}

	htcaps_mask->ht_capabilities_info |= msk;
	htcaps->ht_capabilities_info &= ~msk;
	htcaps->ht_capabilities_info |= (tx_stbc << 7) & msk;

	return 0;
}


static int wpa_set_rx_stbc(struct wpa_supplicant *wpa_s,
			   struct ieee80211_ht_capabilities *htcaps,
			   struct ieee80211_ht_capabilities *htcaps_mask,
			   int rx_stbc)
{
	le16 msk = host_to_le16(HT_CAP_INFO_RX_STBC_MASK);

	if (rx_stbc == -1)
		return 0;

	wpa_msg(wpa_s, MSG_DEBUG, "set_rx_stbc: %d", rx_stbc);

	if (rx_stbc < 0 || rx_stbc > 3) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR,
			"rx_stbc: %d out of range. Must be 0-3 or -1", rx_stbc);
#endif
		SL_PRINTF(WLAN_SUPP_RX_STBC_OUT_OF_RANGE, WLAN_UMAC, LOG_ERROR, "rx_stbc: %d", rx_stbc);
		return -EINVAL;
	}

	htcaps_mask->ht_capabilities_info |= msk;
	htcaps->ht_capabilities_info &= ~msk;
	htcaps->ht_capabilities_info |= (rx_stbc << 8) & msk;

	return 0;
}


void wpa_supplicant_apply_ht_overrides(
	struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
	struct wpa_driver_associate_params *params)
{
	struct ieee80211_ht_capabilities *htcaps;
	struct ieee80211_ht_capabilities *htcaps_mask;

	if (!ssid)
		return;

	params->disable_ht = ssid->disable_ht;
	if (!params->htcaps || !params->htcaps_mask)
		return;

	htcaps = (struct ieee80211_ht_capabilities *) params->htcaps;
	htcaps_mask = (struct ieee80211_ht_capabilities *) params->htcaps_mask;
	wpa_set_htcap_mcs(wpa_s, htcaps, htcaps_mask, ssid->ht_mcs);
	wpa_disable_max_amsdu(wpa_s, htcaps, htcaps_mask,
			      ssid->disable_max_amsdu);
	wpa_set_ampdu_factor(wpa_s, htcaps, htcaps_mask, ssid->ampdu_factor);
	wpa_set_ampdu_density(wpa_s, htcaps, htcaps_mask, ssid->ampdu_density);
	wpa_set_disable_ht40(wpa_s, htcaps, htcaps_mask, ssid->disable_ht40);
	wpa_set_disable_sgi(wpa_s, htcaps, htcaps_mask, ssid->disable_sgi);
	wpa_set_disable_ldpc(wpa_s, htcaps, htcaps_mask, ssid->disable_ldpc);
	wpa_set_rx_stbc(wpa_s, htcaps, htcaps_mask, ssid->rx_stbc);
	wpa_set_tx_stbc(wpa_s, htcaps, htcaps_mask, ssid->tx_stbc);

	if (ssid->ht40_intolerant) {
		le16 bit = host_to_le16(HT_CAP_INFO_40MHZ_INTOLERANT);
		htcaps->ht_capabilities_info |= bit;
		htcaps_mask->ht_capabilities_info |= bit;
	}
}

#endif /* CONFIG_HT_OVERRIDES */


#ifdef CONFIG_VHT_OVERRIDES
#if UNUSED_FEAT_IN_SUPP_29
void wpa_supplicant_apply_vht_overrides(
	struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
	struct wpa_driver_associate_params *params)
{
	struct ieee80211_vht_capabilities *vhtcaps;
	struct ieee80211_vht_capabilities *vhtcaps_mask;

	if (!ssid)
		return;

	params->disable_vht = ssid->disable_vht;

	vhtcaps = (void *) params->vhtcaps;
	vhtcaps_mask = (void *) params->vhtcaps_mask;

	if (!vhtcaps || !vhtcaps_mask)
		return;

	vhtcaps->vht_capabilities_info = host_to_le32(ssid->vht_capa);
	vhtcaps_mask->vht_capabilities_info = host_to_le32(ssid->vht_capa_mask);

#ifdef CONFIG_HT_OVERRIDES
	if (ssid->disable_sgi) {
		vhtcaps_mask->vht_capabilities_info |= (VHT_CAP_SHORT_GI_80 |
							VHT_CAP_SHORT_GI_160);
		vhtcaps->vht_capabilities_info &= ~(VHT_CAP_SHORT_GI_80 |
						    VHT_CAP_SHORT_GI_160);
		wpa_msg(wpa_s, MSG_DEBUG,
			"disable-sgi override specified, vht-caps: 0x%x",
			vhtcaps->vht_capabilities_info);
	}

	/* if max ampdu is <= 3, we have to make the HT cap the same */
	if (ssid->vht_capa_mask & VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MAX) {
		int max_ampdu;

		max_ampdu = (ssid->vht_capa &
			     VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MAX) >>
			VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MAX_SHIFT;

		max_ampdu = max_ampdu < 3 ? max_ampdu : 3;
		wpa_set_ampdu_factor(wpa_s,
				     (void *) params->htcaps,
				     (void *) params->htcaps_mask,
				     max_ampdu);
	}
#endif /* CONFIG_HT_OVERRIDES */

#define OVERRIDE_MCS(i)							\
	if (ssid->vht_tx_mcs_nss_ ##i >= 0) {				\
		vhtcaps_mask->vht_supported_mcs_set.tx_map |=		\
			host_to_le16(3 << 2 * (i - 1));			\
		vhtcaps->vht_supported_mcs_set.tx_map |=		\
			host_to_le16(ssid->vht_tx_mcs_nss_ ##i <<	\
				     2 * (i - 1));			\
	}								\
	if (ssid->vht_rx_mcs_nss_ ##i >= 0) {				\
		vhtcaps_mask->vht_supported_mcs_set.rx_map |=		\
			host_to_le16(3 << 2 * (i - 1));			\
		vhtcaps->vht_supported_mcs_set.rx_map |=		\
			host_to_le16(ssid->vht_rx_mcs_nss_ ##i <<	\
				     2 * (i - 1));			\
	}

	OVERRIDE_MCS(1);
	OVERRIDE_MCS(2);
	OVERRIDE_MCS(3);
	OVERRIDE_MCS(4);
	OVERRIDE_MCS(5);
	OVERRIDE_MCS(6);
	OVERRIDE_MCS(7);
	OVERRIDE_MCS(8);
}
#endif
#endif /* CONFIG_VHT_OVERRIDES */


#ifdef PCSC_FUNCS
static int pcsc_reader_init(struct wpa_supplicant *wpa_s)
{
	size_t len;

	if (!wpa_s->conf->pcsc_reader)
		return 0;

	wpa_s->scard = scard_init(wpa_s->conf->pcsc_reader);
	if (!wpa_s->scard)
		return 1;

	if (wpa_s->conf->pcsc_pin &&
	    scard_set_pin(wpa_s->scard, wpa_s->conf->pcsc_pin) < 0) {
		scard_deinit(wpa_s->scard);
		wpa_s->scard = NULL;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "PC/SC PIN validation failed");
#endif
		SL_PRINTF(WLAN_SUPP_PC_SC_PIN_VALIDATION_FAILED, WLAN_UMAC, LOG_ERROR);
		return -1;
	}

	len = sizeof(wpa_s->imsi) - 1;
	if (scard_get_imsi(wpa_s->scard, wpa_s->imsi, &len)) {
		scard_deinit(wpa_s->scard);
		wpa_s->scard = NULL;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Could not read IMSI");
#endif
		SL_PRINTF(WLAN_SUPP_COULD_NOT_READ_IMSI, WLAN_UMAC, LOG_ERROR);
		return -1;
	}
	wpa_s->imsi[len] = '\0';

	wpa_s->mnc_len = scard_get_mnc_len(wpa_s->scard);

	wpa_printf(MSG_DEBUG, "SCARD: IMSI %s (MNC length %d)",
		   wpa_s->imsi, wpa_s->mnc_len);

	wpa_sm_set_scard_ctx(wpa_s->wpa, wpa_s->scard);
	eapol_sm_register_scard_ctx(wpa_s->eapol, wpa_s->scard);

	return 0;
}
#endif /* PCSC_FUNCS */


int wpas_init_ext_pw(struct wpa_supplicant *wpa_s)
{
	char *val, *pos;

	ext_password_deinit(wpa_s->ext_pw);
	wpa_s->ext_pw = NULL;
	eapol_sm_set_ext_pw_ctx(wpa_s->eapol, NULL);

	if (!wpa_s->conf->ext_password_backend)
		return 0;

	val = os_strdup(wpa_s->conf->ext_password_backend);
	if (val == NULL)
		return -1;
	pos = os_strchr(val, ':');
	if (pos)
		*pos++ = '\0';

	wpa_printf(MSG_DEBUG, "EXT PW: Initialize backend '%s'", val);

	wpa_s->ext_pw = ext_password_init(val, pos);
	os_free(val);
	if (wpa_s->ext_pw == NULL) {
		wpa_printf(MSG_DEBUG, "EXT PW: Failed to initialize backend");
		return -1;
	}
	eapol_sm_set_ext_pw_ctx(wpa_s->eapol, wpa_s->ext_pw);

	return 0;
}


#ifdef CONFIG_FST

static const u8 * wpas_fst_get_bssid_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;

	return (is_zero_ether_addr(wpa_s->bssid) ||
		wpa_s->wpa_state != WPA_COMPLETED) ? NULL : wpa_s->bssid;
}


static void wpas_fst_get_channel_info_cb(void *ctx,
					 enum hostapd_hw_mode *hw_mode,
					 u8 *channel)
{
	struct wpa_supplicant *wpa_s = ctx;

	if (wpa_s->current_bss) {
		*hw_mode = ieee80211_freq_to_chan(wpa_s->current_bss->freq,
						  channel);
	} else if (wpa_s->hw.num_modes) {
		*hw_mode = wpa_s->hw.modes[0].mode;
	} else {
		WPA_ASSERT(0);
		*hw_mode = 0;
	}
}


static int wpas_fst_get_hw_modes(void *ctx, struct hostapd_hw_modes **modes)
{
	struct wpa_supplicant *wpa_s = ctx;

	*modes = wpa_s->hw.modes;
	return wpa_s->hw.num_modes;
}


static void wpas_fst_set_ies_cb(void *ctx, const struct wpabuf *fst_ies)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_hexdump_buf(MSG_DEBUG, "FST: Set IEs", fst_ies);
	wpa_s->fst_ies = fst_ies;
}


static int wpas_fst_send_action_cb(void *ctx, const u8 *da, struct wpabuf *data)
{
	struct wpa_supplicant *wpa_s = ctx;

	if (os_memcmp(wpa_s->bssid, da, ETH_ALEN) != 0) {
		wpa_printf(MSG_INFO, "FST:%s:bssid=" MACSTR " != da=" MACSTR,
			   __func__, MAC2STR(wpa_s->bssid), MAC2STR(da));
		return -1;
	}
	return wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				   wpa_s->own_addr, wpa_s->bssid,
				   wpabuf_head(data), wpabuf_len(data),
				   0);
}


static const struct wpabuf * wpas_fst_get_mb_ie_cb(void *ctx, const u8 *addr)
{
	struct wpa_supplicant *wpa_s = ctx;

	WPA_ASSERT(os_memcmp(wpa_s->bssid, addr, ETH_ALEN) == 0);
	return wpa_s->received_mb_ies;
}


static void wpas_fst_update_mb_ie_cb(void *ctx, const u8 *addr,
				     const u8 *buf, size_t size)
{
	struct wpa_supplicant *wpa_s = ctx;
	struct mb_ies_info info;

	WPA_ASSERT(os_memcmp(wpa_s->bssid, addr, ETH_ALEN) == 0);

	if (!mb_ies_info_by_ies(&info, buf, size)) {
		wpabuf_free(wpa_s->received_mb_ies);
		wpa_s->received_mb_ies = mb_ies_by_info(&info);
	}
}


static const u8 * wpas_fst_get_peer_first(void *ctx,
					  struct fst_get_peer_ctx **get_ctx,
					  Boolean mb_only)
{
	struct wpa_supplicant *wpa_s = ctx;

	*get_ctx = NULL;
	if (!is_zero_ether_addr(wpa_s->bssid))
		return (wpa_s->received_mb_ies || !mb_only) ?
			wpa_s->bssid : NULL;
	return NULL;
}


static const u8 * wpas_fst_get_peer_next(void *ctx,
					 struct fst_get_peer_ctx **get_ctx,
					 Boolean mb_only)
{
	return NULL;
}

void fst_wpa_supplicant_fill_iface_obj(struct wpa_supplicant *wpa_s,
				       struct fst_wpa_obj *iface_obj)
{
	iface_obj->ctx              = wpa_s;
	iface_obj->get_bssid        = wpas_fst_get_bssid_cb;
	iface_obj->get_channel_info = wpas_fst_get_channel_info_cb;
	iface_obj->get_hw_modes     = wpas_fst_get_hw_modes;
	iface_obj->set_ies          = wpas_fst_set_ies_cb;
	iface_obj->send_action      = wpas_fst_send_action_cb;
	iface_obj->get_mb_ie        = wpas_fst_get_mb_ie_cb;
	iface_obj->update_mb_ie     = wpas_fst_update_mb_ie_cb;
	iface_obj->get_peer_first   = wpas_fst_get_peer_first;
	iface_obj->get_peer_next    = wpas_fst_get_peer_next;
}
#endif /* CONFIG_FST */

#ifdef ENABLE_SUPP_WOWLAN
static int wpas_set_wowlan_triggers(struct wpa_supplicant *wpa_s,
				    const struct wpa_driver_capa *capa)
{
	struct wowlan_triggers *triggers;
	int ret = 0;

	if (!wpa_s->conf->wowlan_triggers)
		return 0;

	triggers = wpa_get_wowlan_triggers(wpa_s->conf->wowlan_triggers, capa);
	if (triggers) {
		ret = wpa_drv_wowlan(wpa_s, triggers);
		os_free(triggers);
	}
	return ret;
}
#endif


enum wpa_radio_work_band wpas_freq_to_band(int freq)
{
	if (freq < 3000)
		return BAND_2_4_GHZ;
	if (freq > 50000)
		return BAND_60_GHZ;
	return BAND_5_GHZ;
}


unsigned int wpas_get_bands(struct wpa_supplicant *wpa_s, const int *freqs)
{
	int i;
	unsigned int band = 0;

	if (freqs) {
		/* freqs are specified for the radio work */
		for (i = 0; freqs[i]; i++)
			band |= wpas_freq_to_band(freqs[i]);
	} else {
		/*
		 * freqs are not specified, implies all
		 * the supported freqs by HW
		 */
		for (i = 0; i < wpa_s->hw.num_modes; i++) {
			if (wpa_s->hw.modes[i].num_channels != 0) {
				if (wpa_s->hw.modes[i].mode ==
				    HOSTAPD_MODE_IEEE80211B ||
				    wpa_s->hw.modes[i].mode ==
				    HOSTAPD_MODE_IEEE80211G)
					band |= BAND_2_4_GHZ;
				else if (wpa_s->hw.modes[i].mode ==
					 HOSTAPD_MODE_IEEE80211A)
					band |= BAND_5_GHZ;
				else if (wpa_s->hw.modes[i].mode ==
					 HOSTAPD_MODE_IEEE80211AD)
					band |= BAND_60_GHZ;
				else if (wpa_s->hw.modes[i].mode ==
					 HOSTAPD_MODE_IEEE80211ANY)
					band = BAND_2_4_GHZ | BAND_5_GHZ |
						BAND_60_GHZ;
			}
		}
	}

	return band;
}


#if UNUSED_FEAT_IN_SUPP_29
static struct wpa_radio * radio_add_interface(struct wpa_supplicant *wpa_s,
					      const char *rn)
{
	struct wpa_supplicant *iface = wpa_s->global->ifaces;
	struct wpa_radio *radio;

	while (rn && iface) {
		radio = iface->radio;
		if (radio && os_strcmp(rn, radio->name) == 0) {
			wpa_printf(MSG_DEBUG, "Add interface %s to existing radio %s",
				   wpa_s->ifname, rn);
			dl_list_add(&radio->ifaces, &wpa_s->radio_list);
			return radio;
		}

		iface = iface->next;
	}

	wpa_printf(MSG_DEBUG, "Add interface %s to a new radio %s",
		   wpa_s->ifname, rn ? rn : "N/A");
	radio = os_zalloc(sizeof(*radio));
	if (radio == NULL)
		return NULL;

	if (rn)
		os_strlcpy(radio->name, rn, sizeof(radio->name));
	dl_list_init(&radio->ifaces);
	dl_list_init(&radio->work);
	dl_list_add(&radio->ifaces, &wpa_s->radio_list);

	return radio;
}


static void radio_work_free(struct wpa_radio_work *work)
{
	if (work->wpa_s->scan_work == work) {
		/* This should not really happen. */
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(work->wpa_s, MSG_INFO, "Freeing radio work '%s'@%p (started=%d) that is marked as scan_work",
			work->type, work, work->started);
#endif
		SL_PRINTF(WLAN_SUPP_FREEING_RADIO_WORK_2, WLAN_UMAC, LOG_INFO, "Freeing radio work '%s'@%4x (started=%d) that is marked as scan_work", work->type, work, work->started);
		work->wpa_s->scan_work = NULL;
	}

#ifdef CONFIG_P2P
	if (work->wpa_s->p2p_scan_work == work) {
		/* This should not really happen. */
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(work->wpa_s, MSG_INFO, "Freeing radio work '%s'@%p (started=%d) that is marked as p2p_scan_work",
			work->type, work, work->started);
#endif
		SL_PRINTF(WLAN_SUPP_FREEING_RADIO_WORK, WLAN_UMAC, LOG_INFO, "Freeing radio work '%s'@%4x (started=%d) that is marked as p2p_scan_work", work->type, work, work->started);
		work->wpa_s->p2p_scan_work = NULL;
	}
#endif /* CONFIG_P2P */

	if (work->started) {
		work->wpa_s->radio->num_active_works--;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(work->wpa_s, MSG_DEBUG,
			"radio_work_free('%s'@%p): num_active_works --> %u",
			work->type, work,
			work->wpa_s->radio->num_active_works);
#endif
		SL_PRINTF(WLAN_SUPP_RADIO_WORK_FREE, WLAN_UMAC, LOG_INFO, "radio_work_free('%s'@%4x): num_active_works --> %d", work->type, work, work->wpa_s->radio->num_active_works);
	}

	dl_list_del(&work->list);
	os_free(work);
}


static int radio_work_is_connect(struct wpa_radio_work *work)
{
	return os_strcmp(work->type, "sme-connect") == 0 ||
		os_strcmp(work->type, "connect") == 0;
}


static int radio_work_is_scan(struct wpa_radio_work *work)
{
	return os_strcmp(work->type, "scan") == 0 ||
		os_strcmp(work->type, "p2p-scan") == 0;
}


static struct wpa_radio_work * radio_work_get_next_work(struct wpa_radio *radio)
{
	struct wpa_radio_work *active_work = NULL;
	struct wpa_radio_work *tmp;

	/* Get the active work to know the type and band. */
	dl_list_for_each(tmp, &radio->work, struct wpa_radio_work, list) {
		if (tmp->started) {
			active_work = tmp;
			break;
		}
	}

	if (!active_work) {
		/* No active work, start one */
		radio->num_active_works = 0;
		dl_list_for_each(tmp, &radio->work, struct wpa_radio_work,
				 list) {
			if (os_strcmp(tmp->type, "scan") == 0 &&
			    radio->external_scan_running &&
			    (((struct wpa_driver_scan_params *)
			      tmp->ctx)->only_new_results ||
			     tmp->wpa_s->clear_driver_scan_cache))
				continue;
			return tmp;
		}
		return NULL;
	}

	if (radio_work_is_connect(active_work)) {
		/*
		 * If the active work is either connect or sme-connect,
		 * do not parallelize them with other radio works.
		 */
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(active_work->wpa_s, MSG_DEBUG,
			"Do not parallelize radio work with %s",
			active_work->type);
#endif
		SL_PRINTF(WLAN_SUPP_DO_NOT_PARALLELIZE_RADIO_WORK_WITH, WLAN_UMAC, LOG_INFO, "%s", active_work->type);
		return NULL;
	}

	dl_list_for_each(tmp, &radio->work, struct wpa_radio_work, list) {
		if (tmp->started)
			continue;

		/*
		 * If connect or sme-connect are enqueued, parallelize only
		 * those operations ahead of them in the queue.
		 */
		if (radio_work_is_connect(tmp))
			break;

		/* Serialize parallel scan and p2p_scan operations on the same
		 * interface since the driver_nl80211 mechanism for tracking
		 * scan cookies does not yet have support for this. */
		if (active_work->wpa_s == tmp->wpa_s &&
		    radio_work_is_scan(active_work) &&
		    radio_work_is_scan(tmp)) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(active_work->wpa_s, MSG_DEBUG,
				"Do not start work '%s' when another work '%s' is already scheduled",
				tmp->type, active_work->type);
#endif
			SL_PRINTF(WLAN_SUPP_DO_NOT_START_WORK, WLAN_UMAC, LOG_INFO, "Do not start work '%s' when another work '%s' is already scheduled", tmp->type, active_work->type);
			continue;
		}
		/*
		 * Check that the radio works are distinct and
		 * on different bands.
		 */
		if (os_strcmp(active_work->type, tmp->type) != 0 &&
		    (active_work->bands != tmp->bands)) {
			/*
			 * If a scan has to be scheduled through nl80211 scan
			 * interface and if an external scan is already running,
			 * do not schedule the scan since it is likely to get
			 * rejected by kernel.
			 */
			if (os_strcmp(tmp->type, "scan") == 0 &&
			    radio->external_scan_running &&
			    (((struct wpa_driver_scan_params *)
			      tmp->ctx)->only_new_results ||
			     tmp->wpa_s->clear_driver_scan_cache))
				continue;

#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(active_work->wpa_s, MSG_DEBUG,
				"active_work:%s new_work:%s",
				active_work->type, tmp->type);
#endif
			SL_PRINTF(WLAN_SUPP_ACTIVE_WORK, WLAN_UMAC, LOG_INFO, "active_work: %s new_work: %s", active_work->type, tmp->type);
			return tmp;
		}
	}

	/* Did not find a radio work to schedule in parallel. */
	return NULL;
}


static void radio_start_next_work(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_radio *radio = eloop_ctx;
	struct wpa_radio_work *work;
	struct os_reltime now, diff;
	struct wpa_supplicant *wpa_s;

	work = dl_list_first(&radio->work, struct wpa_radio_work, list);
	if (work == NULL) {
		radio->num_active_works = 0;
		return;
	}

	wpa_s = dl_list_first(&radio->ifaces, struct wpa_supplicant,
			      radio_list);

	if (!(wpa_s &&
	      wpa_s->drv_flags & WPA_DRIVER_FLAGS_OFFCHANNEL_SIMULTANEOUS)) {
		if (work->started)
			return; /* already started and still in progress */

		if (wpa_s && wpa_s->radio->external_scan_running) {
			wpa_printf(MSG_DEBUG, "Delay radio work start until externally triggered scan completes");
			return;
		}
	} else {
		work = NULL;
		if (radio->num_active_works < MAX_ACTIVE_WORKS) {
			/* get the work to schedule next */
			work = radio_work_get_next_work(radio);
		}
		if (!work)
			return;
	}

	wpa_s = work->wpa_s;
	os_get_reltime(&now);
	os_reltime_sub(&now, &work->time, &diff);
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG,
		"Starting radio work '%s'@%p after %ld.%06ld second wait",
		work->type, work, diff.sec, diff.usec);
#endif
	SL_PRINTF(WLAN_SUPP_STARTING_RADIO_WORK, WLAN_UMAC, LOG_INFO, "Starting radio work '%s'@%4x after %d second wait", work->type, work, diff.sec);
	work->started = 1;
	work->time = now;
	radio->num_active_works++;

	work->cb(work, 0);

	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_OFFCHANNEL_SIMULTANEOUS) &&
	    radio->num_active_works < MAX_ACTIVE_WORKS)
		radio_work_check_next(wpa_s);
}


/*
 * This function removes both started and pending radio works running on
 * the provided interface's radio.
 * Prior to the removal of the radio work, its callback (cb) is called with
 * deinit set to be 1. Each work's callback is responsible for clearing its
 * internal data and restoring to a correct state.
 * @wpa_s: wpa_supplicant data
 * @type: type of works to be removed
 * @remove_all: 1 to remove all the works on this radio, 0 to remove only
 * this interface's works.
 */
#ifdef ENABLE_RRM 
void radio_remove_works(struct wpa_supplicant *wpa_s,
			const char *type, int remove_all)
{
	struct wpa_radio_work *work, *tmp;
	struct wpa_radio *radio = wpa_s->radio;

	dl_list_for_each_safe(work, tmp, &radio->work, struct wpa_radio_work,
			      list) {
		if (type && os_strcmp(type, work->type) != 0)
			continue;

		/* skip other ifaces' works */
		if (!remove_all && work->wpa_s != wpa_s)
			continue;

#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Remove radio work '%s'@%p%s",
			work->type, work, work->started ? " (started)" : "");
#endif
		SL_PRINTF(WLAN_SUPP_REMOVE_RADIO_WORK, WLAN_UMAC, LOG_INFO, "Remove radio work '%s'@%4x", work->type, work);
		work->cb(work, 1);
		radio_work_free(work);
	}

	/* in case we removed the started work */
	radio_work_check_next(wpa_s);
}


void radio_remove_pending_work(struct wpa_supplicant *wpa_s, void *ctx)
{
	struct wpa_radio_work *work;
	struct wpa_radio *radio = wpa_s->radio;

	dl_list_for_each(work, &radio->work, struct wpa_radio_work, list) {
		if (work->ctx != ctx)
			continue;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Free pending radio work '%s'@%p%s",
			work->type, work, work->started ? " (started)" : "");
#endif
		SL_PRINTF(WLAN_SUPP_FREE_PENDING_RADIO_WORK, WLAN_UMAC, LOG_INFO, "Free pending radio work '%s'@%4x", work->type, work);
		radio_work_free(work);
		break;
	}
}

static void radio_remove_interface(struct wpa_supplicant *wpa_s)
{
	struct wpa_radio *radio = wpa_s->radio;

	if (!radio)
		return;

	wpa_printf(MSG_DEBUG, "Remove interface %s from radio %s",
		   wpa_s->ifname, radio->name);
	dl_list_del(&wpa_s->radio_list);
	radio_remove_works(wpa_s, NULL, 0);
	wpa_s->radio = NULL;
	if (!dl_list_empty(&radio->ifaces))
		return; /* Interfaces remain for this radio */

	wpa_printf(MSG_DEBUG, "Remove radio %s", radio->name);
	eloop_cancel_timeout(radio_start_next_work, radio, NULL);
	os_free(radio);
}
#endif
#endif


#if UNUSED_FEAT_IN_SUPP_29
void radio_work_check_next(struct wpa_supplicant *wpa_s)
{
	struct wpa_radio *radio = wpa_s->radio;

	if (dl_list_empty(&radio->work))
		return;
	if (wpa_s->ext_work_in_progress) {
		wpa_printf(MSG_DEBUG,
			   "External radio work in progress - delay start of pending item");
		return;
	}
	eloop_cancel_timeout(radio_start_next_work, radio, NULL);
	eloop_register_timeout(0, 0, radio_start_next_work, radio, NULL);
}


/**
 * radio_add_work - Add a radio work item
 * @wpa_s: Pointer to wpa_supplicant data
 * @freq: Frequency of the offchannel operation in MHz or 0
 * @type: Unique identifier for each type of work
 * @next: Force as the next work to be executed
 * @cb: Callback function for indicating when radio is available
 * @ctx: Context pointer for the work (work->ctx in cb())
 * Returns: 0 on success, -1 on failure
 *
 * This function is used to request time for an operation that requires
 * exclusive radio control. Once the radio is available, the registered callback
 * function will be called. radio_work_done() must be called once the exclusive
 * radio operation has been completed, so that the radio is freed for other
 * operations. The special case of deinit=1 is used to free the context data
 * during interface removal. That does not allow the callback function to start
 * the radio operation, i.e., it must free any resources allocated for the radio
 * work and return.
 *
 * The @freq parameter can be used to indicate a single channel on which the
 * offchannel operation will occur. This may allow multiple radio work
 * operations to be performed in parallel if they apply for the same channel.
 * Setting this to 0 indicates that the work item may use multiple channels or
 * requires exclusive control of the radio.
 */
int radio_add_work(struct wpa_supplicant *wpa_s, unsigned int freq,
		   const char *type, int next,
		   void (*cb)(struct wpa_radio_work *work, int deinit),
		   void *ctx)
{
	struct wpa_radio *radio = wpa_s->radio;
	struct wpa_radio_work *work;
	int was_empty;

	work = os_zalloc(sizeof(*work));
	if (work == NULL)
		return -1;
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Add radio work '%s'@%p", type, work);
#endif
	SL_PRINTF(WLAN_SUPP_ADD_RADIO_WORK, WLAN_UMAC, LOG_INFO, "Add radio work '%s'@%4x", type, work);
	os_get_reltime(&work->time);
	work->freq = freq;
	work->type = type;
	work->wpa_s = wpa_s;
	work->cb = cb;
	work->ctx = ctx;

	if (freq)
		work->bands = wpas_freq_to_band(freq);
	else if (os_strcmp(type, "scan") == 0 ||
		 os_strcmp(type, "p2p-scan") == 0)
		work->bands = wpas_get_bands(wpa_s,
					     ((struct wpa_driver_scan_params *)
					      ctx)->freqs);
	else
		work->bands = wpas_get_bands(wpa_s, NULL);

	was_empty = dl_list_empty(&wpa_s->radio->work);
	if (next)
		dl_list_add(&wpa_s->radio->work, &work->list);
	else
		dl_list_add_tail(&wpa_s->radio->work, &work->list);
	if (was_empty) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "First radio work item in the queue - schedule start immediately");
#endif
		SL_PRINTF(WLAN_SUPP_FIRST_RADIO_WORK_ITEM_IN_THE_QUEUE_SCHEDULE_START_IMMEDIATELY, WLAN_UMAC, LOG_INFO);
		radio_work_check_next(wpa_s);
	} else if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_OFFCHANNEL_SIMULTANEOUS)
		   && radio->num_active_works < MAX_ACTIVE_WORKS) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"Try to schedule a radio work (num_active_works=%u)",
			radio->num_active_works);
#endif
		SL_PRINTF(WLAN_SUPP_TRY_TO_SCHEDULE_A_RADIO_WORK, WLAN_UMAC, LOG_INFO, "num_active_works=%d", radio->num_active_works);
		radio_work_check_next(wpa_s);
	}

	return 0;
}


/**
 * radio_work_done - Indicate that a radio work item has been completed
 * @work: Completed work
 *
 * This function is called once the callback function registered with
 * radio_add_work() has completed its work.
 */
void radio_work_done(struct wpa_radio_work *work)
{
	struct wpa_supplicant *wpa_s = work->wpa_s;
	struct os_reltime now, diff;
	unsigned int started = work->started;

	os_get_reltime(&now);
	os_reltime_sub(&now, &work->time, &diff);
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Radio work '%s'@%p %s in %ld.%06ld seconds",
		work->type, work, started ? "done" : "canceled",
		diff.sec, diff.usec);
#endif
		char* tmpstr = (started ? "done" : "cancelled");
	SL_PRINTF(WLAN_SUPP_RADIO_WORK, WLAN_UMAC, LOG_INFO, "Radio work '%s'@%4x %s", work->type, work, tmpstr);
	radio_work_free(work);
	if (started)
		radio_work_check_next(wpa_s);
}


struct wpa_radio_work *
radio_work_pending(struct wpa_supplicant *wpa_s, const char *type)
{
	struct wpa_radio_work *work;
	struct wpa_radio *radio = wpa_s->radio;

	dl_list_for_each(work, &radio->work, struct wpa_radio_work, list) {
		if (work->wpa_s == wpa_s && os_strcmp(work->type, type) == 0)
			return work;
	}

	return NULL;
}
#endif


static int wpas_init_driver(struct wpa_supplicant *wpa_s,
			    const struct wpa_interface *iface)
{
	const char *ifname, *driver;

	driver = iface->driver;
next_driver:
	if (wpa_supplicant_set_driver(wpa_s, driver) < 0)
		return -1;

	wpa_s->drv_priv = wpa_drv_init(wpa_s, wpa_s->ifname);
	if (wpa_s->drv_priv == NULL) {
		const char *pos;
		pos = driver ? os_strchr(driver, ',') : NULL;
		if (pos) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "Failed to initialize "
				"driver interface - try next driver wrapper");
#endif
			SL_PRINTF(WLAN_SUPP_FAILED_TO_INITIALIZE_DRIVER_INTERFACE_TRY_NEXT_DRIVER_WRAPPER, WLAN_UMAC, LOG_INFO);
			driver = pos + 1;
			goto next_driver;
		}
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Failed to initialize driver "
			"interface");
#endif
		SL_PRINTF(WLAN_SUPP_FAILED_TO_INITIALIZE_DRIVER_INTERFACE, WLAN_UMAC, LOG_ERROR);
		return -1;
	}
	if (wpa_drv_set_param(wpa_s, wpa_s->conf->driver_param) < 0) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Driver interface rejected "
			"driver_param '%s'", wpa_s->conf->driver_param);
#endif
		SL_PRINTF(WLAN_SUPP_DRIVER_INTERFACE_REJECTED_DRIVER_PARAM, WLAN_UMAC, LOG_ERROR, "driver_param %s", (uint32_t)wpa_s->conf->driver_param);
		return -1;
	}

	ifname = wpa_drv_get_ifname(wpa_s);
	if (ifname && os_strcmp(ifname, wpa_s->ifname) != 0) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Driver interface replaced "
			"interface name with '%s'", ifname);
#endif
		SL_PRINTF(WLAN_SUPP_DRIVER_INTERFACE_REPLACED_INTERFACE_NAME, WLAN_UMAC, LOG_INFO, "replaced with %s", ifname);
		os_strlcpy(wpa_s->ifname, ifname, sizeof(wpa_s->ifname));
	}
#if UNUSED_FEAT_IN_SUPP_29
    const char *rn;
	rn = wpa_driver_get_radio_name(wpa_s);
	if (rn && rn[0] == '\0')
		rn = NULL;

	wpa_s->radio = radio_add_interface(wpa_s, rn);
	if (wpa_s->radio == NULL)
		return -1;
#endif
	return 0;
}


#ifdef CONFIG_GAS_SERVER

static void wpas_gas_server_tx_status(struct wpa_supplicant *wpa_s,
				      unsigned int freq, const u8 *dst,
				      const u8 *src, const u8 *bssid,
				      const u8 *data, size_t data_len,
				      enum offchannel_send_action_result result)
{
	wpa_printf(MSG_DEBUG, "GAS: TX status: freq=%u dst=" MACSTR
		   " result=%s",
		   freq, MAC2STR(dst),
		   result == OFFCHANNEL_SEND_ACTION_SUCCESS ? "SUCCESS" :
		   (result == OFFCHANNEL_SEND_ACTION_NO_ACK ? "no-ACK" :
		    "FAILED"));
	gas_server_tx_status(wpa_s->gas_server, dst, data, data_len,
			     result == OFFCHANNEL_SEND_ACTION_SUCCESS);
}


static void wpas_gas_server_tx(void *ctx, int freq, const u8 *da,
			       struct wpabuf *buf, unsigned int wait_time)
{
	struct wpa_supplicant *wpa_s = ctx;
	const u8 broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (wait_time > wpa_s->max_remain_on_chan)
		wait_time = wpa_s->max_remain_on_chan;

	offchannel_send_action(wpa_s, freq, da, wpa_s->own_addr, broadcast,
			       wpabuf_head(buf), wpabuf_len(buf),
			       wait_time, wpas_gas_server_tx_status, 0);
}

#endif /* CONFIG_GAS_SERVER */

static int wpa_supplicant_init_iface(struct wpa_supplicant *wpa_s,
				     const struct wpa_interface *iface)
{
	struct wpa_driver_capa capa;
	int capa_res;
	u8 dfs_domain;

	wpa_printf(MSG_DEBUG, "Initializing interface '%s' conf '%s' driver "
		   "'%s' ctrl_interface '%s' bridge '%s'", iface->ifname,
		   iface->confname ? iface->confname : "N/A",
		   iface->driver ? iface->driver : "default",
		   iface->ctrl_interface ? iface->ctrl_interface : "N/A",
		   iface->bridge_ifname ? iface->bridge_ifname : "N/A");

	if (iface->confname) {
#ifdef CONFIG_BACKEND_FILE
		wpa_s->confname = os_rel2abs_path(iface->confname);
		if (wpa_s->confname == NULL) {
			wpa_printf(MSG_ERROR, "Failed to get absolute path "
				   "for configuration file '%s'.",
				   iface->confname);
			return -1;
		}
		wpa_printf(MSG_DEBUG, "Configuration file '%s' -> '%s'",
			   iface->confname, wpa_s->confname);
#else /* CONFIG_BACKEND_FILE */
		wpa_s->confname = os_strdup(iface->confname);
#endif /* CONFIG_BACKEND_FILE */
		wpa_s->conf = wpa_config_read(wpa_s->confname, NULL);
		if (wpa_s->conf == NULL) {
			wpa_printf(MSG_ERROR, "Failed to read or parse "
				   "configuration '%s'.", wpa_s->confname);
			return -1;
		}
		wpa_s->confanother = os_rel2abs_path(iface->confanother);
		if (wpa_s->confanother &&
		    !wpa_config_read(wpa_s->confanother, wpa_s->conf)) {
			wpa_printf(MSG_ERROR,
				   "Failed to read or parse configuration '%s'.",
				   wpa_s->confanother);
			return -1;
		}

		/*
		 * Override ctrl_interface and driver_param if set on command
		 * line.
		 */
		if (iface->ctrl_interface) {
			os_free(wpa_s->conf->ctrl_interface);
			wpa_s->conf->ctrl_interface =
				os_strdup(iface->ctrl_interface);
		}

		if (iface->driver_param) {
			os_free(wpa_s->conf->driver_param);
			wpa_s->conf->driver_param =
				os_strdup(iface->driver_param);
		}

		if (iface->p2p_mgmt && !iface->ctrl_interface) {
			os_free(wpa_s->conf->ctrl_interface);
			wpa_s->conf->ctrl_interface = NULL;
		}
	} else
		wpa_s->conf = wpa_config_alloc_empty(iface->ctrl_interface,
						     iface->driver_param);

	if (wpa_s->conf == NULL) {
		wpa_printf(MSG_ERROR, "\nNo configuration found.");
		return -1;
	}

	if (iface->ifname == NULL) {
		wpa_printf(MSG_ERROR, "\nInterface name is required.");
		return -1;
	}
	if (os_strlen(iface->ifname) >= sizeof(wpa_s->ifname)) {
		wpa_printf(MSG_ERROR, "\nToo long interface name '%s'.",
			   iface->ifname);
		return -1;
	}
	os_strlcpy(wpa_s->ifname, iface->ifname, sizeof(wpa_s->ifname));

	if (iface->bridge_ifname) {
		if (os_strlen(iface->bridge_ifname) >=
		    sizeof(wpa_s->bridge_ifname)) {
			wpa_printf(MSG_ERROR, "\nToo long bridge interface "
				   "name '%s'.", iface->bridge_ifname);
			return -1;
		}
		os_strlcpy(wpa_s->bridge_ifname, iface->bridge_ifname,
			   sizeof(wpa_s->bridge_ifname));
	}

	/* RSNA Supplicant Key Management - INITIALIZE */
	eapol_sm_notify_portEnabled(wpa_s->eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);

	/* Initialize driver interface and register driver event handler before
	 * L2 receive handler so that association events are processed before
	 * EAPOL-Key packets if both become available for the same select()
	 * call. */
	if (wpas_init_driver(wpa_s, iface) < 0)
		return -1;

	if (wpa_supplicant_init_wpa(wpa_s) < 0)
		return -1;

	wpa_sm_set_ifname(wpa_s->wpa, wpa_s->ifname,
			  wpa_s->bridge_ifname[0] ? wpa_s->bridge_ifname :
			  NULL);
	wpa_sm_set_fast_reauth(wpa_s->wpa, wpa_s->conf->fast_reauth);

	if (wpa_s->conf->dot11RSNAConfigPMKLifetime &&
	    wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_LIFETIME,
			     wpa_s->conf->dot11RSNAConfigPMKLifetime)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Invalid WPA parameter value for "
			"dot11RSNAConfigPMKLifetime");
#endif
		SL_PRINTF(WLAN_SUPP_INVALID_WPA_PARAMETER_VALUE_FOR_DOT11RSNACONFIGPMKLIFETIME, WLAN_UMAC, LOG_ERROR);
		return -1;
	}

	if (wpa_s->conf->dot11RSNAConfigPMKReauthThreshold &&
	    wpa_sm_set_param(wpa_s->wpa, RSNA_PMK_REAUTH_THRESHOLD,
			     wpa_s->conf->dot11RSNAConfigPMKReauthThreshold)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Invalid WPA parameter value for "
			"dot11RSNAConfigPMKReauthThreshold");
#endif
		SL_PRINTF(WLAN_SUPP_INVALID_WPA_PARAMETER_VALUE_FOR_DOT11RSNACONFIGPMKREAUTHTHRESHOLD, WLAN_UMAC, LOG_ERROR);
		return -1;
	}

	if (wpa_s->conf->dot11RSNAConfigSATimeout &&
	    wpa_sm_set_param(wpa_s->wpa, RSNA_SA_TIMEOUT,
			     wpa_s->conf->dot11RSNAConfigSATimeout)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Invalid WPA parameter value for "
			"dot11RSNAConfigSATimeout");
#endif
		SL_PRINTF(WLAN_SUPP_INVALID_WPA_PARAMETER_VALUE_FOR_DOT11RSNACONFIGSATIMEOUT, WLAN_UMAC, LOG_ERROR);
		return -1;
	}

	wpa_s->hw.modes = wpa_drv_get_hw_feature_data(wpa_s,
						      &wpa_s->hw.num_modes,
						      &wpa_s->hw.flags,
						      &dfs_domain);
	if (wpa_s->hw.modes) {
		u16 i;

		for (i = 0; i < wpa_s->hw.num_modes; i++) {
			if (wpa_s->hw.modes[i].vht_capab) {
				wpa_s->hw_capab = CAPAB_VHT;
				break;
			}

			if (wpa_s->hw.modes[i].ht_capab &
			    HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET)
				wpa_s->hw_capab = CAPAB_HT40;
			else if (wpa_s->hw.modes[i].ht_capab &&
				 wpa_s->hw_capab == CAPAB_NO_HT_VHT)
				wpa_s->hw_capab = CAPAB_HT;
		}
	}

	capa_res = wpa_drv_get_capa(wpa_s, &capa);
	if (capa_res == 0) {
		wpa_s->drv_capa_known = 1;
		wpa_s->drv_flags = capa.flags;
		wpa_s->drv_enc = capa.enc;
		wpa_s->drv_smps_modes = capa.smps_modes;
		wpa_s->drv_rrm_flags = capa.rrm_flags;
		wpa_s->probe_resp_offloads = capa.probe_resp_offloads;
		wpa_s->max_scan_ssids = capa.max_scan_ssids;
		wpa_s->max_sched_scan_ssids = capa.max_sched_scan_ssids;
		wpa_s->max_sched_scan_plans = capa.max_sched_scan_plans;
		wpa_s->max_sched_scan_plan_interval =
			capa.max_sched_scan_plan_interval;
		wpa_s->max_sched_scan_plan_iterations =
			capa.max_sched_scan_plan_iterations;
		wpa_s->sched_scan_supported = capa.sched_scan_supported;
		wpa_s->max_match_sets = capa.max_match_sets;
		wpa_s->max_remain_on_chan = capa.max_remain_on_chan;
		wpa_s->max_stations = capa.max_stations;
		wpa_s->extended_capa = capa.extended_capa;
		wpa_s->extended_capa_mask = capa.extended_capa_mask;
		wpa_s->extended_capa_len = capa.extended_capa_len;
		wpa_s->num_multichan_concurrent =
			capa.num_multichan_concurrent;
		wpa_s->wmm_ac_supported = capa.wmm_ac_supported;

		if (capa.mac_addr_rand_scan_supported)
			wpa_s->mac_addr_rand_supported |= MAC_ADDR_RAND_SCAN;
		if (wpa_s->sched_scan_supported &&
		    capa.mac_addr_rand_sched_scan_supported)
			wpa_s->mac_addr_rand_supported |=
				(MAC_ADDR_RAND_SCHED_SCAN | MAC_ADDR_RAND_PNO);

		wpa_drv_get_ext_capa(wpa_s, WPA_IF_STATION);
		if (wpa_s->extended_capa &&
		    wpa_s->extended_capa_len >= 3 &&
		    wpa_s->extended_capa[2] & 0x40)
			wpa_s->multi_bss_support = 1;
	}
	if (wpa_s->max_remain_on_chan == 0)
		wpa_s->max_remain_on_chan = 1000;

	/*
	 * Only take p2p_mgmt parameters when P2P Device is supported.
	 * Doing it here as it determines whether l2_packet_init() will be done
	 * during wpa_supplicant_driver_init().
	 */
	if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE)
		wpa_s->p2p_mgmt = iface->p2p_mgmt;

	if (wpa_s->num_multichan_concurrent == 0)
		wpa_s->num_multichan_concurrent = 1;

	if (wpa_supplicant_driver_init(wpa_s) < 0)
		return -1;

#ifdef CONFIG_TDLS
	if (!iface->p2p_mgmt && wpa_tdls_init(wpa_s->wpa))
		return -1;
#endif /* CONFIG_TDLS */

	if (wpa_s->conf->country[0] && wpa_s->conf->country[1] &&
	    wpa_drv_set_country(wpa_s, wpa_s->conf->country)) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Failed to set country");
#endif
		SL_PRINTF(WLAN_SUPP_FAILED_TO_SET_COUNTRY, WLAN_UMAC, LOG_INFO);
		return -1;
	}

#ifdef CONFIG_FST
	if (wpa_s->conf->fst_group_id) {
		struct fst_iface_cfg cfg;
		struct fst_wpa_obj iface_obj;

		fst_wpa_supplicant_fill_iface_obj(wpa_s, &iface_obj);
		os_strlcpy(cfg.group_id, wpa_s->conf->fst_group_id,
			   sizeof(cfg.group_id));
		cfg.priority = wpa_s->conf->fst_priority;
		cfg.llt = wpa_s->conf->fst_llt;

		wpa_s->fst = fst_attach(wpa_s->ifname, wpa_s->own_addr,
					&iface_obj, &cfg);
		if (!wpa_s->fst) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_msg(wpa_s, MSG_ERROR,
				"FST: Cannot attach iface %s to group %s",
				wpa_s->ifname, cfg.group_id);
#endif
			SL_PRINTF(WLAN_SUPP_FST_CANNOT_ATTACH_IFACE_TO_GROUP, WLAN_UMAC, LOG_ERROR, "iface %s to group %s", wpa_s->ifname, cfg.group_id);
			return -1;
		}
	}
#endif /* CONFIG_FST */

	if (wpas_wps_init(wpa_s))
		return -1;

#ifdef CONFIG_GAS_SERVER
	wpa_s->gas_server = gas_server_init(wpa_s, wpas_gas_server_tx);
	if (!wpa_s->gas_server) {
		wpa_printf(MSG_ERROR, "Failed to initialize GAS server");
		return -1;
	}
#endif /* CONFIG_GAS_SERVER */

#ifdef CONFIG_DPP
	if (wpas_dpp_init(wpa_s) < 0)
		return -1;
#endif /* CONFIG_DPP */

	if (wpa_supplicant_init_eapol(wpa_s) < 0)
		return -1;
	wpa_sm_set_eapol(wpa_s->wpa, wpa_s->eapol);

#ifdef CTRL_IFACE
	wpa_s->ctrl_iface = wpa_supplicant_ctrl_iface_init(wpa_s);
	if (wpa_s->ctrl_iface == NULL) {
		wpa_printf(MSG_ERROR,
			   "Failed to initialize control interface '%s'.\n"
			   "You may have another wpa_supplicant process "
			   "already running or the file was\n"
			   "left by an unclean termination of wpa_supplicant "
			   "in which case you will need\n"
			   "to manually remove this file before starting "
			   "wpa_supplicant again.\n",
			   wpa_s->conf->ctrl_interface);
		return -1;
	}
#endif

#ifdef CONFIG_GAS
	wpa_s->gas = gas_query_init(wpa_s);
	if (wpa_s->gas == NULL) {
		wpa_printf(MSG_ERROR, "Failed to initialize GAS query");
		return -1;
	}
#endif
#ifdef CONFIG_P2P
	if ((!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE) ||
	     wpa_s->p2p_mgmt) &&
	    wpas_p2p_init(wpa_s->global, wpa_s) < 0) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_msg(wpa_s, MSG_ERROR, "Failed to init P2P");
#endif
		SL_PRINTF(WLAN_SUPP_FAILED_TO_INIT_P2P, WLAN_UMAC, LOG_ERROR);
		return -1;
	}
#endif
	if (wpa_bss_init(wpa_s) < 0)
		return -1;

#ifdef CONFIG_PMKSA_CACHE_EXTERNAL
#ifdef CONFIG_MESH
	dl_list_init(&wpa_s->mesh_external_pmksa_cache);
#endif /* CONFIG_MESH */
#endif /* CONFIG_PMKSA_CACHE_EXTERNAL */

	/*
	 * Set Wake-on-WLAN triggers, if configured.
	 * Note: We don't restore/remove the triggers on shutdown (it doesn't
	 * have effect anyway when the interface is down).
	 */
#ifdef ENABLE_SUPP_WOWLAN
	if (capa_res == 0 && wpas_set_wowlan_triggers(wpa_s, &capa) < 0)
		return -1;
#endif

#ifdef CONFIG_EAP_PROXY
{
	size_t len;
	wpa_s->mnc_len = eapol_sm_get_eap_proxy_imsi(wpa_s->eapol, -1,
						     wpa_s->imsi, &len);
	if (wpa_s->mnc_len > 0) {
		wpa_s->imsi[len] = '\0';
		wpa_printf(MSG_DEBUG, "eap_proxy: IMSI %s (MNC length %d)",
			   wpa_s->imsi, wpa_s->mnc_len);
	} else {
		wpa_printf(MSG_DEBUG, "eap_proxy: IMSI not available");
	}
}
#endif /* CONFIG_EAP_PROXY */

#ifdef PCSC_FUNCS
	if (pcsc_reader_init(wpa_s) < 0)
		return -1;
#endif

	if (wpas_init_ext_pw(wpa_s) < 0)
		return -1;

	//wpas_rrm_reset(wpa_s);

	wpas_sched_scan_plans_set(wpa_s, wpa_s->conf->sched_scan_plans);

#ifdef CONFIG_HS20
	hs20_init(wpa_s);
#endif /* CONFIG_HS20 */
#ifdef CONFIG_MBO_STA
	if (!wpa_s->disable_mbo_oce && wpa_s->conf->oce) {
		if ((wpa_s->conf->oce & OCE_STA) &&
		    (wpa_s->drv_flags & WPA_DRIVER_FLAGS_OCE_STA))
			wpa_s->enable_oce = OCE_STA;
		if ((wpa_s->conf->oce & OCE_STA_CFON) &&
		    (wpa_s->drv_flags & WPA_DRIVER_FLAGS_OCE_STA_CFON)) {
			/* TODO: Need to add STA-CFON support */
			wpa_printf(MSG_ERROR,
				   "OCE STA-CFON feature is not yet supported");
		}
	}
	wpas_mbo_update_non_pref_chan(wpa_s, wpa_s->conf->non_pref_chan);
#endif /* CONFIG_MBO_STA */

	wpa_supplicant_set_default_scan_ies(wpa_s);

	return 0;
}


static void wpa_supplicant_deinit_iface(struct wpa_supplicant *wpa_s,
					int notify, int terminate)
{
	struct wpa_global *global = wpa_s->global;
	struct wpa_supplicant *iface, *prev;
#ifdef CONFIG_P2P
	int dyn_sta_ap_switch_enable = 0;
	if (wpa_s == wpa_s->parent)
	{
		sl_wpa_driver_wrapper(wpa_s, WPA_DRV_CHK_DYN_STA_AP_SWITCH, &dyn_sta_ap_switch_enable);
		if (dyn_sta_ap_switch_enable) {
			wpas_p2p_group_remove(wpa_s, wpa_s->ifname);
 		} else {
			wpas_p2p_group_remove(wpa_s, "*");
		}
	}
#endif
	iface = global->ifaces;
	while (iface) {
		if (iface->p2pdev == wpa_s)
			iface->p2pdev = iface->parent;
		if (iface == wpa_s || iface->parent != wpa_s) {
			iface = iface->next;
			continue;
		}
		wpa_printf(MSG_DEBUG,
			   "Remove remaining child interface %s from parent %s",
			   iface->ifname, wpa_s->ifname);
		prev = iface;
		iface = iface->next;
		wpa_supplicant_remove_iface(global, prev, terminate);
	}

	wpa_s->disconnected = 1;
	if (wpa_s->drv_priv) {
		wpa_supplicant_deauthenticate(wpa_s,
					      WLAN_REASON_DEAUTH_LEAVING);

		wpa_drv_set_countermeasures(wpa_s, 0);
		wpa_clear_keys(wpa_s, NULL);
	}

	wpa_supplicant_cleanup(wpa_s);
#ifdef CONFIG_P2P
	wpas_p2p_deinit_iface(wpa_s);
#endif
#ifdef CTRL_IFACE
	wpas_ctrl_radio_work_flush(wpa_s);
#endif
#ifdef ENABLE_RRM 
	radio_remove_interface(wpa_s);
#endif

#ifdef CONFIG_FST
	if (wpa_s->fst) {
		fst_detach(wpa_s->fst);
		wpa_s->fst = NULL;
	}
	if (wpa_s->received_mb_ies) {
		wpabuf_free(wpa_s->received_mb_ies);
		wpa_s->received_mb_ies = NULL;
	}
#endif /* CONFIG_FST */

	if (wpa_s->drv_priv)
		wpa_drv_deinit(wpa_s);

	if (notify)
		wpas_notify_iface_removed(wpa_s);

	if (terminate)
		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_TERMINATING);

#ifdef CTRL_IFACE
	if (wpa_s->ctrl_iface) {
		wpa_supplicant_ctrl_iface_deinit(wpa_s->ctrl_iface);
		wpa_s->ctrl_iface = NULL;
	}
#endif

#ifdef CONFIG_MESH
	if (wpa_s->ifmsh) {
		wpa_supplicant_mesh_iface_deinit(wpa_s, wpa_s->ifmsh);
		wpa_s->ifmsh = NULL;
	}
#endif /* CONFIG_MESH */

	if (wpa_s->conf != NULL) {
		wpa_config_free(wpa_s->conf);
		wpa_s->conf = NULL;
	}

	os_free(wpa_s->ssids_from_scan_req);

	os_free(wpa_s);
}


#ifdef CONFIG_MATCH_IFACE

/**
 * wpa_supplicant_match_iface - Match an interface description to a name
 * @global: Pointer to global data from wpa_supplicant_init()
 * @ifname: Name of the interface to match
 * Returns: Pointer to the created interface description or %NULL on failure
 */
struct wpa_interface * wpa_supplicant_match_iface(struct wpa_global *global,
						  const char *ifname)
{
	int i;
	struct wpa_interface *iface, *miface;

	for (i = 0; i < global->params.match_iface_count; i++) {
		miface = &global->params.match_ifaces[i];
		if (!miface->ifname ||
		    fnmatch(miface->ifname, ifname, 0) == 0) {
			iface = os_zalloc(sizeof(*iface));
			if (!iface)
				return NULL;
			*iface = *miface;
			iface->ifname = ifname;
			return iface;
		}
	}

	return NULL;
}


/**
 * wpa_supplicant_match_existing - Match existing interfaces
 * @global: Pointer to global data from wpa_supplicant_init()
 * Returns: 0 on success, -1 on failure
 */
static int wpa_supplicant_match_existing(struct wpa_global *global)
{
	struct if_nameindex *ifi, *ifp;
	struct wpa_supplicant *wpa_s;
	struct wpa_interface *iface;

	ifp = if_nameindex();
	if (!ifp) {
		wpa_printf(MSG_ERROR, "if_nameindex: %s", strerror(errno));
		return -1;
	}

	for (ifi = ifp; ifi->if_name; ifi++) {
		wpa_s = wpa_supplicant_get_iface(global, ifi->if_name);
		if (wpa_s)
			continue;
		iface = wpa_supplicant_match_iface(global, ifi->if_name);
		if (iface) {
			wpa_s = wpa_supplicant_add_iface(global, iface, NULL);
			os_free(iface);
			if (wpa_s)
				wpa_s->matched = 1;
		}
	}

	if_freenameindex(ifp);
	return 0;
}

#endif /* CONFIG_MATCH_IFACE */


/**
 * wpa_supplicant_add_iface - Add a new network interface
 * @global: Pointer to global data from wpa_supplicant_init()
 * @iface: Interface configuration options
 * @parent: Parent interface or %NULL to assign new interface as parent
 * Returns: Pointer to the created interface or %NULL on failure
 *
 * This function is used to add new network interfaces for %wpa_supplicant.
 * This can be called before wpa_supplicant_run() to add interfaces before the
 * main event loop has been started. In addition, new interfaces can be added
 * dynamically while %wpa_supplicant is already running. This could happen,
 * e.g., when a hotplug network adapter is inserted.
 */
struct wpa_supplicant * wpa_supplicant_add_iface(struct wpa_global *global,
						 struct wpa_interface *iface,
						 struct wpa_supplicant *parent)
{
	struct wpa_supplicant *wpa_s;
	struct wpa_interface t_iface;
	struct wpa_ssid *ssid;

	if (global == NULL || iface == NULL)
		return NULL;

	wpa_s = wpa_supplicant_alloc(parent);
	if (wpa_s == NULL)
		return NULL;

	wpa_s->global = global;

	t_iface = *iface;
	if (global->params.override_driver) {
		wpa_printf(MSG_DEBUG, "Override interface parameter: driver "
			   "('%s' -> '%s')",
			   iface->driver, global->params.override_driver);
		t_iface.driver = global->params.override_driver;
	}
	if (global->params.override_ctrl_interface) {
		wpa_printf(MSG_DEBUG, "Override interface parameter: "
			   "ctrl_interface ('%s' -> '%s')",
			   iface->ctrl_interface,
			   global->params.override_ctrl_interface);
		t_iface.ctrl_interface =
			global->params.override_ctrl_interface;
	}
	if (wpa_supplicant_init_iface(wpa_s, &t_iface)) {
		wpa_printf(MSG_DEBUG, "Failed to add interface %s",
			   iface->ifname);
		wpa_supplicant_deinit_iface(wpa_s, 0, 0);
		return NULL;
	}

	if (iface->p2p_mgmt == 0) {
		/* Notify the control interfaces about new iface */
		if (wpas_notify_iface_added(wpa_s)) {
			wpa_supplicant_deinit_iface(wpa_s, 1, 0);
			return NULL;
		}

		for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next)
			wpas_notify_network_added(wpa_s, ssid);
	}

	wpa_s->next = global->ifaces;
	global->ifaces = wpa_s;

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Added interface %s", wpa_s->ifname);
#endif
	SL_PRINTF(WLAN_SUPP_ADDED_INTERFACE, WLAN_UMAC, LOG_INFO, "interface: %s", wpa_s->ifname);
	wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);

#ifdef CONFIG_P2P
	if (wpa_s->global->p2p == NULL &&
	    !wpa_s->global->p2p_disabled && !wpa_s->conf->p2p_disabled &&
	    (wpa_s->drv_flags & WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE) &&
	    wpas_p2p_add_p2pdev_interface(
		    wpa_s, wpa_s->global->params.conf_p2p_dev) < 0) {
		wpa_printf(MSG_INFO,
			   "P2P: Failed to enable P2P Device interface");
		/* Try to continue without. P2P will be disabled. */
	}
#endif /* CONFIG_P2P */

	return wpa_s;
}


/**
 * wpa_supplicant_remove_iface - Remove a network interface
 * @global: Pointer to global data from wpa_supplicant_init()
 * @wpa_s: Pointer to the network interface to be removed
 * Returns: 0 if interface was removed, -1 if interface was not found
 *
 * This function can be used to dynamically remove network interfaces from
 * %wpa_supplicant, e.g., when a hotplug network adapter is ejected. In
 * addition, this function is used to remove all remaining interfaces when
 * %wpa_supplicant is terminated.
 */
int wpa_supplicant_remove_iface(struct wpa_global *global,
				struct wpa_supplicant *wpa_s,
				int terminate)
{
	struct wpa_supplicant *prev;
#ifdef CONFIG_MESH
	unsigned int mesh_if_created = wpa_s->mesh_if_created;
	char *ifname = NULL;
	struct wpa_supplicant *parent = wpa_s->parent;
#endif /* CONFIG_MESH */

	/* Remove interface from the global list of interfaces */
	prev = global->ifaces;
	if (prev == wpa_s) {
		global->ifaces = wpa_s->next;
	} else {
		while (prev && prev->next != wpa_s)
			prev = prev->next;
		if (prev == NULL)
			return -1;
		prev->next = wpa_s->next;
	}

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Removing interface %s", wpa_s->ifname);
#endif
	SL_PRINTF(WLAN_SUPP_REMOVING_INTERFACE, WLAN_UMAC, LOG_INFO, "interface: %s", wpa_s->ifname);

#ifdef CONFIG_MESH
	if (mesh_if_created) {
		ifname = os_strdup(wpa_s->ifname);
		if (ifname == NULL) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_ERROR,
				"mesh: Failed to malloc ifname");
#endif
			SL_PRINTF(WLAN_SUPP_MESH_FAILED_TO_MALLOC_IFNAME, WLAN_UMAC, LOG_ERROR);
			return -1;
		}
	}
#endif /* CONFIG_MESH */

	if (global->p2p_group_formation == wpa_s)
		global->p2p_group_formation = NULL;
	if (global->p2p_invite_group == wpa_s)
		global->p2p_invite_group = NULL;
	wpa_supplicant_deinit_iface(wpa_s, 1, terminate);

#ifdef CONFIG_MESH
	if (mesh_if_created) {
		wpa_drv_if_remove(parent, WPA_IF_MESH, ifname);
		os_free(ifname);
	}
#endif /* CONFIG_MESH */

	return 0;
}


#if UNUSED_FEAT_IN_SUPP_29
/**
 * wpa_supplicant_get_eap_mode - Get the current EAP mode
 * @wpa_s: Pointer to the network interface
 * Returns: Pointer to the eap mode or the string "UNKNOWN" if not found
 */
const char * wpa_supplicant_get_eap_mode(struct wpa_supplicant *wpa_s)
{
	const char *eapol_method;

        if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt) == 0 &&
            wpa_s->key_mgmt != WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		return "NO-EAP";
	}

	eapol_method = eapol_sm_get_method_name(wpa_s->eapol);
	if (eapol_method == NULL)
		return "UNKNOWN-EAP";

	return eapol_method;
}


/**
 * wpa_supplicant_get_iface - Get a new network interface
 * @global: Pointer to global data from wpa_supplicant_init()
 * @ifname: Interface name
 * Returns: Pointer to the interface or %NULL if not found
 */
struct wpa_supplicant * wpa_supplicant_get_iface(struct wpa_global *global,
						 const char *ifname)
{
	struct wpa_supplicant *wpa_s;

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		if (os_strcmp(wpa_s->ifname, ifname) == 0)
			return wpa_s;
	}
	return NULL;
}
#endif


#ifndef CONFIG_NO_WPA_MSG
static const char * wpa_supplicant_msg_ifname_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;
	if (wpa_s == NULL)
		return NULL;
	return wpa_s->ifname;
}
#endif /* CONFIG_NO_WPA_MSG */


#ifndef WPA_SUPPLICANT_CLEANUP_INTERVAL
#define WPA_SUPPLICANT_CLEANUP_INTERVAL 10
#endif /* WPA_SUPPLICANT_CLEANUP_INTERVAL */

#if UNUSED_FEAT_IN_SUPP_29
/* Periodic cleanup tasks */
static void wpas_periodic(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_global *global = eloop_ctx;
	struct wpa_supplicant *wpa_s;

	eloop_register_timeout(WPA_SUPPLICANT_CLEANUP_INTERVAL, 0,
			       wpas_periodic, global, NULL);

#ifdef CONFIG_P2P
	if (global->p2p)
		p2p_expire_peers(global->p2p);
#endif /* CONFIG_P2P */

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		wpa_bss_flush_by_age(wpa_s, wpa_s->conf->bss_expiration_age);
#ifdef CONFIG_AP
		ap_periodic(wpa_s);
#endif /* CONFIG_AP */
	}
}
#endif


/**
 * wpa_supplicant_init - Initialize %wpa_supplicant
 * @params: Parameters for %wpa_supplicant
 * Returns: Pointer to global %wpa_supplicant data, or %NULL on failure
 *
 * This function is used to initialize %wpa_supplicant. After successful
 * initialization, the returned data pointer can be used to add and remove
 * network interfaces, and eventually, to deinitialize %wpa_supplicant.
 */
struct wpa_global * wpa_supplicant_init(struct wpa_params *params)
{
	struct wpa_global *global;
	int ret, i;

	if (params == NULL)
		return NULL;

#ifdef CONFIG_DRIVER_NDIS
	{
		void driver_ndis_init_ops(void);
		driver_ndis_init_ops();
	}
#endif /* CONFIG_DRIVER_NDIS */

#ifndef CONFIG_NO_WPA_MSG
	wpa_msg_register_ifname_cb(wpa_supplicant_msg_ifname_cb);
#endif /* CONFIG_NO_WPA_MSG */

	if (params->wpa_debug_file_path)
		wpa_debug_open_file(params->wpa_debug_file_path);
	else
#if UNUSED_FEAT_IN_SUPP_29		
		wpa_debug_setup_stdout();
#endif	
	if (params->wpa_debug_syslog)
		wpa_debug_open_syslog();
	if (params->wpa_debug_tracing) {
		ret = wpa_debug_open_linux_tracing();
		if (ret) {
			wpa_printf(MSG_ERROR,
				   "Failed to enable trace logging");
			return NULL;
		}
	}

	ret = eap_register_methods();
	if (ret) {
		wpa_printf(MSG_ERROR, "Failed to register EAP methods");
		if (ret == -2)
			wpa_printf(MSG_ERROR, "Two or more EAP methods used "
				   "the same EAP type.");
		return NULL;
	}

	global = os_zalloc(sizeof(*global));
	if (global == NULL)
		return NULL;
	dl_list_init(&global->p2p_srv_bonjour);
	dl_list_init(&global->p2p_srv_upnp);
	global->params.daemonize = params->daemonize;
	global->params.wait_for_monitor = params->wait_for_monitor;
	global->params.dbus_ctrl_interface = params->dbus_ctrl_interface;
	if (params->pid_file)
		global->params.pid_file = os_strdup(params->pid_file);
	if (params->ctrl_interface)
		global->params.ctrl_interface =
			os_strdup(params->ctrl_interface);
	if (params->ctrl_interface_group)
		global->params.ctrl_interface_group =
			os_strdup(params->ctrl_interface_group);
	if (params->override_driver)
		global->params.override_driver =
			os_strdup(params->override_driver);
	if (params->override_ctrl_interface)
		global->params.override_ctrl_interface =
			os_strdup(params->override_ctrl_interface);
#ifdef CONFIG_MATCH_IFACE
	global->params.match_iface_count = params->match_iface_count;
	if (params->match_iface_count) {
		global->params.match_ifaces =
			os_calloc(params->match_iface_count,
				  sizeof(struct wpa_interface));
		os_memcpy(global->params.match_ifaces,
			  params->match_ifaces,
			  params->match_iface_count *
			  sizeof(struct wpa_interface));
	}
#endif /* CONFIG_MATCH_IFACE */
#ifdef CONFIG_P2P
	if (params->conf_p2p_dev)
		global->params.conf_p2p_dev =
			os_strdup(params->conf_p2p_dev);
#endif /* CONFIG_P2P */
#ifdef WPA_DEBUG
	wpa_debug_level = global->params.wpa_debug_level =
		params->wpa_debug_level;
	wpa_debug_show_keys = global->params.wpa_debug_show_keys =
		params->wpa_debug_show_keys;
	wpa_debug_timestamp = global->params.wpa_debug_timestamp =
		params->wpa_debug_timestamp;

	wpa_printf(MSG_DEBUG, "wpa_supplicant v" VERSION_STR);
#endif

	if (eloop_init()) {
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
		wpa_supplicant_deinit(global);
		return NULL;
	}

	random_init(params->entropy_file);

#ifdef CTRL_IFACE
	global->ctrl_iface = wpa_supplicant_global_ctrl_iface_init(global);
	if (global->ctrl_iface == NULL) {
		wpa_supplicant_deinit(global);
		return NULL;
	}
#endif

	if (wpas_notify_supplicant_initialized(global)) {
		wpa_supplicant_deinit(global);
		return NULL;
	}

	for (i = 0; wpa_drivers[i]; i++)
		global->drv_count++;
	if (global->drv_count == 0) {
		wpa_printf(MSG_ERROR, "No drivers enabled");
		wpa_supplicant_deinit(global);
		return NULL;
	}
	global->drv_priv = os_calloc(global->drv_count, sizeof(void *));
	if (global->drv_priv == NULL) {
		wpa_supplicant_deinit(global);
		return NULL;
	}

#ifdef CONFIG_WIFI_DISPLAY
	if (wifi_display_init(global) < 0) {
		wpa_printf(MSG_ERROR, "Failed to initialize Wi-Fi Display");
		wpa_supplicant_deinit(global);
		return NULL;
	}
#endif /* CONFIG_WIFI_DISPLAY */
#if UNUSED_FEAT_IN_SUPP_29
	eloop_register_timeout(WPA_SUPPLICANT_CLEANUP_INTERVAL, 0,
			       wpas_periodic, global, NULL);
#endif
	return global;
}


/**
 * wpa_supplicant_run - Run the %wpa_supplicant main event loop
 * @global: Pointer to global data from wpa_supplicant_init()
 * Returns: 0 after successful event loop run, -1 on failure
 *
 * This function starts the main event loop and continues running as long as
 * there are any remaining events. In most cases, this function is running as
 * long as the %wpa_supplicant process in still in use.
 */
#if UNUSED_FEAT_IN_SUPP_29
int wpa_supplicant_run(struct wpa_global *global)
{
	struct wpa_supplicant *wpa_s;

	if (global->params.daemonize &&
	    (wpa_supplicant_daemon(global->params.pid_file) /*||
	     eloop_sock_requeue()*/))
		return -1;

#ifdef CONFIG_MATCH_IFACE
	if (wpa_supplicant_match_existing(global))
		return -1;
#endif

	if (global->params.wait_for_monitor) {
		for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next)
			if (wpa_s->ctrl_iface && !wpa_s->p2p_mgmt)
				wpa_supplicant_ctrl_iface_wait(
					wpa_s->ctrl_iface);
	}

	eloop_register_signal_terminate(wpa_supplicant_terminate, global);
	eloop_register_signal_reconfig(wpa_supplicant_reconfig, global);

	eloop_run();

	return 0;
}
#endif


/**
 * wpa_supplicant_deinit - Deinitialize %wpa_supplicant
 * @global: Pointer to global data from wpa_supplicant_init()
 *
 * This function is called to deinitialize %wpa_supplicant and to free all
 * allocated resources. Remaining network interfaces will also be removed.
 */
void wpa_supplicant_deinit(struct wpa_global *global)
{
	int i;

	if (global == NULL)
		return;

#if UNUSED_FEAT_IN_SUPP_29
	eloop_cancel_timeout(wpas_periodic, global, NULL);
#endif

#ifdef CONFIG_WIFI_DISPLAY
	wifi_display_deinit(global);
#endif /* CONFIG_WIFI_DISPLAY */

	while (global->ifaces)
		wpa_supplicant_remove_iface(global, global->ifaces, 1);

#ifdef CTRL_IFACE
	if (global->ctrl_iface)
		wpa_supplicant_global_ctrl_iface_deinit(global->ctrl_iface);
#endif

	wpas_notify_supplicant_deinitialized(global);

	eap_peer_unregister_methods();
#ifdef CONFIG_AP
	eap_server_unregister_methods();
#endif /* CONFIG_AP */

	for (i = 0; wpa_drivers[i] && global->drv_priv; i++) {
		if (!global->drv_priv[i])
			continue;
		wpa_drivers[i]->global_deinit(global->drv_priv[i]);
	}
	os_free(global->drv_priv);

	random_deinit();

	eloop_destroy();

	if (global->params.pid_file) {
		os_daemonize_terminate(global->params.pid_file);
		os_free(global->params.pid_file);
	}
	os_free(global->params.ctrl_interface);
	os_free(global->params.ctrl_interface_group);
	os_free(global->params.override_driver);
	os_free(global->params.override_ctrl_interface);
#ifdef CONFIG_MATCH_IFACE
	os_free(global->params.match_ifaces);
#endif /* CONFIG_MATCH_IFACE */
#ifdef CONFIG_P2P
	os_free(global->params.conf_p2p_dev);
#endif /* CONFIG_P2P */

	os_free(global->p2p_disallow_freq.range);
	os_free(global->p2p_go_avoid_freq.range);
	os_free(global->add_psk);

	os_free(global);
	wpa_debug_close_syslog();
	wpa_debug_close_file();
	wpa_debug_close_linux_tracing();
}

#ifdef RSI_ENABLE_CCX
#if UNUSED_FEAT_IN_SUPP_29
void
wpa_cckm_hmac_calculate_wpa(struct wpa_supplicant *wpa, u8 *bssid, u8 *tsf)
{
	struct wpa_sm *wps = wpa->wpa;
	/* Advance the rekey number first */
	++wps->rekey_number;
	wpa_cckm_hmac_calculate(wps, wps->assoc_wpa_ie, wps->assoc_wpa_ie_len,
			&wps->own_addr[0], bssid, wps->rekey_number, tsf, wps->mic, 8);
	wpa_drv_cckm_reassoc(wpa, wps->mic, wps->rekey_number);
	/* Calculate new PTK for the AP */
	cckm_driver_newptk(wps, bssid);
}
#endif
#endif

#if UNUSED_FEAT_IN_SUPP_29
void wpa_supplicant_update_config(struct wpa_supplicant *wpa_s)
{
	if ((wpa_s->conf->changed_parameters & CFG_CHANGED_COUNTRY) &&
	    wpa_s->conf->country[0] && wpa_s->conf->country[1]) {
		char country[3];
		country[0] = wpa_s->conf->country[0];
		country[1] = wpa_s->conf->country[1];
		country[2] = '\0';
		if (wpa_drv_set_country(wpa_s, country) < 0) {
			wpa_printf(MSG_ERROR, "Failed to set country code "
				   "'%s'", country);
		}
	}

	if (wpa_s->conf->changed_parameters & CFG_CHANGED_EXT_PW_BACKEND)
		wpas_init_ext_pw(wpa_s);

	if (wpa_s->conf->changed_parameters & CFG_CHANGED_SCHED_SCAN_PLANS)
		wpas_sched_scan_plans_set(wpa_s, wpa_s->conf->sched_scan_plans);

#ifdef ENABLE_SUPP_WOWLAN
	if (wpa_s->conf->changed_parameters & CFG_CHANGED_WOWLAN_TRIGGERS) {
		struct wpa_driver_capa capa;
		int res = wpa_drv_get_capa(wpa_s, &capa);

		if (res == 0 && wpas_set_wowlan_triggers(wpa_s, &capa) < 0)
			wpa_printf(MSG_ERROR,
				   "Failed to update wowlan_triggers to '%s'",
				   wpa_s->conf->wowlan_triggers);
	}
#endif

	if (wpa_s->conf->changed_parameters & CFG_CHANGED_DISABLE_BTM)
		wpa_supplicant_set_default_scan_ies(wpa_s);

#ifdef CONFIG_WPS
	wpas_wps_update_config(wpa_s);
#endif /* CONFIG_WPS */
	wpas_p2p_update_config(wpa_s);
	wpa_s->conf->changed_parameters = 0;
}
#endif


void add_freq(int *freqs, int *num_freqs, int freq)
{
	int i;

	for (i = 0; i < *num_freqs; i++) {
		if (freqs[i] == freq)
			return;
	}

	freqs[*num_freqs] = freq;
	(*num_freqs)++;
}


static int * get_bss_freqs_in_ess(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss *bss, *cbss;
	const int max_freqs = 10;
	int *freqs;
	int num_freqs = 0;

	freqs = os_calloc(max_freqs + 1, sizeof(int));
	if (freqs == NULL)
		return NULL;

	cbss = wpa_s->current_bss;

	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		if (bss == cbss)
			continue;
		if (bss->ssid_len == cbss->ssid_len &&
		    os_memcmp(bss->ssid, cbss->ssid, bss->ssid_len) == 0 &&
		    wpa_blacklist_get(wpa_s, bss->bssid) == NULL) {
			add_freq(freqs, &num_freqs, bss->freq);
			if (num_freqs == max_freqs)
				break;
		}
	}

	if (num_freqs == 0) {
		os_free(freqs);
		freqs = NULL;
	}

	return freqs;
}


void wpas_connection_failed(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	int timeout;
	int count;
	int *freqs = NULL;

#ifdef ENABLE_RRM
	wpas_connect_work_done(wpa_s);
#endif

	/*
	 * Remove possible authentication timeout since the connection failed.
	 */
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);

	/*
	 * There is no point in blacklisting the AP if this event is
	 * generated based on local request to disconnect.
	 */
	if (wpa_s->own_disconnect_req) {
		wpa_s->own_disconnect_req = 0;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
			"Ignore connection failure due to local request to disconnect");
#endif
		SL_PRINTF(WLAN_SUPP_IGNORE_CONNECTION_FAILURE_DUE_TO_LOCAL_REQUEST_TO_DISCONNECT, WLAN_UMAC, LOG_INFO);
		return;
	}
	if (wpa_s->disconnected) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "Ignore connection failure "
			"indication since interface has been put into "
			"disconnected state");
#endif
		SL_PRINTF(WLAN_SUPP_IGNORE_CONNECTION_FAILURE_INDICATION_SINCE_INTERFACE_HAS_BEEN_PUT_INTO_DISCONNECTED_STATE, WLAN_UMAC, LOG_INFO);
		return;
	}

	/*
	 * Add the failed BSSID into the blacklist and speed up next scan
	 * attempt if there could be other APs that could accept association.
	 * The current blacklist count indicates how many times we have tried
	 * connecting to this AP and multiple attempts mean that other APs are
	 * either not available or has already been tried, so that we can start
	 * increasing the delay here to avoid constant scanning.
	 */
	count = wpa_blacklist_add(wpa_s, bssid);
	if (count == 1 && wpa_s->current_bss) {
		/*
		 * This BSS was not in the blacklist before. If there is
		 * another BSS available for the same ESS, we should try that
		 * next. Otherwise, we may as well try this one once more
		 * before allowing other, likely worse, ESSes to be considered.
		 */
		freqs = get_bss_freqs_in_ess(wpa_s);
		if (freqs) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "Another BSS in this ESS "
				"has been seen; try it next");
#endif
			SL_PRINTF(WLAN_SUPP_ANOTHER_BSS_IN_THIS_ESS_HAS_BEEN_SEEN_TRY_IT_NEXT, WLAN_UMAC, LOG_INFO);
			wpa_blacklist_add(wpa_s, bssid);
			/*
			 * On the next scan, go through only the known channels
			 * used in this ESS based on previous scans to speed up
			 * common load balancing use case.
			 */
			os_free(wpa_s->next_scan_freqs);
			wpa_s->next_scan_freqs = freqs;
		}
	}

	/*
	 * Add previous failure count in case the temporary blacklist was
	 * cleared due to no other BSSes being available.
	 */
	count += wpa_s->extra_blacklist_count;

	if (count > 3 && wpa_s->current_ssid) {
		wpa_printf(MSG_DEBUG, "Continuous association failures - "
			   "consider temporary network disabling");
		wpas_auth_failed(wpa_s, "CONN_FAILED");
	}

	switch (count) {
	case 1:
		timeout = 100;
		break;
	case 2:
		timeout = 500;
		break;
	case 3:
		timeout = 1000;
		break;
	case 4:
		timeout = 5000;
		break;
	default:
		timeout = 10000;
		break;
	}

	int feat_blacklist_enabled = 0;
	sl_wpa_driver_wrapper(wpa_s, WPA_DRV_CHK_FEAT_BLACKLIST, &feat_blacklist_enabled);
	if (feat_blacklist_enabled) {
		wpa_printf(MSG_DEBUG, "OBE: Overwriting scan registered timeout to 100 ms");
		timeout = 100;
	}
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Blacklist count %d --> request scan in %d "
		"ms", count, timeout);
#endif
	SL_PRINTF(WLAN_SUPP_BLACKLIST_COUNT, WLAN_UMAC, LOG_INFO, "Blacklist count %d --> request scan in %d ms", count, timeout);

	/*
	 * TODO: if more than one possible AP is available in scan results,
	 * could try the other ones before requesting a new scan.
	 */

	/* speed up the connection attempt with normal scan */
	wpa_s->normal_scans = 0;
	wpa_supplicant_req_scan(wpa_s, timeout / 1000,
				1000 * (timeout % 1000));
}


#ifdef CONFIG_FILS
void fils_connection_failure(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid = wpa_s->current_ssid;
	const u8 *realm, *username, *rrk;
	size_t realm_len, username_len, rrk_len;
	u16 next_seq_num;

	if (!ssid || !ssid->eap.erp || !wpa_key_mgmt_fils(ssid->key_mgmt) ||
	    eapol_sm_get_erp_info(wpa_s->eapol, &ssid->eap,
				  &username, &username_len,
				  &realm, &realm_len, &next_seq_num,
				  &rrk, &rrk_len) != 0 ||
	    !realm)
		return;

	wpa_hexdump_ascii(MSG_DEBUG,
			  "FILS: Store last connection failure realm",
			  realm, realm_len);
	os_free(wpa_s->last_con_fail_realm);
	wpa_s->last_con_fail_realm = os_malloc(realm_len);
	if (wpa_s->last_con_fail_realm) {
		wpa_s->last_con_fail_realm_len = realm_len;
		os_memcpy(wpa_s->last_con_fail_realm, realm, realm_len);
	}
}
#endif /* CONFIG_FILS */


int wpas_driver_bss_selection(struct wpa_supplicant *wpa_s)
{
	return wpa_s->conf->ap_scan == 2 ||
		(wpa_s->drv_flags & WPA_DRIVER_FLAGS_BSS_SELECTION);
}


#if defined(CONFIG_CTRL_IFACE) || defined(CONFIG_CTRL_IFACE_DBUS_NEW)
int wpa_supplicant_ctrl_iface_ctrl_rsp_handle(struct wpa_supplicant *wpa_s,
					      struct wpa_ssid *ssid,
					      const char *field,
					      const char *value)
{
#ifdef IEEE8021X_EAPOL
	struct eap_peer_config *eap = &ssid->eap;

	wpa_printf(MSG_DEBUG, "CTRL_IFACE: response handle field=%s", field);
	wpa_hexdump_ascii_key(MSG_DEBUG, "CTRL_IFACE: response value",
			      (const u8 *) value, os_strlen(value));

	switch (wpa_supplicant_ctrl_req_from_string(field)) {
	case WPA_CTRL_REQ_EAP_IDENTITY:
		os_free(eap->identity);
		eap->identity = (u8 *) os_strdup(value);
		eap->identity_len = os_strlen(value);
		eap->pending_req_identity = 0;
		if (ssid == wpa_s->current_ssid)
			wpa_s->reassociate = 1;
		break;
	case WPA_CTRL_REQ_EAP_PASSWORD:
		bin_clear_free(eap->password, eap->password_len);
		eap->password = (u8 *) os_strdup(value);
		eap->password_len = os_strlen(value);
		eap->pending_req_password = 0;
		if (ssid == wpa_s->current_ssid)
			wpa_s->reassociate = 1;
		break;
	case WPA_CTRL_REQ_EAP_NEW_PASSWORD:
		bin_clear_free(eap->new_password, eap->new_password_len);
		eap->new_password = (u8 *) os_strdup(value);
		eap->new_password_len = os_strlen(value);
		eap->pending_req_new_password = 0;
		if (ssid == wpa_s->current_ssid)
			wpa_s->reassociate = 1;
		break;
	case WPA_CTRL_REQ_EAP_PIN:
		str_clear_free(eap->pin);
		eap->pin = os_strdup(value);
		eap->pending_req_pin = 0;
		if (ssid == wpa_s->current_ssid)
			wpa_s->reassociate = 1;
		break;
	case WPA_CTRL_REQ_EAP_OTP:
		bin_clear_free(eap->otp, eap->otp_len);
		eap->otp = (u8 *) os_strdup(value);
		eap->otp_len = os_strlen(value);
		os_free(eap->pending_req_otp);
		eap->pending_req_otp = NULL;
		eap->pending_req_otp_len = 0;
		break;
	case WPA_CTRL_REQ_EAP_PASSPHRASE:
		str_clear_free(eap->private_key_passwd);
		eap->private_key_passwd = os_strdup(value);
		eap->pending_req_passphrase = 0;
		if (ssid == wpa_s->current_ssid)
			wpa_s->reassociate = 1;
		break;
	case WPA_CTRL_REQ_SIM:
		str_clear_free(eap->external_sim_resp);
		eap->external_sim_resp = os_strdup(value);
		eap->pending_req_sim = 0;
		break;
	case WPA_CTRL_REQ_PSK_PASSPHRASE:
		if (wpa_config_set(ssid, "psk", value, 0) < 0)
			return -1;
		ssid->mem_only_psk = 1;
		if (ssid->passphrase)
			wpa_config_update_psk(ssid);
		if (wpa_s->wpa_state == WPA_SCANNING && !wpa_s->scanning)
			wpa_supplicant_req_scan(wpa_s, 0, 0);
		break;
	case WPA_CTRL_REQ_EXT_CERT_CHECK:
		if (eap->pending_ext_cert_check != PENDING_CHECK)
			return -1;
		if (os_strcmp(value, "good") == 0)
			eap->pending_ext_cert_check = EXT_CERT_CHECK_GOOD;
		else if (os_strcmp(value, "bad") == 0)
			eap->pending_ext_cert_check = EXT_CERT_CHECK_BAD;
		else
			return -1;
		break;
	default:
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Unknown field '%s'", field);
		return -1;
	}

	return 0;
#else /* IEEE8021X_EAPOL */
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: IEEE 802.1X not included");
	return -1;
#endif /* IEEE8021X_EAPOL */
}
#endif /* CONFIG_CTRL_IFACE || CONFIG_CTRL_IFACE_DBUS_NEW */


int wpas_network_disabled(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	int i;
	unsigned int drv_enc;

	if (wpa_s->p2p_mgmt)
		return 1; /* no normal network profiles on p2p_mgmt interface */

	if (ssid == NULL)
		return 1;

	if (ssid->disabled)
		return 1;

	if (wpa_s->drv_capa_known)
		drv_enc = wpa_s->drv_enc;
	else
		drv_enc = (unsigned int) -1;

	for (i = 0; i < NUM_WEP_KEYS; i++) {
		size_t len = ssid->wep_key_len[i];
		if (len == 0)
			continue;
		if (len == 5 && (drv_enc & WPA_DRIVER_CAPA_ENC_WEP40))
			continue;
		if (len == 13 && (drv_enc & WPA_DRIVER_CAPA_ENC_WEP104))
			continue;
		if (len == 16 && (drv_enc & WPA_DRIVER_CAPA_ENC_WEP128))
			continue;
		return 1; /* invalid WEP key */
	}

	if (wpa_key_mgmt_wpa_psk(ssid->key_mgmt) && !ssid->psk_set &&
	    (!ssid->passphrase || ssid->ssid_len != 0) && !ssid->ext_psk &&
	    !(wpa_key_mgmt_sae(ssid->key_mgmt) && ssid->sae_password) &&
	    !ssid->mem_only_psk)
		return 1;

	return 0;
}


int wpas_get_ssid_pmf(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
#ifdef CONFIG_IEEE80211W
	if (ssid == NULL || ssid->ieee80211w == MGMT_FRAME_PROTECTION_DEFAULT) {
#if 0
		if (wpa_s->conf->pmf == MGMT_FRAME_PROTECTION_OPTIONAL &&
		    !(wpa_s->drv_enc & WPA_DRIVER_CAPA_ENC_BIP)) {
			/*
			 * Driver does not support BIP -- ignore pmf=1 default
			 * since the connection with PMF would fail and the
			 * configuration does not require PMF to be enabled.
			 */
			return NO_MGMT_FRAME_PROTECTION;
		}
#endif
		if (ssid &&
		    (ssid->key_mgmt &
		     ~(WPA_KEY_MGMT_NONE | WPA_KEY_MGMT_WPS |
		       WPA_KEY_MGMT_IEEE8021X_NO_WPA)) == 0) {
			/*
			 * Do not use the default PMF value for non-RSN networks
			 * since PMF is available only with RSN and pmf=2
			 * configuration would otherwise prevent connections to
			 * all open networks.
			 */
			return NO_MGMT_FRAME_PROTECTION;
		}

		return wpa_s->conf->pmf;
	}

	return ssid->ieee80211w;
#else /* CONFIG_IEEE80211W */
	return NO_MGMT_FRAME_PROTECTION;
#endif /* CONFIG_IEEE80211W */
}


#if UNUSED_FEAT_IN_SUPP_29
int wpas_is_p2p_prioritized(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->global->conc_pref == WPA_CONC_PREF_P2P)
		return 1;
	if (wpa_s->global->conc_pref == WPA_CONC_PREF_STA)
		return 0;
	return -1;
}
#endif


void wpas_auth_failed(struct wpa_supplicant *wpa_s, char *reason)
{
	struct wpa_ssid *ssid = wpa_s->current_ssid;
	int dur;
	struct os_reltime now;

	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "Authentication failure but no known "
			   "SSID block");
		return;
	}

	if (ssid->key_mgmt == WPA_KEY_MGMT_WPS)
		return;

	ssid->auth_failures++;

#ifdef CONFIG_P2P
	if (ssid->p2p_group &&
	    (wpa_s->p2p_in_provisioning || wpa_s->show_group_started)) {
		/*
		 * Skip the wait time since there is a short timeout on the
		 * connection to a P2P group.
		 */
		return;
	}
#endif /* CONFIG_P2P */

	if (ssid->auth_failures > 50)
		dur = 300;
	else if (ssid->auth_failures > 10)
		dur = 120;
	else if (ssid->auth_failures > 5)
		dur = 90;
	else if (ssid->auth_failures > 3)
		dur = 60;
	else if (ssid->auth_failures > 2)
		dur = 30;
	else if (ssid->auth_failures > 1)
		dur = 20;
	else
		dur = 10;

	if (ssid->auth_failures > 1 &&
	    wpa_key_mgmt_wpa_ieee8021x(ssid->key_mgmt))
		dur += os_random() % (ssid->auth_failures * 10);

	os_get_reltime(&now);
	if (now.sec + dur <= ssid->disabled_until.sec)
		return;

	ssid->disabled_until.sec = now.sec + dur;

	wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_TEMP_DISABLED
		"id=%d ssid=\"%s\" auth_failures=%u duration=%d reason=%s",
		ssid->id, wpa_ssid_txt(ssid->ssid, ssid->ssid_len),
		ssid->auth_failures, dur, reason);
}


void wpas_clear_temp_disabled(struct wpa_supplicant *wpa_s,
			      struct wpa_ssid *ssid, int clear_failures)
{
	if (ssid == NULL)
		return;

	if (ssid->disabled_until.sec) {
		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_REENABLED
			"id=%d ssid=\"%s\"",
			ssid->id, wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
	}
	ssid->disabled_until.sec = 0;
	ssid->disabled_until.usec = 0;
	if (clear_failures)
		ssid->auth_failures = 0;
}


int disallowed_bssid(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	size_t i;

	if (wpa_s->disallow_aps_bssid == NULL)
		return 0;

	for (i = 0; i < wpa_s->disallow_aps_bssid_count; i++) {
		if (os_memcmp(wpa_s->disallow_aps_bssid + i * ETH_ALEN,
			      bssid, ETH_ALEN) == 0)
			return 1;
	}

	return 0;
}


int disallowed_ssid(struct wpa_supplicant *wpa_s, const u8 *ssid,
		    size_t ssid_len)
{
	size_t i;

	if (wpa_s->disallow_aps_ssid == NULL || ssid == NULL)
		return 0;

	for (i = 0; i < wpa_s->disallow_aps_ssid_count; i++) {
		struct wpa_ssid_value *s = &wpa_s->disallow_aps_ssid[i];
		if (ssid_len == s->ssid_len &&
		    os_memcmp(ssid, s->ssid, ssid_len) == 0)
			return 1;
	}

	return 0;
}


/**
 * wpas_request_connection - Request a new connection
 * @wpa_s: Pointer to the network interface
 *
 * This function is used to request a new connection to be found. It will mark
 * the interface to allow reassociation and request a new scan to find a
 * suitable network to connect to.
 */
void wpas_request_connection(struct wpa_supplicant *wpa_s)
{
	wpa_s->normal_scans = 0;
	wpa_s->scan_req = NORMAL_SCAN_REQ;
	wpa_supplicant_reinit_autoscan(wpa_s);
	wpa_s->extra_blacklist_count = 0;
	wpa_s->disconnected = 0;
	wpa_s->reassociate = 1;
	wpa_s->last_owe_group = 0;

	if (wpa_supplicant_fast_associate(wpa_s) != 1)
		wpa_supplicant_req_scan(wpa_s, 0, 0);
	else
		wpa_s->reattach = 0;
}

#if UNUSED_FEAT_IN_SUPP_29

/**
 * wpas_request_disconnection - Request disconnection
 * @wpa_s: Pointer to the network interface
 *
 * This function is used to request disconnection from the currently connected
 * network. This will stop any ongoing scans and initiate deauthentication.
 */
void wpas_request_disconnection(struct wpa_supplicant *wpa_s)
{
#ifdef CONFIG_SME
	wpa_s->sme.prev_bssid_set = 0;
#endif /* CONFIG_SME */
	wpa_s->reassociate = 0;
	wpa_s->disconnected = 1;
	wpa_supplicant_cancel_sched_scan(wpa_s);
	wpa_supplicant_cancel_scan(wpa_s);
	wpa_supplicant_deauthenticate(wpa_s, WLAN_REASON_DEAUTH_LEAVING);
	eloop_cancel_timeout(wpas_network_reenabled, wpa_s, NULL);
	radio_remove_works(wpa_s, "connect", 0);
	radio_remove_works(wpa_s, "sme-connect", 0);
}


void dump_freq_data(struct wpa_supplicant *wpa_s, const char *title,
		    struct wpa_used_freq_data *freqs_data,
		    unsigned int len)
{
	unsigned int i;

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "Shared frequencies (len=%u): %s",
		len, title);
#endif
	SL_PRINTF(WLAN_SUPP_SHARED_FREQUENCIES, WLAN_UMAC, LOG_INFO, "(len=%d): %s", len, title);
	for (i = 0; i < len; i++) {
		struct wpa_used_freq_data *cur = &freqs_data[i];
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "freq[%u]: %d, flags=0x%X",
			i, cur->freq, cur->flags);
#endif
		SL_PRINTF(WLAN_SUPP_SHARED_FREQUENCIES_ITH, WLAN_UMAC, LOG_INFO, "freq[%d]: %d, flags=%4x", i, cur->freq, cur->flags);
	}
}
#endif


#ifdef CONFIG_P2P
/*
 * Find the operating frequencies of any of the virtual interfaces that
 * are using the same radio as the current interface, and in addition, get
 * information about the interface types that are using the frequency.
 */
int get_shared_radio_freqs_data(struct wpa_supplicant *wpa_s,
				struct wpa_used_freq_data *freqs_data,
				unsigned int len)
{
	struct wpa_supplicant *ifs;
	u8 bssid[ETH_ALEN];
	int freq;
	unsigned int idx = 0, i;

#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG,
		"Determining shared radio frequencies (max len %u)", len);
#endif
	SL_PRINTF(WLAN_SUPP_DETERMINING_SHARED_RADIO_FREQUENCIES_MAX_LEN, WLAN_UMAC, LOG_INFO, "max len: %d", len);
	os_memset(freqs_data, 0, sizeof(struct wpa_used_freq_data) * len);

	dl_list_for_each(ifs, &wpa_s->radio->ifaces, struct wpa_supplicant,
			 radio_list) {
		if (idx == len)
			break;

		if (ifs->current_ssid == NULL || ifs->assoc_freq == 0)
			continue;

		if (ifs->current_ssid->mode == WPAS_MODE_AP ||
		    ifs->current_ssid->mode == WPAS_MODE_P2P_GO ||
		    ifs->current_ssid->mode == WPAS_MODE_MESH)
			freq = ifs->current_ssid->frequency;
		else if (wpa_drv_get_bssid(ifs, bssid) == 0)
			freq = ifs->assoc_freq;
		else
			continue;

		/* Hold only distinct freqs */
		for (i = 0; i < idx; i++)
			if (freqs_data[i].freq == freq)
				break;

		if (i == idx)
			freqs_data[idx++].freq = freq;

		if (ifs->current_ssid->mode == WPAS_MODE_INFRA) {
			freqs_data[i].flags |= ifs->current_ssid->p2p_group ?
				WPA_FREQ_USED_BY_P2P_CLIENT :
				WPA_FREQ_USED_BY_INFRA_STATION;
		}
	}

	dump_freq_data(wpa_s, "completed iteration", freqs_data, idx);
	return idx;
}


/*
 * Find the operating frequencies of any of the virtual interfaces that
 * are using the same radio as the current interface.
 */
int get_shared_radio_freqs(struct wpa_supplicant *wpa_s,
			   int *freq_array, unsigned int len)
{
	struct wpa_used_freq_data *freqs_data;
	int num, i;

	os_memset(freq_array, 0, sizeof(int) * len);

	freqs_data = os_calloc(len, sizeof(struct wpa_used_freq_data));
	if (!freqs_data)
		return -1;

	num = get_shared_radio_freqs_data(wpa_s, freqs_data, len);
	for (i = 0; i < num; i++)
		freq_array[i] = freqs_data[i].freq;

	os_free(freqs_data);

	return num;
}
#endif


#if UNUSED_FEAT_IN_SUPP_29
struct wpa_supplicant *
wpas_vendor_elem(struct wpa_supplicant *wpa_s, enum wpa_vendor_elem_frame frame)
{
	switch (frame) {
#ifdef CONFIG_P2P
	case VENDOR_ELEM_PROBE_REQ_P2P:
	case VENDOR_ELEM_PROBE_RESP_P2P:
	case VENDOR_ELEM_PROBE_RESP_P2P_GO:
	case VENDOR_ELEM_BEACON_P2P_GO:
	case VENDOR_ELEM_P2P_PD_REQ:
	case VENDOR_ELEM_P2P_PD_RESP:
	case VENDOR_ELEM_P2P_GO_NEG_REQ:
	case VENDOR_ELEM_P2P_GO_NEG_RESP:
	case VENDOR_ELEM_P2P_GO_NEG_CONF:
	case VENDOR_ELEM_P2P_INV_REQ:
	case VENDOR_ELEM_P2P_INV_RESP:
	case VENDOR_ELEM_P2P_ASSOC_REQ:
	case VENDOR_ELEM_P2P_ASSOC_RESP:
		return wpa_s->p2pdev;
#endif /* CONFIG_P2P */
	default:
		return wpa_s;
	}
}

void wpas_vendor_elem_update(struct wpa_supplicant *wpa_s)
{
	unsigned int i;
	char buf[30];

	wpa_printf(MSG_DEBUG, "Update vendor elements");

	for (i = 0; i < NUM_VENDOR_ELEM_FRAMES; i++) {
		if (wpa_s->vendor_elem[i]) {
			int res;

			res = os_snprintf(buf, sizeof(buf), "frame[%u]", i);
			if (!os_snprintf_error(sizeof(buf), res)) {
				wpa_hexdump_buf(MSG_DEBUG, buf,
						wpa_s->vendor_elem[i]);
			}
		}
	}

#ifdef CONFIG_P2P
	if (wpa_s->parent == wpa_s &&
	    wpa_s->global->p2p &&
	    !wpa_s->global->p2p_disabled)
		p2p_set_vendor_elems(wpa_s->global->p2p, wpa_s->vendor_elem);
#endif /* CONFIG_P2P */
}


int wpas_vendor_elem_remove(struct wpa_supplicant *wpa_s, int frame,
			    const u8 *elem, size_t len)
{
	u8 *ie, *end;

	ie = wpabuf_mhead_u8(wpa_s->vendor_elem[frame]);
	end = ie + wpabuf_len(wpa_s->vendor_elem[frame]);

	for (; ie + 1 < end; ie += 2 + ie[1]) {
		if (ie + len > end)
			break;
		if (os_memcmp(ie, elem, len) != 0)
			continue;

		if (wpabuf_len(wpa_s->vendor_elem[frame]) == len) {
			wpabuf_free(wpa_s->vendor_elem[frame]);
			wpa_s->vendor_elem[frame] = NULL;
		} else {
			os_memmove(ie, ie + len, end - (ie + len));
			wpa_s->vendor_elem[frame]->used -= len;
		}
		wpas_vendor_elem_update(wpa_s);
		return 0;
	}

	return -1;
}

#endif

struct hostapd_hw_modes * get_mode(struct hostapd_hw_modes *modes,
				   u16 num_modes, enum hostapd_hw_mode mode)
{
	u16 i;

	for (i = 0; i < num_modes; i++) {
		if (modes[i].mode == mode)
			return &modes[i];
	}

	return NULL;
}


static struct
wpa_bss_tmp_disallowed * wpas_get_disallowed_bss(struct wpa_supplicant *wpa_s,
						 const u8 *bssid)
{
	struct wpa_bss_tmp_disallowed *bss;

	dl_list_for_each(bss, &wpa_s->bss_tmp_disallowed,
			 struct wpa_bss_tmp_disallowed, list) {
		if (os_memcmp(bssid, bss->bssid, ETH_ALEN) == 0)
			return bss;
	}

	return NULL;
}


static int wpa_set_driver_tmp_disallow_list(struct wpa_supplicant *wpa_s)
{
	struct wpa_bss_tmp_disallowed *tmp;
	unsigned int num_bssid = 0;
	u8 *bssids;
	int ret;

	bssids = os_malloc(dl_list_len(&wpa_s->bss_tmp_disallowed) * ETH_ALEN);
	if (!bssids)
		return -1;
	dl_list_for_each(tmp, &wpa_s->bss_tmp_disallowed,
			 struct wpa_bss_tmp_disallowed, list) {
		os_memcpy(&bssids[num_bssid * ETH_ALEN], tmp->bssid,
			  ETH_ALEN);
		num_bssid++;
	}
	ret = wpa_drv_set_bssid_blacklist(wpa_s, num_bssid, bssids);
	os_free(bssids);
	return ret;
}


static void wpa_bss_tmp_disallow_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct wpa_bss_tmp_disallowed *tmp, *bss = timeout_ctx;

	/* Make sure the bss is not already freed */
	dl_list_for_each(tmp, &wpa_s->bss_tmp_disallowed,
			 struct wpa_bss_tmp_disallowed, list) {
		if (bss == tmp) {
			dl_list_del(&tmp->list);
			os_free(tmp);
			wpa_set_driver_tmp_disallow_list(wpa_s);
			break;
		}
	}
}


void wpa_bss_tmp_disallow(struct wpa_supplicant *wpa_s, const u8 *bssid,
			  unsigned int sec, int rssi_threshold)
{
	struct wpa_bss_tmp_disallowed *bss;

	bss = wpas_get_disallowed_bss(wpa_s, bssid);
	if (bss) {
		eloop_cancel_timeout(wpa_bss_tmp_disallow_timeout, wpa_s, bss);
		goto finish;
	}

	bss = os_malloc(sizeof(*bss));
	if (!bss) {
		wpa_printf(MSG_DEBUG,
			   "Failed to allocate memory for temp disallow BSS");
		return;
	}

	os_memcpy(bss->bssid, bssid, ETH_ALEN);
	dl_list_add(&wpa_s->bss_tmp_disallowed, &bss->list);
	wpa_set_driver_tmp_disallow_list(wpa_s);

finish:
	bss->rssi_threshold = rssi_threshold;
	eloop_register_timeout(sec, 0, wpa_bss_tmp_disallow_timeout,
			       wpa_s, bss);
}

int wpa_is_bss_tmp_disallowed(struct wpa_supplicant *wpa_s,
			      struct wpa_bss *bss)
{
	struct wpa_bss_tmp_disallowed *disallowed = NULL, *tmp, *prev;

	dl_list_for_each_safe(tmp, prev, &wpa_s->bss_tmp_disallowed,
			 struct wpa_bss_tmp_disallowed, list) {
		if (os_memcmp(bss->bssid, tmp->bssid, ETH_ALEN) == 0) {
			disallowed = tmp;
			break;
		}
	}
	if (!disallowed)
		return 0;

	if (disallowed->rssi_threshold != 0 &&
	    bss->level > disallowed->rssi_threshold)
		return 0;

	return 1;
}


#if UNUSED_FEAT_IN_SUPP_29
int wpas_enable_mac_addr_randomization(struct wpa_supplicant *wpa_s,
				       unsigned int type, const u8 *addr,
				       const u8 *mask)
{
	if ((addr && !mask) || (!addr && mask)) {
		wpa_printf(MSG_INFO,
			   "MAC_ADDR_RAND_SCAN invalid addr/mask combination");
		return -1;
	}

	if (addr && mask && (!(mask[0] & 0x01) || (addr[0] & 0x01))) {
		wpa_printf(MSG_INFO,
			   "MAC_ADDR_RAND_SCAN cannot allow multicast address");
		return -1;
	}

	if (type & MAC_ADDR_RAND_SCAN) {
		if (wpas_mac_addr_rand_scan_set(wpa_s, MAC_ADDR_RAND_SCAN,
						addr, mask))
			return -1;
	}

	if (type & MAC_ADDR_RAND_SCHED_SCAN) {
		if (wpas_mac_addr_rand_scan_set(wpa_s, MAC_ADDR_RAND_SCHED_SCAN,
						addr, mask))
			return -1;

		if (wpa_s->sched_scanning && !wpa_s->pno)
			wpas_scan_restart_sched_scan(wpa_s);
	}

	if (type & MAC_ADDR_RAND_PNO) {
		if (wpas_mac_addr_rand_scan_set(wpa_s, MAC_ADDR_RAND_PNO,
						addr, mask))
			return -1;

		if (wpa_s->pno) {
			wpas_stop_pno(wpa_s);
			wpas_start_pno(wpa_s);
		}
	}

	return 0;
}


int wpas_disable_mac_addr_randomization(struct wpa_supplicant *wpa_s,
					unsigned int type)
{
	wpas_mac_addr_rand_scan_clear(wpa_s, type);
	if (wpa_s->pno) {
		if (type & MAC_ADDR_RAND_PNO) {
			wpas_stop_pno(wpa_s);
			wpas_start_pno(wpa_s);
		}
	} else if (wpa_s->sched_scanning && (type & MAC_ADDR_RAND_SCHED_SCAN)) {
		wpas_scan_restart_sched_scan(wpa_s);
	}

	return 0;
}
#endif
#ifdef CONFIG_SAE
static int index_within_array(const int *array, int idx)
{
	int i;
	for (i = 0; i < idx; i++) {
		if (array[i] <= 0)
			return 0;
	}
	return 1;
}
static int sme_set_sae_group(struct wpa_supplicant *wpa_s)
{
	int *groups = wpa_s->conf->sae_groups;
#ifdef SUPPLICANT_PORTING
	int default_groups[] = { 19, 0 };
#else
	int default_groups[] = { 19, 20, 21, 0 };
#endif
	if (!groups || groups[0] <= 0)
		groups = default_groups;
	if (!index_within_array(groups, wpa_s->sme.sae_group_index))
		return -1;
	for (;;) {
		int group = groups[wpa_s->sme.sae_group_index];
		if (group <= 0)
			break;
		if (sae_set_group(&wpa_s->sme.sae, group) == 0) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG, "SME: Selected SAE group %d",
					wpa_s->sme.sae.group);
#endif
			SL_PRINTF(WLAN_SUPP_SME_SELECTED_SAE_GROUP, WLAN_UMAC, LOG_INFO, "group %d", wpa_s->sme.sae.group);
			return 0;
		}
		wpa_s->sme.sae_group_index++;
	}
	return -1;
}
static struct wpabuf * sme_auth_build_sae_commit(struct wpa_supplicant *wpa_s,
		struct wpa_ssid *ssid,
		const u8 *bssid, int external,
		int reuse, int *ret_use_pt,
		Boolean *ret_use_pk)
{
	struct wpabuf *buf;
	size_t len;
	const char *password;
	struct wpa_bss *bss;
	int use_pt = 0;
	Boolean use_pk = FALSE;
	u8 rsnxe_capa = 0;

	if (ret_use_pt)
		*ret_use_pt = 0;
	if (ret_use_pk)
		*ret_use_pk = FALSE;
		
#ifdef CONFIG_TESTING_OPTIONS
	if (wpa_s->sae_commit_override) {
		wpa_printf(MSG_DEBUG, "SAE: TESTING - commit override");
		buf = wpabuf_alloc(4 + wpabuf_len(wpa_s->sae_commit_override));
		if (!buf)
			return NULL;
		if (!external) {
			wpabuf_put_le16(buf, 1); /* Transaction seq# */
			wpabuf_put_le16(buf, WLAN_STATUS_SUCCESS);
		}
		wpabuf_put_buf(buf, wpa_s->sae_commit_override);
		return buf;
	}
#endif /* CONFIG_TESTING_OPTIONS */
	password = ssid->sae_password;
	if (!password)
		password = ssid->passphrase;

	if (!password) {
		wpa_printf(MSG_DEBUG, "SAE: No password available");
		return NULL;
	}
	if (reuse && wpa_s->sme.sae.tmp &&
			os_memcmp(bssid, wpa_s->sme.sae.tmp->bssid, ETH_ALEN) == 0) {
		wpa_printf(MSG_DEBUG,
				"SAE: Reuse previously generated PWE on a retry with the same AP");
		use_pt = wpa_s->sme.sae.h2e;
		use_pk = wpa_s->sme.sae.pk;
		goto reuse_data;
	}
	if (sme_set_sae_group(wpa_s) < 0) {
		wpa_printf(MSG_DEBUG, "SAE: Failed to select group");
		return NULL;
	}
	
	bss = wpa_bss_get_bssid_latest(wpa_s, bssid);
	if (!bss) {
		wpa_printf(MSG_DEBUG,
			   "SAE: BSS not available, update scan result to get BSS");
		wpa_supplicant_update_scan_results(wpa_s);
		bss = wpa_bss_get_bssid_latest(wpa_s, bssid);
	}
	if (bss) {
		const u8 *rsnxe;

		rsnxe = wpa_bss_get_ie(bss, WLAN_EID_RSNX);
		if (rsnxe && rsnxe[1] >= 1)
			rsnxe_capa = rsnxe[2];
	}

		if (ssid->sae_password_id && wpa_s->conf->sae_pwe != 3)
		use_pt = 1;
#ifdef CONFIG_SAE_PK
	if ((rsnxe_capa & BIT(WLAN_RSNX_CAPAB_SAE_PK)) &&
	    ssid->sae_pk != SAE_PK_MODE_DISABLED &&
	    ((ssid->sae_password &&
	      sae_pk_valid_password(ssid->sae_password)) ||
	     (!ssid->sae_password && ssid->passphrase &&
	      sae_pk_valid_password(ssid->passphrase)))) {
		use_pt = 1;
		use_pk = true;
	}

	if (ssid->sae_pk == SAE_PK_MODE_ONLY && !use_pk) {
		wpa_printf(MSG_DEBUG,
			   "SAE: Cannot use PK with the selected AP");
		return NULL;
	}
#endif /* CONFIG_SAE_PK */
	
	if (use_pt || wpa_s->conf->sae_pwe == 1 || wpa_s->conf->sae_pwe == 2) {
		use_pt = !!(rsnxe_capa & BIT(WLAN_RSNX_CAPAB_SAE_H2E));

		if ((wpa_s->conf->sae_pwe == 1 || ssid->sae_password_id) &&
		    wpa_s->conf->sae_pwe != 3 &&
		    !use_pt) {
			wpa_printf(MSG_DEBUG,
				   "SAE: Cannot use H2E with the selected AP");
			return NULL;
		}
	}
	
	if (use_pt &&
	    sae_prepare_commit_pt(&wpa_s->sme.sae, ssid->pt,
				  wpa_s->own_addr, bssid,
				  wpa_s->sme.sae_rejected_groups, NULL) < 0)
		return NULL;
	if (!use_pt && 
	    sae_prepare_commit(wpa_s->own_addr, bssid,
				(u8 *) password, os_strlen(password),
				ssid->sae_password_id,
				&wpa_s->sme.sae) < 0) {
		wpa_printf(MSG_DEBUG, "SAE: Could not pick PWE");
		return NULL;
	}
	if (wpa_s->sme.sae.tmp) {
		os_memcpy(wpa_s->sme.sae.tmp->bssid, bssid, ETH_ALEN);
		if (use_pt && use_pk)
			wpa_s->sme.sae.pk = 1;
#ifdef CONFIG_SAE_PK
		os_memcpy(wpa_s->sme.sae.tmp->own_addr, wpa_s->own_addr,
			  ETH_ALEN);
		os_memcpy(wpa_s->sme.sae.tmp->peer_addr, bssid, ETH_ALEN);
		sae_pk_set_password(&wpa_s->sme.sae, password);
#endif /* CONFIG_SAE_PK */
	}
	
reuse_data:
	len = wpa_s->sme.sae_token ? wpabuf_len(wpa_s->sme.sae_token) : 0;
	if (ssid->sae_password_id)
		len += 4 + os_strlen(ssid->sae_password_id);
	buf = wpabuf_alloc(4 + SAE_COMMIT_MAX_LEN + len);
	if (buf == NULL)
		return NULL;
	if (!external) {
		wpabuf_put_le16(buf, 1); /* Transaction seq# */
		if (use_pk)
			wpabuf_put_le16(buf, WLAN_STATUS_SAE_PK);
		else if (use_pt)
			wpabuf_put_le16(buf, WLAN_STATUS_SAE_HASH_TO_ELEMENT);
		else
			wpabuf_put_le16(buf,WLAN_STATUS_SUCCESS);
	}
	sae_write_commit(&wpa_s->sme.sae, buf, wpa_s->sme.sae_token,
			ssid->sae_password_id);
	if (ret_use_pt)
		*ret_use_pt = use_pt;
	if (ret_use_pk)
		*ret_use_pk = use_pk;

	return buf;
}
static struct wpabuf * sme_auth_build_sae_confirm(struct wpa_supplicant *wpa_s,
		int external)
{
	struct wpabuf *buf;
	buf = wpabuf_alloc(4 + SAE_CONFIRM_MAX_LEN);
	if (buf == NULL)
		return NULL;
	if (!external) {
		wpabuf_put_le16(buf, 2); /* Transaction seq# */
		wpabuf_put_le16(buf, WLAN_STATUS_SUCCESS);
	}
	sae_write_confirm(&wpa_s->sme.sae, buf);
	return buf;
}
static int sme_external_auth_build_buf(struct wpabuf *buf,
				       struct wpabuf *params,
				       const u8 *sa, const u8 *da,
				       u16 auth_transaction, u16 seq_num,
				       u16 status_code)
{
	struct ieee80211_mgmt *resp;

	resp = wpabuf_put(buf, offsetof(struct ieee80211_mgmt,
					u.auth.variable));

	resp->frame_control = host_to_le16((WLAN_FC_TYPE_MGMT << 2) |
					   (WLAN_FC_STYPE_AUTH << 4));
	os_memcpy(resp->da, da, ETH_ALEN);
	os_memcpy(resp->sa, sa, ETH_ALEN);
	os_memcpy(resp->bssid, da, ETH_ALEN);
	resp->u.auth.auth_alg = host_to_le16(WLAN_AUTH_SAE);
	resp->seq_ctrl = host_to_le16(seq_num << 4);
	resp->u.auth.auth_transaction = host_to_le16(auth_transaction);
	resp->u.auth.status_code = host_to_le16(status_code);
	if (params)
		wpabuf_put_buf(buf, params);

	return 0;
}
static int sme_external_auth_send_sae_commit(struct wpa_supplicant *wpa_s,
					     const u8 *bssid,
					     struct wpa_ssid *ssid)
{
	struct wpabuf *resp, *buf;
	int use_pt;
	Boolean use_pk;
	u16 status;
	uint8 prev_sae_state = 0;

	resp = sme_auth_build_sae_commit(wpa_s, ssid, bssid, 1, 0, &use_pt,
					 &use_pk);
	if (!resp) {
		wpa_printf(MSG_DEBUG, "SAE: Failed to build SAE commit");
		return -1;
	}
	prev_sae_state = wpa_s->sme.sae.state;
	wpa_s->sme.sae.state = SAE_COMMITTED;
	if(prev_sae_state == SAE_NOTHING) {
		supp_mgmt_if_ctx.is_sae_commited = 1;
		sl_wpa_driver_wrapper(wpa_s, WPA_DRV_INDICATE_SAE_COMMITED_STATE, NULL);
	}
	buf = wpabuf_alloc(4 + SAE_COMMIT_MAX_LEN + wpabuf_len(resp));
	if (!buf) {
		wpabuf_free(resp);
		return -1;
	}

	wpa_s->sme.seq_num++;
	if (use_pk)
		status = WLAN_STATUS_SAE_PK;
	else if (use_pt)
		status = WLAN_STATUS_SAE_HASH_TO_ELEMENT;
	else
		status = WLAN_STATUS_SUCCESS;
	sme_external_auth_build_buf(buf, resp, wpa_s->own_addr,
				    bssid, 1, wpa_s->sme.seq_num, status);
	wpa_drv_send_mlme(wpa_s, wpabuf_head(buf), wpabuf_len(buf), 1, 0);
	wpabuf_free(resp);
	wpabuf_free(buf);

	return 0;
}
static void sme_send_external_auth_status(struct wpa_supplicant *wpa_s,
		u16 status)
{
	struct external_auth params;
	os_memset(&params, 0, sizeof(params));
	params.status = status;
	params.ssid = wpa_s->sme.ext_auth_ssid;
	params.ssid_len = wpa_s->sme.ext_auth_ssid_len;
	params.bssid = wpa_s->sme.ext_auth_bssid;
#if UNUSED_FEAT_IN_SUPP_29
	if (wpa_s->conf->sae_pmkid_in_assoc && status == WLAN_STATUS_SUCCESS)
		params.pmkid = wpa_s->sme.sae.pmkid;
#endif
	wpa_drv_send_external_auth_status(wpa_s, &params);
}
static int sme_handle_external_auth_start(struct wpa_supplicant *wpa_s,
					  union wpa_event_data *data)
{
	struct wpa_ssid *ssid;
	size_t ssid_str_len = data->external_auth.ssid_len;
	const u8 *ssid_str = data->external_auth.ssid;

	/* Get the SSID conf from the ssid string obtained */
	for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next) {
		if (!wpas_network_disabled(wpa_s, ssid) &&
		    ssid_str_len == ssid->ssid_len &&
		    os_memcmp(ssid_str, ssid->ssid, ssid_str_len) == 0 &&
		    (ssid->key_mgmt & (WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_FT_SAE)))
			break;
	}
	if (!ssid ||
	    sme_external_auth_send_sae_commit(wpa_s, data->external_auth.bssid,
					      ssid) < 0)
		return -1;

	return 0;
}

static void sme_external_auth_send_sae_confirm(struct wpa_supplicant *wpa_s,
		const u8 *da)
{
	struct wpabuf *resp, *buf;

	resp = sme_auth_build_sae_confirm(wpa_s, 1);
	if (!resp) {
		wpa_printf(MSG_DEBUG, "SAE: Confirm message buf alloc failure");
		return;
	}
	wpa_s->sme.sae.state = SAE_CONFIRMED;
	buf = wpabuf_alloc(4 + SAE_CONFIRM_MAX_LEN + wpabuf_len(resp));
	if (!buf) {
		wpa_printf(MSG_DEBUG, "SAE: Auth Confirm buf alloc failure");
		wpabuf_free(resp);
		return;
	}
	wpa_s->sme.seq_num++;
	sme_external_auth_build_buf(buf, resp, wpa_s->own_addr,
			da, 2, wpa_s->sme.seq_num, WLAN_STATUS_SUCCESS);
	wpa_drv_send_mlme(wpa_s, wpabuf_head(buf), wpabuf_len(buf), 1, 0);
	wpabuf_free(resp);
	wpabuf_free(buf);
}

static int sme_sae_is_group_enabled(struct wpa_supplicant *wpa_s, int group)
{
       int *groups = wpa_s->conf->sae_groups;
       int default_groups[] = { 19, 20, 21, 0 };
       int i;

       if (!groups)
               groups = default_groups;

       for (i = 0; groups[i] > 0; i++) {
               if (groups[i] == group)
                       return 1;
       }

       return 0;
}


static int sme_check_sae_rejected_groups(struct wpa_supplicant *wpa_s,
                                        const struct wpabuf *groups)
{
       size_t i, count;
       const u8 *pos;

       if (!groups)
               return 0;

       pos = wpabuf_head(groups);
       count = wpabuf_len(groups) / 2;
       for (i = 0; i < count; i++) {
               int enabled;
               u16 group;

               group = WPA_GET_LE16(pos);
               pos += 2;
               enabled = sme_sae_is_group_enabled(wpa_s, group);
               wpa_printf(MSG_DEBUG, "SAE: Rejected group %u is %s",
                          group, enabled ? "enabled" : "disabled");
               if (enabled)
                       return 1;
       }

       return 0;
}


void sme_external_auth_trigger(struct wpa_supplicant *wpa_s,
			       union wpa_event_data *data)
{
	uint8 prev_sae_state = 0;
#if  UNUSED_FEAT_IN_SUPP_29
	if (RSN_SELECTOR_GET(&data->external_auth.key_mgmt_suite) !=
	    RSN_AUTH_KEY_MGMT_SAE)
		return;
#endif
	if (data->external_auth.action == EXT_AUTH_START) {
		if (!data->external_auth.bssid || !data->external_auth.ssid)
			return;
		os_memcpy(wpa_s->sme.ext_auth_bssid, data->external_auth.bssid,
			  ETH_ALEN);
		os_memcpy(wpa_s->sme.ext_auth_ssid, data->external_auth.ssid,
			  data->external_auth.ssid_len);
		wpa_s->sme.ext_auth_ssid_len = data->external_auth.ssid_len;
		wpa_s->sme.seq_num = 0;
		prev_sae_state = wpa_s->sme.sae.state;
		wpa_s->sme.sae.state = SAE_NOTHING;
		if((prev_sae_state != wpa_s->sme.sae.state) && (prev_sae_state > SAE_NOTHING)) {
				supp_mgmt_if_ctx.is_sae_commited = 0;
				sl_wpa_driver_wrapper(wpa_s, WPA_DRV_INDICATE_SAE_COMMITED_STATE, NULL);
		}
		wpa_s->sme.sae.send_confirm = 0;
		wpa_s->sme.sae_group_index = 0;
		if (sme_handle_external_auth_start(wpa_s, data) < 0)
			sme_send_external_auth_status(wpa_s,
					      WLAN_STATUS_UNSPECIFIED_FAILURE);
	} else if (data->external_auth.action == EXT_AUTH_ABORT) {
		/* Report failure to driver for the wrong trigger */
		sme_send_external_auth_status(wpa_s,
					      WLAN_STATUS_UNSPECIFIED_FAILURE);
	}
}

static int sme_sae_auth(struct wpa_supplicant *wpa_s, u16 auth_transaction,
		u16 status_code, const u8 *data, size_t len,
        int external, const u8 *sa)
{
	int *groups;
#if UNUSED_FEAT_IN_SUPP_29
	wpa_dbg(wpa_s, MSG_DEBUG, "SME: SAE authentication transaction %u "
			"status code %u", auth_transaction, status_code);
#endif
	SL_PRINTF(WLAN_SUPP_SME_SAE_AUTHENTICATION, WLAN_UMAC, LOG_INFO, "transaction %d status code %d", auth_transaction, status_code);
	if (auth_transaction == 1 &&
		status_code == WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ &&
		wpa_s->sme.sae.state == SAE_COMMITTED &&
		(external || wpa_s->current_bss) && wpa_s->current_ssid) {
#ifdef SUPPLICANT_PORTING
	    int default_groups[] = { 19, 0 };
#else
	    int default_groups[] = { 19, 20, 21, 0 };
#endif
		u16 group;
		const u8 *token_pos;
		size_t token_len;
		int h2e = 0;
		groups = wpa_s->conf->sae_groups;
		if (!groups || groups[0] <= 0)
			groups = default_groups;
		wpa_hexdump(MSG_DEBUG, "SME: SAE anti-clogging token request",
                           data, len);
		if (len < sizeof(le16)) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_DEBUG,
					"SME: Too short SAE anti-clogging token request");
#endif
			SL_PRINTF(WLAN_SUPP_SME_TOO_SHORT_SAE_ANTI_CLOGGING_TOKEN_REQUEST, WLAN_UMAC, LOG_INFO);
			return -1;
		}
		group = WPA_GET_LE16(data);
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG,
				"SME: SAE anti-clogging token requested (group %u)",
				group);
#endif
		SL_PRINTF(WLAN_SUPP_SME_SAE_ANTI_CLOGGING_TOKEN_REQUESTED, WLAN_UMAC, LOG_INFO, "group: %d", group);
		if (sae_group_allowed(&wpa_s->sme.sae, groups, group) !=
				WLAN_STATUS_SUCCESS) {
#if UNUSED_FEAT_IN_SUPP_29
			wpa_dbg(wpa_s, MSG_ERROR,
					"SME: SAE group %u of anti-clogging request is invalid",
					group);
#endif
			SL_PRINTF(WLAN_SUPP_SME_SAE_GROUP_OF_ANTI_CLOGGING_REQUEST_IS_INVALID, WLAN_UMAC, LOG_ERROR, "group %d", group);
			return -1;
		}
		wpabuf_free(wpa_s->sme.sae_token);
		token_pos = data + sizeof(le16);
		token_len = len - sizeof(le16);
		h2e = wpa_s->sme.sae.h2e;
		if (h2e) {
				if (token_len < 3) {
						wpa_dbg(wpa_s, MSG_DEBUG,
								"SME: Too short SAE anti-clogging token container");
						return -1;
				}
				if (token_pos[0] != WLAN_EID_EXTENSION ||
					token_pos[1] == 0 ||
					token_pos[1] > token_len - 2 ||
					token_pos[2] != WLAN_EID_EXT_ANTI_CLOGGING_TOKEN) {
						wpa_dbg(wpa_s, MSG_DEBUG,
								"SME: Invalid SAE anti-clogging token container header");
						return -1;
				}
				token_len = token_pos[1] - 1;
				token_pos += 3;
		}
		wpa_s->sme.sae_token = wpabuf_alloc_copy(token_pos, token_len);
		wpa_hexdump_buf(MSG_DEBUG, "SME: Requested anti-clogging token",
                               wpa_s->sme.sae_token);
		sme_external_auth_send_sae_commit(
				wpa_s, wpa_s->sme.ext_auth_bssid,
				wpa_s->current_ssid);
		return 0;
	}
	if (auth_transaction == 1 &&
			status_code == WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED &&
			wpa_s->sme.sae.state == SAE_COMMITTED &&
			(external || wpa_s->current_bss) && wpa_s->current_ssid) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: SAE group not supported");
#endif
		SL_PRINTF(WLAN_SUPP_SME_SAE_GROUP_NOT_SUPPORTED, WLAN_UMAC, LOG_INFO);
		int_array_add_unique(&wpa_s->sme.sae_rejected_groups,
                                    wpa_s->sme.sae.group);
		wpa_s->sme.sae_group_index++;
		if (sme_set_sae_group(wpa_s) < 0){
			return -1; /* no other groups enabled */
        }
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "SME: Try next enabled SAE group");
#endif
		SL_PRINTF(WLAN_SUPP_SME_TRY_NEXT_ENABLED_SAE_GROUP, WLAN_UMAC, LOG_INFO);
		sme_external_auth_send_sae_commit(
				wpa_s, wpa_s->sme.ext_auth_bssid,
				wpa_s->current_ssid);
		return 0;
	}
	if (auth_transaction == 1 &&
			status_code == WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER) {
#if UNUSED_FEAT_IN_SUPP_29
		const u8 *bssid = sa ? sa : wpa_s->pending_bssid;
		wpa_msg(wpa_s, MSG_INFO,
				WPA_EVENT_SAE_UNKNOWN_PASSWORD_IDENTIFIER MACSTR,
				MAC2STR(bssid));
#endif
		return -1;
	}
	if (status_code != WLAN_STATUS_SUCCESS &&
		status_code != WLAN_STATUS_SAE_HASH_TO_ELEMENT &&
		status_code != WLAN_STATUS_SAE_PK) {
#if UNUSED_FEAT_IN_SUPP_29
			const u8 *bssid = sa ? sa : wpa_s->pending_bssid;
			wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_AUTH_REJECT MACSTR
					" auth_type=%u auth_transaction=%u status_code=%u",
					MAC2STR(bssid), WLAN_AUTH_SAE,
					auth_transaction, status_code);
#endif
			return -1;
       }
	if (auth_transaction == 1) {
		u16 res;
		groups = wpa_s->conf->sae_groups;
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "SME SAE commit");
#endif
		SL_PRINTF(WLAN_SUPP_SME_SAE_COMMIT, WLAN_UMAC, LOG_INFO);
		if ((!external && wpa_s->current_bss == NULL) ||
				 wpa_s->current_ssid == NULL)
				return -1;
		if (wpa_s->sme.sae.state != SAE_COMMITTED) {
				wpa_printf(MSG_DEBUG,
							"SAE: Ignore commit message while waiting for confirm");
				return 0;
		}
		if (wpa_s->sme.sae.h2e && status_code == WLAN_STATUS_SUCCESS) {
				wpa_printf(MSG_DEBUG,
							"SAE: Unexpected use of status code 0 in SAE commit when H2E was expected");
				return -1;
		}
		if ((!wpa_s->sme.sae.h2e || wpa_s->sme.sae.pk) &&
			status_code == WLAN_STATUS_SAE_HASH_TO_ELEMENT) {
				wpa_printf(MSG_DEBUG,
							"SAE: Unexpected use of status code for H2E in SAE commit when H2E was not expected");
				return -1;
		}
		if (!wpa_s->sme.sae.pk &&
			status_code == WLAN_STATUS_SAE_PK) {
				wpa_printf(MSG_DEBUG,
							"SAE: Unexpected use of status code for PK in SAE commit when PK was not expected");
				return -1;
		}
		if (groups && groups[0] <= 0)
			groups = NULL;
		res = sae_parse_commit(&wpa_s->sme.sae, data, len, NULL, NULL,
				       groups, status_code ==
				       WLAN_STATUS_SAE_HASH_TO_ELEMENT ||
				       status_code == WLAN_STATUS_SAE_PK);
		if (res == SAE_SILENTLY_DISCARD) {
			wpa_printf(MSG_DEBUG,
					"SAE: Drop commit message due to reflection attack");
			return 0;
		}
		if (res != WLAN_STATUS_SUCCESS)
			return -1;
		if (wpa_s->sme.sae.tmp &&
				sme_check_sae_rejected_groups(
						wpa_s,
						wpa_s->sme.sae.tmp->peer_rejected_groups))
					return -1;
		if (sae_process_commit(&wpa_s->sme.sae) < 0) {
			wpa_printf(MSG_DEBUG, "SAE: Failed to process peer "
					"commit");
			return -1;
		}
		wpabuf_free(wpa_s->sme.sae_token);
		wpa_s->sme.sae_token = NULL;
		sme_external_auth_send_sae_confirm(wpa_s, sa);
		return 0;
	} else if (auth_transaction == 2) {
#if UNUSED_FEAT_IN_SUPP_29
		wpa_dbg(wpa_s, MSG_DEBUG, "SME SAE confirm");
#endif
#ifdef SUPPLICANT_PORTING
	// If a CONFIRM 2 frame is recived when STA is in Accepted state, then the latest CONFIRM 2 frame is dropped
	if (wpa_s->sme.sae.state == SAE_ACCEPTED) {
			return 2;
	}
#endif
		SL_PRINTF(WLAN_SUPP_SME_SAE_CONFIRM, WLAN_UMAC, LOG_INFO);
		if (wpa_s->sme.sae.state != SAE_CONFIRMED){
#ifdef SUPPLICANT_PORTING
            return -2;
#else
			return -1;
#endif
        }
		if (sae_check_confirm(&wpa_s->sme.sae, data, len) < 0)
			return -1;
		wpa_s->sme.sae.state = SAE_ACCEPTED;
		sae_clear_temp_data(&wpa_s->sme.sae);
		if (external) {
			sme_send_external_auth_status(wpa_s,
					WLAN_STATUS_SUCCESS);
		}
		return 1;
	}
	return -1;
}

static int sme_sae_set_pmk(struct wpa_supplicant *wpa_s, const u8 *bssid)
{
	wpa_printf(MSG_DEBUG,
		   "SME: SAE completed - setting PMK for 4-way handshake");
	wpa_sm_set_pmk(wpa_s->wpa, wpa_s->sme.sae.pmk, PMK_LEN,
		       wpa_s->sme.sae.pmkid, bssid);
#if UNUSED_FEAT_IN_SUPP_29
	if (wpa_s->conf->sae_pmkid_in_assoc) {
		/* Update the own RSNE contents now that we have set the PMK
		 * and added a PMKSA cache entry based on the successfully
		 * completed SAE exchange. In practice, this will add the PMKID
		 * into RSNE. */
		if (wpa_s->sme.assoc_req_ie_len + 2 + PMKID_LEN >
		    sizeof(wpa_s->sme.assoc_req_ie)) {
			wpa_msg(wpa_s, MSG_WARNING,
				"RSN: Not enough room for inserting own PMKID into RSNE");
			return -1;
		}
		if (wpa_insert_pmkid(wpa_s->sme.assoc_req_ie,
				     &wpa_s->sme.assoc_req_ie_len,
				     wpa_s->sme.sae.pmkid) < 0)
			return -1;
		wpa_hexdump(MSG_DEBUG,
			    "SME: Updated Association Request IEs",
			    wpa_s->sme.assoc_req_ie,
			    wpa_s->sme.assoc_req_ie_len);
	}
#endif
	return 0;
}

void sme_external_auth_mgmt_rx(struct wpa_supplicant *wpa_s,
		const u8 *auth_frame, size_t len)
{
	const struct ieee80211_mgmt *header;
	size_t auth_length;
	header = (const struct ieee80211_mgmt *) auth_frame;
	auth_length = IEEE80211_HDRLEN + sizeof(header->u.auth);

	if(!wpa_s)
		return;

	if (len < auth_length) {
		sme_send_external_auth_status(wpa_s,
				WLAN_STATUS_UNSPECIFIED_FAILURE);
		return;
	}
	if (le_to_host16(header->u.auth.auth_alg) == WLAN_AUTH_SAE) {
		int res;
		res = sme_sae_auth(
				wpa_s, le_to_host16(header->u.auth.auth_transaction),
				le_to_host16(header->u.auth.status_code),
				header->u.auth.variable,
				len - auth_length, 1, header->sa);
		if (res < 0) {
            if(le_to_host16(header->u.auth.status_code) == WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED){
                sme_send_external_auth_status(
                        wpa_s, le_to_host16(header->u.auth.status_code));
            }
            else if (res == -2){
                sme_send_external_auth_status(
                         wpa_s, WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION);
            }
            else{
                sme_send_external_auth_status(
                        wpa_s, WLAN_STATUS_UNSPECIFIED_FAILURE);
            }
			return;
		}
		if (res != 1)
			return;
		wpa_printf(MSG_DEBUG,
				"SME: SAE completed - setting PMK for 4-way handshake");

		if (sme_sae_set_pmk(wpa_s, wpa_s->sme.ext_auth_bssid) < 0)
			return;
		
		sl_wpa_driver_wrapper(wpa_s, WPA_DRV_INDICATE_SAE_SUCC, NULL);
	}
}
#endif /* CONFIG_SAE */
