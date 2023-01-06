/**
 * @file
 *
 * @defgroup dhcp6 DHCPv6
 * @ingroup ip6
 * DHCPv6 client: IPv6 address autoconfiguration as per
 * RFC 3315 (stateful DHCPv6) and
 * RFC 3736 (stateless DHCPv6).
 *
 * TODO:
 * - enable/disable API to not always start when RA is received
 * - only start requests if a valid local address is available on the netif
 * - only start information requests if required (not for every RA)
 *
 * dhcp6_enable_stateful() enables stateful DHCPv6 for a netif (stateless disabled)\n
 * dhcp6_enable_stateless() enables stateless DHCPv6 for a netif (stateful disabled)\n
 * dhcp6_disable() disable DHCPv6 for a netif
 *
 * When enabled, requests are only issued after receipt of RA with the
 * corresponding bits set.
 */

/*
 * Copyright (c) 2018 Simon Goldschmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 */

#include "lwip/opt.h"

#if LWIP_IPV6 && LWIP_IPV6_DHCP6 /* don't build if not configured for use in lwipopts.h */

#include "lwip/dhcp6.h"
#include "lwip/prot/dhcp6.h"
#include "lwip/prot/iana.h"
#include "lwip/def.h"
#include "lwip/udp.h"
#include "lwip/dns.h"

#include <string.h>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif
#ifndef LWIP_HOOK_DHCP6_APPEND_OPTIONS
#define LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, state, msg, msg_type, options_len_ptr, max_len)
#endif
#ifndef LWIP_HOOK_DHCP6_PARSE_OPTION
#define LWIP_HOOK_DHCP6_PARSE_OPTION(netif, dhcp6, state, msg, msg_type, option, len, pbuf, offset) do { LWIP_UNUSED_ARG(msg); } while(0)
#endif

#if LWIP_DNS && LWIP_DHCP6_MAX_DNS_SERVERS
#if DNS_MAX_SERVERS > LWIP_DHCP6_MAX_DNS_SERVERS
#define LWIP_DHCP6_PROVIDE_DNS_SERVERS LWIP_DHCP6_MAX_DNS_SERVERS
#else
#define LWIP_DHCP6_PROVIDE_DNS_SERVERS DNS_MAX_SERVERS
#endif
#else
#define LWIP_DHCP6_PROVIDE_DNS_SERVERS 0
#endif


/** Option handling: options are parsed in dhcp6_parse_reply
 * and saved in an array where other functions can load them from.
 * This might be moved into the struct dhcp6 (not necessarily since
 * lwIP is single-threaded and the array is only used while in recv
 * callback). */
enum dhcp6_option_idx {
  DHCP6_OPTION_IDX_CLI_ID = 0,
  DHCP6_OPTION_IDX_SERVER_ID,
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
  DHCP6_OPTION_IDX_DNS_SERVER,
  DHCP6_OPTION_IDX_DOMAIN_LIST,
#endif /* LWIP_DHCP_PROVIDE_DNS_SERVERS */
#if LWIP_DHCP6_GET_NTP_SRV
  DHCP6_OPTION_IDX_NTP_SERVER,
#endif /* LWIP_DHCP_GET_NTP_SRV */
#if LWIP_IPV6_DHCP6_STATEFUL
  DHCP6_OPTION_IDX_PREFERENCE,
  DHCP6_OPTION_IDX_IA_NA,
  DHCP6_OPTION_IDX_STATUS_CODE,
#endif
  DHCP6_OPTION_IDX_MAX
};

struct dhcp6_option_info {
  u8_t option_given;
  u16_t val_start;
  u16_t val_length;
};

/** Holds the decoded option info, only valid while in dhcp6_recv. */
struct dhcp6_option_info dhcp6_rx_options[DHCP6_OPTION_IDX_MAX];

#define dhcp6_option_given(dhcp6, idx)           (dhcp6_rx_options[idx].option_given != 0)
#define dhcp6_got_option(dhcp6, idx)             (dhcp6_rx_options[idx].option_given = 1)
#define dhcp6_clear_option(dhcp6, idx)           (dhcp6_rx_options[idx].option_given = 0)
#define dhcp6_clear_all_options(dhcp6)           (memset(dhcp6_rx_options, 0, sizeof(dhcp6_rx_options)))
#define dhcp6_get_option_start(dhcp6, idx)       (dhcp6_rx_options[idx].val_start)
#define dhcp6_get_option_length(dhcp6, idx)      (dhcp6_rx_options[idx].val_length)
#define dhcp6_set_option(dhcp6, idx, start, len) do { dhcp6_rx_options[idx].val_start = (start); dhcp6_rx_options[idx].val_length = (len); }while(0)


const ip_addr_t dhcp6_All_DHCP6_Relay_Agents_and_Servers = IPADDR6_INIT_HOST(0xFF020000, 0, 0, 0x00010002);
const ip_addr_t dhcp6_All_DHCP6_Servers = IPADDR6_INIT_HOST(0xFF020000, 0, 0, 0x00010003);

static struct udp_pcb *dhcp6_pcb;
static u8_t dhcp6_pcb_refcount;

static sys_lock_t dhcp6_mutex;

/* receive, unfold, parse and free incoming messages */
static void dhcp6_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_globals *ip_data, u16_t port);

/** Ensure DHCP PCB is allocated and bound */
static err_t
dhcp6_inc_pcb_refcount(void)
{
  if (dhcp6_pcb_refcount == 0) {
    LWIP_ASSERT("dhcp6_inc_pcb_refcount(): memory leak", dhcp6_pcb == NULL);

    /* allocate UDP PCB */
    dhcp6_pcb = udp_new_ip6();

    if (dhcp6_pcb == NULL) {
      return ERR_MEM;
    }

    ip_set_option(dhcp6_pcb, SOF_BROADCAST);

    /* set up local and remote port for the pcb -> listen on all interfaces on all src/dest IPs */
    udp_bind(dhcp6_pcb, IP6_ADDR_ANY, DHCP6_CLIENT_PORT);
    udp_recv(dhcp6_pcb, dhcp6_recv, NULL);
  }

  dhcp6_pcb_refcount++;

  return ERR_OK;
}

/** Free DHCP PCB if the last netif stops using it */
static void
dhcp6_dec_pcb_refcount(void)
{
  LWIP_ASSERT("dhcp6_pcb_refcount(): refcount error", (dhcp6_pcb_refcount > 0));
  dhcp6_pcb_refcount--;

  if (dhcp6_pcb_refcount == 0) {
    udp_remove(dhcp6_pcb);
    dhcp6_pcb = NULL;
  }
}

/**
 * @ingroup dhcp6
 * Set a statically allocated struct dhcp6 to work with.
 * Using this prevents dhcp6_start to allocate it using mem_malloc.
 *
 * @param netif the netif for which to set the struct dhcp
 * @param dhcp6 (uninitialised) dhcp6 struct allocated by the application
 */
void
dhcp6_set_struct(struct netif *netif, struct dhcp6 *dhcp6)
{
  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("dhcp6 != NULL", dhcp6 != NULL);
  LWIP_ASSERT("netif already has a struct dhcp6 set", netif_dhcp6_data(netif) == NULL);

  /* clear data structure */
  memset(dhcp6, 0, sizeof(struct dhcp6));
  /* dhcp6_set_state(&dhcp, DHCP6_STATE_OFF); */
  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, dhcp6);
}

/**
 * @ingroup dhcp6
 * Removes a struct dhcp6 from a netif.
 *
 * ATTENTION: Only use this when not using dhcp6_set_struct() to allocate the
 *            struct dhcp6 since the memory is passed back to the heap.
 *
 * @param netif the netif from which to remove the struct dhcp
 */
void dhcp6_cleanup(struct netif *netif)
{
  LWIP_ASSERT("netif != NULL", netif != NULL);

  SYS_ARCH_LOCK(&dhcp6_mutex);
  if (netif_dhcp6_data(netif) != NULL) {
    mem_free(netif_dhcp6_data(netif));
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, NULL);
  }
  SYS_ARCH_UNLOCK(&dhcp6_mutex);
}

static struct dhcp6*
dhcp6_get_struct(struct netif *netif, const char *dbg_requester)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
  if (dhcp6 == NULL) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("%s: mallocing new DHCPv6 client\n", dbg_requester));
    dhcp6 = (struct dhcp6 *)mem_malloc(sizeof(struct dhcp6));
    if (dhcp6 == NULL) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("%s: could not allocate dhcp6\n", dbg_requester));
      return NULL;
    }

    /* clear data structure, this implies DHCP6_STATE_OFF */
    memset(dhcp6, 0, sizeof(struct dhcp6));
    /* store this dhcp6 client in the netif */
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, dhcp6);
  } else {
    /* already has DHCP6 client attached */
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("%s: using existing DHCPv6 client\n", dbg_requester));
  }

  if (!dhcp6->pcb_allocated) {
    if (dhcp6_inc_pcb_refcount() != ERR_OK) { /* ensure DHCP6 PCB is allocated */
      mem_free(dhcp6);
      netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6, NULL);
      return NULL;
    }
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("%s: allocated dhcp6", dbg_requester));
    dhcp6->pcb_allocated = 1;
  }
  return dhcp6;
}

/*
 * Set the DHCPv6 state
 * If the state changed, reset the number of tries.
 */
static void
dhcp6_set_state(struct dhcp6 *dhcp6, u8_t new_state, const char *dbg_caller)
{
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("DHCPv6 state: %d -> %d (%s)\n",
    dhcp6->state, new_state, dbg_caller));
  if (new_state != dhcp6->state) {
    dhcp6->state = new_state;
    dhcp6->tries = 0;
    dhcp6->request_timeout = 0;
#if LWIP_IPV6_DHCP6_STATEFUL
    dhcp6->elapsed_time = 0;
#endif
  }
}

static int
dhcp6_stateless_enabled(struct dhcp6 *dhcp6)
{
  if ((dhcp6->state == DHCP6_STATE_STATELESS_IDLE) ||
      (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG)) {
    return 1;
  }
  return 0;
}

/**
 * Create a DHCPv6 request, fill in common headers
 *
 * @param netif the netif under DHCPv6 control
 * @param dhcp6 dhcp6 control struct
 * @param message_type message type of the request
 * @param opt_len_alloc option length to allocate
 * @param options_out_len option length on exit
 * @return a pbuf for the message
 */
static struct pbuf *
dhcp6_create_msg(struct netif *netif, struct dhcp6 *dhcp6, u8_t message_type,
                 u16_t opt_len_alloc, u16_t *options_out_len)
{
  struct pbuf *p_out;
  struct dhcp6_msg *msg_out;

  LWIP_ERROR("dhcp6_create_msg: netif != NULL", (netif != NULL), return NULL;);
  LWIP_ERROR("dhcp6_create_msg: dhcp6 != NULL", (dhcp6 != NULL), return NULL;);
  p_out = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcp6_msg) + opt_len_alloc, PBUF_RAM);
  if (p_out == NULL) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp6_create_msg(): could not allocate pbuf\n"));
    return NULL;
  }
  LWIP_ASSERT("dhcp6_create_msg: check that first pbuf can hold struct dhcp6_msg",
              (p_out->len >= sizeof(struct dhcp6_msg) + opt_len_alloc));

  /* @todo: limit new xid for certain message types? */
  /* reuse transaction identifier in retransmissions */
  if (dhcp6->tries == 0) {
    dhcp6->xid = LWIP_RAND() & 0xFFFFFF;
  }

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
              ("transaction id xid(%"X32_F")\n", dhcp6->xid));

  msg_out = (struct dhcp6_msg *)p_out->payload;
  memset(msg_out, 0, sizeof(struct dhcp6_msg) + opt_len_alloc);

  msg_out->msgtype = message_type;
  msg_out->transaction_id[0] = (u8_t)(dhcp6->xid >> 16);
  msg_out->transaction_id[1] = (u8_t)(dhcp6->xid >> 8);
  msg_out->transaction_id[2] = (u8_t)dhcp6->xid;
  *options_out_len = 0;
  return p_out;
}

static u16_t
dhcp6_option_short(u16_t options_out_len, u8_t *options, u16_t value)
{
  options[options_out_len++] = (u8_t)((value & 0xff00U) >> 8);
  options[options_out_len++] = (u8_t) (value & 0x00ffU);
  return options_out_len;
}

static u16_t
dhcp6_option_optionrequest(u16_t options_out_len, u8_t *options, const u16_t *req_options,
                           u16_t num_req_options, u16_t max_len)
{
  size_t i;
  u16_t ret;

  LWIP_ASSERT("dhcp6_option_optionrequest: options_out_len + sizeof(struct dhcp6_msg) + addlen <= max_len",
    sizeof(struct dhcp6_msg) + options_out_len + 4U + (2U * num_req_options) <= max_len);
  LWIP_UNUSED_ARG(max_len);

  ret = dhcp6_option_short(options_out_len, options, DHCP6_OPTION_ORO);
  ret = dhcp6_option_short(ret, options, 2 * num_req_options);
  for (i = 0; i < num_req_options; i++) {
    ret = dhcp6_option_short(ret, options, req_options[i]);
  }
  return ret;
}

/* All options are added, shrink the pbuf to the required size */
static void
dhcp6_msg_finalize(u16_t options_out_len, struct pbuf *p_out)
{
  /* shrink the pbuf to the actual content length */
  pbuf_realloc(p_out, (u16_t)(sizeof(struct dhcp6_msg) + options_out_len));
}

static void
dhcp6_set_req_timeout(struct dhcp6 *dhcp6, u16_t initial_rt, u16_t max_rt)
{
  u32_t secs;
  u32_t msecs;

  LWIP_ASSERT("dhcp6->tries > 0", dhcp6->tries > 0);
  secs = (dhcp6->tries < 16) ? (initial_rt << (dhcp6->tries - 1)) : max_rt;
  if (secs > max_rt) {
      secs = max_rt;
  }
  msecs = secs * 1000;
  msecs += (((u64_t)LWIP_RAND() * msecs / 5) >> 32) - msecs / 10; /* Apply +-0.1 random factor */
  dhcp6->request_timeout = (u16_t)((msecs + DHCP6_TIMER_MSECS - 1) / DHCP6_TIMER_MSECS);
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
              ("set request timeout to %"U32_F" msecs\n", msecs));
}

#if LWIP_IPV6_DHCP6_STATEFUL

static u16_t
dhcp6_option_long(u16_t options_out_len, u8_t *options, u32_t value)
{
  u32_t nvalue = htonl(value);

  memcpy(&options[options_out_len], &nvalue, sizeof(u32_t));
  return (options_out_len + sizeof(u32_t));
}

static u16_t
dhcp6_option_clientid(struct netif *netif, u16_t opt_out_len, u8_t *options, u16_t max_len)
{
  LWIP_ASSERT("dhcp6_option_clientid: opt_out_len + sizeof(struct dhcp6_msg) + addlen <= max_len",
    sizeof(struct dhcp6_msg) + opt_out_len + 4 + 4 + NETIF_MAX_HWADDR_LEN <= max_len);
  LWIP_UNUSED_ARG(max_len);

  /* Generates the DUID from the link-layer address (DUID-LL). */
  opt_out_len = dhcp6_option_short(opt_out_len, options, DHCP6_OPTION_CLIENTID);
  opt_out_len = dhcp6_option_short(opt_out_len, options, 4 + NETIF_MAX_HWADDR_LEN);
  opt_out_len = dhcp6_option_short(opt_out_len, options, DHCP6_DUID_LL);
  opt_out_len = dhcp6_option_short(opt_out_len, options, LWIP_IANA_HWTYPE_ETHERNET);
  memcpy(&options[opt_out_len], netif->hwaddr, NETIF_MAX_HWADDR_LEN);
  return (opt_out_len + NETIF_MAX_HWADDR_LEN);
}

static u16_t
dhcp6_option_serverid(struct dhcp6 *dhcp6, u16_t opt_out_len, u8_t *options, u16_t max_len)
{
  LWIP_ASSERT("dhcp6_option_serverid: opt_out_len + sizeof(struct dhcp6_msg) + addlen <= max_len",
    sizeof(struct dhcp6_msg) + opt_out_len + 4 + dhcp6->server_id_len <= max_len);
  LWIP_UNUSED_ARG(max_len);

  opt_out_len = dhcp6_option_short(opt_out_len, options, DHCP6_OPTION_SERVERID);
  opt_out_len = dhcp6_option_short(opt_out_len, options, dhcp6->server_id_len);
  memcpy(&options[opt_out_len], dhcp6->server_id, dhcp6->server_id_len);
  return (opt_out_len + dhcp6->server_id_len);
}

static u16_t
dhcp6_option_elapsed_time(struct dhcp6 *dhcp6, u16_t opt_out_len, u8_t *options, u16_t max_len)
{
  u32_t elapsed_time = dhcp6->elapsed_time * DHCP6_TIMER_MSECS / 10;    /* hundredths of a second */

  LWIP_ASSERT("dhcp6_option_elapsed_time: options_out_len + sizeof(struct dhcp6_msg) + addlen <= max_len",
    sizeof(struct dhcp6_msg) + opt_out_len + 4 + 2 <= max_len);
  LWIP_UNUSED_ARG(max_len);

  opt_out_len = dhcp6_option_short(opt_out_len, options, DHCP6_OPTION_ELAPSED_TIME);
  opt_out_len = dhcp6_option_short(opt_out_len, options, 2);
  if (elapsed_time > 0xFFFF) {
    elapsed_time = 0xFFFF;
  }
  opt_out_len = dhcp6_option_short(opt_out_len, options, elapsed_time);
  return opt_out_len;
}

static u16_t
dhcp6_option_ia_na(u32_t iaid, ip6_addr_t *addr, u16_t opt_out_len, u8_t *options, u16_t max_len)
{
  u16_t opt_len = 12 + (addr ? 4 + sizeof(addr->addr) + 8 : 0);

  LWIP_ASSERT("dhcp6_option_ia_na: options_out_len + sizeof(struct dhcp6_msg) + addlen <= max_len",
    sizeof(struct dhcp6_msg) + opt_out_len + 4 + opt_len <= max_len);
  LWIP_UNUSED_ARG(max_len);

  opt_out_len = dhcp6_option_short(opt_out_len, options, DHCP6_OPTION_IA_NA);
  opt_out_len = dhcp6_option_short(opt_out_len, options, opt_len);
  opt_out_len = dhcp6_option_long(opt_out_len, options, iaid);
  opt_out_len = dhcp6_option_long(opt_out_len, options, 0); /* T1 */
  opt_out_len = dhcp6_option_long(opt_out_len, options, 0); /* T2 */
  if (addr) {
    opt_out_len = dhcp6_option_short(opt_out_len, options, DHCP6_OPTION_IAADDR);
    opt_out_len = dhcp6_option_short(opt_out_len, options, sizeof(addr->addr) + 8);
    memcpy(&options[opt_out_len], &addr->addr, sizeof(addr->addr));
    opt_out_len += sizeof(addr->addr);
    opt_out_len = dhcp6_option_long(opt_out_len, options, 0); /* preferred-lifetime */
    opt_out_len = dhcp6_option_long(opt_out_len, options, 0); /* valid-lifetime */
  }
  return opt_out_len;
}

static u32_t dhcp6_get_addr_timer(u32_t seconds)
{
  u64_t timer;

  if (seconds == IP6_ADDR_LIFE_INFINITE) {
    return IP6_ADDR_LIFE_INFINITE;
  }
  if (seconds == 0) {
    /* Pick a random time (used for renew requests). */
    return (LWIP_RAND() & 0xFF);
  }
  timer = seconds * 1000ULL / DHCP6_TIMER_MSECS;
  if (timer >= IP6_ADDR_LIFE_INFINITE) {
    return (IP6_ADDR_LIFE_INFINITE - 1);
  } else {
    return (u32_t)timer;
  }
}

static void
dhcp6_solicit(struct netif *netif, struct dhcp6 *dhcp6)
{
  struct pbuf *p_out;
  u16_t opt_out_len;

  dhcp6_set_state(dhcp6, DHCP6_STATE_SOLICIT, "dhcp6_solicit");
  p_out = dhcp6_create_msg(netif, dhcp6, DHCP6_SOLICIT,
    4 + 4 + NETIF_MAX_HWADDR_LEN /* CLIENTID */ + 4 + 2 /* ELAPSED_TIME */ + 4 + 12 /* IA_NA */,
    &opt_out_len);
  if (p_out != NULL) {
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);
    err_t err;

    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_solicit: making request\n"));
    opt_out_len = dhcp6_option_clientid(netif, opt_out_len, options, p_out->len);
    opt_out_len = dhcp6_option_elapsed_time(dhcp6, opt_out_len, options, p_out->len);
    opt_out_len = dhcp6_option_ia_na(0, NULL, opt_out_len, options, p_out->len);
    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_SOLICIT, msg_out, DHCP6_SOLICIT,
                                   opt_out_len, p_out->len);
    dhcp6_msg_finalize(opt_out_len, p_out);
    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers,
      DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
                ("dhcp6_solicit: udp_send -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  } else {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
      ("dhcp6_solicit: could not allocate DHCP6 request\n"));
  }
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
  dhcp6_set_req_timeout(dhcp6, 1, 3600);
}

static void
dhcp6_request(struct netif *netif, struct dhcp6 *dhcp6, u8_t req_type)
{
  struct pbuf *p_out;
  u16_t opt_len, opt_out_len;

  opt_len = 4 + 4 + NETIF_MAX_HWADDR_LEN /* CLIENTID */ +
      4 + 2 /* ELAPSED_TIME */ +
      4 + 12 + 4 + sizeof(ip6_addr_t) + 8 /* IA_NA with one encapsulated IAADDR */;
  if (dhcp6->server_id_len) {
    opt_len += 4 + dhcp6->server_id_len /* SERVERID */;
  }
  p_out = dhcp6_create_msg(netif, dhcp6, req_type, opt_len, &opt_out_len);
  if (p_out != NULL) {
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);
    err_t err;

    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_request: making request\n"));
    opt_out_len = dhcp6_option_clientid(netif, opt_out_len, options, p_out->len);
    opt_out_len = dhcp6_option_elapsed_time(dhcp6, opt_out_len, options, p_out->len);
    if (dhcp6->server_id_len) {
      opt_out_len = dhcp6_option_serverid(dhcp6, opt_out_len, options, p_out->len);
    }
    opt_out_len = dhcp6_option_ia_na(dhcp6->iaid, &dhcp6->addr, opt_out_len, options, p_out->len);
    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_REQUESTING_ADDR, msg_out,
                                   req_type, opt_out_len, p_out->len);
    dhcp6_msg_finalize(opt_out_len, p_out);
    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers,
      DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
                ("dhcp6_request: udp_send -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  } else {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
      ("dhcp6_request: could not allocate DHCP6 request\n"));
  }
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
}

static void
dhcp6_request_addr(struct netif *netif, struct dhcp6 *dhcp6)
{
  dhcp6_set_state(dhcp6, DHCP6_STATE_REQUESTING_ADDR, "dhcp6_request_addr");
  dhcp6_request(netif, dhcp6, DHCP6_REQUEST);
  dhcp6_set_req_timeout(dhcp6, 1, 30);
}

static void
dhcp6_renew(struct netif *netif, struct dhcp6 *dhcp6)
{
  dhcp6_set_state(dhcp6, DHCP6_STATE_RENEW, "dhcp6_renew");
  dhcp6_request(netif, dhcp6, DHCP6_RENEW);
  dhcp6_set_req_timeout(dhcp6, 10, 600);
}

static void
dhcp6_rebind(struct netif *netif, struct dhcp6 *dhcp6)
{
  dhcp6->server_id_len = 0; /* forget any known server */
  dhcp6_set_state(dhcp6, DHCP6_STATE_REBIND, "dhcp6_rebind");
  dhcp6_request(netif, dhcp6, DHCP6_REBIND);
  dhcp6_set_req_timeout(dhcp6, 10, 600);
}

static void
dhcp6_handle_advertise(struct netif *netif, struct pbuf *p_msg_in)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
  u8_t pref = 0;
  u16_t op_len, op_start;
  u16_t server_id_len, server_id_start;
  u32_t iaid;
  u16_t addr_start = 0;

  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_PREFERENCE)) {
    op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_PREFERENCE);
    if (op_len == 1) {
      op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_PREFERENCE);
      pref = pbuf_get_at(p_msg_in, op_start);
    }
  }
  if (((dhcp6->preference > 0) && (pref <= dhcp6->preference)) ||
      !dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_SERVER_ID) ||
      !dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_IA_NA)) {
    return;
  }
  server_id_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_SERVER_ID);
  if (server_id_len > sizeof(dhcp6->server_id)) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
      ("dhcp6_handle_advertise: server ID length %"U16_F" too large\n", server_id_len));
    return;
  }
  op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_IA_NA);

  /* The IA_NA option must contain at least one encapsulated IA Address option. */
  if (op_len >= 12 + 12 + sizeof(dhcp6->addr.addr)) {
    u16_t ia_na_opt;

    op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_IA_NA);
    ia_na_opt = op_start + 12;  /* IA_NA-options start after IAID, T1, T2 */
    pbuf_copy_partial(p_msg_in, &iaid, sizeof(iaid), op_start);
    while (ia_na_opt + 12 + sizeof(dhcp6->addr.addr) <= op_start + op_len) {
      u16_t op;
      u16_t len;

      pbuf_copy_partial(p_msg_in, &op, 2, ia_na_opt);
      op = ntohs(op);
      pbuf_copy_partial(p_msg_in, &len, 2, ia_na_opt + 2);
      len = ntohs(len);
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_TRACE,
        ("dhcp6_handle_advertise: IA_NA option %"U16_F", length %"U16_F"\n", op, len));
      if ((op == DHCP6_OPTION_IAADDR) && (len >= sizeof(dhcp6->addr.addr) + 8)) {
        addr_start = ia_na_opt + 4;
        break;
      }
      ia_na_opt += 4 + len;
    }
  } else {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
      ("dhcp6_handle_advertise: IA_NA option length %"U16_F" too small\n", op_len));
  }
  if (!addr_start) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
      ("dhcp6_handle_advertise: IP address not found\n"));
    return;
  }
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_TRACE,
    ("dhcp6_handle_advertise: setting preferred server (preference %"U16_F", "
    "previous preference %"U16_F")\n", (u16_t)pref, (u16_t)dhcp6->preference));
  dhcp6->preference = pref;
  server_id_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_SERVER_ID);
  pbuf_copy_partial(p_msg_in, &dhcp6->server_id, server_id_len, server_id_start);
  dhcp6->server_id_len = server_id_len;
  dhcp6->iaid = ntohl(iaid);
  pbuf_copy_partial(p_msg_in, &dhcp6->addr.addr, sizeof(dhcp6->addr.addr), addr_start);
  if ((pref == 255) || (dhcp6->tries > 1)) {
    dhcp6_request_addr(netif, dhcp6);
  }
}

static void
dhcp6_handle_reply(struct netif *netif, struct pbuf *p_msg_in)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
  u16_t op_len, op_start;
  u16_t status_code;

  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE)) {
    op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE);
    if (op_len < sizeof(status_code)) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        ("dhcp6_handle_reply: invalid length %"U16_F" of status code option\n", op_len));
      return;
    }
    op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE);
    pbuf_copy_partial(p_msg_in, &status_code, sizeof(status_code), op_start);
    status_code = ntohs(status_code);
    if (status_code != DHCP6_STATUS_SUCCESS) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        ("dhcp6_handle_reply: status code %"U16_F"\n", status_code));
      return;
    }
  }
  if (!dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_IA_NA)) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
      ("dhcp6_handle_reply: missing IA_NA option\n"));
    return;
  }
  op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_IA_NA);

  /* The IA_NA option must contain at least one encapsulated IA Address option. */
  if (op_len >= 12 + 12 + sizeof(dhcp6->addr.addr)) {
    u32_t t1, t2;
    u16_t ia_na_opt;
    u32_t pref_life, valid_life;
    int addr_found = 0;
    err_t err;
    s8_t addr_idx;

    op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_IA_NA);
    pbuf_copy_partial(p_msg_in, &t1, sizeof(t1), op_start + 4);
    t1 = ntohl(t1);
    pbuf_copy_partial(p_msg_in, &t2, sizeof(t2), op_start + 8);
    t2 = ntohl(t2);
    if (t1 > t2) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        ("dhcp6_handle_reply: T1 (%"U32_F") > T2 (%"U32_F")\n", t1, t2));
      return;
    }
    ia_na_opt = op_start + 12;
    while (ia_na_opt + 12 + sizeof(dhcp6->addr.addr) <= op_start + op_len) {
      u16_t op;
      u16_t len;

      pbuf_copy_partial(p_msg_in, &op, sizeof(op), ia_na_opt);
      op = ntohs(op);
      pbuf_copy_partial(p_msg_in, &len, sizeof(len), ia_na_opt + 2);
      len = ntohs(len);
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_TRACE,
        ("dhcp6_handle_reply: IA_NA option %"U16_F", length %"U16_F"\n", op, len));
      switch (op) {
      case DHCP6_OPTION_IAADDR:
        if (len < sizeof(dhcp6->addr.addr) + 8) {
          LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
            ("dhcp6_handle_reply: invalid length %"U16_F" of IA Address option\n", len));
          return;
        }
        pbuf_copy_partial(p_msg_in, &pref_life, sizeof(pref_life),
                          ia_na_opt + sizeof(dhcp6->addr.addr));
        pref_life = ntohl(pref_life);
        pbuf_copy_partial(p_msg_in, &valid_life, sizeof(valid_life),
                          ia_na_opt + sizeof(dhcp6->addr.addr) + 4);
        valid_life = ntohl(valid_life);
        addr_found = 1;
        break;
      case DHCP6_OPTION_STATUS_CODE:
        if (len < sizeof(status_code)) {
          LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
            ("dhcp6_handle_reply: invalid length %"U16_F" of status code IA_NA option\n", len));
          return;
        }
        pbuf_copy_partial(p_msg_in, &status_code, sizeof(status_code), ia_na_opt + 4);
        status_code = ntohs(status_code);
        if (status_code != DHCP6_STATUS_SUCCESS) {
          LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
            ("dhcp6_handle_reply: status code %"U16_F" in IA_NA option\n", status_code));
          return;
        }
        break;
      }
      ia_na_opt += 4 + len;
    }
    if (!addr_found) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        ("dhcp6_handle_reply: no IP address found\n"));
      return;
    }
    err = netif_add_ip6_address(netif, &dhcp6->addr, &addr_idx);
    if (err == ERR_OK) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_TRACE,
        ("dhcp6_handle_reply: IP address assigned, preferred life %"U32_F", valid life %"U32_F", "
        "T1 %"U32_F", T2 %"U32_F"\n", pref_life, valid_life, t1, t2));
      netif_ip6_addr_set_pref_life(netif, addr_idx, pref_life);
      netif_ip6_addr_set_valid_life(netif, addr_idx, valid_life);
      dhcp6->t1 = dhcp6_get_addr_timer(t1);
      dhcp6->t2 = dhcp6_get_addr_timer(t2);
      dhcp6->addr_idx = addr_idx;
    } else {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
        ("dhcp6_handle_reply: could not add IP address (%d)\n", (int)err));
    }
    dhcp6_set_state(dhcp6, DHCP6_STATE_STATEFUL_IDLE, "dhcp6_handle_reply");
  }
}

static int
dhcp6_stateful_enabled(struct dhcp6 *dhcp6)
{
  if (dhcp6->state == DHCP6_STATE_OFF) {
    return 0;
  }
  if (dhcp6_stateless_enabled(dhcp6)) {
    return 0;
  }
  return 1;
}

static void
dhcp6_stateful_init(struct netif *netif, struct dhcp6 *dhcp6)
{
  dhcp6->preference = 0;
  ip6_addr_set_zero(&dhcp6->addr);
  dhcp6_solicit(netif, dhcp6);
}

#endif

/**
 * @ingroup dhcp6
 * Enable stateful DHCPv6 on this netif
 * Requests are sent on receipt of an RA message with the
 * ND6_RA_FLAG_MANAGED_ADDR_CONFIG flag set.
 *
 * A struct dhcp6 will be allocated for this netif if not
 * set via @ref dhcp6_set_struct before.
 *
 * @todo: stateful DHCPv6 not supported, yet
 */
err_t
dhcp6_enable_stateful(struct netif *netif)
{
#if LWIP_IPV6_DHCP6_STATEFUL
  err_t err;
  SYS_ARCH_LOCK(&dhcp6_mutex);
  struct dhcp6 *dhcp6 = dhcp6_get_struct(netif, "dhcp6_enable_stateful");
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
    ("dhcp6_enable_stateful(%c%c%"U16_F")\n", netif->name[0], netif->name[1], (u16_t)netif->num));
  if (dhcp6 == NULL) {
    err = ERR_MEM;
    goto out;
  }
  if (dhcp6_stateful_enabled(dhcp6)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE,
      ("dhcp6_enable_stateful: stateful DHCPv6 already enabled\n"));
    err = ERR_OK;
    goto out;
  } else if (dhcp6->state != DHCP6_STATE_OFF) {
    /* stateless running */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE,
      ("dhcp6_enable_stateful: switching from stateless to stateful DHCPv6\n"));
  }
  dhcp6_stateful_init(netif, dhcp6);
  err = ERR_OK;
out:
  SYS_ARCH_UNLOCK(&dhcp6_mutex);
  return err;
#else
  LWIP_UNUSED_ARG(netif);
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("stateful DHCPv6 not enabled\n"));
  return ERR_VAL;
#endif
}

/**
 * @ingroup dhcp6
 * Enable stateless DHCPv6 on this netif
 * Requests are sent on receipt of an RA message with the
 * ND6_RA_FLAG_OTHER_CONFIG flag set.
 *
 * A struct dhcp6 will be allocated for this netif if not
 * set via @ref dhcp6_set_struct before.
 */
err_t
dhcp6_enable_stateless(struct netif *netif)
{
  struct dhcp6 *dhcp6;
  err_t err;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_enable_stateless(netif=%p) %c%c%"U16_F"\n", (void *)netif, netif->name[0], netif->name[1], (u16_t)netif->num));

  SYS_ARCH_LOCK(&dhcp6_mutex);
  dhcp6 = dhcp6_get_struct(netif, "dhcp6_enable_stateless()");
  if (dhcp6 == NULL) {
    err = ERR_MEM;
    goto out;
  }
  if (dhcp6_stateless_enabled(dhcp6)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_enable_stateless(): stateless DHCPv6 already enabled"));
    err = ERR_OK;
    goto out;
  } else if (dhcp6->state != DHCP6_STATE_OFF) {
    /* stateful running */
    /* @todo: stop stateful once it is implemented */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_enable_stateless(): switching from stateful to stateless DHCPv6"));
  }
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_enable_stateless(): stateless DHCPv6 enabled\n"));
  dhcp6_set_state(dhcp6, DHCP6_STATE_STATELESS_IDLE, "dhcp6_enable_stateless");
  err = ERR_OK;
out:
  SYS_ARCH_UNLOCK(&dhcp6_mutex);
  return err;
}

/**
 * @ingroup dhcp6
 * Disable stateful or stateless DHCPv6 on this netif
 * Requests are sent on receipt of an RA message with the
 * ND6_RA_FLAG_OTHER_CONFIG flag set.
 */
void
dhcp6_disable(struct netif *netif)
{
  struct dhcp6 *dhcp6;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_disable(netif=%p) %c%c%"U16_F"\n", (void *)netif, netif->name[0], netif->name[1], (u16_t)netif->num));

  SYS_ARCH_LOCK(&dhcp6_mutex);
  dhcp6 = netif_dhcp6_data(netif);
  if (dhcp6 != NULL) {
    if (dhcp6->state != DHCP6_STATE_OFF) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_disable(): DHCPv6 disabled (old state: %s)\n",
        (dhcp6_stateless_enabled(dhcp6) ? "stateless" : "stateful")));
      dhcp6_set_state(dhcp6, DHCP6_STATE_OFF, "dhcp6_disable");
      if (dhcp6->pcb_allocated != 0) {
        dhcp6_dec_pcb_refcount(); /* free DHCPv6 PCB if not needed any more */
        dhcp6->pcb_allocated = 0;
      }
    }
  }
  SYS_ARCH_UNLOCK(&dhcp6_mutex);
}

#if LWIP_IPV6_DHCP6_STATELESS
static void
dhcp6_information_request(struct netif *netif, struct dhcp6 *dhcp6)
{
  const u16_t requested_options[] = {
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
    DHCP6_OPTION_DNS_SERVERS, 
    DHCP6_OPTION_DOMAIN_LIST
#endif
#if LWIP_DHCP6_GET_NTP_SRV
    , DHCP6_OPTION_SNTP_SERVERS
#endif
  };
  
  struct pbuf *p_out;
  u16_t options_out_len;
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_information_request()\n"));
  /* create and initialize the DHCP message header */
  p_out = dhcp6_create_msg(netif, dhcp6, DHCP6_INFOREQUEST, 4 + sizeof(requested_options), &options_out_len);
  if (p_out != NULL) {
    err_t err;
    struct dhcp6_msg *msg_out = (struct dhcp6_msg *)p_out->payload;
    u8_t *options = (u8_t *)(msg_out + 1);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_information_request: making request\n"));

    options_out_len = dhcp6_option_optionrequest(options_out_len, options, requested_options,
      LWIP_ARRAYSIZE(requested_options), p_out->len);
    LWIP_HOOK_DHCP6_APPEND_OPTIONS(netif, dhcp6, DHCP6_STATE_REQUESTING_CONFIG, msg_out,
      DHCP6_INFOREQUEST, options_out_len, p_out->len);
    dhcp6_msg_finalize(options_out_len, p_out);

    err = udp_sendto_if(dhcp6_pcb, p_out, &dhcp6_All_DHCP6_Relay_Agents_and_Servers, DHCP6_SERVER_PORT, netif);
    pbuf_free(p_out);
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_information_request: INFOREQUESTING -> %d\n", (int)err));
    LWIP_UNUSED_ARG(err);
  } else {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("dhcp6_information_request: could not allocate DHCP6 request\n"));
  }
  dhcp6_set_state(dhcp6, DHCP6_STATE_REQUESTING_CONFIG, "dhcp6_information_request");
  if (dhcp6->tries < 255) {
    dhcp6->tries++;
  }
  dhcp6_set_req_timeout(dhcp6, 1, 3600);
}

static err_t
dhcp6_request_config(struct netif *netif, struct dhcp6 *dhcp6)
{
  /* stateless mode enabled and no request running? */
  if (dhcp6->state == DHCP6_STATE_STATELESS_IDLE) {
    /* send Information-request and wait for answer; setup receive timeout */
    dhcp6_information_request(netif, dhcp6);
  }

  return ERR_OK;
}

static void
dhcp6_abort_config_request(struct dhcp6 *dhcp6)
{
  if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
    /* abort running request */
    dhcp6_set_state(dhcp6, DHCP6_STATE_STATELESS_IDLE, "dhcp6_abort_config_request");
  }
}

/* Handle a REPLY to INFOREQUEST
 * This parses DNS and NTP server addresses from the reply.
 */
static void
dhcp6_handle_config_reply(struct netif *netif, struct pbuf *p_msg_in)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);

  LWIP_UNUSED_ARG(dhcp6);
  LWIP_UNUSED_ARG(p_msg_in);

#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER)) {
    ip_addr_t dns_addr;
    ip6_addr_t *dns_addr6;
    u16_t op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
    u16_t op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
    u16_t idx;
    u8_t n;

    ip_addr_set_zero_ip6(&dns_addr);
    dns_addr6 = ip_2_ip6(&dns_addr);
    for (n = 0, idx = op_start; (idx < op_start + op_len) && (n < LWIP_DHCP6_PROVIDE_DNS_SERVERS);
         n++, idx += sizeof(struct ip6_addr_packed)) {
      u16_t copied = pbuf_copy_partial(p_msg_in, dns_addr6, sizeof(struct ip6_addr_packed), idx);
      if (copied != sizeof(struct ip6_addr_packed)) {
        /* pbuf length mismatch */
        return;
      }
      ip6_addr_assign_zone(dns_addr6, IP6_UNKNOWN, netif);
      /* @todo: do we need a different offset than DHCP(v4)? */
      dns_setserver(n, &dns_addr);
    }
  }
  /* @ todo: parse and set Domain Search List */
#endif /* LWIP_DHCP6_PROVIDE_DNS_SERVERS */

#if LWIP_DHCP6_GET_NTP_SRV
  if (dhcp6_option_given(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER)) {
    ip_addr_t ntp_server_addrs[LWIP_DHCP6_MAX_NTP_SERVERS];
    u16_t op_start = dhcp6_get_option_start(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
    u16_t op_len = dhcp6_get_option_length(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
    u16_t idx;
    u8_t n;

    for (n = 0, idx = op_start; (idx < op_start + op_len) && (n < LWIP_DHCP6_MAX_NTP_SERVERS);
         n++, idx += sizeof(struct ip6_addr_packed)) {
      u16_t copied;
      ip6_addr_t *ntp_addr6 = ip_2_ip6(&ntp_server_addrs[n]);
      ip_addr_set_zero_ip6(&ntp_server_addrs[n]);
      copied = pbuf_copy_partial(p_msg_in, ntp_addr6, sizeof(struct ip6_addr_packed), idx);
      if (copied != sizeof(struct ip6_addr_packed)) {
        /* pbuf length mismatch */
        return;
      }
      ip6_addr_assign_zone(ntp_addr6, IP6_UNKNOWN, netif);
    }
    dhcp6_set_ntp_servers(n, ntp_server_addrs);
  }
#endif /* LWIP_DHCP6_GET_NTP_SRV */
}
#endif /* LWIP_IPV6_DHCP6_STATELESS */

/** This function is called from nd6 module when an RA messsage is received
 * It triggers DHCPv6 requests (if enabled).
 */
void
dhcp6_nd6_ra_trigger(struct netif *netif, u8_t managed_addr_config, u8_t other_config)
{
  struct dhcp6 *dhcp6;

  LWIP_ASSERT("netif != NULL", netif != NULL);
  SYS_ARCH_LOCK(&dhcp6_mutex);
  dhcp6 = netif_dhcp6_data(netif);

  LWIP_UNUSED_ARG(managed_addr_config);
  LWIP_UNUSED_ARG(other_config);
  LWIP_UNUSED_ARG(dhcp6);

#if LWIP_IPV6_DHCP6_STATELESS
  if (dhcp6 != NULL) {
    if (dhcp6_stateless_enabled(dhcp6)) {
      if (other_config) {
        dhcp6_request_config(netif, dhcp6);
      } else {
        dhcp6_abort_config_request(dhcp6);
      }
    }
  }
#endif /* LWIP_IPV6_DHCP6_STATELESS */
  SYS_ARCH_UNLOCK(&dhcp6_mutex);
}

/**
 * Parse the DHCPv6 message and extract the DHCPv6 options.
 *
 * Extract the DHCPv6 options (offset + length) so that we can later easily
 * check for them or extract the contents.
 */
static err_t
dhcp6_parse_reply(struct pbuf *p, struct dhcp6 *dhcp6)
{
  u16_t offset;
  u16_t offset_max;
  u16_t options_idx;
  struct dhcp6_msg *msg_in;

  LWIP_UNUSED_ARG(dhcp6);

  /* clear received options */
  dhcp6_clear_all_options(dhcp6);
  msg_in = (struct dhcp6_msg *)p->payload;

  /* parse options */

  options_idx = sizeof(struct dhcp6_msg);
  /* parse options to the end of the received packet */
  offset_max = p->tot_len;

  offset = options_idx;
  /* at least 4 byte to read? */
  while ((offset + 4 <= offset_max)) {
    u8_t op_len_buf[4];
    u8_t *op_len;
    u16_t op;
    u16_t len;
    u16_t val_offset = (u16_t)(offset + 4);
    if (val_offset < offset) {
      /* overflow */
      return ERR_BUF;
    }
    /* copy option + length, might be split accross pbufs */
    op_len = (u8_t *)pbuf_get_contiguous(p, op_len_buf, 4, 4, offset);
    if (op_len == NULL) {
      /* failed to get option and length */
      return ERR_VAL;
    }
    op = (op_len[0] << 8) | op_len[1];
    len = (op_len[2] << 8) | op_len[3];
    offset = val_offset + len;
    if (offset < val_offset) {
      /* overflow */
      return ERR_BUF;
    }

    switch (op) {
      case (DHCP6_OPTION_CLIENTID):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_CLI_ID);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_CLI_ID, val_offset, len);
        break;
      case (DHCP6_OPTION_SERVERID):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_SERVER_ID);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_SERVER_ID, val_offset, len);
        break;
#if LWIP_DHCP6_PROVIDE_DNS_SERVERS
      case (DHCP6_OPTION_DNS_SERVERS):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_DNS_SERVER, val_offset, len);
        break;
      case (DHCP6_OPTION_DOMAIN_LIST):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_DOMAIN_LIST);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_DOMAIN_LIST, val_offset, len);
        break;
#endif /* LWIP_DHCP6_PROVIDE_DNS_SERVERS */
#if LWIP_DHCP6_GET_NTP_SRV
      case (DHCP6_OPTION_SNTP_SERVERS):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_NTP_SERVER, val_offset, len);
        break;
#endif /* LWIP_DHCP6_GET_NTP_SRV*/
#if LWIP_IPV6_DHCP6_STATEFUL
      case (DHCP6_OPTION_PREFERENCE):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_PREFERENCE);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_PREFERENCE, val_offset, len);
        break;
      case (DHCP6_OPTION_IA_NA):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_IA_NA);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_IA_NA, val_offset, len);
        break;
      case (DHCP6_OPTION_STATUS_CODE):
        dhcp6_got_option(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE);
        dhcp6_set_option(dhcp6, DHCP6_OPTION_IDX_STATUS_CODE, val_offset, len);
        break;
#endif
      default:
        LWIP_DEBUGF(DHCP6_DEBUG, ("skipping option %"U16_F" in options\n", op));
        LWIP_HOOK_DHCP6_PARSE_OPTION(ip_current_netif(), dhcp6, dhcp6->state, msg_in,
          msg_in->msgtype, op, len, q, val_offset);
        break;
    }
  }
  return ERR_OK;
}

static void
dhcp6_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_globals *ip_data, u16_t port)
{
  struct netif *netif = ip_data->current_input_netif;
  SYS_ARCH_LOCK(&dhcp6_mutex);
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
  const ip_addr_t *addr = &ip_data->current_iphdr_src;
  struct dhcp6_msg *reply_msg = (struct dhcp6_msg *)p->payload;
  u8_t msg_type;
  u32_t xid;

  LWIP_UNUSED_ARG(arg);

  /* Caught DHCPv6 message from netif that does not have DHCPv6 enabled? -> not interested */
  if ((dhcp6 == NULL) || (dhcp6->pcb_allocated == 0)) {
    goto free_pbuf_and_return;
  }

  LWIP_ERROR("invalid server address type", IP_IS_V6(addr), goto free_pbuf_and_return;);

  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_recv(pbuf = %p) from DHCPv6 server %s port %"U16_F"\n", (void *)p,
    ipaddr_ntoa(addr), port));
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("pbuf->len = %"U16_F"\n", p->len));
  LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("pbuf->tot_len = %"U16_F"\n", p->tot_len));
  /* prevent warnings about unused arguments */
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(addr);
  LWIP_UNUSED_ARG(port);

  if (p->len < sizeof(struct dhcp6_msg)) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("DHCPv6 reply message or pbuf too short\n"));
    goto free_pbuf_and_return;
  }

  /* match transaction ID against what we expected */
  xid = reply_msg->transaction_id[0] << 16;
  xid |= reply_msg->transaction_id[1] << 8;
  xid |= reply_msg->transaction_id[2];
  if (xid != dhcp6->xid) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                ("transaction id mismatch reply_msg->xid(%"X32_F")!= dhcp6->xid(%"X32_F")\n", xid, dhcp6->xid));
    goto free_pbuf_and_return;
  }
  /* option fields could be unfold? */
  if (dhcp6_parse_reply(p, dhcp6) != ERR_OK) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("problem unfolding DHCPv6 message - too short on memory?\n"));
    goto free_pbuf_and_return;
  }

  /* read DHCP message type */
  msg_type = reply_msg->msgtype;
  /* message type is DHCP6 REPLY? */
  if (msg_type == DHCP6_REPLY) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("DHCP6_REPLY received\n"));
#if LWIP_IPV6_DHCP6_STATELESS
    /* in info-requesting state? */
    if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
      dhcp6_set_state(dhcp6, DHCP6_STATE_STATELESS_IDLE, "dhcp6_recv");
      dhcp6_handle_config_reply(netif, p);
    } else
#endif /* LWIP_IPV6_DHCP6_STATELESS */
#if LWIP_IPV6_DHCP6_STATEFUL
    if ((dhcp6->state >= DHCP6_STATE_REQUESTING_ADDR) && (dhcp6->state <= DHCP6_STATE_REBIND)) {
      dhcp6_handle_reply(netif, p);
    } else
#endif
    {
      /* @todo: handle reply in other states? */
    }
  } else if (msg_type == DHCP6_ADVERTISE) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("DHCP6_ADVERTISE received\n"));
#if LWIP_IPV6_DHCP6_STATEFUL
    if (dhcp6->state == DHCP6_STATE_SOLICIT) {
      dhcp6_handle_advertise(netif, p);
    }
#endif
  } else {
    /* @todo: handle other message types */
  }

free_pbuf_and_return:
  SYS_ARCH_UNLOCK(&dhcp6_mutex);
  pbuf_free(p);
}

/**
 * A DHCPv6 request has timed out.
 *
 * The timer that was started with the DHCPv6 request has
 * timed out, indicating no response was received in time.
 */
static void
dhcp6_timeout(struct netif *netif, struct dhcp6 *dhcp6)
{
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp6_timeout()\n"));

  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(dhcp6);

#if LWIP_IPV6_DHCP6_STATELESS
  /* back-off period has passed, or server selection timed out */
  if (dhcp6->state == DHCP6_STATE_REQUESTING_CONFIG) {
    LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_timeout(): retrying information request\n"));
    dhcp6_information_request(netif, dhcp6);
  }
#endif /* LWIP_IPV6_DHCP6_STATELESS */
#if LWIP_IPV6_DHCP6_STATEFUL
  if (dhcp6->state == DHCP6_STATE_SOLICIT) {
    if ((dhcp6->tries == 1) && ip6_addr_isglobal(&dhcp6->addr)) {
      dhcp6_request_addr(netif, dhcp6);
    } else {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_timeout(): retrying solicit\n"));
      dhcp6_solicit(netif, dhcp6);
    }
  } else if (dhcp6->state == DHCP6_STATE_REQUESTING_ADDR) {
    if (dhcp6->tries < 10) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_timeout(): retrying address request\n"));
      dhcp6_request_addr(netif, dhcp6);
    } else {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6_timeout(): failed to get address from server, restarting\n"));
      dhcp6_stateful_init(netif, dhcp6);
    }
  } else if (dhcp6->state == DHCP6_STATE_RENEW) {
    if (dhcp6->t2 > 0) {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE, ("dhcp6_timeout(): retrying address renewal\n"));
      dhcp6_renew(netif, dhcp6);
    } else {
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6_timeout(): failed to renew address, rebinding\n"));
      dhcp6_rebind(netif, dhcp6);
    }
  }
#endif
}

static u8_t
dhcp6_tmr_netif(struct netif *netif, void *priv)
{
  struct dhcp6 *dhcp6 = netif_dhcp6_data(netif);
  /* only act on DHCPv6 configured interfaces */
  if (dhcp6 != NULL) {
#if LWIP_IPV6_DHCP6_STATEFUL
    if (dhcp6->elapsed_time != 0xFFFF) {
      dhcp6->elapsed_time++;
    }
    if ((dhcp6->state >= DHCP6_STATE_STATEFUL_IDLE) &&
        (dhcp6->state <= DHCP6_STATE_REBIND)) {
      if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, dhcp6->addr_idx))) {
        LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE,
          ("dhcp6_tmr: IP address invalidated, restarting\n"));
        dhcp6_stateful_init(netif, dhcp6);
      } else {
        if ((dhcp6->t2 > 0) && (dhcp6->t2 != IP6_ADDR_LIFE_INFINITE)) {
          dhcp6->t2--;
        }
        if ((dhcp6->t1 > 0) && (dhcp6->t1 != IP6_ADDR_LIFE_INFINITE) && (--dhcp6->t1 == 0)) {
          dhcp6_renew(netif, dhcp6);
        }
      }
    }
#endif
    /* timer is active (non zero), and is about to trigger now */
    if (dhcp6->request_timeout > 1) {
      dhcp6->request_timeout--;
    } else if (dhcp6->request_timeout == 1) {
      dhcp6->request_timeout--;
      /* { dhcp6->request_timeout == 0 } */
      LWIP_DEBUGF(DHCP6_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp6_tmr(): request timeout\n"));
      /* this client's request timeout triggered */
      dhcp6_timeout(netif, dhcp6);
    }
  }
  return false;
}

/**
 * DHCPv6 timeout handling (this function must be called every 500ms,
 * see @ref DHCP6_TIMER_MSECS).
 *
 * A DHCPv6 server is expected to respond within a short period of time.
 * This timer checks whether an outstanding DHCPv6 request is timed out.
 */
void
dhcp6_tmr(void)
{
  SYS_ARCH_LOCK(&dhcp6_mutex);
  /* loop through netif's */
  netif_iterate(dhcp6_tmr_netif, NULL);
  SYS_ARCH_UNLOCK(&dhcp6_mutex);
}

#endif /* LWIP_IPV6 && LWIP_IPV6_DHCP6 */
