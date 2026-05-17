/**
 * @file
 * IPv4 static route table implementation
 *
 * Provides a fixed-size routing table with longest-prefix-match lookup,
 * primarily for DHCP Option 121 (RFC 3442) classless static routes.
 */

/*
 * Copyright (c) 2026 Timo Gatsonides
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
 * Author: Timo Gatsonides
 */

#include "lwip/opt.h"

#if LWIP_DHCP_CLASSLESS_STATIC_ROUTES

#include "lwip/ip4_route_table.h"
#include "lwip/def.h"
#include "lwip/sys.h"

#include <string.h>

/* Route table storage - sorted by prefix_len descending for LPM */
static struct ip4_route_entry route_table[LWIP_IPV4_NUM_ROUTE_ENTRIES];

/* Lock for thread-safe access */
static sys_lock_t route_lock;

/* Number of active entries in the table */
static int route_entry_count;

/* Compute netmask from prefix length in network byte order */
u32_t
ip4_prefix_to_mask(u8_t prefix_len)
{
  if (prefix_len == 0)
    return 0;
  if (prefix_len >= IP4_MAX_PREFIX_LEN)
    return 0xFFFFFFFF;
  return lwip_htonl(~((1UL << (32 - prefix_len)) - 1));
}

/* Check if a destination address matches a route entry */
static int
route_matches(const struct ip4_route_entry *entry, const ip4_addr_t *dest)
{
  u32_t mask = ip4_prefix_to_mask(entry->prefix_len);
  return (dest->addr & mask) == (entry->dest.addr & mask);
}

/* Find insertion point to maintain sorted order (descending prefix_len) */
static int
find_insert_position(u8_t prefix_len)
{
  int i;
  for (i = 0; i < route_entry_count; i++) {
    if (prefix_len > route_table[i].prefix_len)
      return i;
  }
  return route_entry_count;
}

/* Find an existing route matching dest/prefix_len/netif, returns index or -1 */
static int
find_existing_route(const ip4_addr_t *dest, u8_t prefix_len, struct netif *netif)
{
  u32_t mask = ip4_prefix_to_mask(prefix_len);
  u32_t masked_dest = dest->addr & mask;
  int i;

  for (i = 0; i < route_entry_count; i++) {
    if (route_table[i].prefix_len == prefix_len &&
        (route_table[i].dest.addr & mask) == masked_dest &&
        (netif == NULL || route_table[i].netif == netif)) {
      return i;
    }
  }
  return -1;
}

void
ip4_route_table_init(void)
{
  SYS_ARCH_LOCK_INIT(&route_lock);
  memset(route_table, 0, sizeof(route_table));
  route_entry_count = 0;
}

err_t
ip4_route_add(const ip4_addr_t *dest, u8_t prefix_len,
              const ip4_addr_t *gateway, struct netif *netif, u8_t flags)
{
  err_t ret = ERR_OK;
  int existing;
  int pos;
  int i;
  u32_t mask;

  LWIP_ERROR("ip4_route_add: dest != NULL", dest != NULL, return ERR_ARG);
  LWIP_ERROR("ip4_route_add: gateway != NULL", gateway != NULL, return ERR_ARG);
  LWIP_ERROR("ip4_route_add: netif != NULL", netif != NULL, return ERR_ARG);
  LWIP_ERROR("ip4_route_add: prefix_len <= IP4_MAX_PREFIX_LEN",
             prefix_len <= IP4_MAX_PREFIX_LEN, return ERR_ARG);

  SYS_ARCH_LOCK(&route_lock);

  /* check for existing route with same dest/prefix/netif and update it */
  existing = find_existing_route(dest, prefix_len, netif);
  if (existing >= 0) {
    ip4_addr_copy(route_table[existing].gateway, *gateway);
    route_table[existing].flags = flags;
    goto out;
  }

  if (route_entry_count >= LWIP_IPV4_NUM_ROUTE_ENTRIES) {
    ret = ERR_MEM;
    goto out;
  }

  /* find insertion point to maintain sorted order */
  pos = find_insert_position(prefix_len);

  /* shift entries down to make room */
  for (i = route_entry_count; i > pos; i--) {
    memcpy(&route_table[i], &route_table[i - 1],
           sizeof(struct ip4_route_entry));
  }

  /* insert new entry */
  mask = ip4_prefix_to_mask(prefix_len);
  route_table[pos].dest.addr = dest->addr & mask;
  ip4_addr_copy(route_table[pos].gateway, *gateway);
  route_table[pos].prefix_len = prefix_len;
  route_table[pos].flags = flags;
  route_table[pos].netif = netif;
  route_entry_count++;

out:
  SYS_ARCH_UNLOCK(&route_lock);
  return ret;
}

void
ip4_route_remove(const ip4_addr_t *dest, u8_t prefix_len, struct netif *netif)
{
  int idx;
  int i;

  LWIP_ERROR("ip4_route_remove: dest != NULL", dest != NULL, return);
  LWIP_ERROR("ip4_route_remove: prefix_len <= IP4_MAX_PREFIX_LEN",
             prefix_len <= IP4_MAX_PREFIX_LEN, return);

  SYS_ARCH_LOCK(&route_lock);

  idx = find_existing_route(dest, prefix_len, netif);
  if (idx >= 0) {
    for (i = idx; i < route_entry_count - 1; i++) {
      memcpy(&route_table[i], &route_table[i + 1],
             sizeof(struct ip4_route_entry));
    }
    memset(&route_table[route_entry_count - 1], 0,
           sizeof(struct ip4_route_entry));
    route_entry_count--;
  }

  SYS_ARCH_UNLOCK(&route_lock);
}

void
ip4_route_remove_netif(struct netif *netif, u8_t flags)
{
  int i;
  int j;

  SYS_ARCH_LOCK(&route_lock);

  i = 0;
  while (i < route_entry_count) {
    if ((route_table[i].netif == netif) &&
        (route_table[i].flags & flags) == flags) {
      for (j = i; j < route_entry_count - 1; j++) {
        memcpy(&route_table[j], &route_table[j + 1],
               sizeof(struct ip4_route_entry));
      }
      memset(&route_table[route_entry_count - 1], 0,
             sizeof(struct ip4_route_entry));
      route_entry_count--;
    } else {
      i++;
    }
  }

  SYS_ARCH_UNLOCK(&route_lock);
}

u8_t
ip4_route_find(const ip4_addr_t *dest, struct ip4_route_entry *out_entry)
{
  u8_t found = 0;
  int i;

  LWIP_ERROR("ip4_route_find: dest != NULL", dest != NULL, return 0);

  SYS_ARCH_LOCK(&route_lock);

  /*
   * Table is sorted by prefix_len descending, so the first match
   * is the longest prefix match.
   */
  for (i = 0; i < route_entry_count; i++) {
    if (route_table[i].netif != NULL && route_matches(&route_table[i], dest)) {
      if (out_entry != NULL)
        memcpy(out_entry, &route_table[i], sizeof(*out_entry));
      found = 1;
      break;
    }
  }

  SYS_ARCH_UNLOCK(&route_lock);
  return found;
}

struct netif *
ip4_static_route(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  struct ip4_route_entry entry;
  LWIP_UNUSED_ARG(src);

  if (ip4_route_find(dest, &entry))
    return entry.netif;
  return NULL;
}

u8_t
ip4_get_gateway(struct netif *netif, const ip4_addr_t *dest, ip4_addr_t *out_gateway)
{
  u8_t found = 0;
  int i;

  LWIP_ERROR("ip4_get_gateway: netif != NULL", netif != NULL, return 0);
  LWIP_ERROR("ip4_get_gateway: dest != NULL", dest != NULL, return 0);

  SYS_ARCH_LOCK(&route_lock);

  for (i = 0; i < route_entry_count; i++) {
    if (route_table[i].netif == netif) {
      u32_t mask = ip4_prefix_to_mask(route_table[i].prefix_len);
      if ((dest->addr & mask) == (route_table[i].dest.addr & mask)) {
        if (out_gateway != NULL)
          ip4_addr_copy(*out_gateway, route_table[i].gateway);
        found = 1;
        break;
      }
    }
  }

  SYS_ARCH_UNLOCK(&route_lock);
  return found;
}

u8_t
ip4_route_exists(struct netif *netif, u8_t flags)
{
  u8_t found = 0;
  int i;

  LWIP_ERROR("ip4_route_exists: netif != NULL", netif != NULL, return 0);

  SYS_ARCH_LOCK(&route_lock);

  for (i = 0; i < route_entry_count; i++) {
    if (route_table[i].netif == netif &&
        (route_table[i].flags & flags) == flags) {
      found = 1;
      break;
    }
  }

  SYS_ARCH_UNLOCK(&route_lock);
  return found;
}

#endif /* LWIP_DHCP_CLASSLESS_STATIC_ROUTES */
