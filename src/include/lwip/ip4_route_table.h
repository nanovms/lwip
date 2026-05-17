/**
 * @file
 * IPv4 static route table for DHCP Option 121 (Classless Static Routes)
 *
 * Provides a static routing table for IPv4 with longest-prefix-match lookups.
 * Primarily used to store routes learned from DHCP Option 121 (RFC 3442).
 */

/*
 * Copyright (c) 2025 Timo Gatsonides
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

#ifndef LWIP_HDR_IP4_ROUTE_TABLE_H
#define LWIP_HDR_IP4_ROUTE_TABLE_H

#include "lwip/opt.h"

#if LWIP_DHCP_CLASSLESS_STATIC_ROUTES

#include "lwip/ip4_addr.h"
#include "lwip/err.h"
#include "lwip/netif.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IP4_MAX_PREFIX_LEN              32

/* Route entry flags */
#define IP4_ROUTE_FLAG_NONE             0x00
#define IP4_ROUTE_FLAG_DHCP             0x01  /* Route learned from DHCP Option 121 */
#define IP4_ROUTE_FLAG_STATIC           0x02  /* Manually configured static route */

struct ip4_route_entry {
  ip4_addr_t dest;        /**< Destination network address (masked) */
  ip4_addr_t gateway;     /**< Next-hop gateway IP address */
  u8_t prefix_len;        /**< CIDR prefix length (0-32) */
  u8_t flags;             /**< Route flags (IP4_ROUTE_FLAG_*) */
  struct netif *netif;    /**< Associated network interface (NULL = unused entry) */
};

/** Compute netmask from prefix length in network byte order */
u32_t ip4_prefix_to_mask(u8_t prefix_len);

/** Initialize the route table - must be called before other functions */
void ip4_route_table_init(void);

/**
 * Add a route to the static route table.
 * Table is kept sorted by prefix length (longest first) for LPM lookups.
 *
 * @param dest destination network address
 * @param prefix_len CIDR prefix length (0-32)
 * @param gateway next-hop gateway IP address
 * @param netif associated network interface
 * @param flags route flags (IP4_ROUTE_FLAG_*)
 * @return ERR_OK on success, ERR_MEM if table full, ERR_ARG if invalid args
 */
err_t ip4_route_add(const ip4_addr_t *dest, u8_t prefix_len,
                    const ip4_addr_t *gateway, struct netif *netif, u8_t flags);

/** Remove a specific route from the table */
void ip4_route_remove(const ip4_addr_t *dest, u8_t prefix_len, struct netif *netif);

/** Remove routes matching a network interface and flags */
void ip4_route_remove_netif(struct netif *netif, u8_t flags);

/**
 * Check whether a route with the given netif and flags exists.
 *
 * @param netif network interface to check
 * @param flags route flags to match
 * @return 1 if such a route exists, 0 otherwise
 */
u8_t ip4_route_exists(struct netif *netif, u8_t flags);

/**
 * Find the best matching route for a destination address (longest prefix match).
 * Copies route entry to out_entry if found.
 *
 * @param dest destination IP address to look up
 * @param out_entry pointer to route entry to fill (may be NULL)
 * @return 1 if route found, 0 otherwise
 */
u8_t ip4_route_find(const ip4_addr_t *dest, struct ip4_route_entry *out_entry);

/**
 * Route lookup hook for lwIP integration (LWIP_HOOK_IP4_ROUTE_SRC).
 *
 * @param src source IPv4 address (may be NULL)
 * @param dest destination IPv4 address
 * @return network interface to use, or NULL if no static route matches
 */
struct netif *ip4_static_route(const ip4_addr_t *src, const ip4_addr_t *dest);

/**
 * Get the gateway address for a destination from the static route table.
 * Copies gateway to out_gateway if found.
 *
 * @param netif network interface to match
 * @param dest destination IP address to look up
 * @param out_gateway pointer to store the gateway address (may be NULL)
 * @return 1 if route found, 0 otherwise
 */
u8_t ip4_get_gateway(struct netif *netif, const ip4_addr_t *dest, ip4_addr_t *out_gateway);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_DHCP_CLASSLESS_STATIC_ROUTES */

#endif /* LWIP_HDR_IP4_ROUTE_TABLE_H */
