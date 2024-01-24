/**
 * @file
 * Error Management module
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/err.h"
#include "lwip/def.h"
#include "lwip/sys.h"

#include "lwip/errno.h"

#if !NO_SYS
/** Table to quickly map an lwIP error (err_t) to a socket error
  * by using -err as an index */
static const int err_to_errno_table[] = {
  0,             /* ERR_OK          0      No error, everything OK. */
  ENOMEM,        /* ERR_MEM        -1      Out of memory error.     */
  ENOBUFS,       /* ERR_BUF        -2      Buffer error.            */
  EWOULDBLOCK,   /* ERR_TIMEOUT    -3      Timeout                  */
  EHOSTUNREACH,  /* ERR_RTE        -4      Routing problem.         */
  EINPROGRESS,   /* ERR_INPROGRESS -5      Operation in progress    */
  EINVAL,        /* ERR_VAL        -6      Illegal value.           */
  EWOULDBLOCK,   /* ERR_WOULDBLOCK -7      Operation would block.   */
  EADDRINUSE,    /* ERR_USE        -8      Address in use.          */
  EALREADY,      /* ERR_ALREADY    -9      Already connecting.      */
  EISCONN,       /* ERR_ISCONN     -10     Conn already established.*/
  ENOTCONN,      /* ERR_CONN       -11     Not connected.           */
  -1,            /* ERR_IF         -12     Low-level netif error    */
  ECONNABORTED,  /* ERR_ABRT       -13     Connection aborted.      */
  ECONNRESET,    /* ERR_RST        -14     Connection reset.        */
  ENOTCONN,      /* ERR_CLSD       -15     Connection closed.       */
  EIO            /* ERR_ARG        -16     Illegal argument.        */
};

int
err_to_errno(err_t err)
{
  if ((err > 0) || (-err >= (err_t)LWIP_ARRAYSIZE(err_to_errno_table))) {
    return EIO;
  }
  return err_to_errno_table[-err];
}
#endif /* !NO_SYS */

#ifdef LWIP_DEBUG

static const sstring err_strerr[] = {
  ss_static_init("Ok."),                    /* ERR_OK          0  */
  ss_static_init("Out of memory error."),   /* ERR_MEM        -1  */
  ss_static_init("Buffer error."),          /* ERR_BUF        -2  */
  ss_static_init("Timeout."),               /* ERR_TIMEOUT    -3  */
  ss_static_init("Routing problem."),       /* ERR_RTE        -4  */
  ss_static_init("Operation in progress."), /* ERR_INPROGRESS -5  */
  ss_static_init("Illegal value."),         /* ERR_VAL        -6  */
  ss_static_init("Operation would block."), /* ERR_WOULDBLOCK -7  */
  ss_static_init("Address in use."),        /* ERR_USE        -8  */
  ss_static_init("Already connecting."),    /* ERR_ALREADY    -9  */
  ss_static_init("Already connected."),     /* ERR_ISCONN     -10 */
  ss_static_init("Not connected."),         /* ERR_CONN       -11 */
  ss_static_init("Low-level netif error."), /* ERR_IF         -12 */
  ss_static_init("Connection aborted."),    /* ERR_ABRT       -13 */
  ss_static_init("Connection reset."),      /* ERR_RST        -14 */
  ss_static_init("Connection closed."),     /* ERR_CLSD       -15 */
  ss_static_init("Illegal argument."),      /* ERR_ARG        -16 */
};

/**
 * Convert an lwip internal error to a string representation.
 *
 * @param err an lwip internal err_t
 * @return a string representation for err
 */
sstring
lwip_strerr(err_t err)
{
  if ((err > 0) || (-err >= (err_t)LWIP_ARRAYSIZE(err_strerr))) {
    return ss("Unknown error.");
  }
  return err_strerr[-err];
}

#endif /* LWIP_DEBUG */
