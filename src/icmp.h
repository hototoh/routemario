#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

void
icmp_rcv(struct rte_mbuf *buf);

void
icmp_send(struct rte_mbuf *buf);

void
icmp_send_time_exceeded(struct rte_mbuf *buf, uint32_t dst_ip_addr);

void
icmp_send_destination_unreachable(struct rte_mbuf *buf, uint32_t dst_ip_addr);


#endif
