#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

int icmp_rcv(struct rte_mbuf *buf);

int icmp_send(struct rte_mbuf *buf);

void icmp_send_time_exceeded(struct rte_mbuf *buf);

#endif
