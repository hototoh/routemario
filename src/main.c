/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#define NDEBUG
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_random.h>
#include <rte_log.h>
#include <rte_pci.h>
#include <rte_cycles.h>
#include <rte_dev.h>
#include <rte_mbuf.h>
#include <rte_devargs.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_lpm.h>

#include "eth.h"
#include "fdb.h"
#include "mario_config.h"
#include "global_mario.h"


#define mmalloc(x) rte_malloc("rmario", (x), 0)
#define mfree(x) rte_free((x))

#define RTE_LOGTYPE_MARIO RTE_LOGTYPE_USER1

#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define NB_MBUF   8192
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_RX_QUEUE_PER_LCORE 16

/**
 * Global variables
 */
uint8_t _mid;

/**
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 256
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**
 * RSS 
 */
#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static const struct rte_eth_conf port_conf = {
	.rxmode = {
    .mq_mode = ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
  .rx_adv_conf = {
    .rss_conf = {
      .rss_key=hash_key,
      .rss_hf = ETH_RSS_IP,
    },
  },
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

/* ethernet addresses of ports */
static struct ether_addr rmario_ports_eth_addr[RTE_MAX_ETHPORTS];
struct rte_mempool *rmario_pktmbuf_pool = NULL;
static unsigned int rmario_rx_queue_per_lcore = RTE_MAX_ETHPORTS;

#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* default period is 10 seconds */
static int64_t timer_period = 5 * TIMER_MILLISECOND * 1000;

static void
rmario_main_process(void)
{
  unsigned lcore_id = rte_lcore_id();
  struct mbuf_queue *q = get_routing_Q();
  struct rte_mbuf *pkt_burst[MAX_PKT_BURST];
  uint8_t n_ports = rte_eth_dev_count();
  uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
  const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
  
  RTE_LOG(INFO, MARIO, "[%u] Main loop start.\n",lcore_id);
	prev_tsc = 0;
	timer_tsc = 0;
  while(1) {
    cur_tsc = rte_rdtsc();
    
    diff_tsc = cur_tsc - prev_tsc;
    if (unlikely(diff_tsc > drain_tsc)) {
      for(uint8_t port_id = 0; port_id < n_ports; port_id++) {
        uint16_t len = (get_eth_tx_Q(port_id))->len;
				if (len == 0) continue;
        eth_queue_xmit(port_id, len);
        (get_eth_tx_Q(port_id))->len = 0;
      }
      prev_tsc = cur_tsc;
    }

    /* RX */
    for (uint8_t port_id = 0; port_id < n_ports; port_id++) {
      unsigned n_rx = rte_eth_rx_burst(port_id, (uint16_t) lcore_id,
                                       pkt_burst, MAX_PKT_BURST);
      if (n_rx == 0) continue;
      if (port_id == _mid) // external port
        eth_input(pkt_burst, n_rx, port_id);
      else { // internal port
        eth_internal_input(pkt_burst, n_rx, port_id);        
      }
    }
  }
  return ;
}

#define MAX_ROUTING_TX 32
static int
rmario_launch_one_lcore(void * unused)
{
	// RTE_LOG(INFO, MARIO, "[%u] Processing launch\n", rte_lcore_id());
  set_nic_queue_id(rte_lcore_id());
  struct mbuf_queue *q = create_mbuf_queue(MAX_ROUTING_TX);
  if (q == NULL) {
    RTE_LOG(ERR, MARIO, "[%u] fail to create routing queue\n", rte_lcore_id());
    return EXIT_FAILURE;    
  }
  set_routing_Q(q); 
  
  struct mbuf_queues *qs;
  qs = create_mbuf_queues(rte_eth_dev_count(),  MAX_PKT_BURST);
  if (qs == NULL) {
    RTE_LOG(ERR, MARIO, "[%u] fail to create eth tx queue\n", rte_lcore_id());
    return EXIT_FAILURE;
  }
  set_eth_tx_Qs(qs);
  
  rmario_main_process();  
	return 0;
}

static void
rmario_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n",
	       prgname);
}

static unsigned int
rmario_parse_node_id(const char *q_arg)
{
  int node_id = atoi(q_arg);
  RTE_LOG(INFO, MARIO, "Node ID is `%d`\n", node_id);
  return node_id;
}

static unsigned int
rmario_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return (unsigned int) n;
}

static int
rmario_parse_args(int argc, char **argv)
{
  bool arg_flag = false;
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  static struct option lgopts[] = {
    {NULL, 0, 0, 0}
  };

  argvopt = argv;  
  while((opt = getopt_long(argc, argvopt, "q:i:", lgopts, &option_index))
        != EOF){
    switch (opt) {
      case 'q':
        rmario_rx_queue_per_lcore = rmario_parse_nqueue(optarg);
        if (rmario_rx_queue_per_lcore == 0) {
          RTE_LOG(ERR, MARIO, "Invalid queue number\n");
          return -1;
        }
        break;
      case 'i':
        _mid = rmario_parse_node_id(optarg);
        arg_flag = true;
        break;
      default:
        rmario_usage(prgname);
        return -1;
    }
  }

  if (!arg_flag) {
    RTE_LOG(ERR, MARIO, "node id must be set (-i)\n");    
    return -1;
  }

  ret = optind - 1;
  optind = 0; 
  return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

#define FDB_SIZE (1 << 20)
#define MBUF_DATA_SIZE (2048 + RTE_PKTMBUF_HEADROOM)

int
main(int argc, char **argv)
{
  int ret;
  uint8_t n_ports;
  unsigned lcore_count;
  
  ret = rte_eal_init(argc, argv);
  if (ret < 0) 
    rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
  argc -= ret;
  argv += ret;

  ret = rmario_parse_args(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid MARIO arguments\n");

  lcore_count = rte_lcore_count();
  n_ports = rte_eth_dev_count();
  RTE_LOG(INFO, MARIO, "Find %u logical cores\n" , lcore_count);

  rmario_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 32, 0,
                                                MBUF_DATA_SIZE, 
                                                rte_socket_id());
  if (rmario_pktmbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

  n_ports = rte_eth_dev_count();
  if (n_ports == 0) 
    rte_exit(EXIT_FAILURE, "No Ethernet ports - byte\n");
  RTE_LOG(INFO, MARIO, "Find %u ethernet ports\n", n_ports);

  if (n_ports > RTE_MAX_ETHPORTS)
    n_ports = RTE_MAX_ETHPORTS;

	/* Each logical core is assigned a dedicated TX queue on each port. */
  /*
  for(uint8_t port_id = 0; port_id < n_ports; port_id++) {
    rte_eth_dev_info_get(port_id, &dev_info);
  }
  */

  /* Initialize global variables. */
  intfs = create_l3_interfaces(n_ports);
  if (intfs == NULL) {
    rte_exit(EXIT_FAILURE, "Fail to crate l3 interface instances.\n");
  }

  fdb_tb = create_fdb_table(FDB_SIZE);
  if (fdb_tb == NULL) {
    rte_exit(EXIT_FAILURE, "Fail to crate fdb table.\n");
  }

  arp_tb = create_arp_table(FDB_SIZE);
  if (arp_tb == NULL) {
    rte_exit(EXIT_FAILURE, "Fail to crate arp table.\n");
  }

  rib = rte_lpm_create("rib", rte_socket_id(), 1 << 10, 0);
  if (rib == NULL) {
    rte_exit(EXIT_FAILURE, "Fail to crate RIB.\n");
  }

 
  /* Load configuration */
  if (load_config("./test_len.conf")) {
    rte_exit(EXIT_FAILURE, "Fail to load configuration.\n");
  }  
  RTE_LOG(INFO, MARIO, "conf\n");

	/* Initialise each port */
  for(uint8_t port_id = 0; port_id < n_ports; port_id++) {
    RTE_LOG(INFO, MARIO, "Initializing port %u...", port_id);
    fflush(stdout);
    ret = rte_eth_dev_configure(port_id, lcore_count, lcore_count, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
               ret, (unsigned)port_id);
    RTE_LOG(INFO, MARIO, "done\n");
		rte_eth_macaddr_get(port_id, &rmario_ports_eth_addr[port_id]);

		/* init one RX queue */
    for (uint8_t core_id = 0; core_id < lcore_count; core_id++) {
      ret = rte_eth_rx_queue_setup(port_id, core_id, nb_rxd,
                                   (unsigned int)rte_eth_dev_socket_id(port_id),
                                   NULL,
                                   rmario_pktmbuf_pool);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, 
                 "rte_eth_rx_queue_setup:err=%d, port=%u queue=%u\n",
                 ret, (unsigned) port_id, (unsigned) core_id);
    }

		/* init one TX queue */
    for (uint8_t core_id = 0; core_id < lcore_count; core_id++) {
      ret = rte_eth_tx_queue_setup(port_id, core_id, nb_txd,
                                   (unsigned int)rte_eth_dev_socket_id(port_id),
                                   NULL);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, 
                 "rte_eth_tx_queue_setup:err=%d, port=%u queue=%u\n",
                 ret, (unsigned) port_id, (unsigned) core_id);
    }

		/* Start device */
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
               ret, (unsigned) port_id);

    rte_eth_promiscuous_enable(port_id);

    RTE_LOG(INFO, MARIO,
            "Port %u, MAC address %02x:%02x:%02x:%02x:%02x:%02x\n\n",
            port_id,
            rmario_ports_eth_addr[port_id].addr_bytes[0],
            rmario_ports_eth_addr[port_id].addr_bytes[1],
            rmario_ports_eth_addr[port_id].addr_bytes[2],
            rmario_ports_eth_addr[port_id].addr_bytes[3],
            rmario_ports_eth_addr[port_id].addr_bytes[4],
            rmario_ports_eth_addr[port_id].addr_bytes[5]);
#ifdef PORT_STATS
    memset(&port_statistics, 0, sizeof(port_statistics));
#endif
  }

	check_all_ports_link_status(n_ports);

  /**
   * L2 filter 
   */
  for(uint8_t mac = 0; mac < n_ports; mac++){
    struct rte_eth_flex_filter filter;
    filter.len = 8;
    filter.bytes[0] = (uint8_t)(0xf) + (mac<<4);
    for(uint8_t i = 1; i <8; i++){
      filter.bytes[i] = 0;
    }
    filter.mask[0] = (uint8_t)0b10000000;
    filter.priority = 1;
    filter.queue = mac;
    for(uint8_t port = 0; port < n_ports; port++){
      if(port == _mid){
        continue;
      }
      printf("mac = %d, port = %d\n", mac, port);
      ret  = rte_eth_dev_filter_ctrl(port,
                                     RTE_ETH_FILTER_FLEXIBLE,
                                     RTE_ETH_FILTER_ADD,
                                     &filter);
    }
  }

	/* launch per-lcore init on every lcore */
  rte_eal_mp_remote_launch(rmario_launch_one_lcore, NULL, CALL_MASTER);
  {
    uint8_t lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
      if (rte_eal_wait_lcore(lcore_id) < 0)
        return -1;
    }
  }

  return 0;
}

