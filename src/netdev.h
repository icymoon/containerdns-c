#ifndef _DNSNETDEV_H_
#define _DNSNETDEV_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_udp.h>
#include <rte_ip.h>


#define NETIF_MAX_PKT_BURST         32

#define UDP_PORT_53 0x3500 // port 53
#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)



struct netif_queue_stats
{
    uint64_t pkts_rcv;  /* Total number of receive packets */
    uint64_t pkts_2kni; /* Total number of receive pkts to kni */
    uint64_t pkts_icmp; /* Total number of receive pkts to kni */
    
    uint64_t dns_pkts_rcv; /* Total number of successfully received packets. */
    uint64_t dns_pkts_snd; /* Total number of successfully transmitted packets. */
    uint64_t pkt_dropped; /* Total number of dropped packets by software. */   
    uint64_t pkt_len_err; /* pkt len err. */

    uint64_t dns_lens_rcv; /* Total lens of  received packets. */
    uint64_t dns_lens_snd; /* Total lens of  transmitted packets. */
       
} __rte_cache_aligned;


/* RX/TX queue conf for lcore */
struct netif_queue_conf
{
    uint16_t port_id;
    uint16_t rx_queue_id;   
    uint16_t tx_queue_id;
    struct netif_queue_stats stats;
    uint16_t tx_len;
    struct rte_mbuf *tx_mbufs[NETIF_MAX_PKT_BURST];
    
    uint16_t kni_len;
    struct rte_mbuf *kni_mbufs[NETIF_MAX_PKT_BURST];   
} __rte_cache_aligned;


struct net_device {

    uint16_t max_rx_queues;   
    uint16_t max_tx_queues;
    uint16_t max_rx_desc;
    uint16_t max_tx_desc;
    struct ether_addr hwaddr;

    struct netif_queue_conf l_netif_queue_conf[RTE_MAX_LCORE];
};

//extern struct net_device  kdns_net_device;
void netif_statsdata_get(struct netif_queue_stats *sta);
void netif_statsdata_reset(void);


int packet_l2_handle(struct rte_mbuf *pkt, struct netif_queue_conf *conf);

void netif_queue_core_bind(void);

struct netif_queue_conf* netif_queue_conf_get(uint16_t lcore_id);
void init_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac, \
    struct ether_addr *dst_mac, uint16_t ether_type);
uint16_t init_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
    uint32_t dst_addr, uint16_t pktdata_len);
uint16_t init_udp_header(struct udp_hdr *udp_hdr, uint16_t src_port,
    uint16_t dst_port, uint16_t pktdata_len);

int kni_free_kni(uint8_t port_id);

void dns_kni_enqueue(struct netif_queue_conf *conf,struct rte_mbuf **mbufs,uint16_t rx_len);
uint16_t dns_kni_dequeue(struct rte_mbuf **mbufs,uint16_t pkts_len);
void dns_dpdk_init(void);



#endif
