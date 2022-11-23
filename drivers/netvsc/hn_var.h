/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2009-2018 Microsoft Corp.
 * Copyright (c) 2016 Brocade Communications Systems, Inc.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 */

// #include <rte_eal_paging.h>
// #include <ethdev_driver.h>

#include <inttypes.h>
#include <stdbool.h>
#include <uk/allocpool.h>
#include <uk/netbuf.h>
#include <uk/netdev.h>
#include <uk/sglist.h>
#include <uk/spinlock.h>

#include <vmbus/vmbus_chanvar.h>

/*
 * Tunable ethdev params
 */
#define HN_MIN_RX_BUF_SIZE	1024
#define HN_MAX_XFER_LEN		2048
#define	HN_MAX_MAC_ADDRS	1
#define HN_MAX_CHANNELS		64

/* Claimed to be 12232B */
#define HN_MTU_MAX		(9 * 1024)

/* Retry interval */
#define HN_CHAN_INTERVAL_US	100

/* Host monitor interval */
#define HN_CHAN_LATENCY_NS	50000

#define HN_TXCOPY_THRESHOLD	512
#define HN_RXCOPY_THRESHOLD	256

#define HN_RX_EXTMBUF_ENABLE	0

#ifndef PAGE_MASK
//#define PAGE_MASK (rte_mem_page_size() - 1)
#define PAGE_MASK __PAGE_MASK
#endif

/* START UK defines */
typedef uint64_t rte_iova_t;
#define RTE_BAD_IOVA 0

#define RNDIS_DELAY_MS 10
#define rte_delay_ms(ms)
#define rte_delay_us(us)
/* END */

struct hn_data;
struct hn_txdesc;

struct hn_stats {
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	errors;
	uint64_t	ring_full;
	uint64_t	channel_full;
	uint64_t	multicast;
	uint64_t	broadcast;
	/* Size bins in array as RFC 2819, undersized [0], 64 [1], etc */
	uint64_t	size_bins[8];
};

struct uk_netdev_tx_queue {
	/* The netfront device */
	struct hn_dev *hn_dev;
	/* The libuknet queue identifier */
	uint16_t lqueue_id;
	/* True if initialized */
	bool initialized;

	struct hn_data  *hv;
	struct vmbus_channel *chan;
	uint16_t	port_id;
	uint16_t	queue_id;
	uint32_t	free_thresh;
	// struct rte_mempool *txdesc_pool;
	struct uk_allocpool *txdesc_pool;
	// const struct rte_memzone *tx_rndis_mz;
	void		*tx_rndis;
	rte_iova_t	tx_rndis_iova;

	/* Applied packet transmission aggregation limits. */
	uint32_t	agg_szmax;
	uint32_t	agg_pktmax;
	uint32_t	agg_align;

	/* Packet transmission aggregation states */
	struct hn_txdesc *agg_txd;
	uint32_t	agg_pktleft;
	uint32_t	agg_szleft;
	struct rndis_packet_msg *agg_prevpkt;

	struct hn_stats stats;
};

struct uk_netdev_rx_queue {
	/* The netfront device */
	struct hn_dev *hn_dev;
	/* The libuknet queue identifier */
	uint16_t lqueue_id;
	/* True if initialized */
	bool initialized;

	/* The flag to interrupt on the transmit queue */
	uint8_t intr_enabled;

	struct hn_data  *hv;
	struct vmbus_channel *chan;
	// struct rte_mempool *mb_pool;
	// struct rte_ring *rx_ring;

	// rte_spinlock_t ring_lock;
	uk_spinlock ring_lock;
	uint32_t event_sz;
	uint16_t port_id;
	uint16_t queue_id;
	struct hn_stats stats;

	void *event_buf;
	struct hn_rx_bufinfo *rxbuf_info;
	// rte_atomic32_t  rxbuf_outstanding;
};


/* multi-packet data from host */
struct hn_rx_bufinfo {
	struct vmbus_channel *chan;
	// struct hn_rx_queue *rxq;
	struct uk_netdev_rx_queue *rxq;
	uint64_t	xactid;
// 	struct rte_mbuf_ext_shared_info shinfo;
} __rte_cache_aligned;

#define HN_INVALID_PORT	UINT16_MAX

// enum vf_device_state {
// 	vf_unknown = 0,
// 	vf_removed,
// 	vf_configured,
// 	vf_started,
// 	vf_stopped,
// };

// struct hn_vf_ctx {
// 	uint16_t	vf_port;

// 	/* We have taken ownership of this VF port from DPDK */
// 	bool		vf_attached;

// 	/* VSC has requested to switch data path to VF */
// 	bool		vf_vsc_switched;

// 	/* VSP has reported the VF is present for this NIC */
// 	bool		vf_vsp_reported;

// 	enum vf_device_state	vf_state;
// };

// struct hv_hotadd_context {
// 	LIST_ENTRY(hv_hotadd_context) list;
// 	struct hn_data *hv;
// 	struct rte_devargs da;
// 	int eal_hot_plug_retry;
// };

/* From DPDK/lib/net/rte_ether.h */
/**
 * Macro to print six-bytes of MAC address in hex format
 */
#define RTE_ETHER_ADDR_PRT_FMT     "%02X:%02X:%02X:%02X:%02X:%02X"

/* From DPDK/lib/eal/include/rte_dev.h */
/**
 * A generic memory resource representation.
 */
struct rte_mem_resource {
	uint64_t phys_addr; /**< Physical address, 0 if not resource. */
	uint64_t len;       /**< Length of the resource. */
	void *addr;         /**< Virtual address, NULL when not mapped. */
};

/* From DPDK/lib/eal/include/generic/rte_atomic.h */
/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int32_t cnt; /**< An internal counter value. */
} rte_atomic32_t;

/*------------------------- 32 bit atomic operations -------------------------*/

/**
 * Atomic compare and set.
 *
 * (atomic) equivalent to:
 *   if (*dst == exp)
 *     *dst = src (all 32-bit words)
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param exp
 *   The expected value.
 * @param src
 *   The new value.
 * @return
 *   Non-zero on success; 0 on failure.
 */
static inline int
rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src);

// #ifdef RTE_FORCE_INTRINSICS
static inline int
rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}
// #endif

/**
 * Atomically add a 32-bit value to a counter and return the result.
 *
 * Atomically adds the 32-bits value (inc) to the atomic counter (v) and
 * returns the value of v after addition.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 * @return
 *   The value of v after the addition.
 */
static inline int32_t
rte_atomic32_add_return(rte_atomic32_t *v, int32_t inc)
{
	return __sync_add_and_fetch(&v->cnt, inc);
}

struct hn_data {
	struct uk_alloc *a;

	// struct rte_vmbus_device *vmbus;
	struct vmbus_device *vmbus;
	// struct hn_rx_queue *primary;
	struct uk_netdev_rx_queue *primary;
	// rte_rwlock_t    vf_lock;
	uint16_t	port_id;

	// struct hn_vf_ctx	vf_ctx;

	uint8_t		closed;
	uint8_t		vlan_strip;

	uint32_t	link_status;
	uint32_t	link_speed;

	struct rte_mem_resource *rxbuf_res;	/* UIO resource for Rx */
	uint32_t		rxbuf_gpadl;
	uint32_t	rxbuf_section_cnt;	/* # of Rx sections */
	uint32_t	rx_copybreak;
	uint32_t	rx_extmbuf_enable;
	uint16_t	max_queues;		/* Max available queues */
	uint16_t	num_queues;
	uint64_t	rss_offloads;

	// rte_spinlock_t	chim_lock;
	uk_spinlock chim_lock;
	// struct rte_mem_resource *chim_res;	/* UIO resource for Tx */
	struct rte_mem_resource chim_res;
	// struct rte_bitmap *chim_bmap;		/* Send buffer map */
	uint32_t		chim_gpadl;
	void		*chim_bmem;
	uint32_t	tx_copybreak;
	uint32_t	chim_szmax;		/* Max size per buffer */
	uint32_t	chim_cnt;		/* Max packets per buffer */

	uint32_t	latency;
	uint32_t	nvs_ver;
	uint32_t	ndis_ver;
	uint32_t	rndis_agg_size;
	uint32_t	rndis_agg_pkts;
	uint32_t	rndis_agg_align;

	volatile uint32_t  rndis_pending;
	rte_atomic32_t	rndis_req_id;
	uint8_t		rndis_resp[256];

	uint32_t	rss_hash;
	uint8_t		rss_key[40];
	uint16_t	rss_ind[128];

	// struct rte_eth_dev_owner owner;

	struct vmbus_channel *channels[HN_MAX_CHANNELS];

	// rte_spinlock_t	hotadd_lock;
	// LIST_HEAD(hotadd_list, hv_hotadd_context) hotadd_list;
	// char		*vf_devargs;
};

static inline struct vmbus_channel *
hn_primary_chan(const struct hn_data *hv)
{
	return hv->channels[0];
}

uint32_t hn_process_events(struct hn_data *hv, uint16_t queue_id,
		       uint32_t tx_limit);

// uint16_t hn_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
// 		      uint16_t nb_pkts);
// uint16_t hn_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
// 		      uint16_t nb_pkts);
int
hn_xmit(struct uk_netdev *n,
		struct uk_netdev_tx_queue *txq,
		struct uk_netbuf *pkt);
int
hn_recv(struct uk_netdev *n __unused,
		struct uk_netdev_rx_queue *rxq,
		struct uk_netbuf **pkt);
	


// int	hn_chim_init(struct rte_eth_dev *dev);
int	hn_chim_init(struct uk_netdev *dev);
// void	hn_chim_uninit(struct rte_eth_dev *dev);
// int	hn_dev_link_update(struct rte_eth_dev *dev, int wait);
// int	hn_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
// 			      uint16_t nb_desc, unsigned int socket_id,
// 			      const struct rte_eth_txconf *tx_conf);
// void	hn_dev_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid);
// void	hn_dev_tx_queue_info(struct rte_eth_dev *dev, uint16_t queue_idx,
// 			     struct rte_eth_txq_info *qinfo);
// int	hn_dev_tx_done_cleanup(void *arg, uint32_t free_cnt);
// int	hn_dev_tx_descriptor_status(void *arg, uint16_t offset);

// struct hn_rx_queue *hn_rx_queue_alloc(struct hn_data *hv,
// 				      uint16_t queue_id,
// 				      unsigned int socket_id);
// int	hn_dev_rx_queue_setup(struct rte_eth_dev *dev,
// 			      uint16_t queue_idx, uint16_t nb_desc,
// 			      unsigned int socket_id,
// 			      const struct rte_eth_rxconf *rx_conf,
// 			      struct rte_mempool *mp);
// void	hn_dev_rx_queue_info(struct rte_eth_dev *dev, uint16_t queue_id,
// 			     struct rte_eth_rxq_info *qinfo);
// void	hn_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid);
// uint32_t hn_dev_rx_queue_count(void *rx_queue);
// int	hn_dev_rx_queue_status(void *rxq, uint16_t offset);
// void	hn_dev_free_queues(struct rte_eth_dev *dev);

// /*
//  * Get VF device for existing netvsc device
//  * Assumes vf_lock is held.
//  */
// static inline struct rte_eth_dev *
// hn_get_vf_dev(const struct hn_data *hv)
// {
// 	if (hv->vf_ctx.vf_attached)
// 		return &rte_eth_devices[hv->vf_ctx.vf_port];
// 	else
// 		return NULL;
// }

// int	hn_vf_info_get(struct hn_data *hv,
// 		       struct rte_eth_dev_info *info);
// int	hn_vf_add(struct rte_eth_dev *dev, struct hn_data *hv);
// int	hn_vf_configure_locked(struct rte_eth_dev *dev,
// 			       const struct rte_eth_conf *dev_conf);
// const uint32_t *hn_vf_supported_ptypes(struct rte_eth_dev *dev);
// int	hn_vf_start(struct rte_eth_dev *dev);
// void	hn_vf_reset(struct rte_eth_dev *dev);
// int	hn_vf_close(struct rte_eth_dev *dev);
// int	hn_vf_stop(struct rte_eth_dev *dev);

// int	hn_vf_allmulticast_enable(struct rte_eth_dev *dev);
// int	hn_vf_allmulticast_disable(struct rte_eth_dev *dev);
// int	hn_vf_promiscuous_enable(struct rte_eth_dev *dev);
// int	hn_vf_promiscuous_disable(struct rte_eth_dev *dev);
// int	hn_vf_mc_addr_list(struct rte_eth_dev *dev,
// 			   struct rte_ether_addr *mc_addr_set,
// 			   uint32_t nb_mc_addr);

// int	hn_vf_tx_queue_setup(struct rte_eth_dev *dev,
// 			     uint16_t queue_idx, uint16_t nb_desc,
// 			     unsigned int socket_id,
// 			     const struct rte_eth_txconf *tx_conf);
// void	hn_vf_tx_queue_release(struct hn_data *hv, uint16_t queue_id);
// int	hn_vf_tx_queue_status(struct hn_data *hv, uint16_t queue_id, uint16_t offset);

// int	hn_vf_rx_queue_setup(struct rte_eth_dev *dev,
// 			     uint16_t queue_idx, uint16_t nb_desc,
// 			     unsigned int socket_id,
// 			     const struct rte_eth_rxconf *rx_conf,
// 			     struct rte_mempool *mp);
// void	hn_vf_rx_queue_release(struct hn_data *hv, uint16_t queue_id);

// int	hn_vf_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);
// int	hn_vf_stats_reset(struct rte_eth_dev *dev);
// int	hn_vf_xstats_get_names(struct rte_eth_dev *dev,
// 			       struct rte_eth_xstat_name *xstats_names,
// 			       unsigned int size);
// int	hn_vf_xstats_get(struct rte_eth_dev *dev,
// 			 struct rte_eth_xstat *xstats,
// 			 unsigned int offset, unsigned int n);
// int	hn_vf_xstats_reset(struct rte_eth_dev *dev);
// int	hn_vf_rss_hash_update(struct rte_eth_dev *dev,
// 			      struct rte_eth_rss_conf *rss_conf);
// int	hn_vf_reta_hash_update(struct rte_eth_dev *dev,
// 			       struct rte_eth_rss_reta_entry64 *reta_conf,
// 			       uint16_t reta_size);
// int	hn_eth_rmv_event_callback(uint16_t port_id,
// 				  enum rte_eth_event_type event __rte_unused,
// 				  void *cb_arg, void *out __rte_unused);

struct hn_dev {
	/* vmbus device */
	struct vmbus_device *vmbusdev;
	/* Network device */
	struct uk_netdev netdev;

	/* List of the Rx/Tx queues */
	uint16_t txqs_num;
	uint16_t rxqs_num;
	struct uk_netdev_tx_queue *txqs;
	struct uk_netdev_rx_queue *rxqs;
	/* Maximum number of queue pairs */
	uint16_t  max_queue_pairs;
	/* True if using split event channels */
	/* bool split_evtchn; */
	// struct vmbus_channel **channels;
	// struct vmbus_channel *channels[HN_MAX_CHANNELS];

	/* The netdevice identifier */
	uint16_t uid;
	/* The mtu */
	uint16_t mtu;
	/* The hw address of the netdevice */
	struct uk_hwaddr hw_addr;
	/* RX promiscuous mode. */
	uint8_t promisc : 1;

	void *dev_private;
};

#define to_hn_dev(dev) \
	__containerof(dev, struct hn_dev, netdev)

/* Taken from dpdk/lib/net/rte_ether.h */

#define RTE_ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */
#define RTE_ETHER_TYPE_LEN  2 /**< Length of Ethernet type field. */
#define RTE_ETHER_CRC_LEN   4 /**< Length of Ethernet CRC. */
#define RTE_ETHER_HDR_LEN   \
	(RTE_ETHER_ADDR_LEN * 2 + \
		RTE_ETHER_TYPE_LEN) /**< Length of Ethernet header. */
#define RTE_ETHER_MIN_LEN   64    /**< Minimum frame len, including CRC. */
#define RTE_ETHER_MAX_LEN   1518  /**< Maximum frame len, including CRC. */
#define RTE_ETHER_MTU       \
	(RTE_ETHER_MAX_LEN - RTE_ETHER_HDR_LEN - \
		RTE_ETHER_CRC_LEN) /**< Ethernet MTU. */

/* Moved from hn_rxtx.c */
/*
 * Per-transmit book keeping.
 * A slot in transmit ring (chim_index) is reserved for each transmit.
 *
 * There are two types of transmit:
 *   - buffered transmit where chimney buffer is used and RNDIS header
 *     is in the buffer. mbuf == NULL for this case.
 *
 *   - direct transmit where RNDIS header is in the in  rndis_pkt
 *     mbuf is freed after transmit.
 *
 * Descriptors come from per-port pool which is used
 * to limit number of outstanding requests per device.
 */
struct hn_txdesc {
	// struct rte_mbuf *m;
	struct uk_netbuf *m;

	uint16_t	queue_id;
	uint32_t	chim_index;
	uint32_t	chim_size;
	uint32_t	data_size;
	uint32_t	packets;

	struct rndis_packet_msg *rndis_pkt;
};

/* From FreeBSD if_hnvar.h */
#define HN_CHIM_SIZE			(15 * 1024 * 1024)

#define HN_RXBUF_SIZE			(31 * 1024 * 1024)
#define HN_RXBUF_SIZE_COMPAT		(15 * 1024 * 1024)