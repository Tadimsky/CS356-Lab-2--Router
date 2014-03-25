/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);
	/* Ethernet */

	// check if packet is valid ethernet
	uint32_t minsize = sizeof(sr_ethernet_hdr_t);
	if (len < minsize) {
		fprintf(stderr, "This is not a valid ETHERNET packet, length is too short.");
		return;
	}
	uint16_t  type = ethertype(packet);
	switch (type) {
		case ethertype_ip:
			sr_handle_ip_packet(sr, packet, len, interface);
			break;

		case ethertype_arp:
			sr_handle_arp_packet(sr, packet, len, interface);
			break;
		default:

		return;
	}


}/* end sr_ForwardPacket */


void sr_handle_arp_packet(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface) {
	uint32_t minsize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	if (len < minsize) {
		fprintf(stderr, "This is not a valid ARP packet, length is too short.\n");
		return;
	}

}

void sr_handle_ip_packet(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface) {

	uint32_t minsize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
	if (len < minsize) {
		fprintf(stderr, "This is not a valid IP packet, length is too short.\n");
		return;
	}
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	uint16_t computed_cksum = cksum((void*)packet, len);
	uint16_t old_sum = iphdr->ip_sum;
	iphdr->ip_sum = 0;
	if (computed_cksum != old_sum) {
		fprintf(stderr, "This is not a valid IP packet, the checksum does not match.\n");
		return;
	}
	iphdr->ip_sum = computed_cksum;

	if (sr_packet_is_final_destination(sr, iphdr)) {
		uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
		if (ip_proto == ip_protocol_icmp) {
			sr_handle_icmp_packet(sr, packet, len, interface);
		}
		else {
			// we are the final destination
			// send a port unreachable message to the sender
		}
	}
	else {
		// forward the packet
		// decrement ttl by 1
		// recompute checksum
		// etc
	}

}

void sr_handle_icmp_packet(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface) {
	uint32_t minsize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	if (len < minsize) {
		fprintf(stderr, "This is not a valid ICMP packet, length is too short.\n");
		return;
	}
	sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	// implement this
}

/**
 * Determines whether we are the final destination of the packet.
 * Iterates through the interfaces of the router to determine this.
 */
bool sr_packet_is_final_destination(struct sr_instance* sr, sr_ip_hdr_t * header) {
	struct sr_if * cur_iface = sr->if_list;
	while (cur_iface != NULL) {
		if (header->ip_dst == cur_iface->ip) {
			return true;
		}
	}
	return false;
}

/**
 * Determines whether we are the sender of the current packet.
 * Iterates through the interfaces of the router to determine this.
 */
bool sr_packet_is_sender(struct sr_instance* sr, sr_ip_hdr_t * header) {
	struct sr_if * cur_iface = sr->if_list;
	while (cur_iface != NULL) {
		if (header->ip_src == cur_iface->ip) {
			return true;
		}
	}
	return false;
}

/**
 * Performs longest prefix match on IP address and the routes for the router.
 */
struct sr_rt * sr_route_prefix_match(struct sr_instance * sr, in_addr_t * addr) {
	struct sr_rt * current = sr->routing_table;
	int max_len = -1;
	struct sr_rt * best_match;

	while (current != NULL) {
		if ((current->mask.s_addr & addr) == (ntohl(current->dest.s_addr) & current->mask.s_addr)) {
			int size = sr_util_mask_length(current->mask);
			if (size > max_len) {
				max_len = size;
				best_match = current;
			}
		}
		current = current->next;
	}
	return best_match;


}

int sr_util_mask_length(in_addr_t mask) {
	int size = 0;
	// make it 10...0
	int checker = 1 << 31;

	while ((checker != 0) && ((checker & mask) != 0)) {
		size++;
		checker = checker >> 1;
	}
	return size;
}

void sr_encap_and_send_pkt(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint32_t dip, int send_icmp, enum sr_ethertype type) {
	struct sr_arpentry *arp_entry;
	struct sr_arpreq *arp_req;
	struct sr_ethernet_hdr eth_hdr;
	uint8_t *eth_pkt;
	struct sr_if *interface;
	struct sr_rt *rt;
	unsigned int eth_pkt_len;
    
	/* Look up shortest prefix match in your routing table. */
	rt = sr_longest_prefix_match(sr, ip_in_addr(dip));
    
	/* If the entry doesn't exist, send ICMP host unreachable and return if necessary. */
	if (rt == 0) {
		if (send_icmp)
			sr_send_icmp(sr, packet, len, 3, 0);
		return;
	}
    
	/* Fetch the appropriate outgoing interface. */
	interface = sr_get_interface(sr, rt->interface);
    
	/* If there is already an arp entry in the cache, send now. */
	arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
	if (arp_entry || type == ethertype_arp) {
        
		/* Create the ethernet packet. */
		eth_pkt_len = len + sizeof(eth_hdr);
		eth_hdr.ether_type = htons(type);
        
		/* Destination is broadcast if it is an arp request. */
		if (type == ethertype_arp && ((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request))
			memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
        
		/* Destination is the arp entry mac if it is an ip packet or and are reply. */
		else
			memcpy(eth_hdr.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
		memcpy(eth_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);
		eth_pkt = malloc(eth_pkt_len);
		memcpy(eth_pkt, &eth_hdr, sizeof(eth_hdr));
		memcpy(eth_pkt + sizeof(eth_hdr), packet, len);
		sr_send_packet(sr, eth_pkt, eth_pkt_len, rt->interface);
		free(eth_pkt);
		if (arp_entry)
			free(arp_entry);
        
        /* Otherwise add it to the arp request queue. */
	} else {
		eth_pkt = malloc(len);
		memcpy(eth_pkt, packet, len);
		arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, eth_pkt, len, rt->interface);
		sr_arpreq_handle(sr, arp_req);
		free(eth_pkt);
	}
}

