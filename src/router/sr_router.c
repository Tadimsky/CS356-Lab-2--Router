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
	if (computed_cksum != iphdr->ip_sum) {
		fprintf(stderr, "This is not a valid IP packet, the checksum does not match.\n");
		return;
	}

	if (sr_packet_is_final_destination(sr, iphdr)) {
		uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
		if (ip_proto == ip_protocol_icmp) {
			sr_handle_icmp_packet(sr, packet, len, interface);
		}
		else {

		}
		// we are the final destination
		// send a port unreachable message to the sender
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

