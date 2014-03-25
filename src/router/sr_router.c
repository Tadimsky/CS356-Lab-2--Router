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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
/* IP Field defaults */
#define IP_DEFAULT_TTL 15

/* ICMP Echo Reply Type */
#define ICMP_ECHO_REPLY_TYPE 0
/* ICMP Echo Request Type */
#define ICMP_ECHO_REQUEST_TYPE 8

/* ICMP Type 3 Messages */
#define ICMP_DESTINATION_NET_UNREACHABLE_CODE 0
#define ICMP_DESTINATION_HOST_UNREACHABLE_CODE 1
#define ICMP_PORT_UNREACHABLE_CODE 3

/* ICMP TTL Type */
#define ICMP_TIME_EXCEEDED_TYPE 11
#define ICMP_TIME_EXCEEDED_CODE 0

void sr_handle_arp_packet(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len,	char* interface);
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface);
void sr_handle_icmp_packet(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface);
bool sr_packet_is_final_destination(struct sr_instance* sr, sr_ip_hdr_t * header);
bool sr_packet_is_sender(struct sr_instance* sr, sr_ip_hdr_t * header);
struct sr_rt * sr_route_prefix_match(struct sr_instance * sr, in_addr_t * addr);
int sr_util_mask_length(in_addr_t mask);
void sr_encap_and_send_pkt(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint32_t dip, int send_icmp, enum sr_ethertype type);


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


/*
 TODO: add check for TTL before sending down to sub methods
*/
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

	/* check if packet is valid ethernet */
	uint32_t minsize = sizeof(sr_ethernet_hdr_t);
	if (len < minsize) {
		fprintf(stderr, "This is not a valid ETHERNET packet, length is too short.");
		return;
	}
	uint16_t  type = ethertype(packet);
	switch (type) {
		case ethertype_ip:
			sr_handle_ip_packet(sr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
			break;

		case ethertype_arp:
			sr_handle_arp_packet(sr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
			break;
		default:

		return;
	}


}/* end sr_ForwardPacket */


/**
 * Handles an ARP packet that is received by the router.
 * @param packet pointer points to the beginning of the ARP header
 * @param len is the length of the ARP packet
 */
void sr_handle_arp_packet(struct sr_instance* sr,
                          uint8_t * packet/* lent */,
                          unsigned int len,
                          char* interface) {
	if (len < sizeof(sr_arp_hdr_t)) {
		fprintf(stderr, "This is not a valid ARP packet, length is too short.\n");
		return;
	}
	
	sr_arp_hdr_t *arphdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	
	if(arphdr->ar_op == 1){ /* it's a request */
        /* implicit decleration stuff TODO fix*/
        memcpy((void*) (arphdr->ar_tha), (void *) (arphdr->ar_sha), (sizeof(unsigned char) * ETHER_ADDR_LEN));
		uint32_t target = arphdr->ar_tip;
		arphdr->ar_tip = arphdr->ar_sip;
		arphdr->ar_sip = target;
        
		struct sr_if* interface = sr->if_list;
		while(interface != NULL){
			
			if(interface->ip == target){
                memcpy((void*) (arphdr->ar_sha), (void *) (interface->addr), (sizeof(unsigned char) * ETHER_ADDR_LEN));
				/*arphdr->ar_sha = interface->addr;*/
				break;
			}
            
			interface++;
		}
	}
	else if (arphdr->ar_op == 2){ /* it's a reply*/
		
		sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip);
		
	}
    
}

/**
 * Handles an IP packet that is received by the router.
 * @param packet pointer points to the beginning of the IP header
 * @param len is the length of the IP packet
 */
void sr_handle_ip_packet(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface) {
	if (len < sizeof(sr_ip_hdr_t)) {
		fprintf(stderr, "This is not a valid IP packet, length is too short.\n");
		return;
	}
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet);

	uint16_t old_sum = iphdr->ip_sum;
	iphdr->ip_sum = 0;
	uint16_t computed_cksum = cksum((void*)packet, len);


	if (computed_cksum != old_sum) {
		fprintf(stderr, "This is not a valid IP packet, the checksum does not match.\n");
		return;
	}
	iphdr->ip_sum = computed_cksum;

	if (sr_packet_is_final_destination(sr, iphdr)) {
		uint8_t ip_proto = ip_protocol(packet);
		if (ip_proto == ip_protocol_icmp) {
			sr_handle_icmp_packet(sr, packet + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t), interface);
		}
		else {
			/* we are the final destination */
			/* send a port unreachable message to the sender */
			sr_icmp_send_type_3(sr, iphdr, ICMP_PORT_UNREACHABLE_CODE);
		}
	}
	else {
		if (iphdr->ip_ttl <= 1) {
			/* error, ttl has expired
			 send error message
			 */
			sr_icmp_send_ttl_expired(sr, iphdr, len, interface);
			return;
		}
		iphdr->ip_ttl--;
		iphdr->ip_sum = 0;
		iphdr->ip_sum = cksum((void*)iphdr, len);

		struct sr_rt * route = sr_route_prefix_match(sr, iphdr->ip_dst);
		if (route != NULL) {
			uint8_t * fwd = malloc(len + sizeof(sr_ethernet_hdr_t));
			memcpy(fwd + sizeof(sr_ethernet_hdr_t), iphdr, len);
			/* send the packet */
			free(fwd);
		}
		else {
			/* no route found
			 * send network unreachable */
			sr_icmp_send_type_3(sr,iphdr, ICMP_DESTINATION_NET_UNREACHABLE_CODE);
		}
	}

}

/* Create an ethernet frame WITH its payload following
   Has NO logic for handling data greater than ethernet's MTU
  destination ethernet address, source ethernet address, packet type ID
 */
uint8_t * create_ethernet_packet (uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t ether_type, uint8_t * payload, int payload_size) {
    
    void * pkt = malloc(sizeof(sr_ethernet_hdr_t) + payload_size);
    sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) pkt;
    memcpy((void *) eth_hdr->ether_dhost, (void *) ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy((void *) eth_hdr->ether_shost, (void *) ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    eth_hdr->ether_type = ether_type;

    void * ptr = pkt;
    ptr += sizeof(sr_ethernet_hdr_t);
    memcpy(ptr, payload, payload_size);
    return (uint8_t *) pkt;
}

/*
 Create an IP packet given the memory where it should be placed.  
 Calling function will need to have created an ethernet frame. 
 destination_ptr correlates to the pointer for the ethernet header + sizeof ethernet header.
 TODO: not sure what form payload_size should take
 TODO: do these values need nthos?
 TODO: add the actual payload to pkt
 */
sr_ip_hdr_t * create_ip_packet(uint8_t* destination_ptr, uint8_t* payload, uint8_t ip_proto, int payload_size, uint32_t ip_src, uint32_t ip_dst){
    sr_ip_hdr_t * pkt = (sr_ip_hdr_t *) payload;
    /* assuming the syntax in sr_protocol.h -> sr_ip_hdr means starts out
     with 4 for relevant fields
     TODO: not sure about tos, id, frag, ttl
     Need to find method for this address
    */
    pkt->ip_tos = 0;
    pkt->ip_len = (uint16_t) (sizeof(sr_ip_hdr_t) + payload_size);
    pkt->ip_id = 0;
    pkt->ip_off = 0;
    pkt->ip_ttl = IP_DEFAULT_TTL;
    pkt->ip_p = ip_proto;
    pkt->ip_sum = 0;
    pkt->ip_src =ip_src;
    pkt->ip_dst = ip_dst;
    pkt->ip_sum = cksum(((void *) pkt), payload_size);
    return pkt;
}

/**
 * Handles an ICMP packet that is received by the router.
 * @param packet pointer points to the beginning of the ICMP header
 * @param len is the length of the ICMP packet
 */
void sr_handle_icmp_packet(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface) {
	if (len < sizeof(sr_icmp_hdr_t)) {
		fprintf(stderr, "This is not a valid ICMP packet, length is too short.\n");
		return;
	}
	sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t*)(packet);

	/* implement this */
    uint8_t type = icmp_hdr->icmp_type;
    /*if this is an echo request*/
    if (type == ICMP_ECHO_REQUEST_TYPE ){
        /*uint8_t code = icmp_hdr->icmp_code;*/
        sr_ip_hdr_t * sr_ip_hdr = (sr_ip_hdr_t)(packet + sizeof(sr_ethernet_hdr_t));
        uint32_t src_ip = sr_ip_hdr->ip_src;
        /*TODO: not sure where want the malloc to take place, 
        especially if need to create an ip Packet */
        sr_icmp_hdr_t * echo_reply = malloc(sizeof(sr_icmp_hdr_t));
        echo_reply->icmp_type = 0;
        echo_reply->icmp_code = 0;
        /*place holder 0 for consistent checksum calculations*/
        echo_reply->icmp_sum = 0;
        /* find actual method call for this address*/
        uint32_t this_ip = 0;
        
        echo_reply->icmp_sum = cksum((void *) echo_reply, (int) sizeof(sr_icmp_hdr_t));
        uint8_t * buf = create_ip_packet(echo_reply, ip_protocol_icmp, ((unsigned int) sizeof(sr_icmp_hdr_t), this_ip, uint_32_t src_ip);
                                         
        /*TODO: find out if have to wrap this in an IP packet first.
        question is does sr_send_packet take any payload, or an IP packet
        Also find out call to get iface
        */
                                         
        const char* iface = "this is not right";
                                         
        /*sr_send_packet expects a regualr int*/
        int bufsize = (int) (((sr_ip_hdr_t) buf)->ip_len);
        sr_send_packet(sr, buf, bufsize, iface);
    }
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
		if ((current->mask.s_addr & *addr) == (ntohl(current->dest.s_addr) & current->mask.s_addr)) {
			int size = sr_util_mask_length(current->mask.s_addr);
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
	/* make it 10...0 */
	int checker = 1 << 31;

	while ((checker != 0) && ((checker & mask) != 0)) {
		size++;
		checker = checker >> 1;
	}
	return size;
}

void sr_wrap_and_send_pkt(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint32_t dip, int send_icmp, enum sr_ethertype type) {
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

void sr_icmp_send(struct sr_instance * sr, sr_ip_hdr_t * packet, uint32_t len, char interface, uint8_t type) {

	if (type == TTL_EXPIRED) {

	}
	else if (type == TYPE_THREE) {

	}
	else if (type == ECHO_REPLY) {

	}
}

void sr_icmp_send_ttl_expired(struct sr_instance * sr, sr_ip_hdr_t * packet, uint32_t len, char interface) {

}

void sr_icmp_send_type_3(struct sr_instance * sr, sr_ip_hdr_t * packet, uint8_t icmp_code) {
	uint8_t * icmp_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t));
	/* setup ip header */


	/* get route for the packet to send back to sender */
	struct sr_rt * route = sr_route_prefix_match(sr, packet->ip_src);
	if (route == NULL) {
		/* error */
		return;
	}
	/* get interface that corresponds to the route */
	struct sr_if * iface = sr_get_interface(sr, route->interface);
	if (iface == NULL) {
		/* error */
		return;
	}

	sr_icmp_t3_hdr_t * icmp_header = (sr_icmp_t3_hdr_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	icmp_header->icmp_type = 3;
	icmp_header->icmp_code = icmp_code;
	icmp_header->icmp_sum = 0;
	/* data is first bit of original date */
	memcpy(icmp_header->data, packet, ICMP_DATA_SIZE);
	icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
	/* send the packet */
	free(icmp_packet);


}

void sr_icmp_send_echo_reply(struct sr_instance * sr, sr_ip_hdr_t * packet, uint32_t len, char interface) {

}


