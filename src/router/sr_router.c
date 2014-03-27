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

#include "sr_router.h"

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

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
void sr_arpreq_send_packets(struct sr_instance * sr, struct sr_arpreq * req);

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
	if (ntohl(len) < minsize) {
		fprintf(stderr, "This is not a valid ETHERNET packet, length is too short.");
		return;
	}
	print_hdrs(packet, len);
	uint16_t  type = ethertype(packet);

	void * pkt = (void*)packet;
	switch (type) {
		case ethertype_ip:
			Debug("Received IP Packet\n");
			sr_handle_ip_packet(sr, pkt + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
			break;

		case ethertype_arp:
			Debug("Received ARP Packet\n");
			sr_handle_arp_packet(sr, pkt + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
			break;
		default:

		return;
	}


}/* end sr_ForwardPacket */



/* Create an ethernet frame only.
 Has NO logic for handling data greater than ethernet's MTU
 destination ethernet address, source ethernet address, packet type ID
 */
bool create_ethernet_header (sr_ethernet_hdr_t * eth_hdr, uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t ether_type) {
	/* MAC addresses are arrays of 8 byte segments so do not need network/host order conversion */
    memcpy((void *) eth_hdr->ether_dhost, (void *) ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy((void *) eth_hdr->ether_shost, (void *) ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ether_type);
    return true;
}

/*
	Setups an IP header at the memory address provided.
	ip_src and ip_dst should be in network byte order.
 */
bool create_ip_header(sr_ip_hdr_t * pkt, uint8_t ip_proto, int payload_size, uint32_t ip_src, uint32_t ip_dst){
    /* assuming the syntax in sr_protocol.h -> sr_ip_hdr means starts out
     with 4 for relevant fields
     TODO: not sure about tos, id, frag, ttl
     */
    pkt->ip_tos = IP_DEFAULT_TOS;
    pkt->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + payload_size));
    pkt->ip_id = htons(IP_DEFAULT_ID);
    pkt->ip_off = htons(IP_DEFAULT_OFF);
    pkt->ip_ttl = IP_DEFAULT_TTL;
    pkt->ip_p = ip_proto;
    pkt->ip_sum = 0;
    /* htons? */
    pkt->ip_src = htonl(ip_src);
    pkt->ip_dst = htonl(ip_dst);
    pkt->ip_sum = cksum(((void *) pkt), sizeof(sr_ip_hdr_t));
    return true;
}
/*
	Create an ICMP header. Does calculating of checksum for you at the memory address provided.
*/
bool create_icmp_header(sr_icmp_hdr_t * icmp_hdr, uint8_t icmp_type, uint8_t icmp_code){
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum  = 0 ;
    icmp_hdr->icmp_sum = cksum((void *)icmp_hdr, sizeof(sr_icmp_hdr_t));
    return true;
}


/* Create a header for an icmp t3
 TODO: memory handling may not work for this and other similar routines*/
bool create_icmp_t3_header(sr_icmp_t3_hdr_t * icmp_t3_hdr, uint8_t icmp_code, uint8_t* data){
    icmp_t3_hdr->icmp_type = ICMP_T3_TYPE;
    icmp_t3_hdr->icmp_code = icmp_code;
    icmp_t3_hdr->next_mtu = ICMP_NEXT_MTU;
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->unused = ICMP_UNUSED;

    memcpy((icmp_t3_hdr->data), data, sizeof(uint8_t) * ICMP_DATA_SIZE);
    
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    
    return true;
}

/* Create arp header */
bool create_arp_header(sr_arp_hdr_t * arp_hdr, unsigned short arp_op, unsigned char * ar_sha, uint32_t ar_sip, unsigned char * ar_tha, uint32_t ar_tip) {
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);

    arp_hdr->ar_hln = ETHER_ADDR_LEN * sizeof(uint8_t);
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op);
    memcpy((void *) arp_hdr->ar_sha , ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
    arp_hdr->ar_sip = htonl(ar_sip);
    if (arp_op == arp_op_reply) {
    	memcpy((void *) arp_hdr->ar_tha , ar_tha, sizeof(unsigned char) * ETHER_ADDR_LEN);
    }
    else {
    	memset(arp_hdr->ar_tha, 0, sizeof(unsigned char) * ETHER_ADDR_LEN);
    }

    arp_hdr->ar_tip = htonl(ar_tip);
    return true;
}

void sr_arp_send_message(struct sr_instance * sr, unsigned short ar_op, unsigned char * ar_tha, uint32_t ar_tip, char * interface) {
	/* TODO: do we just use the first item in the list? */
	struct sr_if * iface = sr_get_interface(sr, interface);
	if (iface == NULL) {
		fprintf(stderr, "Invalid Interface: %s.\n", interface);
		return;
	}

    uint32_t ar_sip = ntohl(iface->ip);
    unsigned char * ar_sha = malloc(sizeof(unsigned char) * ETHER_ADDR_LEN);
    memcpy((void*) ar_sha, iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
    
    sr_ethernet_hdr_t * frame = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    create_ethernet_header(frame, ar_tha, (uint8_t *)ar_sha, ethertype_arp);
    
    void * ptr = (void *) frame;
    ptr += sizeof(sr_ethernet_hdr_t);

    create_arp_header((sr_arp_hdr_t *) ptr, ar_op, ar_sha, ar_sip, ar_tha, ar_tip);

    fprintf(stderr, "Sending ARP:\n");
    print_hdrs((uint8_t *)frame, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_send_packet(sr, (uint8_t*) frame, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface );
    
    free(frame);
}

/**
 * Takes a packet that is destined for an IP address and then sends out an ARP request in order to find the MAC address.
 * Queues the packet on the request queue so that when the reply is received it will send the packet out.
 */
void sr_arp_request(struct sr_instance * sr, uint32_t ip_addr, uint8_t * packet, unsigned int packet_len, char * interface) {
	unsigned char value[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	sr_arp_send_message(sr, arp_op_request, value, ip_addr, interface);
	sr_arpcache_queuereq(&(sr->cache), ip_addr, packet, packet_len, interface);
}

/*Send a non type 3 icmp message*/
void sr_icmp_send_message(struct sr_instance * sr, uint8_t icmp_type, uint8_t icmp_code,sr_ip_hdr_t * packet, char* interface) {

    /* Get source and destination MACs */
    uint8_t * ether_shost = malloc(sizeof(unsigned char) * ETHER_ADDR_LEN);

    struct sr_if * iface = sr_get_interface(sr, interface);
	if (iface == NULL) {
		fprintf(stderr, "Invalid Interface: %s.\n", interface);
	}
    memcpy((void*) ether_shost, iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);

    uint8_t * ether_dhost = malloc(sizeof(unsigned char) * ETHER_ADDR_LEN);
    struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), packet->ip_src);
    if (entry != NULL) {
    	memcpy(ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
    }

    /* Icmp is always IP */
    uint16_t ether_type = ethertype_ip;
    
    /* Allocate memory for Ethernet frame and fill it with an Eth header */



    sr_ethernet_hdr_t * frame = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    create_ethernet_header(frame, ether_dhost, ether_shost, ether_type);
    
    void * ptr = (void *) frame;
    ptr += sizeof(sr_ethernet_hdr_t);
    
    /* TODO:Do we need to use sr_rt at all? */
    uint32_t ip_src = ntohl(packet->ip_dst);
    uint32_t ip_dst= ntohl(packet->ip_src);
    
    /* Place IP header right after the Ethernet Header*/
    create_ip_header((sr_ip_hdr_t *)ptr, ip_protocol_icmp, sizeof(sr_icmp_hdr_t), ip_src, ip_dst);
    
    /* Place ICMP header right after IP header */
    ptr += sizeof(sr_ip_hdr_t);
    create_icmp_header((sr_icmp_hdr_t*)ptr, icmp_type, icmp_code);
    
    unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    if (entry == NULL) {
    	/* do not know the MAC, need to send arp request and queue packet on this request */
    	sr_arp_request(sr, ip_dst, (uint8_t *) frame, packet_len, interface);
    }
    else {
    	/* Send the ethernet frame to the desired interface! */
		sr_send_packet(sr, (uint8_t*) frame, packet_len, interface );
    }
    /* Don't forget to free no longer needed memory*/
    free(frame);
}

/*
 Send a t3 message.  The ip header passed in will be put in the data field along with the first 8 bytes of the IP payload
 */
void sr_icmp_send_t3_message(struct sr_instance * sr, uint8_t icmp_code, sr_ip_hdr_t * packet, char* interface){
    /* Get source and destination MACs */
    uint8_t ether_shost;
    struct sr_if * iface = sr_get_interface(sr, interface);
	if (iface == NULL) {
		fprintf(stderr, "Invalid Interface: %s.\n", interface);
	}

    memcpy((void*) &ether_shost, iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
    uint8_t ether_dhost;


    struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), packet->ip_src);
	if (entry != NULL) {
		memcpy(&ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
	}
    
    /* Icmp is always IP */
    uint16_t ether_type = ethertype_ip;
    
    /* Allocate memory for Ethernet frame and fill it with an Eth header */
    sr_ethernet_hdr_t * frame = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t) +  sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    create_ethernet_header(frame, &ether_dhost, &ether_shost, ether_type);
    void * ptr = (void *) frame;
    ptr += sizeof(sr_ethernet_hdr_t);
    
    /* TODO:Do we need to use sr_rt at all? */
    uint32_t ip_src = ntohl(packet->ip_dst);
    uint32_t ip_dst= ntohl(packet->ip_src);
    
    /* Place IP header right after the Ethernet Header*/
    create_ip_header((sr_ip_hdr_t * )ptr, ip_protocol_icmp, sizeof(sr_icmp_hdr_t), ip_src, ip_dst);
    
    /* Place ICMPT3 header right after IP header */
    ptr += sizeof(sr_ip_hdr_t);
    /* The data field of the t3 header is the IP header and the first 8 bytes of the IP payload */
    create_icmp_t3_header((sr_icmp_t3_hdr_t *) ptr, icmp_code, (uint8_t *) packet);
    uint32_t packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    
    if (entry == NULL) {
    	/* send arp request and queue packet behind this request */
    	sr_arp_request(sr, ip_dst, (uint8_t *) frame, packet_len, interface);
    }
    else {
		/* Send the ethernet frame to the desired interface! */
		sr_send_packet(sr, (uint8_t*) frame, packet_len, interface);
		/* Don't forget to free no longer needed memory*/
    }
    free(frame);
}

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
	
	sr_arp_hdr_t *arphdr = (sr_arp_hdr_t*)(packet);
	arphdr->ar_op = ntohs(arphdr->ar_op);
	arphdr->ar_hrd = ntohs(arphdr->ar_hrd);
	arphdr->ar_pro = ntohs(arphdr->ar_pro);
	arphdr->ar_tip = ntohl(arphdr->ar_tip);
	arphdr->ar_sip = ntohl(arphdr->ar_sip);
	
	if(arphdr->ar_op == 1){ /* it's a request */
        /* implicit decleration stuff TODO fix */
        memcpy((void*) (arphdr->ar_tha), (void *) (arphdr->ar_sha), (sizeof(unsigned char) * ETHER_ADDR_LEN)); /* switch around the fields (dest to src, vice versa) */
		uint32_t target = arphdr->ar_tip;
		arphdr->ar_tip = arphdr->ar_sip;
		arphdr->ar_sip = target;
        
		struct sr_if* interfaceList = sr->if_list;
		while(interfaceList != NULL){ /* iterate through interfaces till it finds the intended target, fills in respective MAC */
			
			if(ntohl(interfaceList->ip) == target){
                memcpy((void*) (arphdr->ar_sha), (void *) (interfaceList->addr), (sizeof(unsigned char) * ETHER_ADDR_LEN));
				/*arphdr->ar_sha = interface->addr;*/
				sr_arp_send_message(sr, ARP_REPLY, arphdr->ar_tha, arphdr->ar_tip, interface); /* send the reply */
				break;
			}
            interfaceList = interfaceList->next;
		}


	}
	else if (arphdr->ar_op == 2){ /* it's a reply*/
		fprintf(stderr, "Got an ARP Reply!\n");
		struct sr_arpreq* pending = sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip); /* store mapping in arpcache */
		while(pending != NULL){
			if(pending->ip == arphdr->ar_sip){
				sr_arpreq_send_packets(sr, pending);
			}
			pending = pending->next;
		}
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
	uint16_t computed_cksum = cksum((void*)packet, sizeof(sr_ip_hdr_t));


	if (computed_cksum != old_sum) {
		fprintf(stderr, "This is not a valid IP packet, the checksum does not match.\n");
		return;
	}
	iphdr->ip_sum = computed_cksum;

	if (sr_packet_is_final_destination(sr, iphdr)) {
		uint8_t ip_proto = ip_protocol(packet);
		if (ip_proto == ip_protocol_icmp) {
			/*NOTE: changed from sr_handle_icmp_packet(sr, packet + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t), interface);*/
            sr_handle_icmp_packet(sr, packet , len , interface);
		}
		else {
			/* we are the final destination */
			/* send a port unreachable message to the sender */
            sr_icmp_send_t3_message(sr, ICMP_PORT_UNREACHABLE_CODE, iphdr, interface);
			/*sr_icmp_send_type_3(sr, iphdr, ICMP_PORT_UNREACHABLE_CODE);*/
		}
	}
	else {
		if (iphdr->ip_ttl <= 1) {
			/* error, ttl has expired
			 send error message
			 */
            
			/*sr_icmp_send_ttl_expired(sr, iphdr, len, interface);*/
            sr_icmp_send_message(sr, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE, (sr_ip_hdr_t *)packet, interface);
			return;
		}
		iphdr->ip_ttl--;
		iphdr->ip_sum = 0;
		iphdr->ip_sum = cksum((void*)iphdr, len);

		struct sr_rt * route = sr_route_prefix_match(sr, &iphdr->ip_dst);
		if (route != NULL) {
			uint8_t * fwd = malloc(len + sizeof(sr_ethernet_hdr_t));
			memcpy(fwd + sizeof(sr_ethernet_hdr_t), iphdr, len);
            sr_ethernet_hdr_t * frame = (sr_ethernet_hdr_t *) fwd;
            
            /* Get source info*/
            struct sr_if * iface = sr_get_interface(sr, interface);
            if (iface == NULL) {
                fprintf(stderr, "Invalid Interface: %s.\n", interface);
            }
            uint8_t * ether_dhost;
            /* Get destination info*/
            struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), iphdr->ip_dst);
            if (entry != NULL) {
                memcpy(&ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
                memcpy((void *) (frame->ether_shost), iface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
                memcpy((void *) (frame->ether_dhost), ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
                frame->ether_type = ethertype_ip;
                sr_send_packet(sr, fwd, len + sizeof(sr_ethernet_hdr_t), interface);
                free(fwd);
            } else {
                /* Put IP packet in queue, send out arp request and cant send*/
                sr_arpcache_queuereq(&sr->cache, iphdr->ip_dst, (uint8_t *) iphdr, len, interface);
                sr_arp_request(sr, iphdr->ip_dst, (uint8_t *) iphdr, len, interface);
            }
            
		}
		else {
			/* no route found
			 * send network unreachable */
			/*sr_icmp_send_type_3(sr,iphdr, ICMP_DESTINATION_NET_UNREACHABLE_CODE);*/
            sr_icmp_send_t3_message(sr, ICMP_DESTINATION_NET_UNREACHABLE_CODE, iphdr, interface);
		}
	}

}


/**
 * Handles an ICMP packet that is received by the router.
 * @param packet pointer points to the beginning of the ICMP header NOTE: now points to the IP header
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
	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet);
    sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (((void *) packet)+ sizeof(sr_ip_hdr_t));

	/* implement this */
    /*
    uint16_t sum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    
     If the checksum doesnt match, discard */
    /* checksums not working for some reason
    if (sum != cksum((void *) icmp_hdr, sizeof(sr_icmp_hdr_t))){
    	fprintf(stderr, "This is not a valid ICMP packet, the checksums do not match.\n");
        return;
    }
    */
    
    uint8_t type = icmp_hdr->icmp_type;
    /*if this is an echo request*/
    switch (type) {
		case ICMP_ECHO_REQUEST_TYPE:
			sr_icmp_send_message(sr, ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_REPLY_CODE, ip_hdr, interface);
			break;
         /* TODO: not sure what cases need handling*/
		case ICMP_TIME_EXCEEDED_TYPE:
			
			break;
		default:
			/* # yolo swag */
            break;
            
    }
    fprintf(stderr, "yolo\n");
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
		cur_iface = cur_iface->next;
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
	struct sr_rt * best_match = NULL;

	while (current != NULL) {
		in_addr_t left = (current->mask.s_addr & *addr);
		in_addr_t right = (current->dest.s_addr & current->mask.s_addr);

		if (left == right) {
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
	uint8_t size = 0;
	/* make it 10...0 */
	uint32_t checker = 1 << 31;

	while ((checker != 0) && ((checker & mask) != 0)) {
		size++;
		checker = checker >> 1;
	}
	return size;
}
