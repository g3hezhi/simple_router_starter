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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

static void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);
static void sr_forward_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len);
struct sr_if *sr_get_interface_from_addr(struct sr_instance *sr, const unsigned char *addr);
struct sr_if *sr_get_interface_from_ip(struct sr_instance *sr, uint32_t ip_nbo);
static void sr_handle_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len);
static void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code);

static void sr_lookup_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *oiface, uint32_t ip);
struct sr_rt *sr_longest_prefix_match_lookup(struct sr_instance *sr, uint32_t ip);
static void sr_handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);
static void sr_send_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *oiface, struct sr_if *tiface);
static void sr_send_arp_request(struct sr_instance *sr, struct sr_if *oiface, uint32_t tip);

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

    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Failed to process ETHERNET header, insufficient length\n");
        return;
    }
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    
    uint16_t ether_type = ntohs(eth_hdr->ether_type);
    struct sr_if *iface = sr_get_interface(sr, interface);
    
    if (ether_type == ethertype_ip) {
        sr_handle_ip(sr, packet, len, iface);
    } else if (ether_type == ethertype_arp) {
        sr_handle_arp(sr, packet, len, iface);
    }
}

void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    assert(sr);
    assert(packet);
    assert(iface);
    
    
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "Failed to process IP header, insufficient length\n");
        return;
    }
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    
    if (len < sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4)) {
        fprintf(stderr, "Failed to process IP header, insufficient length\n");
        return;
    }
    
    /* verify checksum */
    uint16_t received_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    
    uint16_t computed_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    ip_hdr->ip_sum = received_cksum;
    
    if (received_cksum != computed_cksum) {
        fprintf(stderr, "Failed to process IP header, incorrect checksum\n");
        return;
    }
     
    struct sr_if *diface = sr_get_interface_from_ip(sr, ip_hdr->ip_dst);
    
    if (!diface) {
        sr_forward_ip(sr, packet, len);
    } else {
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_handle_icmp(sr, packet, len);
        } else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0011) {
            sr_send_icmp(sr, packet, len, 3, 3);
        }
    }
}

void sr_forward_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
    assert(sr);
    assert(packet);
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
   
    ip_hdr->ip_ttl--;
    
    if (ip_hdr->ip_ttl == 0) {
        sr_send_icmp(sr, packet, len, 11, 0);
        return;
    }
    

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    
    
    struct sr_rt *rt = sr_longest_prefix_match_lookup(sr, ip_hdr->ip_dst);
    
    if (!rt) {
        sr_send_icmp(sr, packet, len, 3, 0);
        return;
    }
    
    
    struct sr_if *oiface = sr_get_interface(sr, rt->interface);
    
    sr_lookup_and_send(sr, packet, len, oiface, rt->gw.s_addr);
} 

void sr_handle_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
    assert(sr);
    assert(packet);
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    
    if (len < sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4) + sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "Failed to process ICMP header, insufficient length\n");
        return;
    }
    
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

    uint16_t received_cksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    
    uint16_t computed_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
    icmp_hdr->icmp_sum = received_cksum;
    
    if (received_cksum != computed_cksum) {
        fprintf(stderr, "Failed to process ICMP header, incorrect checksum\n");
        return;
    }
    
    if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
        sr_send_icmp(sr, packet, len, 0, 0);
    }
} 

void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code)
{
    assert(sr);
    assert(packet);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
    

    struct sr_rt *rt = sr_longest_prefix_match_lookup(sr, ip_hdr->ip_src);
    
    if (!rt) {
        
        return;
    }
    
    
    struct sr_if *oiface = sr_get_interface(sr, rt->interface);
    
    if (icmp_type == 0) {
        
        memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        
        uint32_t ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_dst;
        
        
        icmp_hdr->icmp_type = 0;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
       
        sr_lookup_and_send(sr, packet, len, oiface, rt->gw.s_addr);
    } else if (icmp_type == 3) {
        unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t *buf = (uint8_t *)malloc(new_len);
        assert(buf);
        
        sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
       
        memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_ip);
        
    
        new_ip_hdr->ip_v = 4;
        new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        new_ip_hdr->ip_tos = 0;
        new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_hdr->ip_id = htons(0);
        new_ip_hdr->ip_off = htons(IP_DF);
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        
        if (icmp_code == 3) {
            new_ip_hdr->ip_src = ip_hdr->ip_dst;
        } else {
            new_ip_hdr->ip_src = oiface->ip;
        }
        
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
        
        /* icmp header */
        new_icmp_hdr->icmp_type = icmp_type;
        new_icmp_hdr->icmp_code = icmp_code;
        new_icmp_hdr->unused = 0;
        new_icmp_hdr->next_mtu = 0;
        memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        
        new_icmp_hdr->icmp_sum = 0;
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        
        /* print_hdrs(buf, new_len); */
        sr_lookup_and_send(sr, buf, new_len, oiface, rt->gw.s_addr);
        free(buf);
    } else if (icmp_type == 11) {
        unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t *buf = (uint8_t *)malloc(new_len);
        assert(buf);
        
        sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        /* ethernet header */
        memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_ip);
        
        /* ip header */
        new_ip_hdr->ip_v = 4;
        new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        new_ip_hdr->ip_tos = 0;
        new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_hdr->ip_id = htons(0);
        new_ip_hdr->ip_off = htons(IP_DF);
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        new_ip_hdr->ip_src = oiface->ip;
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
        
        /* icmp header */
        new_icmp_hdr->icmp_type = icmp_type;
        new_icmp_hdr->icmp_code = icmp_code;
        new_icmp_hdr->unused = 0;
        memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        
        new_icmp_hdr->icmp_sum = 0;
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        
        /* print_hdrs(buf, new_len); */
        sr_lookup_and_send(sr, buf, new_len, oiface, rt->gw.s_addr);
        free(buf);
    }
} /* -- sr_send_icmp -- */

void sr_lookup_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *oiface, uint32_t ip)
{
    assert(sr);
    assert(packet);
    assert(oiface);
    
    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip);
    
    if (entry) {
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        
        memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
        
        sr_send_packet(sr, packet, len, oiface->name);
        
        free(entry);
    } else {
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip, packet, len, oiface->name);
        
        sr_handle_arpreq(sr, req);
    }
} /* -- sr_lookup_and_send -- */

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
{
    assert(sr);
    assert(req);
    
    if (difftime(time(NULL), req->sent) >= 1.0) {
        if (req->times_sent >= 5) {
            struct sr_packet *pkt = NULL;
            sr_ethernet_hdr_t *eth_hdr = NULL;
            struct sr_if *iface = NULL;
            
            pkt = req->packets;
            
            while (pkt) {
                eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
                iface = sr_get_interface_from_addr(sr, eth_hdr->ether_dhost);
                
                /* do not send an ICMP message for an ICMP message */
                if (iface) {
                    sr_send_icmp(sr, pkt->buf, pkt->len, 3, 1);
                }
                
                pkt = pkt->next;
            }
            
            sr_arpreq_destroy(&(sr->cache), req);
        } else {
            struct sr_if *oiface = sr_get_interface(sr, req->packets->iface);
            
            sr_send_arp_request(sr, oiface, req->ip);
            
            req->sent = time(NULL);
            req->times_sent++;
        }
    }
} /* -- sr_handle_arpreq -- */

void sr_handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    assert(sr);
    assert(packet);
    assert(iface);
    
    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "Failed to process ARP header, insufficient length\n");
        return;
    }
    
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* print_hdr_arp((uint8_t *)arp_hdr); */
    
    /* check hardware type */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        return;
    }
    
    /* check protocol */
    if (ntohs(arp_hdr->ar_pro) != ethertype_ip) {
        return;
    }
    
    /* is it for me? */
    struct sr_if *tiface = sr_get_interface_from_ip(sr, arp_hdr->ar_tip);
    
    if (!tiface) {
        return;
    }
    
    unsigned short arp_op = ntohs(arp_hdr->ar_op);
    
    if (arp_op == arp_op_request) {
        sr_send_arp_reply(sr, packet, iface, tiface);
    } else if (arp_op == arp_op_reply) {
        struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        
        if (req) {
            struct sr_packet *pkt = NULL;
            struct sr_if *oiface = NULL;
            sr_ethernet_hdr_t *eth_hdr = NULL;
            
            pkt = req->packets;
            
            while (pkt) {
                oiface = sr_get_interface(sr, pkt->iface);
                
                eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
                
                memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
                
                sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                
                pkt = pkt->next;
            }
            
            sr_arpreq_destroy(&(sr->cache), req);
        }
    }
} /* -- sr_handle_arp -- */

void sr_send_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *oiface, struct sr_if *tiface)
{
    assert(sr);
    assert(packet);
    assert(oiface);
    assert(tiface);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf);
    
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    
    /* ethernet header */
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = eth_hdr->ether_type;
    
    /* arp header */
    new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = arp_hdr->ar_pln;
    new_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(new_arp_hdr->ar_sha, tiface->addr, ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip = tiface->ip;
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;
    
    /* print_hdrs(buf, len); */
    sr_send_packet(sr, buf, len, oiface->name);
    free(buf);
} /* -- sr_send_arp_reply -- */

void sr_send_arp_request(struct sr_instance *sr, struct sr_if *oiface, uint32_t tip)
{
    assert(sr);
    assert(oiface);
    
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    
    /* ethernet header */
    memset(eth_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);
    
    /* arp header */
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, oiface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = oiface->ip;
    memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = tip;
    
    /* print_hdrs(buf, len); */
    sr_send_packet(sr, buf, len, oiface->name);
    free(buf);
} /* -- sr_send_arp_request -- */

struct sr_rt *sr_longest_prefix_match_lookup(struct sr_instance *sr, uint32_t ip)
{
    struct sr_rt *rt_walker = 0;
    struct sr_rt *prefix_match = 0;
    uint32_t prefix_len = 0;
    
    assert(sr);
    
    rt_walker = sr->routing_table;
    
    while (rt_walker) {
        if ((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == (ip & rt_walker->mask.s_addr)) {
            if (prefix_len <= rt_walker->mask.s_addr) {
                prefix_match = rt_walker;
                prefix_len = rt_walker->mask.s_addr;
            }
        }
        
        rt_walker = rt_walker->next;
    }
    
    return prefix_match;
}

struct sr_if *sr_get_interface_from_addr(struct sr_instance *sr, const unsigned char *addr)
{
    struct sr_if *if_walker = 0;
    
    assert(addr);
    assert(sr);
    
    if_walker = sr->if_list;
    
    while (if_walker) {
        if (!memcmp(if_walker->addr, addr, ETHER_ADDR_LEN)) {
            return if_walker;
        }
        
        if_walker = if_walker->next;
    }
    
    return 0;
} /* -- sr_get_interface_from_addr -- */

/*---------------------------------------------------------------------
 * Method: sr_get_interface_from_ip
 * Scope: Global
 *
 * Given an IP address return the interface record or 0 if it doesn't
 * exist.
 *
 *---------------------------------------------------------------------*/

struct sr_if *sr_get_interface_from_ip(struct sr_instance *sr, uint32_t ip_nbo)
{
    struct sr_if *if_walker = 0;
    
    assert(sr);
    
    if_walker = sr->if_list;
    
    while (if_walker) {
        if (if_walker->ip == ip_nbo) {
            return if_walker;
        }
        
        if_walker = if_walker->next;
    }
    
    return 0;
} /* -- sr_get_interface_from_ip -- */