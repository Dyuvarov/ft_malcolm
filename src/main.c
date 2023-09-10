#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "ft_status.h"
#include "malcolm_validator.h"
#include "ft_spoof.h"
#include "libft.h"


char   *chooseInterface(void)
{
    struct ifaddrs  *ifaddr, *ifa; //for network interfaces
    char            *interface_name;

    if (getifaddrs(&ifaddr) < 0)
    {
        printf("ERROR: Can't get network interfaces");
        perror("getifaddrs");
        exit(CANT_GET_NETWORK_INTERFACES);
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

//TODO fix leaks or delete
char   *ipv4_to_str(uint8_t *addr)
{
    int     i = 0;
    char    *str = "";

    for(; i < IP_LEN; ++i)
    {
        char *cur = ft_itoa(addr[i]);
        str = ft_strjoin(str, cur);
        if (i < IP_LEN-1) {
            str = ft_strjoin(str, ".");
        }
    }
    return str;
}

int     spoof(struct spoofaddrs addrs, char *interface_name, int sock)
{
    char                done, buf[sizeof(struct ft_ethhdr) + sizeof(struct ft_arphdr)], arp_src_ip[IP_LEN+IP_LEN], arp_src_mac[MAC_LEN+MAC_LEN];
    size_t              reclen;
    struct sockaddr     from;
    socklen_t           fromlen;
    struct ft_ethhdr    *eth;
    struct ft_arphdr    *arp;
    uint16_t            ptype, opcode;

    fromlen = sizeof(from);
    done = 0;

    printf("waiting for ARP request\n");
    while (!done)
    {
        reclen = recvfrom(sock, buf, ETH_FRAME_LEN, 0, &from, &fromlen);
        if(reclen < 0)
        {
            perror("ERROR: Can't receive message\n");
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

        printf("received arp request from ip=%s, mac=%s\n", ipv4_to_str(arp->spa), "");
        done = 1;
    }
}

void parse_ip_v4(char *str_ip, uint8_t *dst)
{
    in_addr_t ip = inet_addr(str_ip);
    uint8_t *ptr = (uint8_t*)&ip;
    for(int i = 0; i < IP_LEN; ++i)
    {
        dst[i] = ptr[i];
    }
}

void parse_mac(char *mac, uint8_t *dst)
{
    char** part = ft_split(mac, ':');
    int i = 0;

    while (part && *part)
    {

        dst[i++] = ft_atoi_base(*part, "0123456789abcdef");
        ++part;
    }
}


int     main(int argc, char** argv)
{
    int                 validation_result, sock;
    char                *ip_source, *ip_target, *mac_source, *mac_target, *interface_name;
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


    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));    
    // sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        printf("ERROR: Can't open socket\n");
        perror("socket");
        return CANT_OPEN_SOCKET;
    }

    spoof(spaddrs, interface_name, sock);

    return SUCCESS;
}
