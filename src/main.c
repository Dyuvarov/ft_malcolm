#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "ft_status.h"
#include "malcolm_validator.h"
#include "libft.h"


struct spoofaddrs
{
    char    *ip_source;
    char    *mac_source;
    char    *ip_target;
    char    *mac_target;
};


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

int     spoof(struct spoofaddrs addrs, char *interface_name, int sock)
{
    char                done, buf[ETH_FRAME_LEN];
    size_t              reclen;
    struct sockaddr     from;
    socklen_t           fromlen;
    struct arphdr      *arp;
    struct ether_header *eth;
    uint16_t            type;
    uint16_t            opcode;

    fromlen = sizeof(from);
    done = 0;

    printf("interface: %s\n", interface_name);
    printf("waiting for ARP request\n");
    while (!done)
    {
        reclen = recvfrom(sock, buf, ETH_FRAME_LEN, 0, &from, &fromlen);
        if(reclen < 0)
        {
            perror("ERROR: Can't receive message\n");
            exit(CANT_RECEIVE_MESSAGE);
        }
        ft_bzero(buf+reclen, ETH_FRAME_LEN - reclen);
        
        eth = (struct ether_header *)buf;
        type = ntohs(eth->ether_type);
        arp = (struct arphdr *) (buf + sizeof(struct ether_header));
        opcode = ntohs(arp->ar_op);
        if (!(type == ETHERTYPE_ARP && opcode == ARPOP_REQUEST))
        {
            continue;
        }
        printf("received arp request\n");
        done = 1;

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

    spaddrs.ip_source = argv[1];
    spaddrs.ip_target = argv[3];
    spaddrs.mac_source = argv[2];
    spaddrs.mac_target = argv[4];
    
    interface_name = chooseInterface();
    printf("using interface: %s\n", interface_name);


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
