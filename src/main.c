#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
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

int     spoof(struct spoofaddrs addrs, char *interface_name, int sock)
{
    char                done, buf[sizeof(struct ft_ethhdr) + sizeof(struct ft_arphdr)];
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
