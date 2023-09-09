#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include "ft_status.h"
#include "malcolm_validator.h"
#include "libft.h"


char*   chooseInterface(void)
{
    struct ifaddrs  *ifaddr, *ifa; //for network interfaces
    char            *interface_name;

    if (getifaddrs(&ifaddr) < 0)
    {
        printf("Can't get network interfaces");
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


int     main(int argc, char** argv)
{
    int             validation_result, sock;
    char            *ip_source, *ip_target, *mac_source, *mac_target, *interface_name;

    validation_result = validate_args(argc, argv);
    if (validation_result != SUCCESS) {
        return validation_result;
    }

    ip_source = argv[1];
    ip_target = argv[3];
    mac_source = argv[2];
    mac_target = argv[4];
    printf("%s, %s, %s, %s\n", ip_source, ip_target, mac_source, mac_target);
    
    interface_name = chooseInterface();
    printf("using interface: %s\n", interface_name);


    sock = socket(AF_PACKET, SOCK_RAW, 0);    
    // sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        printf("Can't open socket\n");
        perror("socket");
        return CANT_OPEN_SOCKET;
    }

    return SUCCESS;
}
