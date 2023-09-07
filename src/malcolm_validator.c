#include "malcolm_validator.h"
#include "libft.h"
#include "ft_status.h"
#include <stdio.h>

int validate_ip_v4(char const* ip)
{
    int     partsCount = 0;
    char**  part = ft_split(ip, '.');

    while(part && *part)
    {
        int value = ft_atoi(*part);
        if (value < 0 || value > 255 || (value == 0 && (ft_strlen(*part) != 1 || **part != '0') )) {
            return INVALID_ARGS;
        }
        ++partsCount;
        ++part;
    }

    if (partsCount != 4)
    {
        return INVALID_ARGS;
    }

    return SUCCESS;
}

int validate_mac(char const* mac)
{
    int partsCount = 0;
    char** part = ft_split(mac, ':');

    while (part && *part)
    {
        while(**part)
        {
            if(!(**part >= '0' && **part <='9') && !(**part >='a' && **part <= 'f'))
            {
                return INVALID_ARGS;
            }
            ++(*part);
        }
        ++partsCount;
        ++part;
    }

    if (partsCount != 6)
    {
        return INVALID_ARGS;
    }

    return SUCCESS;
}

int validate_args(int argc, char** argv)
{
    char*   source_ip;
    char*   source_mac;
    char*   target_ip;
    char*   target_mac;

    if (argc != 5) {
        printf("INVALID ARGS! Expected: <source ip> <source mac address> <target ip> <target mac address>");
        return INVALID_ARGS;
    }
    source_ip = argv[1];
    source_mac = argv[2];
    target_ip = argv[3];
    target_mac = argv[4];

    if (validate_ip_v4(source_ip) == INVALID_ARGS) {
        printf("source ip has invalid format");
        return INVALID_ARGS;
    }
    if(validate_mac(source_mac) == INVALID_ARGS) {
        printf("source MAC has invalid format");
        return INVALID_ARGS;
    }
    if (validate_ip_v4(target_ip) == INVALID_ARGS) {
        printf("target ip has invalid format");
        return INVALID_ARGS;
    }
    if(validate_mac(target_mac) == INVALID_ARGS) {
        printf("target MAC has invalid format");
        return INVALID_ARGS;
    }
    return SUCCESS;
}