#include "parser.h"

void    parse_ip_v4(char *str_ip, uint8_t *dst)
{
    in_addr_t ip = inet_addr(str_ip);
    uint8_t *ptr = (uint8_t*)&ip;
    for(int i = 0; i < IP_LEN; ++i)
    {
        dst[i] = ptr[i];
    }
}

void    parse_mac(char *mac, uint8_t *dst)
{
    char** part = ft_split(mac, ':');
    int i = 0;

    while (part && *part)
    {
        dst[i++] = ft_atoi_base(*part, "0123456789abcdef");
        ++part;
    }
}