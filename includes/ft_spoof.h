#ifndef FT_SPOOF_H
#define FT_SPOOF_H

#define MAC_LEN 6  // length of mac address in bytes
#define IP_LEN  4  // length of ip address in bytes

// follownig RFC 826
struct ft_ethhdr
{
    uint8_t     trgt_mac[MAC_LEN]; // target mac address
    uint8_t     src_mac[MAC_LEN];  // source mac address
    u_int16_t   type;              // protocol type (ARP or other)
};

// follownig RFC 826
struct ft_arphdr
{
    uint16_t    hrd;           // hardware address space
    uint16_t    pro;           // protocol address space
    uint8_t     hln;           // hardware address length
    uint8_t     pln;           // protocol address length
    uint16_t    op;            // ARP opcode (request / response)
    uint8_t     sha[MAC_LEN];  // hardware address of sender
    uint8_t     spa[IP_LEN];   // protocol address of sender
    uint8_t     tha[MAC_LEN];  // hardware address of target
    uint8_t     tpa[IP_LEN];   // protocol address of target
};

// follownig RFC 826
struct ft_arpbody
{
    struct ft_ethhdr eth;
    struct ft_arphdr arp;
};

struct spoofaddrs
{
    uint8_t  ip_source[IP_LEN];
    uint8_t  mac_source[MAC_LEN];
    uint8_t  ip_target[IP_LEN];
    uint8_t  mac_target[MAC_LEN];
};

#endif //FT_SPOOF_H