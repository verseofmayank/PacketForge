#include <iostream>
#include <cstring>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/headers.hpp"

void print_mac(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003)); // ETH_P_ALL

    if (sock < 0) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "Raw socket created. Listening for packets... (Ctrl+C to stop)\n" << std::endl;

    unsigned char buffer[65536];

    while (true) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);

        if (data_size < 0) {
            std::cerr << "recvfrom failed: " << strerror(errno) << std::endl;
            break;
        }

        EthHeader* eth = (EthHeader*)buffer;
        uint16_t ethertype = ntohs(eth->ethertype);

        printf("--- Packet (%d bytes) ---\n", data_size);
        printf("Src MAC: "); print_mac(eth->src_mac); printf("\n");
        printf("Dst MAC: "); print_mac(eth->dst_mac); printf("\n");
        printf("EtherType: 0x%04x\n", ethertype);

        if (ethertype == 0x0800) { // IPv4
            IPHeader* ip = (IPHeader*)(buffer + sizeof(EthHeader));
            int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

            struct in_addr src, dst;
            src.s_addr = ip->src_ip;
            dst.s_addr = ip->dst_ip;

            printf("Src IP: %s\n", inet_ntoa(src));
            printf("Dst IP: %s\n", inet_ntoa(dst));
            printf("Protocol: %d ", ip->protocol);

            unsigned char* transport = buffer + sizeof(EthHeader) + ip_header_len;

            if (ip->protocol == 6) { // TCP
                TCPHeader* tcp = (TCPHeader*)transport;
                printf("(TCP)\n");
                printf("Src Port: %d\n", ntohs(tcp->src_port));
                printf("Dst Port: %d\n", ntohs(tcp->dst_port));
            }
            else if (ip->protocol == 17) { // UDP
                UDPHeader* udp = (UDPHeader*)transport;
                printf("(UDP)\n");
                printf("Src Port: %d\n", ntohs(udp->src_port));
                printf("Dst Port: %d\n", ntohs(udp->dst_port));
            }
            else if (ip->protocol == 1) {
                printf("(ICMP)\n");
            }
            else {
                printf("(Other)\n");
            }
        }
        else if (ethertype == 0x0806) {
            printf("ARP packet\n");
        }

        printf("\n");
    }

    close(sock);
    return 0;
}

