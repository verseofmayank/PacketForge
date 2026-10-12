#include <iostream>
#include <cstring>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/headers.hpp"
#include "../include/rules.hpp"

void print_mac(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Check packet against rule table, return matching action
Action checkRules(const std::string& src_ip, const std::string& dst_ip, int dst_port) {
    for (auto& rule : ruleTable) {
        bool src_match = (rule.src_ip == "any" || rule.src_ip == src_ip);
        bool dst_match = (rule.dst_ip == "any" || rule.dst_ip == dst_ip);
        bool port_match = (rule.dst_port == -1 || rule.dst_port == dst_port);

        if (src_match && dst_match && port_match) {
            return rule.action;
        }
    }
    return Action::ALLOW; // fallback
}

int main() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003)); // ETH_P_ALL

    if (sock < 0) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "PacketForge running. Listening + filtering... (Ctrl+C to stop)\n" << std::endl;

    unsigned char buffer[65536];
    long total = 0, allowed = 0, dropped = 0;

    while (true) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (data_size < 0) break;

        total++;
        EthHeader* eth = (EthHeader*)buffer;
        uint16_t ethertype = ntohs(eth->ethertype);

        if (ethertype != 0x0800) continue; // only handle IPv4 for forwarding

        IPHeader* ip = (IPHeader*)(buffer + sizeof(EthHeader));
        int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

        struct in_addr src, dst;
        src.s_addr = ip->src_ip;
        dst.s_addr = ip->dst_ip;
        std::string src_ip = inet_ntoa(src);
        std::string dst_ip = inet_ntoa(dst);

        int dst_port = -1;
        unsigned char* transport = buffer + sizeof(EthHeader) + ip_header_len;

        if (ip->protocol == 6) {
            TCPHeader* tcp = (TCPHeader*)transport;
            dst_port = ntohs(tcp->dst_port);
        } else if (ip->protocol == 17) {
            UDPHeader* udp = (UDPHeader*)transport;
            dst_port = ntohs(udp->dst_port);
        }

        Action decision = checkRules(src_ip, dst_ip, dst_port);

        printf("Src: %s -> Dst: %s:%d | Protocol: %d | Decision: %s\n",
               src_ip.c_str(), dst_ip.c_str(), dst_port, ip->protocol,
               decision == Action::ALLOW ? "ALLOW" : "DROP");

        if (decision == Action::ALLOW) allowed++;
        else dropped++;

        if (total % 20 == 0) {
            printf("\n[Stats] Total: %ld | Allowed: %ld | Dropped: %ld\n\n", total, allowed, dropped);
        }
    }

    close(sock);
    return 0;
}
