#include "packetforge/capture.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
namespace packetforge {
namespace {
volatile std::sig_atomic_t stopped = 0;
void stop(int) { stopped = 1; }
class Socket {
    int fd_;
public:
    explicit Socket(int fd) : fd_(fd) {}
    ~Socket() { if (fd_ >= 0) ::close(fd_); }
    Socket(const Socket&) = delete; Socket& operator=(const Socket&) = delete;
    int get() const { return fd_; }
};
struct Signals {
    struct sigaction old_int{}, old_term{};
    Signals() {
        stopped = 0; struct sigaction action{}; action.sa_handler = stop; sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, &old_int) < 0) throw std::runtime_error("cannot install SIGINT handler");
        if (sigaction(SIGTERM, &action, &old_term) < 0) {
            sigaction(SIGINT, &old_int, nullptr); throw std::runtime_error("cannot install SIGTERM handler");
        }
    }
    ~Signals() { sigaction(SIGINT, &old_int, nullptr); sigaction(SIGTERM, &old_term, nullptr); }
};
void check(int rc, const char* message) { if (rc < 0) throw std::runtime_error(std::string(message)+": "+std::strerror(errno)); }
}
void list_interfaces() {
    struct if_nameindex* interfaces = if_nameindex();
    if (!interfaces) throw std::runtime_error("could not enumerate interfaces");
    std::cout << "PacketForge | available capture interfaces\n";
    for (auto* i = interfaces; i->if_index; ++i) std::cout << i->if_index << "\t" << i->if_name << '\n';
    if_freenameindex(interfaces);
}
CaptureResult capture_live(const CaptureOptions& options, const PacketConsumer& consume, const std::function<void()>& tick) {
    const auto index = if_nametoindex(options.interface.c_str());
    if (!index) throw std::runtime_error("unknown interface: " + options.interface + "; use packetforge interfaces");
    Socket socket(::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL)));
    if (socket.get() < 0) throw std::runtime_error(std::string("AF_PACKET capture: ") + std::strerror(errno)
        + ". Live capture requires CAP_NET_RAW (or sudo) on an authorized Linux interface; offline analysis needs neither.");
    ifreq request{}; std::strncpy(request.ifr_name, options.interface.c_str(), IFNAMSIZ-1);
    check(ioctl(socket.get(), SIOCGIFHWADDR, &request), "interface hardware type");
    if (request.ifr_hwaddr.sa_family != ARPHRD_ETHER && request.ifr_hwaddr.sa_family != ARPHRD_LOOPBACK)
        throw std::runtime_error("capture requires Ethernet or Linux loopback link framing");
    sockaddr_ll address{}; address.sll_family = AF_PACKET; address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(index);
    check(bind(socket.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)), "bind interface");
    int enabled = 1;
    check(setsockopt(socket.get(), SOL_PACKET, PACKET_AUXDATA, &enabled, sizeof(enabled)), "PACKET_AUXDATA");
    check(setsockopt(socket.get(), SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled)), "SO_TIMESTAMPNS");
    if (options.promiscuous) {
        packet_mreq membership{}; membership.mr_ifindex = static_cast<int>(index); membership.mr_type = PACKET_MR_PROMISC;
        check(setsockopt(socket.get(), SOL_PACKET, PACKET_ADD_MEMBERSHIP, &membership, sizeof(membership)), "promiscuous membership");
    }
    Signals signals; CaptureResult result;
    std::array<std::uint8_t, 262144> buffer{};
    const auto begin = std::chrono::steady_clock::now(); auto last_tick = begin;
    Timestamp last_timestamp = 0;
    while (!stopped && (!options.count || result.packets < options.count)) {
        const auto now = std::chrono::steady_clock::now();
        if (options.duration > 0 && std::chrono::duration<double>(now-begin).count() >= options.duration) break;
        if (tick && now-last_tick >= std::chrono::seconds(1)) { tick(); last_tick = now; }
        pollfd poller{socket.get(), POLLIN, 0}; const int ready = poll(&poller, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        check(ready, "capture poll"); if (!ready) continue;
        if (poller.revents & (POLLERR | POLLHUP | POLLNVAL)) throw std::runtime_error("capture socket disconnected");
        iovec iov{buffer.data(), buffer.size()-4};
        alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(tpacket_auxdata))+CMSG_SPACE(sizeof(timespec))> control{};
        msghdr message{}; message.msg_iov = &iov; message.msg_iovlen = 1;
        message.msg_control = control.data(); message.msg_controllen = control.size();
        const auto received = recvmsg(socket.get(), &message, MSG_TRUNC);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) check(-1, "recvmsg");
        auto wire = static_cast<std::uint32_t>(received);
        auto captured = std::min<std::size_t>(static_cast<std::size_t>(received), iov.iov_len);
        Timestamp timestamp = now_timestamp();
        for (auto* c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message,c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_TIMESTAMPNS && c->cmsg_len >= CMSG_LEN(sizeof(timespec))) {
                timespec ts{}; std::memcpy(&ts, CMSG_DATA(c), sizeof(ts)); timestamp = ts.tv_sec*second + ts.tv_nsec;
            }
            if (c->cmsg_level == SOL_PACKET && c->cmsg_type == PACKET_AUXDATA && c->cmsg_len >= CMSG_LEN(sizeof(tpacket_auxdata))) {
                tpacket_auxdata aux{}; std::memcpy(&aux, CMSG_DATA(c), sizeof(aux));
                if ((aux.tp_status & TP_STATUS_VLAN_VALID) && captured >= 14) {
                    std::memmove(buffer.data()+16, buffer.data()+12, captured-12);
                    const std::uint16_t tpid = (aux.tp_status & TP_STATUS_VLAN_TPID_VALID) ? aux.tp_vlan_tpid : 0x8100;
                    buffer[12] = static_cast<std::uint8_t>(tpid >> 8); buffer[13] = static_cast<std::uint8_t>(tpid);
                    buffer[14] = static_cast<std::uint8_t>(aux.tp_vlan_tci >> 8); buffer[15] = static_cast<std::uint8_t>(aux.tp_vlan_tci);
                    captured += 4; wire += 4;
                }
            }
        }
        // A wall-clock correction must not run sliding windows backwards.
        timestamp = std::max(timestamp, last_timestamp); last_timestamp = timestamp;
        consume(parse_packet(buffer.data(), captured, wire, timestamp)); ++result.packets;
    }
    tpacket_stats stats{}; socklen_t length = sizeof(stats);
    if (getsockopt(socket.get(), SOL_PACKET, PACKET_STATISTICS, &stats, &length) == 0) result.kernel_drops = stats.tp_drops;
    result.interrupted = stopped != 0; return result;
}
}
