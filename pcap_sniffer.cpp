#include <pcap.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>

namespace {

constexpr std::size_t kEthernetHeaderSize = 14;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint16_t kEtherTypeQinQ = 0x88a8;
constexpr std::uint8_t kProtocolTcp = 6;

std::uint16_t read_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::string mac_to_string(const std::uint8_t* mac) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i != 0) out << ':';
        out << std::setw(2) << static_cast<unsigned>(mac[i]);
    }
    return out.str();
}

std::string ipv4_to_string(const std::uint8_t* ip) {
    std::ostringstream out;
    out << static_cast<unsigned>(ip[0]) << '.' << static_cast<unsigned>(ip[1]) << '.'
        << static_cast<unsigned>(ip[2]) << '.' << static_cast<unsigned>(ip[3]);
    return out.str();
}

bool begins_with_http(std::string_view data) {
    constexpr std::array<std::string_view, 10> prefixes = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/"
    };
    return std::any_of(prefixes.begin(), prefixes.end(), [data](std::string_view prefix) {
        return data.size() >= prefix.size() && data.compare(0, prefix.size(), prefix) == 0;
    });
}

bool is_common_http_port(std::uint16_t port) {
    return port == 80 || port == 8000 || port == 8080 || port == 8888;
}

void print_http_bytes(const std::uint8_t* data, std::size_t length) {
    std::cout << "  HTTP Message (" << length << " bytes):\n";
    for (std::size_t i = 0; i < length; ++i) {
        const unsigned char c = data[i];
        if (c == '\r') {
            if (i + 1 >= length || data[i + 1] != '\n') std::cout << "\\r";
        } else if (c == '\n' || c == '\t' || std::isprint(c)) {
            std::cout << static_cast<char>(c);
        } else {
            std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(c) << std::dec;
        }
    }
    if (length == 0 || data[length - 1] != '\n') std::cout << '\n';
}

void handle_packet(u_char*, const pcap_pkthdr* header, const u_char* raw_packet) {
    const auto* packet = reinterpret_cast<const std::uint8_t*>(raw_packet);
    const std::size_t captured = header->caplen;

    if (captured < kEthernetHeaderSize) return;

    std::size_t network_offset = kEthernetHeaderSize;
    std::uint16_t ether_type = read_u16(packet + 12);

    while (ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinQ) {
        if (captured < network_offset + 4) return;
        ether_type = read_u16(packet + network_offset + 2);
        network_offset += 4;
    }
    if (ether_type != kEtherTypeIpv4 || captured < network_offset + 20) return;

    const std::uint8_t* ip = packet + network_offset;
    if ((ip[0] >> 4) != 4) return;
    const std::size_t ip_header_len = static_cast<std::size_t>(ip[0] & 0x0f) * 4;
    if (ip_header_len < 20 || captured < network_offset + ip_header_len) return;
    if (ip[9] != kProtocolTcp) return;

    const std::uint16_t ip_total_len = read_u16(ip + 2);
    if (ip_total_len < ip_header_len + 20) return;

    const std::size_t tcp_offset = network_offset + ip_header_len;
    if (captured < tcp_offset + 20) return;
    const std::uint8_t* tcp = packet + tcp_offset;
    const std::size_t tcp_header_len = static_cast<std::size_t>(tcp[12] >> 4) * 4;
    if (tcp_header_len < 20 || captured < tcp_offset + tcp_header_len) return;
    if (ip_total_len < ip_header_len + tcp_header_len) return;

    const std::uint16_t src_port = read_u16(tcp);
    const std::uint16_t dst_port = read_u16(tcp + 2);
    const std::size_t payload_offset = tcp_offset + tcp_header_len;
    const std::size_t payload_len_from_ip = ip_total_len - ip_header_len - tcp_header_len;
    const std::size_t captured_payload_len = captured > payload_offset ? captured - payload_offset : 0;
    const std::size_t payload_len = std::min(payload_len_from_ip, captured_payload_len);

    std::cout << "\n========== TCP Packet ==========" << '\n';
    std::cout << "Ethernet Header\n"
              << "  src mac: " << mac_to_string(packet + 6) << '\n'
              << "  dst mac: " << mac_to_string(packet) << '\n';
    std::cout << "IP Header (" << ip_header_len << " bytes)\n"
              << "  src ip : " << ipv4_to_string(ip + 12) << '\n'
              << "  dst ip : " << ipv4_to_string(ip + 16) << '\n';
    std::cout << "TCP Header (" << tcp_header_len << " bytes)\n"
              << "  src port: " << src_port << '\n'
              << "  dst port: " << dst_port << '\n';

    if (payload_len == 0) {
        std::cout << "  HTTP Message: <no TCP payload>\n";
        return;
    }

    const auto* payload = packet + payload_offset;
    const std::string_view payload_view(reinterpret_cast<const char*>(payload), payload_len);
    if (is_common_http_port(src_port) || is_common_http_port(dst_port) || begins_with_http(payload_view)) {
        print_http_bytes(payload, payload_len);
    } else {
        std::cout << "  HTTP Message: <payload is not recognized as plaintext HTTP>\n";
    }
}

void print_usage(const char* program) {
    std::cerr << "Usage:\n"
              << "  " << program << " -i <interface>\n"
              << "  " << program << " -r <capture.pcap>\n"
              << "  " << program << " -l\n";
}

void list_devices() {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* raw_devices = nullptr;
    if (pcap_findalldevs(&raw_devices, errbuf) == -1) {
        throw std::runtime_error(std::string("pcap_findalldevs: ") + errbuf);
    }
    std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> devices(raw_devices, pcap_freealldevs);
    for (const pcap_if_t* d = devices.get(); d != nullptr; d = d->next) {
        std::cout << d->name;
        if (d->description) std::cout << " - " << d->description;
        std::cout << '\n';
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::strcmp(argv[1], "-l") == 0) {
        try {
            list_devices();
            return EXIT_SUCCESS;
        } catch (const std::exception& e) {
            std::cerr << e.what() << '\n';
            return EXIT_FAILURE;
        }
    }
    if (argc != 3 || (std::strcmp(argv[1], "-i") != 0 && std::strcmp(argv[1], "-r") != 0)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* raw_handle = nullptr;
    if (std::strcmp(argv[1], "-i") == 0) {
        raw_handle = pcap_open_live(argv[2], 65535, 1, 1000, errbuf);
    } else {
        raw_handle = pcap_open_offline(argv[2], errbuf);
    }
    if (!raw_handle) {
        std::cerr << "pcap_open: " << errbuf << '\n';
        return EXIT_FAILURE;
    }
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(raw_handle, pcap_close);

    if (pcap_datalink(handle.get()) != DLT_EN10MB) {
        std::cerr << "This program supports Ethernet captures (DLT_EN10MB) only.\n";
        return EXIT_FAILURE;
    }

    bpf_program filter{};
    if (pcap_compile(handle.get(), &filter, "tcp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile: " << pcap_geterr(handle.get()) << '\n';
        return EXIT_FAILURE;
    }
    std::unique_ptr<bpf_program, decltype(&pcap_freecode)> filter_guard(&filter, pcap_freecode);
    if (pcap_setfilter(handle.get(), &filter) == -1) {
        std::cerr << "pcap_setfilter: " << pcap_geterr(handle.get()) << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Capturing TCP packets. Press Ctrl+C to stop.\n";
    const int result = pcap_loop(handle.get(), 0, handle_packet, nullptr);
    if (result == -1) {
        std::cerr << "pcap_loop: " << pcap_geterr(handle.get()) << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
