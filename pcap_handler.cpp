#include "pcap_handler.h"
#include <cstdio>

PcapHandler::PcapHandler() : handle(nullptr) {
    errbuf[0] = '\0';
}

PcapHandler::~PcapHandler() {
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}

bool PcapHandler::open(const std::string &interface) {
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        return false;
    }
    return true;
}

std::string PcapHandler::getLastError() const {
    return std::string(errbuf);
}

std::vector<uint8_t> PcapHandler::captureBeacon(const std::string &ap_mac) {
    std::vector<uint8_t> packetData;
    if (handle == nullptr) {
        std::snprintf(errbuf, sizeof(errbuf), "Interface not opened for capture");
        return packetData;
    }

    std::string filterExp = "wlan type mgt subtype beacon and wlan addr3 " + ap_mac;
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filterExp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::snprintf(errbuf, sizeof(errbuf), "pcap_compile error: %s", pcap_geterr(handle));
        return packetData;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::snprintf(errbuf, sizeof(errbuf), "pcap_setfilter error: %s", pcap_geterr(handle));
        pcap_freecode(&fp);
        return packetData;
    }
    pcap_freecode(&fp);

    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    errbuf[0] = '\0';
    while ((res = pcap_next_ex(handle, &header, &data)) != 1) {
        if (res == -1) {
            std::snprintf(errbuf, sizeof(errbuf), "pcap_next_ex error: %s", pcap_geterr(handle));
            return std::vector<uint8_t>();
        }
    }

    packetData.assign(data, data + header->caplen);
    return packetData;
}

bool PcapHandler::sendPacket(const std::vector<uint8_t>& packet) {
    if (handle == nullptr) {
        std::snprintf(errbuf, sizeof(errbuf), "Interface not opened for sending");
        return false;
    }
    if (pcap_sendpacket(handle, packet.data(), packet.size()) != 0) {
        std::snprintf(errbuf, sizeof(errbuf), "pcap_sendpacket failed: %s", pcap_geterr(handle));
        return false;
    }
    return true;
}
