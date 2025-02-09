#ifndef PCAP_HANDLER_H
#define PCAP_HANDLER_H

#include <pcap.h>
#include <string>
#include <vector>

class PcapHandler {
public:
    PcapHandler();
    ~PcapHandler();

    bool open(const std::string &interface);
    std::string getLastError() const;
    std::vector<uint8_t> captureBeacon(const std::string &ap_mac);
    bool sendPacket(const std::vector<uint8_t>& packet);

private:
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif // PCAP_HANDLER_H
