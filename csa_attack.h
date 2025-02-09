#ifndef CSA_ATTACK_H
#define CSA_ATTACK_H

#include <cstdint>
#include <vector>

namespace CSAAttack {

bool removeFCS(std::vector<uint8_t>& packet);

void insertCSA(std::vector<uint8_t>& packet, uint8_t newChannel = 0x0B, uint8_t switchCount = 0x03);
void setUnicastDestination(std::vector<uint8_t>& packet, const uint8_t stationMac[6]);

uint8_t getNewChannelFromBeacon(const std::vector<uint8_t>& packet);
}

#endif // CSA_ATTACK_H
