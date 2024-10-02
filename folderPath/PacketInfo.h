#ifndef PACKETINFO_H
#define PACKETINFO_H

#include <string>
#include <vector>

using namespace std;

struct PacketInfo {
    string sourceIP;
    string destIP;
    string sourceMac;
    string destMac;
    uint16_t sourcePort;
    uint16_t destPort;
    uint8_t protocol; // 6 for TCP, 17 for UDP
};

#endif // PACKETINFO_H
