#ifndef PPLUSNEWSTRUCTS_H
#define PPLUSNEWSTRUCTS_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QStringList>
#include <QDateTime>




struct pPlusstrPacketInfo{
    QString sourceIP;
    QString destIP;
    QString sourceMac;
    QString destMac;

    uint16_t sourcePort;
    uint16_t destPort;

    QString protocol ;
    QString timestamp ;
    int packetLen;
    QString message ;
    QString smtpSender;
    QString smtpRecipient;
    QString mailBody;

    uint16_t finFlag;
    uint16_t ackFlag;


    //cons
    pPlusstrPacketInfo():sourceIP(""), destIP(""), sourceMac(""), destMac(""),
        sourcePort(0), destPort(0), protocol(""), timestamp(""),
        packetLen(0), message(""), smtpSender(""), smtpRecipient(""),
        mailBody(""),finFlag(0),ackFlag(0) {}
};

struct pPlusstrSessıonInfo{
    QString sourceIP;
    QString destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    int streamIndex;
    int packetCount;
    int packetsLen;
    int sourceTodest;
    int sourceTodestLen;
    int destToSource;
    int destToSourceLen;
    QString startTime;
    QString endTime;
    QVector<int> packetIndex;
    QStringList messages;
    QString protocol;
    QString smtpSender;
    QString smtpRecipient;
    QStringList mailB;
    QDateTime lastPacket;
    uint64_t startValueOfStr;
    QVector<uint16_t> flags;


    // Constructor
    /*pPlusstrSessıonInfo() {
        // Varsayılan değerler
        sourceIP = "";
        destIP = "";
        sourcePort = 0;
        destPort = 0;
        streamIndex = 0;
        packetCount = 0;
        packetsLen = 0;
        sourceTodest = 0;
        sourceTodestLen = 0;
        destToSource = 0;
        destToSourceLen = 0;
        startTime = "";
        endTime = "";
        packetIndex = QVector<int>(); // default empty QVector
        messages = QStringList();      // default empty QStringList
        protocol = "";
        smtpSender = "";
        smtpRecipient = "";
        mailB = QStringList();         // default empty QStringList
        lastPacket = QDateTime::currentDateTime(); // mevcut tarih/saat
        startValueOfStr = 0;
        flags = QVector<uint16_t>();   // default empty QVector
    }*/

};

struct pPlussipSessionInfo{
    QString callId;
    QStringList messages;

    QString sourceIp;
    QString destIp;
    QStringList sourceMediaDatas;
    QStringList sourcePorts;
    QStringList destMediaDatas;
    QStringList destPorts;
    QDateTime tms;
    QVector<int> indeks;
    QStringList seqNumberList;


    /*bool operator==(const pPlussipSessionInfo &other) const {
        return cId == other.cId;
    }*/


    /*friend uint qHash(const pPlussipSessionInfo &key, uint seed) {
        return qHash(key.cId, seed);  // cId üzerinden hash hesaplama
    }*/
};

struct pPlussipPacket{
    QString messages;
    QString callId;
    QString ipAdd;
    QStringList mediaDatas;
    QStringList ports;
    int pIndex;
    int control;
    QDateTime tms;
    QString seqNumber;
};


struct rtpPacket{
    uint8_t version;
    uint8_t padding;
    uint8_t extension;
    uint8_t marker;
    uint8_t payloadType;
    uint16_t sequenceNumber;
    uint32_t timestamp;
    uint32_t ssrc;
};

struct rtpSession{
    uint32_t ssrc;
    QDateTime lastPacket;
    QVector<uint8_t> data;
    QString codec;
    int packetCount;
    size_t totalDataSize;

    rtpSession(uint32_t ssrc)
        : ssrc(ssrc), packetCount(0), totalDataSize(0){}

    /*void addPacket(const uint8_t* packetData, size_t length) {
        data.insert(data.end(), packetData, packetData + length);
        totalDataSize += length;
        packetCount++;
        lastPacket = QDateTime::currentDateTime();
    }*/


};




#endif // PPLUSNEWSTRUCTS_H
