#ifndef PCAPPPACKET_H
#define PCAPPPACKET_H

#include "backProcessCls.h"

#include <SipLayer.h>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <PcapPlusPlusVersion.h>
#include <SdpLayer.h>




#include <QString>
#include <QDebug>
#include <QVector>
#include <QFile>
#include <QByteArray>
#include <QDataStream>

#include <filesystem>
#include <QFileInfo>
#include <SipLayer.h>



class pcapPpacket
{
public:
    pcapPpacket(const QString& path);
    void processPcap();
    ~pcapPpacket();

private:
    void parseSipPacket();
    QString sipMethodToQString(pcpp::SipRequestLayer::SipMethod method);
    pcpp::IFileReaderDevice* reader;
    QVector<pcpp::RawPacket> packets;

    QThread* th;
    QString pcapPath;
    int packetCount;

    backProcessCls* bCls;

    QString fileName;
    QString directory;


    //codec
    void createWavFile(QFile &file, uint32_t sampleRate, uint32_t dataSize);

};

#endif // PCAPPPACKET_H
