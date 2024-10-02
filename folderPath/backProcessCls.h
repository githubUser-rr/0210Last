#ifndef BACKPROCESSCLS_H
#define BACKPROCESSCLS_H

#include <QObject>

#include "pPlusnewstructs.h"
#include "PcapFileDevice.h"
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include "TcpLayer.h"
#include "UdpLayer.h"


#include <QString>
#include <QDebug>
#include <QVector>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QPair>
#include <QDateTime>
#include <QThread>



class backProcessCls : public QObject
{
    Q_OBJECT
public:
    backProcessCls(const QString &fileName);
    ~backProcessCls();

    void addRawPacket(const pcpp::RawPacket& pkt, const pPlusstrPacketInfo& p);
    void setIsLastPacket(bool isLast);
    void updateSipMap(const QString& message, const QString& cId,const QString& cSeq, const QString& ip, uint16_t audioPort, uint16_t videoPort,int direction);

    volatile bool isComplete ;

public slots:
    void controlMap();

signals:
    void mapFinished();




private:
    int sessionCount;
    int sipCount;
    int tcpCount;
    int udpCount;

    QPair<uint64_t, uint64_t> stringToInt(const QString& str);
    void addPacketToPcap(const pPlusstrSessıonInfo& p,int lastIndex);

    QDateTime startTime;
    QString pcapName;
    QString defaultPath;
    int streamIndex;
    int streamIndexUdp;

    bool lastPacket;
    bool newPacket;

    QVector<pcpp::RawPacket> packets;
    QHash<uint64_t,pPlusstrSessıonInfo> sessionMap;
    QHash<uint64_t,int> written;


    QHash<uint64_t,pPlussipSessionInfo> sipMap;
    void printSipPcap(const pPlussipSessionInfo& sipPacket);

    QMutex m;

    static QSet<uint64_t> pcapSet;
    static QHash<uint64_t,uint64_t> allSession;
    static QHash<uint64_t,QMutex*> pcapMutex;
    static QMutex globatMutex;

    QPair<uint64_t, uint64_t> calculateInt(const QString& str);


};

#endif // BACKPROCESSCLS_H
