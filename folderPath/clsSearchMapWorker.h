#ifndef CLSSEARCHMAPWORKER_H
#define CLSSEARCHMAPWORKER_H

#include <QObject>
#include <QMutex>
#include <QString>
#include <QHash>
#include <QDateTime>
#include <pcap.h>
#include <QSet>
#include <QMutex>

#include "newstructs.h"

class clsSearchMapWorker : public QObject
{
    Q_OBJECT
public:
    clsSearchMapWorker(QString fName);
    ~clsSearchMapWorker();
    void controlMap();


    void setisLastPacket(bool isLast);
    void setPacketsInfo(const u_char* pkt_data,const pcap_pkthdr* hdr);
    void updateSessionMap(const uint64_t &key, const strSessıonInfo &newMap);

    void appendSipSessionInfo(sipPacket s);
    //void createSipMap();




signals:
    void finished();
    void newSipSessionInfo();

private:

    static QSet<QString> pcapSet;
    static QHash<QString,QMutex*> mutexMap;
    static QMutex globalMt;

    QHash<uint64_t,int> written;

    //QHash<QString,strSessıonInfo> sessionMap;
    QHash<quint64,strSessıonInfo> sessionMap;

    QVector<QVector<quint8>> p;
    QVector<pcap_pkthdr> h ;


    QVector<sipPacket> sipPackets;
    QHash<uint64_t,sipSessionInfo> sipMap;

    QDateTime startChrono;

    bool isLastPacket;
    bool isNewPacket;
    double start;
    double end;

    QString defaultPath;


    QMutex m;
    QString fileName;


    void appendNewPacketsFile(strSessıonInfo s,int lastIndeks);
    void printSipPcap(const sipSessionInfo &info,QString &sipCall,int lastIndex);
    uint64_t stringToInt(const QString& str);




};

#endif // CLSSEARCHMAPWORKER_H
