#ifndef CLSPACKETOPERATION_H
#define CLSPACKETOPERATION_H

#include "newstructs.h"
#include "clsSearchMapWorker.h"



#include <QString>
#include <QVector>
#include <QPair>
#include <QHash>
#include <QDateTime>
#include <pcap.h>
#include <QMultiHash>
#include <QSet>






class clsPacketOperation
{
public:

    clsPacketOperation(const QString& p);
    ~clsPacketOperation();

    void packetCapture(int loopcount=0);


    void printCsvFile();


    clsSearchMapWorker* clsSMap;




protected:

private: //controlOpen(false),handle(nullptr),pCount(0)
    QString filePath;
    QString directory;
    QString fileName;

    QVector<QVector<quint8>> packets;
    QVector<pcap_pkthdr> headers;
    //std::vector<std::vector<u_char>> packets;
    //std::vector<pcap_pkthdr> headers;

    QDateTime objStartTime;
    //chrono::system_clock::time_point objStartTime;

    bool controlOpen;

    QString parsePopPayload(const char* p, int pSize);
    QStringList parseSipMessage(const char *p, int pSize);
    //QPair<QString,QString,QString>  parseSipMessage(const char* p, int pSize);
    QStringList parseSmtp(const char* p, int pSize);
    QHash<QString,QString> mailBodys;

    //std::string parsePopPayload(const char* p, int pSize);
    //std::tuple<std::string, std::string,std::string> parseSipMessage(const char* p, int pSize);
    //std::pair<std::string, std::string> parseSmtp(const char* p, int pSize);

    static void processPacket(void *user, const pcap_pkthdr *header, const u_char *pkt_data);
    void createSessionMap(const strPacketInfo& p);


    QPair<uint64_t,uint64_t> stringToInt(const QString& str);
    void createIntSessionMap(const strPacketInfo& p);



    QHash<QString,strSessıonInfo> sessionMap;
    QHash<quint64,strSessıonInfo> sessionIntMap;



    QStringList parseSipSession(const char* p, int pSize,int packetIndex);
    //QMultiHash<sipSessionInfo,int> sipSessionMap;

    QHash<sipSessionInfo,QVector<int>> sipSessionMap;



    //unordered_map<string,SessıonInfo> sessionMap;



    QHash<QString,int> written;
    //std::unordered_map<std::string,int> written;

    //pcap veri yapıları
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    const u_char* packet;
    struct pcap_pkthdr header;



    QString defaultPath ;
    QString defaultTxtPath ;
    QString defaultCsvPath ;


    int pCount;
    QVector<strPacketInfo> packetsInfo;
    //vector<PacketInfo> noStaticPackets;


    int streamIndex;
    int streamIndexUdp;





};





#endif // CLSPACKETOPERATION_H
