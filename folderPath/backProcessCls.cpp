#include "backProcessCls.h"

#include <QFile>


QSet<uint64_t> backProcessCls::pcapSet;
QHash<uint64_t,QMutex*> backProcessCls::pcapMutex;
QMutex backProcessCls::globatMutex;
QHash<uint64_t,uint64_t> backProcessCls::allSession;



/*backProcessCls::backProcessCls(const QString &fileName)
    : pcapName(fileName), defaultPath("C:\\Users\\remzi\\Desktop\\tParse\\"),lastPacket(false),sessionCount(0),sipCount(0),tcpCount(0),udpCount(0)*/


backProcessCls::backProcessCls(const QString &fileName)
    : pcapName(fileName), defaultPath("C:\\Users\\user\\Desktop\\parseSession\\"),lastPacket(false),sessionCount(0),sipCount(0),tcpCount(0),udpCount(0),isComplete(false){
    startTime = QDateTime::currentDateTime();
    qDebug() << pcapName << " back process cons";

}

backProcessCls::~backProcessCls(){
    m.lock();
    isComplete = true;
    quint64 subTime = startTime.msecsTo(QDateTime::currentDateTime());
    qDebug() << pcapName << " dosyasının back process işlemi " << subTime / 1000.0 << "sn sürdü";
    qDebug() << "Toplam session sayisi : " << sessionCount ;
    qDebug() << "Toplam sip cagiris sayisi : " << sipCount ;
    qDebug() << "Toplam Tcp session sayisi : " << tcpCount;
    qDebug() << "Toplam Udp session sayisi : " << udpCount;

    /*for (auto it = sipMap.begin(); it != sipMap.end(); ++it) {
        uint64_t key = it.key(); // Anahtar
        const sipSessionInfo& sessionInfo = it.value();

        qDebug() << "CallId : " <<sessionInfo.callId;
        qDebug() << "Msg: " <<sessionInfo.messages;
        qDebug() << "seq " << sessionInfo.seqNumberList;
        qDebug() << "Source : " <<sessionInfo.sourceIp;
        qDebug()<< "Dest : " << sessionInfo.destIp;
        qDebug() << "Data :" <<sessionInfo.sourceMediaDatas;
        qDebug() << "Port : " << sessionInfo.sourcePorts;
        qDebug() << "Data :" <<sessionInfo.destMediaDatas;
        qDebug() << "Port : " << sessionInfo.destPorts;
        for (int value : sessionInfo.indeks) {
            qDebug() << value;
        }

        qDebug() << "-----";
    }*/

    sipMap.clear();
    packets.clear();
    sessionMap.clear();
    written.clear();
    m.unlock();



}

void backProcessCls::addRawPacket(const pcpp::RawPacket& pkt, const pPlusstrPacketInfo& p){
    QMutexLocker lck(&m);
    packets.push_back(pkt);
    int pCount = packets.size();
    QString searchString = p.protocol + "-" + p.sourceIP + "-" + QString::number(p.sourcePort) + "-" + p.destIP + "-" + QString::number(p.destPort)  ;
    QPair<uint64_t, int> r = stringToInt(searchString);
    //qDebug() << "Elemn eklendi " << pCount;
    //qDebug() << "Map size " << sessionMap.size();

    auto it = sessionMap.find(r.first);
    if(it == sessionMap.end()){ // aranan eleman yok ekle

        int s = (p.protocol == "TCP") ? streamIndex++ : (p.protocol == "UDP") ? streamIndexUdp++ : pCount;

        pPlusstrSessıonInfo newSession = {p.sourceIP,
                                     p.destIP,
                                     p.sourcePort,
                                     p.destPort,
                                     s,
                                     1,
                                     p.packetLen,
                                     1,
                                     p.packetLen,
                                     0,
                                     0,
                                     p.timestamp,
                                     p.timestamp,
                                     {pCount},
                                     {p.message},
                                     p.protocol,
                                     p.smtpSender,
                                     p.smtpRecipient,
                                     {p.mailBody},
                                     QDateTime::currentDateTime(),
                                     r.second,
                                     {p.ackFlag,p.finFlag}};

        sessionMap[r.first] = newSession;
        sessionCount++;

        if(p.protocol == "TCP"){
            tcpCount++;
        }else if(p.protocol == "UDP"){
            udpCount++;
        }

    }else{ // eleman var güncelle
        pPlusstrSessıonInfo* sI  = &it.value();

        sI->packetCount++;
        sI->packetsLen += p.packetLen;
        sI->endTime = p.timestamp;
        sI->packetIndex.push_back(pCount);
        sI->messages.push_back(p.message);
        sI->lastPacket = QDateTime::currentDateTime();
        sI->flags.push_back(p.ackFlag);
        sI->flags.push_back(p.finFlag);

        if (!p.smtpSender.isEmpty()) {
            if(!sI->smtpSender.contains(p.smtpSender)){
                sI->smtpSender = sI->smtpSender + " - " + p.smtpSender;
            }

        }
        if (!p.smtpRecipient.isEmpty()) {
            if(!sI->smtpRecipient.contains(p.smtpRecipient)){
                sI->smtpRecipient = sI->smtpRecipient + " - " + p.smtpRecipient;
            }

        }
        if(!p.mailBody.isEmpty()){
            sI->mailB.push_back(p.mailBody);
        }

        // yön kontrolü
        if(r.second == sI->startValueOfStr){
            sI->sourceTodest++;
            sI->sourceTodestLen += p.packetLen;

        }else{
            sI->destToSource++;
            sI->destToSourceLen += p.packetLen;

        }

    }
    lck.unlock();
}

void backProcessCls::setIsLastPacket(bool isLast){
    QMutexLocker locker(&m);
    this->lastPacket = isLast;
    locker.unlock();
    qDebug() << "Last paket işaratlendi.";

}


void backProcessCls::controlMap(){
    while(true){
        QMutexLocker locker(&m);
        auto mIt = sessionMap.begin();
        while(mIt != sessionMap.end()){
            pPlusstrSessıonInfo& sInfo = mIt.value();
            uint64_t key = mIt.key();

            bool tcpNeedUpdate = false;
            qint64 subTime = sInfo.lastPacket.msecsTo(QDateTime::currentDateTime());
            if(sInfo.protocol == "TCP"){
                int vecSize = sInfo.flags.size();
                if(vecSize >= 4){ // ack || fin şeklinde sıralı vektörde
                    uint16_t ackF = sInfo.flags[vecSize-2];
                    uint16_t finF = sInfo.flags[vecSize-3];
                    if((ackF == 1) && (finF ==1)){
                        //yazdırma işlemi yaptır
                        qDebug() << "Tcp sessionu başarılı şekilde bitti.";
                        tcpNeedUpdate = true;
                    }
                }
            }

            //|| sInfo.packetCount >= 32
            bool isNeedUpdate = (this->lastPacket || subTime >=3500 || tcpNeedUpdate);
            if(isNeedUpdate){
                addPacketToPcap(sInfo,0);
                mIt = sessionMap.erase(mIt);

            }else{
                ++mIt;
            }

        }
        auto sipIt = sipMap.begin();
        while(sipIt != sipMap.end()){

            pPlussipSessionInfo& sipInfo = sipIt.value();
            uint64_t sKey = sipIt.key();
            int sipSize = sipInfo.messages.size();
            qint64 sub= sipInfo.tms.msecsTo(QDateTime::currentDateTime());
            bool timeout = (sub >=500);

            QString requestMsg = sipInfo.messages[sipSize-2];
            QString responseMsg = sipInfo.messages[sipSize-1];
            QString responseCSeq = sipInfo.seqNumberList.last();

            //qDebug() << requestMsg << responseMsg << responseCSeq;
            bool success = (requestMsg.contains("BYE") && responseMsg.contains("OK") && responseCSeq.contains("BYE"));
            if(timeout || success || lastPacket){
                //yazdır
                if(success){
                    qDebug() << "Basarili sekilde kapandi : " << sipInfo.callId;
                }else{
                    qDebug() << "Timeout : " << sipInfo.callId;
                }
                printSipPcap(sipInfo);
                sipIt = sipMap.erase(sipIt);
            }else{
                ++sipIt;
            }

        }
        if (sessionMap.empty() && lastPacket && sipMap.empty() ) {
            this->isComplete = true;
            break;
        }
        locker.unlock();
        QThread::msleep(100);
    }

    emit mapFinished();
}

QPair<uint64_t, uint64_t> backProcessCls::stringToInt(const QString &str){

    uint64_t v = 0;
    QStringList parts = str.split("-");
    uint64_t totalValue = 0;

    int sPort = parts[2].toUInt() ;
    int dPort = parts[4].toInt() ;
    int uniqValue = (((sPort + dPort ) % 65536) + 1 ) * 3;

    int y = 1;
    for(const QString& p : parts){
        uint64_t charValue = 0;
        for(int i=0;i<p.length();++i){
            charValue+=(static_cast<int>(p[i].unicode()) * (i+1));
        }
        //qDebug() << p << " degeri :" << charValue;
        v += charValue;
        totalValue += (charValue * y);
        y++;
    }

    //qDebug() << str << "unicode degeri : " << v << "Start degeri : " << startV;

    v = v * uniqValue;
    return qMakePair(v,totalValue);

}

QPair<uint64_t, uint64_t> backProcessCls::calculateInt(const QString &str){
    uint64_t rValue = 0;
    uint64_t totalValue = 0;

    QStringList parts = str.split("_");

    int y = 1;

    for(const QString& p : parts){
        uint64_t charValue = 0;
        for(int i=0;i<p.length();i++){
            charValue += static_cast<int>(p[i].unicode()) * (i+1);
        }
        //qDebug() << p << " : " <<charValue;
        rValue += charValue;
        totalValue += (charValue * y);
        y++;
    }
    //qDebug() << str << ": " << rValue;

    return qMakePair(rValue,totalValue);
}


void backProcessCls::addPacketToPcap(const pPlusstrSessıonInfo &p,int lastIndex){

    QString sessionName = p.protocol + "-" + p.sourceIP + "-" + QString::number(p.sourcePort) + "-" + p.destIP + "-" + QString::number(p.destPort);

    bool control = false;

    QPair<uint64_t, uint64_t> result = stringToInt(sessionName);


    QMutexLocker globalLock(&globatMutex);
    QMutex* mt = nullptr;

    if(allSession.contains(result.first)){
        //qDebug() << "Var" << sessionName << " : " << result.first << " : " << result.second;
        uint64_t controlValue = allSession.value(result.first);
        if(result.second != controlValue){
            sessionName = p.protocol + "-" + p.destIP + "-" + QString::number(p.destPort) + "-" + p.sourceIP + "-" + QString::number(p.sourcePort);
        }
        mt = pcapMutex.value(result.first,nullptr);
        mt->lock();
        control = true;

    }else{
        //qDebug() << "Yok" << sessionName << " : " << result.first << " : " << result.second;
        allSession.insert(result.first,result.second);
        mt = new QMutex();
        pcapMutex[result.first] = mt;
        mt->lock();
    }
    //qDebug() << name << "last " << lastIndex;
    QString name = defaultPath + sessionName + ".pcap";
    pcpp::PcapFileWriterDevice pcapWriter(name.toStdString(), pcpp::LINKTYPE_ETHERNET);

    if(control){
        if(!pcapWriter.open(true)){
            qDebug() << "Open append hatası " << name ;
        }
    }else{
        if(!pcapWriter.open()){
            qDebug() << "Open hatası " << name ;
        }
    }
    /*QFile f(name);
    if(f.exists()){
        control = true;
    }*/

    /*QMutexLocker globalLock(&globatMutex);
    QMutex* mt = nullptr;

    if(pcapSet.contains(value) && control){
        //var appen modda aç
        qDebug() << "Var " << name << " : " << value;
        if(!pcapWriter.open(true)){
            qDebug() << "Open append hatası " << name ;
        }
        mt = pcapMutex.value(value,nullptr);
        mt->lock();
    }else{
        //yok normal modda aç
        qDebug() << "Yok" << name << " : " << value;

        if(!pcapWriter.open()){
            qDebug() << "Open hatası " << name ;
        }
        pcapSet.insert(value);
        mt = new QMutex();
        pcapMutex[value] = mt;
        mt->lock();
    }*/



    for(int i = lastIndex;i<p.packetIndex.size();i++){
        int pIndex = p.packetIndex[i];
        pcapWriter.writePacket(packets[pIndex-1]);
    }

    pcapWriter.close();
    mt->unlock();
    globalLock.unlock();

    /*pcpp::PcapFileWriterDevice* pcapWriter = new pcpp::PcapFileWriterDevice(name.toStdString(), pcpp::LINKTYPE_ETHERNET);

    if(!pcapWriter->open(true)){
        qDebug() << "Open hatası " << name ;
        delete pcapWriter;
    }

    for(int i = lastIndex;i<p.packetIndex.size();i++){
        int pIndex = p.packetIndex[i];
        pcapWriter->writePacket(packets[pIndex-1]);
    }

    pcapWriter->close();
    delete pcapWriter;*/

}

void backProcessCls::printSipPcap(const pPlussipSessionInfo &sipPacket){


    QString name = defaultPath + "callId_"+ sipPacket.callId + ".pcap";

    qDebug() << name << "pcap " ;
    pcpp::PcapFileWriterDevice pcapWriter(name.toStdString(), pcpp::LINKTYPE_ETHERNET);
    QPair<uint64_t, uint64_t> returnValue = calculateInt("callId_"+ sipPacket.callId);


    QMutexLocker lck(&globatMutex);
    QMutex* m = nullptr;

    if(allSession.contains(returnValue.first)){
        if(!pcapWriter.open(true)){
            qDebug() << "Open append hatası " << name ;
        }
        m = pcapMutex.value(returnValue.first);
        m->lock();
    }else{
        if(!pcapWriter.open()){
            qDebug() << "Open hatası " << name ;
        }
        allSession.insert(returnValue.first,returnValue.second);
        m = new QMutex();
        pcapMutex[returnValue.first] = m ;
        m->lock();

    }

    /*if(pcapSet.contains(ıntValue)){
        if(!pcapWriter.open(true)){
            qDebug() << "Open append hatası " << name ;
        }
        m = pcapMutex.value(ıntValue);
        m->lock();
    }else{


        if(!pcapWriter.open()){
            qDebug() << "Open hatası " << name ;
        }
        pcapSet.insert(ıntValue);
        m = new QMutex();
        pcapMutex[ıntValue] = m ;
        m->lock();
    }*/



    for(int i = 0;i<sipPacket.indeks.size();i++){
        int pIndex = sipPacket.indeks[i];
        pcapWriter.writePacket(packets[pIndex-1]);
    }

    pcapWriter.close();
    m->unlock();
    lck.unlock();


}



void backProcessCls::updateSipMap(const QString& message, const QString& cId,const QString& cSeq, const QString& ip, uint16_t audioPort, uint16_t videoPort,int direction){

    QMutexLocker sipLock(&m);
    int pIn = this->packets.size() + 1 ;
    uint64_t searchInt = 0;
    int i = 1;
    for(const QChar &c : cId){
        searchInt += static_cast<int>(c.unicode()) * i;
        i++;
    }

    auto it = sipMap.find(searchInt);
    if(it != sipMap.end()){
        //eleman güncelle
        pPlussipSessionInfo* sipInfo = &it.value();
        sipInfo->messages.push_back(message);
        sipInfo->indeks.push_back(pIn);
        sipInfo->seqNumberList.push_back(cSeq);
        sipInfo->tms = QDateTime::currentDateTime();
        if(direction == 0){

            if(!ip.isEmpty()){
                sipInfo->sourceIp = ip;
            }
            if(audioPort != 0){
                sipInfo->sourceMediaDatas.push_back("audio");
                sipInfo->sourcePorts.push_back(QString::number(audioPort));
            }
            if(videoPort != 0){
                sipInfo->sourceMediaDatas.push_back("video");
                sipInfo->sourcePorts.push_back(QString::number(videoPort));
            }

        }else{

            if(!ip.isEmpty()){
                sipInfo->destIp = ip;
            }
            if(audioPort != 0){
                sipInfo->destMediaDatas.push_back("audio");
                sipInfo->destPorts.push_back(QString::number(audioPort));
            }
            if(videoPort != 0){
                sipInfo->destMediaDatas.push_back("video");
                sipInfo->destPorts.push_back(QString::number(videoPort));
            }
        }

    }else{
        //eleman ekle
        sipCount++;
        pPlussipSessionInfo newSip ;
        newSip.callId = cId;
        newSip.messages.push_back(message);
        //newSip.sourceIp = "";
        //newSip.destIp = "";
        //newSip.sourceMediaDatas = QStringList();
        //newSip.sourcePorts = QStringList();
        //newSip.destMediaDatas= QStringList();
        //newSip.destPorts = QStringList();
        newSip.tms = QDateTime::currentDateTime();
        newSip.indeks.push_back(pIn);
        newSip.seqNumberList.push_back(cSeq);

        if(direction == 0){

            if(!ip.isEmpty()){
                newSip.sourceIp = ip;
            }
            if(audioPort != 0){
                newSip.sourceMediaDatas.push_back("audio");
                newSip.sourcePorts.push_back(QString::number(audioPort));
            }
            if(videoPort != 0){
                newSip.sourceMediaDatas.push_back("video");
                newSip.sourcePorts.push_back(QString::number(videoPort));
            }

        }else{

            if(!ip.isEmpty()){
                newSip.destIp = ip;
            }
            if(audioPort != 0){
                newSip.destMediaDatas.push_back("audio");
                newSip.destPorts.push_back(QString::number(audioPort));
            }
            if(videoPort != 0){
                newSip.destMediaDatas.push_back("video");
                newSip.destPorts.push_back(QString::number(videoPort));
            }
        }

        sipMap[searchInt] = newSip;
        //(const QString& message, const QString& cId,const QString& cSeq, const QString& ip, uint16_t audioPort, uint16_t videoPort,int direction)
    }

    //qDebug() << "Sİp size : " << sipMap.size();
}
































