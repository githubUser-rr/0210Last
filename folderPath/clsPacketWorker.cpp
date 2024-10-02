#include "clsPacketWorker.h"
#include "clsPacketOperation.h"
#include "pcapppacket.h"

#include <QThread>
#include <QProcess>
#include <QString>
#include <QMutex>
#include <windows.h>




int clsPacketWorker::currentThread = 0;
QMutex clsPacketWorker::threadMutex;
const int clsPacketWorker::totalCpu = []() {
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    return sys.dwNumberOfProcessors;
}();



clsPacketWorker::clsPacketWorker(const QString& str,int c)
    : path(str),control(c),packet(nullptr),pPlusPacket(nullptr){

    qDebug() << "Packet Worker constructor !! " << currentThread;
}

clsPacketWorker::~clsPacketWorker() {
    //decrementThread();
    HANDLE releaseHandle = GetCurrentThread();
    DWORD_PTR cpus = (DWORD_PTR)-1;

    if(SetThreadAffinityMask(releaseHandle,cpus) == 0){
        qDebug() << "CPU affinity serbest bırakılamadı: " << GetLastError();
    }else{
        qDebug() << "CPU affinity serbest bırakıldı";
    }


    if(packet != nullptr){
        qDebug() << "paacket in";
        delete packet;
        packet = nullptr;
    }



    if(pPlusPacket != nullptr){
        delete pPlusPacket;
        pPlusPacket = nullptr;
    }


}


void clsPacketWorker::incrementThread(){
    threadMutex.lock();
    currentThread++;
    threadMutex.unlock();
    qDebug() << "currentThread arttırıldı ! " << currentThread;

}

void clsPacketWorker::decrementThread(){
    qDebug() << "İn dec";
    threadMutex.lock();
    if(currentThread>0){
        currentThread--;
    }
    threadMutex.unlock();
    qDebug() << "currentThread azaltıldı ! " << currentThread;
}

void clsPacketWorker::createPacket(){
    //qDebug() << "Create Packet" ;
    //int maxThread = QThread::idealThreadCount(); //bunu static const olarak tanımlayabiliriz.

    /*QHash<int, int> usage = GetProcessorUsage();


    int minKey= usage.begin().key();
    int minValue = usage.begin().value();

    QHashIterator<int, int> i(usage);*/
    /*while (i.hasNext()) {
        i.next();

        if(minValue > i.value()){
            minValue = i.value();
            minKey = i.key();
        }
        qDebug() << "Processor" << i.key() << "usage:" << i.value() << "%";
    }

    qDebug() << "Min K : " << minKey << "Min V :" << minValue;*/
    while(true){
        threadMutex.lock();
        int useRate = returnUsageRate();

        qDebug() << "Kullanım oranı : " << useRate;
        //int useRate =
        qDebug() << "Anlık calisan thread sayisi : " << currentThread;
        qDebug() << "Total mantıksal çekirdek sayısı : " << totalCpu;

        if((useRate >= 75) && (currentThread >= totalCpu / 2)){

            threadMutex.unlock();
            qDebug() << path << " dosya thread bind için bekliyor.";
            QThread::msleep(300);
            useRate = returnUsageRate();
        }else{

            int nowCpu = currentThread % totalCpu;
            HANDLE tHandle = GetCurrentThread();
            DWORD_PTR affinity = 1 << nowCpu;

            if (SetThreadAffinityMask(tHandle, affinity) == 0) {
                qDebug() << path << " CPU affinity ayarlanamadı: " << GetLastError() ;
            } else {
                qDebug() << path << "Thread " << nowCpu << ".CPU baglandi" ;
            }
            threadMutex.unlock();
            break;
        }

    }
    incrementThread();

    qDebug() << "Control : " << control;
    if(control == 0){
        qDebug() << "Npcap parse basliyor.";
        packet = new clsPacketOperation(path);
        packet->packetCapture(0);
        //packet->printPacketInfo();
        //packet->printCsvFile(); //bunu aç sonra

        /*delete packet;
        packet = nullptr;*/

    }else{
        qDebug() << "PcapPlusPlus parse basliyor.";
        pPlusPacket = new pcapPpacket(path);
        pPlusPacket->processPcap();
    }


    decrementThread();


    emit createFinished();

}

int clsPacketWorker::returnUsageRate(){


    static ULARGE_INTEGER lastIdleTime = {0}, lastKernelTime = {0}, lastUserTime = {0};
    FILETIME idleTime, kernelTime, userTime;

    GetSystemTimes(&idleTime, &kernelTime, &userTime);

    ULARGE_INTEGER currentIdleTime, currentKernelTime, currentUserTime;
    currentIdleTime.LowPart = idleTime.dwLowDateTime;
    currentIdleTime.HighPart = idleTime.dwHighDateTime;
    currentKernelTime.LowPart = kernelTime.dwLowDateTime;
    currentKernelTime.HighPart = kernelTime.dwHighDateTime;
    currentUserTime.LowPart = userTime.dwLowDateTime;
    currentUserTime.HighPart = userTime.dwHighDateTime;

    ULONGLONG idle = currentIdleTime.QuadPart - lastIdleTime.QuadPart;
    ULONGLONG kernel = currentKernelTime.QuadPart - lastKernelTime.QuadPart;
    ULONGLONG user = currentUserTime.QuadPart - lastUserTime.QuadPart;

    // Değerleri güncelle
    lastIdleTime = currentIdleTime;
    lastKernelTime = currentKernelTime;
    lastUserTime = currentUserTime;

    // Toplam zamanı kontrol et
    ULONGLONG totalTime = kernel + user + idle;
    if (totalTime == 0) {
        return 0; // Ya da başka bir hata değeri döndürebilirsiniz
    }

    double usage = (1.0 - static_cast<double>(idle) / totalTime) * 100.0;
    return static_cast<int>(usage);



}

/*QHash<int, int> clsPacketWorker::GetProcessorUsage(){
    static FILETIME prevIdleTimes[64], prevKernelTimes[64], prevUserTimes[64];
    FILETIME idleTime, kernelTime, userTime;

    QHash<int, int> cpuUsageMap;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int numProcessors = sysInfo.dwNumberOfProcessors;

    for (int i = 0; i < numProcessors; ++i) {
        // İşlemci başına zaman bilgilerini al
        GetSystemTimes(&idleTime, &kernelTime, &userTime);

        ULARGE_INTEGER currentIdleTime, currentKernelTime, currentUserTime;
        currentIdleTime.LowPart = idleTime.dwLowDateTime;
        currentIdleTime.HighPart = idleTime.dwHighDateTime;
        currentKernelTime.LowPart = kernelTime.dwLowDateTime;
        currentKernelTime.HighPart = kernelTime.dwHighDateTime;
        currentUserTime.LowPart = userTime.dwLowDateTime;
        currentUserTime.HighPart = userTime.dwHighDateTime;

        // Geçmiş zamanları al
        ULARGE_INTEGER prevIdle = *(ULARGE_INTEGER*)&prevIdleTimes[i];
        ULARGE_INTEGER prevKernel = *(ULARGE_INTEGER*)&prevKernelTimes[i];
        ULARGE_INTEGER prevUser = *(ULARGE_INTEGER*)&prevUserTimes[i];

        // Zaman farklarını hesapla
        ULONGLONG idleDelta = currentIdleTime.QuadPart - prevIdle.QuadPart;
        ULONGLONG kernelDelta = currentKernelTime.QuadPart - prevKernel.QuadPart;
        ULONGLONG userDelta = currentUserTime.QuadPart - prevUser.QuadPart;
        ULONGLONG totalDelta = kernelDelta + userDelta;

        if (totalDelta == 0) {
            cpuUsageMap[i] = 0;
            continue;
        }

        // İşlemci kullanım oranını hesapla (idle oranını çıkartarak)
        double usage = (1.0 - static_cast<double>(idleDelta) / totalDelta) * 100.0;
        cpuUsageMap[i] = static_cast<int>(usage);


        // Zaman bilgilerini güncelle
        prevIdleTimes[i] = idleTime;
        prevKernelTimes[i] = kernelTime;
        prevUserTimes[i] = userTime;
    }

    return cpuUsageMap;
}*/



QHash<int, int> clsPacketWorker::GetProcessorUsage(){
    static FILETIME prevIdleTime = {};
    static FILETIME prevKernelTime = {};
    static FILETIME prevUserTime = {};
    QHash<int, int> cpuUsageMap;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int numProcessors = sysInfo.dwNumberOfProcessors;

    for (int i = 0; i < numProcessors; ++i) {
        FILETIME idleTime, kernelTime, userTime;
        GetSystemTimes(&idleTime, &kernelTime, &userTime);

        ULARGE_INTEGER currentIdleTime, currentKernelTime, currentUserTime;
        currentIdleTime.LowPart = idleTime.dwLowDateTime;
        currentIdleTime.HighPart = idleTime.dwHighDateTime;
        currentKernelTime.LowPart = kernelTime.dwLowDateTime;
        currentKernelTime.HighPart = kernelTime.dwHighDateTime;
        currentUserTime.LowPart = userTime.dwLowDateTime;
        currentUserTime.HighPart = userTime.dwHighDateTime;

        ULARGE_INTEGER prevIdle, prevKernel, prevUser;
        prevIdle.LowPart = prevIdleTime.dwLowDateTime;
        prevIdle.HighPart = prevIdleTime.dwHighDateTime;
        prevKernel.LowPart = prevKernelTime.dwLowDateTime;
        prevKernel.HighPart = prevKernelTime.dwHighDateTime;
        prevUser.LowPart = prevUserTime.dwLowDateTime;
        prevUser.HighPart = prevUserTime.dwHighDateTime;

        ULONGLONG idleDelta = currentIdleTime.QuadPart - prevIdle.QuadPart;
        ULONGLONG kernelDelta = currentKernelTime.QuadPart - prevKernel.QuadPart;
        ULONGLONG userDelta = currentUserTime.QuadPart - prevUser.QuadPart;
        ULONGLONG totalDelta = kernelDelta + userDelta;

        if (totalDelta == 0) {
            cpuUsageMap[i] = 0;
            continue;
        }

        double usage = (1.0 - static_cast<double>(idleDelta) / totalDelta) * 100.0;
        cpuUsageMap[i] = static_cast<int>(usage);

        prevIdleTime = idleTime;
        prevKernelTime = kernelTime;
        prevUserTime = userTime;
    }

    return cpuUsageMap;
}

