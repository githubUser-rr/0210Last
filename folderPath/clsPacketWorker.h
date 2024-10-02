#ifndef CLSPACKETWORKER_H
#define CLSPACKETWORKER_H

#include <QObject>
#include <QString>
#include <QMutex>
#include <QVector>
#include "clsPacketOperation.h"
#include "pcapppacket.h"


class clsPacketWorker : public QObject
{
    Q_OBJECT
public:
    clsPacketWorker(const QString& str,int c);
    ~clsPacketWorker();

    static void incrementThread();
    static void decrementThread();

    static QMutex threadMutex;
    static int currentThread;

    static const int totalCpu;

public slots:
    void createPacket();

signals:
    void createFinished();

private:
    int control;
    clsPacketOperation* packet;
    pcapPpacket* pPlusPacket;
    QString path;

    int returnUsageRate();

    QHash<int, int> GetProcessorUsage();
    ULONGLONG SubtractTimes(const FILETIME& ftA, const FILETIME& ftB);

};

#endif // CLSPACKETWORKER_H
