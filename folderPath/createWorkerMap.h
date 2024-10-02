#ifndef CREATEWORKERMAP_H
#define CREATEWORKERMAP_H

#include <QObject>

#include "packetoperation.h"

class createWorkerMap : public QObject
{
    Q_OBJECT
public:
    createWorkerMap(PacketOperation* packetOp,const PacketInfo& packetInfo);

public slots:
    void createMap();

signals:
    void finished();

private:
    packetOperation *p;
    PacketInfo pInfo;
};

#endif // CREATEWORKERMAP_H
