#include "createWorkerMap.h"
#include "packetstruct.h"

createWorkerMap::createWorkerMap(PacketOperation* packetOp,const PacketInfo& packetInfo)
    : p(packetOp) , pInfo(packetInfo){

}

void createWorkerMap::createMap(){
    p->createSessionMap(pInfo);
}
