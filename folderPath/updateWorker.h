#ifndef UPDATEWORKER_H
#define UPDATEWORKER_H

#include <QObject>
#include <iostream>
#include <string>
#include "packetstruct.h"
#include "SearchMapWorker.h"

using namespace std;

class updateWorker : public QObject
{
    Q_OBJECT
public:
    updateWorker(string fName);

signals:


private:
    string key;
    SessıonInfo newMap;
    SearchMapWorker *sMapWorker;
};

#endif // UPDATEWORKER_H
