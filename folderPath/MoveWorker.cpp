#include "MoveWorker.h"

#include <QFile>
#include <QDir>
#include <QDebug>
#include <QThread>


/*MoveWorker::MoveWorker(const QString &path) : filePath(path),destPath("C:\\Users\\remzi\\Desktop\\usedFile")*/

MoveWorker::MoveWorker(const QString &path) : filePath(path),destPath("C:\\Users\\user\\Desktop\\used"){
    //qDebug() << "MoveWorker cons basladi .." ;
    fileName = QFileInfo(filePath).fileName();
    //QString newPath = QDir(destPath).filePath(fileName);
    //qDebug() << "MoveWorker file path : " << filePath  ;
    //qDebug() << "MoveWorker new path : " << newPath  ;
}

void MoveWorker::moveFile(){
    //qDebug() << "Move File .." ;
    QString newPath = QDir(destPath).filePath(fileName);
    qDebug()<< newPath;
    if(QFile::rename(filePath,newPath)){
        qDebug() << "Dosya tasindi " ;
        emit moveFinished();

    }else{
        qDebug() << "Dosya tasinamadi !!";
        emit failedMove();
    }

}
