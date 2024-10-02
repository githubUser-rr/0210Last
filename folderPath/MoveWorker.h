#ifndef MOVEWORKER_H
#define MOVEWORKER_H

#include <QObject>
#include <QString>

class MoveWorker : public QObject
{
    Q_OBJECT

public:
    MoveWorker(const QString& path);


public slots:
    void moveFile();

signals:
    void moveFinished();
    void failedMove();

private:
    QString filePath;
    QString destPath;
    QString fileName;
};

#endif // MOVEWORKER_H
