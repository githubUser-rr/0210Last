#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "clsPacketWorker.h"

#include <QDebug>
#include <QFileDialog>
#include <filesystem>
#include <QDir>
#include <QMessageBox>
#include <QThread>






mainwindow::mainwindow(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::mainwindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Dizin Seçici");
    ui->comboBox->setCurrentIndex(1);
    QObject::connect(ui->pButton,&QPushButton::clicked,this,&mainwindow::on_button_clicked);
    connect(ui->selectDirectoryButton, &QPushButton::clicked,
            this, &mainwindow::openDialog);
    QObject::connect(ui->parsePcap,&QPushButton::clicked,this,&mainwindow::parsePcapFile);
    connect(&wt,&QFileSystemWatcher::directoryChanged,this,&mainwindow::changedContent);
    wt.addPath(selectedDirectory);


    //QObject::connect(wt,&QFileSystemWatcher::fileChanged,this,&mainwindow::changedContent);





}

mainwindow::~mainwindow()
{
    delete ui;

}


void mainwindow::on_button_clicked(){
    QFont ft = ui->selectedDirectoryLabel->font();
    if(selectedDirectory.isEmpty()){
        ui->selectedDirectoryLabel->setText("Path Seçilmedi , seçiniz !!");
        ft.setPointSize(11);
        ft.setBold(true);
        ft.setItalic(true);
        //ui->selectedDirectoryLabel->setFont(ft);
    }else{
        QStringList listDir = listDirectory(selectedDirectory);
        if(listDir.size()>0){
            QString combinedList = listDir.join("\n");
            ui->selectedDirectoryLabel->setText(combinedList);
            ft.setPointSize(9);
            //ui->selectedDirectoryLabel->setFont(ft);
            ui->label->setText(QString("Seçilen Dizin : %1").arg(selectedDirectory));
        }else{
            ui->selectedDirectoryLabel->setText("Dizin içeriği boş .");
        }

    }
}



void mainwindow::openDialog(){
    QString defaultPath = QDir::homePath() + "/Desktop";
    QString directory = QFileDialog::getExistingDirectory(this,
                                                         tr("Dizin Seç"),
                                                         defaultPath,
                                                         QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);

    if (!directory.isEmpty()) {
        //qDebug() << "Seçilen dizin:" << directory;
        QString stringName = "Seçilen Dizin : %1";
        stringName = stringName.arg(directory);
        selectedDirectory = directory;
        ui->label->setText(QString("Seçilen Dizin : %1").arg(selectedDirectory));
        ui->selectedDirectoryLabel->setText(directory);
        QStringList directories = wt.directories();
        foreach (const QString &dir, directories) {
            wt.removePath(dir);
        }
        wt.addPath(selectedDirectory);
        QDir dir(selectedDirectory);
        previousFiles = dir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries);
        //qDebug() << "previousFiles: " << previousFiles;

    } else {
        //qDebug() << "Dizin seçilmedi.";
        ui->selectedDirectoryLabel->setText("Hiçbir dizin seçilmedi.");
    }
}


QStringList mainwindow::listDirectory(QString path){
    QDir dir(path);

    if(!dir.exists()){
        qWarning() << "Dizin mevcut değil !!";
    }else{
        QStringList list = dir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries);
        return list;
    }
    return QStringList();
}

void mainwindow::changedContent(){
    QDir dir(selectedDirectory);
    QStringList current = dir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries);

    QStringList onlyPrevious; // silinen
    QStringList onlyCurrent; // eklenen

    for (const QString &item : previousFiles) {
        if (!current.contains(item)) {
            onlyPrevious.append(item);
        }
    }
    for (const QString &i : current) {
        if (!previousFiles.contains(i)) {
            onlyCurrent.append(i);
        }
    }

    if (current != previousFiles) {
        //qDebug() << "Değişiklik algılandı" << selectedDirectory;
        if (onlyPrevious.size() > 0) {
            foreach (const QString &oP, onlyPrevious) {
                qDebug() << "Dosya silindi :" << oP;
            }
        }

        if (onlyCurrent.size() > 0) {
            //qDebug() << "Dosya Eklendi";
            foreach (const QString &oC, onlyCurrent) {
                qDebug() << "Eklenen Dosya : " << oC;
                QString fileType = oC.mid(oC.lastIndexOf('.'));
                if (fileType == ".pcap") {
                    //packetOperation *packetObj = new packetOperation();
                    QString pcapPath = selectedDirectory + "/" + oC;
                    /*packetOperation *pcapObj = new packetOperation(pcapPath.toStdString());
                    pcapObj->packetCapture();
                    pcapObj->printPacketInfo();
                    pcapObj->printSessionMap();
                    delete pcapObj;
                    pcapObj = nullptr;*/

                    int index = ui->comboBox->currentIndex();
                    QThread *thread = new QThread();
                    clsPacketWorker *pw = new clsPacketWorker(pcapPath,index);
                    //PacketWorker *pw = new PacketWorker(pcapPath.toStdString());


                    pw->moveToThread(thread);
                    connect(thread,&QThread::started,pw,&clsPacketWorker::createPacket);
                    connect(pw,&clsPacketWorker::createFinished,thread,&QThread::quit);
                    connect(pw,&clsPacketWorker::createFinished,pw,&clsPacketWorker::deleteLater);
                    connect(thread,&QThread::finished,thread,&QThread::deleteLater);

                    thread->start();

                    qDebug() << pcapPath;
                    //stripe verdiğin pcap ekstra layer kaldırıyor.
                    //cpu indekse göre thread çalıştırmaya bak .cpu.bind()
                }
            }
        }
        previousFiles = current;
    }
}

void mainwindow::parsePcapFile(){
    //qDebug() << "Parsing pcap file ";


    /*QString fileName = QFileDialog::getOpenFileName(nullptr,
                                                    "Pcap Dosyası Seçiniz",
                                                    QDir::homePath() + "/Desktop",
                                                    "Pcap Dosyaları (*.pcap)"); */

    QFileDialog dialog(nullptr,"Pcap Dosyası Seçiniz",QDir::homePath() + "/Desktop","Pcap Dosyaları (*.pcap)");
    dialog.setLabelText(QFileDialog::Accept, "Seç");
    dialog.setLabelText(QFileDialog::Reject, "Vazgeç");

    if (dialog.exec() == QDialog::Accepted) {
        QString fileName = dialog.selectedFiles()[0];
        //qDebug() << fileName ;
        /*packetOperation *p = new packetOperation(fileName.toStdString());
        p->packetCapture(0);
        p->printPacketInfo();
        p->printSessionMap();
        delete p;
        p = nullptr; */

        int index = ui->comboBox->currentIndex();
        QThread *qt = new QThread();
        clsPacketWorker *worker = new clsPacketWorker(fileName,index);
        //PacketWorker *worker = new PacketWorker(fileName.toStdString());
        worker->moveToThread(qt);

        connect(qt,&QThread::started,worker,&clsPacketWorker::createPacket);
        connect(worker,&clsPacketWorker::createFinished,qt,&QThread::quit);
        connect(worker,&clsPacketWorker::createFinished,worker,&clsPacketWorker::deleteLater);
        connect(qt,&QThread::finished,qt,&QThread::deleteLater);
        qt->start();


    }else{
        QMessageBox::warning(nullptr, "Pcap Dosyası Seçilmedi", "Herhangi bir dosya seçilmedi , dosya seçmek için tekrarlayın.");
    }


    //qDebug() << fileName;
}
