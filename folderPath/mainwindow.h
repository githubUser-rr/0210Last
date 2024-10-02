#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QWidget>
#include <QFileSystemWatcher>



QT_BEGIN_NAMESPACE
namespace Ui { class mainwindow; }
QT_END_NAMESPACE

const QString SOURCE_FOLDER = "/home/PacketParse/Source";

class mainwindow : public QWidget
{
    Q_OBJECT

public:
    mainwindow(QWidget *parent = nullptr);
    ~mainwindow();
    QString selectedDirectory;
    QStringList listDirectory(QString path);

private slots:
    void on_button_clicked();
    void openDialog();
    void changedContent();
    void parsePcapFile();

private:
    Ui::mainwindow *ui;
    QFileSystemWatcher wt;
    QStringList previousFiles ;



};
#endif // MAINWINDOW_H
