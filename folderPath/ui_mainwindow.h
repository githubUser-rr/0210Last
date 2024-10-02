/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.7.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_mainwindow
{
public:
    QLabel *selectedDirectoryLabel;
    QLabel *label;
    QSplitter *splitter;
    QPushButton *selectDirectoryButton;
    QPushButton *parsePcap;
    QPushButton *pButton;
    QComboBox *comboBox;

    void setupUi(QWidget *mainwindow)
    {
        if (mainwindow->objectName().isEmpty())
            mainwindow->setObjectName("mainwindow");
        mainwindow->resize(613, 398);
        selectedDirectoryLabel = new QLabel(mainwindow);
        selectedDirectoryLabel->setObjectName("selectedDirectoryLabel");
        selectedDirectoryLabel->setGeometry(QRect(60, 60, 231, 311));
        QFont font;
        font.setPointSize(9);
        selectedDirectoryLabel->setFont(font);
        label = new QLabel(mainwindow);
        label->setObjectName("label");
        label->setGeometry(QRect(40, 30, 361, 31));
        QFont font1;
        font1.setPointSize(10);
        font1.setBold(true);
        font1.setItalic(true);
        font1.setUnderline(true);
        label->setFont(font1);
        splitter = new QSplitter(mainwindow);
        splitter->setObjectName("splitter");
        splitter->setGeometry(QRect(360, 170, 231, 80));
        QSizePolicy sizePolicy(QSizePolicy::Policy::Preferred, QSizePolicy::Policy::Expanding);
        sizePolicy.setHorizontalStretch(100);
        sizePolicy.setVerticalStretch(100);
        sizePolicy.setHeightForWidth(splitter->sizePolicy().hasHeightForWidth());
        splitter->setSizePolicy(sizePolicy);
        splitter->setMaximumSize(QSize(16777215, 99));
        splitter->setOrientation(Qt::Orientation::Vertical);
        selectDirectoryButton = new QPushButton(splitter);
        selectDirectoryButton->setObjectName("selectDirectoryButton");
        splitter->addWidget(selectDirectoryButton);
        parsePcap = new QPushButton(splitter);
        parsePcap->setObjectName("parsePcap");
        splitter->addWidget(parsePcap);
        pButton = new QPushButton(splitter);
        pButton->setObjectName("pButton");
        splitter->addWidget(pButton);
        comboBox = new QComboBox(mainwindow);
        comboBox->addItem(QString());
        comboBox->addItem(QString());
        comboBox->setObjectName("comboBox");
        comboBox->setGeometry(QRect(360, 30, 221, 26));

        retranslateUi(mainwindow);

        QMetaObject::connectSlotsByName(mainwindow);
    } // setupUi

    void retranslateUi(QWidget *mainwindow)
    {
        mainwindow->setWindowTitle(QCoreApplication::translate("mainwindow", "mainwindow", nullptr));
        selectedDirectoryLabel->setText(QCoreApplication::translate("mainwindow", "Path Se\303\247iniz !! ", nullptr));
        label->setText(QCoreApplication::translate("mainwindow", "Se\303\247ilen Klas\303\266r \304\260\303\247eri\304\237i", nullptr));
        selectDirectoryButton->setText(QCoreApplication::translate("mainwindow", "Dinlenecek Dosya Se\303\247iniz", nullptr));
        parsePcap->setText(QCoreApplication::translate("mainwindow", "Pcap Dosyas\304\261 se\303\247iniz", nullptr));
        pButton->setText(QCoreApplication::translate("mainwindow", "Dosya \304\260\303\247eri\304\237i Listele", nullptr));
        comboBox->setItemText(0, QCoreApplication::translate("mainwindow", "Parse With Npcap", nullptr));
        comboBox->setItemText(1, QCoreApplication::translate("mainwindow", "Parse With PcapPlusPlus", nullptr));

    } // retranslateUi

};

namespace Ui {
    class mainwindow: public Ui_mainwindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
