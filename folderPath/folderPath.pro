QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0



#INCLUDEPATH += C:/Users/remzi/Desktop/pPlus/pcapplusplus-24.09-windows-mingw64-x86_64-gcc-14.2.0/include/pcapplusplus


#LIBS += -LC:/Users/remzi/Desktop/pPlus/pcapplusplus-24.09-windows-mingw64-x86_64-gcc-14.2.0/lib \
#        -lPcap++ \
#        -lPacket++ \
#        -lCommon++




#INCLUDEPATH += "C:/Users/remzi/Desktop/sstekLearn/npcap-sdk-1.13/Include"
#LIBS += -L"C:/Users/remzi/Desktop/sstekLearn/npcap-sdk-1.13/Lib/x64" -lwpcap
#LIBS += -lws2_32

INCLUDEPATH += C:\Users\user\Desktop\pPlus\pcapplusplus-24.09-windows-mingw64-x86_64-gcc-14.2.0\include\pcapplusplus
LIBS += -LC:\Users\user\Desktop\pPlus\pcapplusplus-24.09-windows-mingw64-x86_64-gcc-14.2.0\lib \
        -lPcap++ \
        -lPacket++ \
        -lCommon++


INCLUDEPATH += "C:\Users\user\Desktop\npcap-sdk-1.13\Include"
LIBS += -L"C:\Users\user\Desktop\npcap-sdk-1.13\Lib\x64" -lwpcap
LIBS += -lws2_32




SOURCES += \
    MoveWorker.cpp \
    clsPacketOperation.cpp \
    clsPacketWorker.cpp \
    clsSearchMapWorker.cpp \
    main.cpp \
    mainwindow.cpp \
    newstructs.cpp \
    backProcessCls.cpp \
    pcapppacket.cpp \
    pPlusnewstructs.cpp


HEADERS += \
    MoveWorker.h \
    clsPacketOperation.h \
    clsPacketWorker.h \
    clsSearchMapWorker.h \
    mainwindow.h \
    newstructs.h \
    backProcessCls.h \
    pcapppacket.h \
    pPlusnewstructs.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
