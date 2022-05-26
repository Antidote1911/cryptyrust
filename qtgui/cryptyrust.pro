#-------------------------------------------------
#
# Project created by QtCreator 2019-06-06T20:52:47
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = cryptyrust
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++17

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    droparea.cpp \
    adapter.cpp \
    skin/skin.cpp \
    Config.cpp

HEADERS += \
        mainwindow.h \
    droparea.h \
    adapter.h \
    skin/skin.h \
    Config.h

FORMS += \
        mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

#QMAKE_LFLAGS_WINDOWS += -static -static-libgcc -static-libstdc++

unix: LIBS += -L$$PWD/../target/release/ -lcryptyrust_adapter

unix: LIBS += -ldl

INCLUDEPATH += $$PWD/../target/release
DEPENDPATH += $$PWD/../target/release

unix: PRE_TARGETDEPS += $$PWD/../target/release/libcryptyrust_adapter.a

DISTFILES +=

ICON = macCloakerLogo.icns
RC_ICONS = cloaker.ico

win32: LIBS += -L$$PWD/../target/release/ -lcryptyrust_adapter -lws2_32 -luserenv

INCLUDEPATH += $$PWD/../target/release
DEPENDPATH += $$PWD/../target/release

win32:!win32-g++: PRE_TARGETDEPS += $$PWD/../target/release/cryptyrust_adapter.lib
else:win32-g++: PRE_TARGETDEPS += $$PWD/../target/release/libcryptyrust_adapter.a
