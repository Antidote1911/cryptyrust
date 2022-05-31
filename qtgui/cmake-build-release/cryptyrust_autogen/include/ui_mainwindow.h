/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.15.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QWidget>
#include "droparea.h"

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *menu_About;
    QAction *menu_Open;
    QAction *menu_Quit;
    QAction *menu_AboutQt;
    QAction *actionDark;
    QAction *actionLight;
    QAction *actionCrypto;
    QAction *actionAes256Gcm;
    QAction *actiondeoxys;
    QAction *actionChacha20Poly1305;
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    DropArea *label;
    QProgressBar *progBar;
    QComboBox *comboAlgo;
    QMenuBar *menuBar;
    QMenu *menuAbout;
    QMenu *menuFile;
    QMenu *menuConfig;
    QMenu *menuSkin;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(417, 222);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MainWindow->sizePolicy().hasHeightForWidth());
        MainWindow->setSizePolicy(sizePolicy);
        MainWindow->setAutoFillBackground(false);
        menu_About = new QAction(MainWindow);
        menu_About->setObjectName(QString::fromUtf8("menu_About"));
        menu_Open = new QAction(MainWindow);
        menu_Open->setObjectName(QString::fromUtf8("menu_Open"));
        menu_Quit = new QAction(MainWindow);
        menu_Quit->setObjectName(QString::fromUtf8("menu_Quit"));
        menu_AboutQt = new QAction(MainWindow);
        menu_AboutQt->setObjectName(QString::fromUtf8("menu_AboutQt"));
        actionDark = new QAction(MainWindow);
        actionDark->setObjectName(QString::fromUtf8("actionDark"));
        actionDark->setCheckable(true);
        actionLight = new QAction(MainWindow);
        actionLight->setObjectName(QString::fromUtf8("actionLight"));
        actionLight->setCheckable(true);
        actionCrypto = new QAction(MainWindow);
        actionCrypto->setObjectName(QString::fromUtf8("actionCrypto"));
        actionAes256Gcm = new QAction(MainWindow);
        actionAes256Gcm->setObjectName(QString::fromUtf8("actionAes256Gcm"));
        actionAes256Gcm->setCheckable(true);
        actiondeoxys = new QAction(MainWindow);
        actiondeoxys->setObjectName(QString::fromUtf8("actiondeoxys"));
        actiondeoxys->setCheckable(true);
        actionChacha20Poly1305 = new QAction(MainWindow);
        actionChacha20Poly1305->setObjectName(QString::fromUtf8("actionChacha20Poly1305"));
        actionChacha20Poly1305->setCheckable(true);
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        label = new DropArea(centralWidget);
        label->setObjectName(QString::fromUtf8("label"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
        label->setSizePolicy(sizePolicy1);
        label->setAcceptDrops(true);
        label->setAutoFillBackground(true);
        label->setFrameShape(QFrame::Panel);
        label->setFrameShadow(QFrame::Sunken);
        label->setLineWidth(2);
        label->setAlignment(Qt::AlignCenter);

        gridLayout->addWidget(label, 0, 0, 1, 1);

        progBar = new QProgressBar(centralWidget);
        progBar->setObjectName(QString::fromUtf8("progBar"));
        progBar->setValue(24);

        gridLayout->addWidget(progBar, 2, 0, 1, 1);

        comboAlgo = new QComboBox(centralWidget);
        comboAlgo->addItem(QString());
        comboAlgo->addItem(QString());
        comboAlgo->addItem(QString());
        comboAlgo->setObjectName(QString::fromUtf8("comboAlgo"));

        gridLayout->addWidget(comboAlgo, 1, 0, 1, 1);

        MainWindow->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 417, 22));
        menuAbout = new QMenu(menuBar);
        menuAbout->setObjectName(QString::fromUtf8("menuAbout"));
        menuFile = new QMenu(menuBar);
        menuFile->setObjectName(QString::fromUtf8("menuFile"));
        menuConfig = new QMenu(menuBar);
        menuConfig->setObjectName(QString::fromUtf8("menuConfig"));
        menuSkin = new QMenu(menuConfig);
        menuSkin->setObjectName(QString::fromUtf8("menuSkin"));
        MainWindow->setMenuBar(menuBar);

        menuBar->addAction(menuFile->menuAction());
        menuBar->addAction(menuConfig->menuAction());
        menuBar->addAction(menuAbout->menuAction());
        menuAbout->addAction(menu_About);
        menuAbout->addAction(menu_AboutQt);
        menuFile->addAction(menu_Open);
        menuFile->addAction(menu_Quit);
        menuConfig->addAction(menuSkin->menuAction());
        menuSkin->addAction(actionDark);
        menuSkin->addAction(actionLight);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "Cryptyrust", nullptr));
        menu_About->setText(QCoreApplication::translate("MainWindow", "About Cryptyrust", nullptr));
#if QT_CONFIG(tooltip)
        menu_About->setToolTip(QCoreApplication::translate("MainWindow", "About Cryptyrust", nullptr));
#endif // QT_CONFIG(tooltip)
        menu_Open->setText(QCoreApplication::translate("MainWindow", "Open", nullptr));
        menu_Quit->setText(QCoreApplication::translate("MainWindow", "Quit", nullptr));
        menu_AboutQt->setText(QCoreApplication::translate("MainWindow", "About Qt", nullptr));
        actionDark->setText(QCoreApplication::translate("MainWindow", "Dark", nullptr));
        actionLight->setText(QCoreApplication::translate("MainWindow", "Light", nullptr));
        actionCrypto->setText(QCoreApplication::translate("MainWindow", "Crypto", nullptr));
        actionAes256Gcm->setText(QCoreApplication::translate("MainWindow", "Aes256Gcm", nullptr));
        actiondeoxys->setText(QCoreApplication::translate("MainWindow", "deoxys", nullptr));
        actionChacha20Poly1305->setText(QCoreApplication::translate("MainWindow", "Chacha20Poly1305", nullptr));
        label->setText(QCoreApplication::translate("MainWindow", "Drop a normal file here to encrypt\n"
"\n"
"or an encrypted file to decrypt", nullptr));
        comboAlgo->setItemText(0, QCoreApplication::translate("MainWindow", "XChaCha20Poly1305", nullptr));
        comboAlgo->setItemText(1, QCoreApplication::translate("MainWindow", "Aes256Gcm", nullptr));
        comboAlgo->setItemText(2, QCoreApplication::translate("MainWindow", "DeoxysII256", nullptr));

        menuAbout->setTitle(QCoreApplication::translate("MainWindow", "About", nullptr));
        menuFile->setTitle(QCoreApplication::translate("MainWindow", "File", nullptr));
        menuConfig->setTitle(QCoreApplication::translate("MainWindow", "Config", nullptr));
        menuSkin->setTitle(QCoreApplication::translate("MainWindow", "Skin", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
