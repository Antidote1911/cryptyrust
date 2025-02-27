/********************************************************************************
** Form generated from reading UI file 'configDialog.ui'
**
** Created by: Qt User Interface Compiler version 6.8.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CONFIGDIALOG_H
#define UI_CONFIGDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAbstractButton>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_ConfigDialog
{
public:
    QVBoxLayout *verticalLayout;
    QGroupBox *groupBox_2;
    QGridLayout *gridLayout_2;
    QLabel *label_2;
    QSpacerItem *horizontalSpacer_2;
    QComboBox *comboStrength;
    QGroupBox *groupBox_3;
    QGridLayout *gridLayout_3;
    QLabel *label_4;
    QComboBox *comboAlgo;
    QLabel *label_5;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ConfigDialog)
    {
        if (ConfigDialog->objectName().isEmpty())
            ConfigDialog->setObjectName("ConfigDialog");
        ConfigDialog->resize(389, 216);
        verticalLayout = new QVBoxLayout(ConfigDialog);
        verticalLayout->setObjectName("verticalLayout");
        groupBox_2 = new QGroupBox(ConfigDialog);
        groupBox_2->setObjectName("groupBox_2");
        gridLayout_2 = new QGridLayout(groupBox_2);
        gridLayout_2->setObjectName("gridLayout_2");
        label_2 = new QLabel(groupBox_2);
        label_2->setObjectName("label_2");

        gridLayout_2->addWidget(label_2, 0, 0, 1, 1);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Minimum);

        gridLayout_2->addItem(horizontalSpacer_2, 0, 1, 1, 1);

        comboStrength = new QComboBox(groupBox_2);
        comboStrength->addItem(QString::fromUtf8("Interactive"));
        comboStrength->addItem(QString::fromUtf8("Moderate"));
        comboStrength->addItem(QString::fromUtf8("Sensitive"));
        comboStrength->setObjectName("comboStrength");
        comboStrength->setCurrentText(QString::fromUtf8("Interactive"));

        gridLayout_2->addWidget(comboStrength, 0, 2, 1, 1);


        verticalLayout->addWidget(groupBox_2);

        groupBox_3 = new QGroupBox(ConfigDialog);
        groupBox_3->setObjectName("groupBox_3");
        gridLayout_3 = new QGridLayout(groupBox_3);
        gridLayout_3->setObjectName("gridLayout_3");
        label_4 = new QLabel(groupBox_3);
        label_4->setObjectName("label_4");

        gridLayout_3->addWidget(label_4, 0, 0, 1, 1);

        comboAlgo = new QComboBox(groupBox_3);
        comboAlgo->addItem(QString());
        comboAlgo->addItem(QString());
        comboAlgo->addItem(QString());
        comboAlgo->setObjectName("comboAlgo");

        gridLayout_3->addWidget(comboAlgo, 0, 1, 1, 1);


        verticalLayout->addWidget(groupBox_3);

        label_5 = new QLabel(ConfigDialog);
        label_5->setObjectName("label_5");
        QFont font;
        font.setBold(false);
        font.setItalic(true);
        font.setUnderline(false);
        font.setKerning(false);
        label_5->setFont(font);
        label_5->setTextFormat(Qt::TextFormat::PlainText);
        label_5->setAlignment(Qt::AlignmentFlag::AlignCenter);

        verticalLayout->addWidget(label_5);

        buttonBox = new QDialogButtonBox(ConfigDialog);
        buttonBox->setObjectName("buttonBox");
        buttonBox->setOrientation(Qt::Orientation::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::StandardButton::Cancel|QDialogButtonBox::StandardButton::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(ConfigDialog);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, ConfigDialog, qOverload<>(&QDialog::accept));
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, ConfigDialog, qOverload<>(&QDialog::reject));

        QMetaObject::connectSlotsByName(ConfigDialog);
    } // setupUi

    void retranslateUi(QDialog *ConfigDialog)
    {
        ConfigDialog->setWindowTitle(QCoreApplication::translate("ConfigDialog", "Arsenic Configuration", nullptr));
        groupBox_2->setTitle(QCoreApplication::translate("ConfigDialog", "Password derivation", nullptr));
        label_2->setText(QCoreApplication::translate("ConfigDialog", "Strength", nullptr));

        groupBox_3->setTitle(QCoreApplication::translate("ConfigDialog", "Files Encryption", nullptr));
        label_4->setText(QCoreApplication::translate("ConfigDialog", "Encryption algorithm : ", nullptr));
        comboAlgo->setItemText(0, QCoreApplication::translate("ConfigDialog", "XChaCha20-Poly1305", nullptr));
        comboAlgo->setItemText(1, QCoreApplication::translate("ConfigDialog", "Aes-256-Gcm", nullptr));
        comboAlgo->setItemText(2, QCoreApplication::translate("ConfigDialog", "Aes-256-Gcm-Siv", nullptr));

        label_5->setText(QCoreApplication::translate("ConfigDialog", "The decryption routine detect the right parameters automatically.", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ConfigDialog: public Ui_ConfigDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CONFIGDIALOG_H
