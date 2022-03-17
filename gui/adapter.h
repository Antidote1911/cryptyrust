#ifndef ADAPTER_H
#define ADAPTER_H

#include <QFileDialog>
#include <QString>
#include <fstream>
#include "mainwindow.h"

// rust functions
extern "C" void* makeConfig(int, char*, char*, char*, void (*output)(int32_t));
extern "C" char* start(void*);
extern "C" void destroyConfig(void*);
extern "C" void destroyCString(char*);
extern "C" char* get_version2();

enum Mode {
    Encrypt = 0,
    Decrypt = 1,
};

enum Outcome {
    success = 0,
    redo,
    cancel,
};

static const char* FILE_EXTENSION     = ".crypty";
static uint32_t FILE_SIGNATURE        = 0xC10A6BED;

Mode getMode(QString filename);
QString saveDialog(QString inFile, Mode mode);
Outcome passwordPrompts(Mode mode, QString* password);
extern "C" void output(int32_t progress);

#endif // ADAPTER_H
