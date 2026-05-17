#include "mainwindow.h"
#include <QApplication>
#include <QStyleFactory>
#include <QProcess>
#include "adapter.h"

MainWindow *gMainWindow;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    auto Str = get_version2();
    a.setApplicationName("Cryptyrust");
    a.setApplicationVersion(Str);
    MainWindow w;
    w.show();
    return a.exec();
}
