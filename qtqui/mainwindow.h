#pragma once

#include <QMainWindow>
#include <memory>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

  public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    void updateProgress(int);

  private slots:
    void slot_menuAbout();
    void slot_Open();

  private:
    const std::unique_ptr<Ui::MainWindow> m_ui;
    void* config;
    char* ret_msg;
};

extern MainWindow *gMainWindow;
