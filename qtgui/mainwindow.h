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
    void configuration();
    void savePreferences();
    void slot_Open();

  protected:
    void closeEvent(QCloseEvent *event) Q_DECL_OVERRIDE;

  private:
    const std::unique_ptr<Ui::MainWindow> m_ui;
    void loadPreferences();
    void* cryptoConfig{};
    char* ret_msg{};
};

extern MainWindow *gMainWindow;
