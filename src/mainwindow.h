#pragma once

#include <QMainWindow>
#include <QStringList>
#include <QVector>

class QAction;
class QByteArray;
class QCloseEvent;
class QEvent;
class QLabel;
class QMenu;
class QSystemTrayIcon;
class QTableWidget;
class QTextEdit;

struct ProcessEntry
{
    QString name;
    quint32 pid = 0;
    QString path;
    int impact = 0;
    QString level;
    QString reason;
    bool defaultChecked = false;
    bool stoppable = true;
    bool managedService = false;
    QString serviceName;
    QStringList scheduledTasks;
};

struct ManagedServiceState
{
    QString serviceName;
    bool wasRunning = false;
    QStringList disabledTasks;
    bool eaioRecoverySuppressed = false;
    bool eaioStartDisabled = false;
};

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    void showFromTray();
    void applyNativeWindowIcon();

protected:
    void closeEvent(QCloseEvent *event) override;
    void changeEvent(QEvent *event) override;
    bool nativeEvent(const QByteArray &eventType, void *message, long *result) override;

private:
    void buildUi();
    void configureTray();
    void showNativeTrayIcon();
    void hideNativeTrayIcon();
    void applyDarkTheme();
    void hideToTray();
    void requestExit();
    bool showExitChoice();
    bool exitConfirmationDisabled() const;
    void setExitConfirmationDisabled(bool disabled);

    QVector<ProcessEntry> scanRelevantProcesses() const;
    ProcessEntry classify(const QString &name, quint32 pid, const QString &path) const;
    quint32 queryServiceProcessId(const QString &serviceName, bool *running) const;
    QString queryProcessPath(quint32 pid) const;
    bool stopWindowsService(const QString &serviceName, QString *error) const;
    bool startWindowsService(const QString &serviceName, QString *error) const;
    bool setWindowsServiceAutoStart(const QString &serviceName, bool enabled, QString *error) const;
    bool setScheduledTaskEnabled(const QString &taskName, bool enabled, QString *error) const;
    bool setEaioFailureActions(bool enabled, QString *error) const;
    bool quiesceManagedService(const ProcessEntry &entry, QString *error);
    bool stopProcess(quint32 pid, QString *error) const;
    void refresh();
    void enterCsMode();
    void restorePrograms();
    void restartLogiOptions();
    void launchCs2();
    void log(const QString &message);

    QTableWidget *table_ = nullptr;
    QLabel *summary_ = nullptr;
    QLabel *modeStatus_ = nullptr;
    QTextEdit *logView_ = nullptr;
    QSystemTrayIcon *trayIcon_ = nullptr;
    QMenu *trayMenu_ = nullptr;
    QAction *showAction_ = nullptr;
    bool forceQuit_ = false;
    bool hidingToTray_ = false;
    bool trayTipShown_ = false;
    bool nativeTrayIconVisible_ = false;
    void *nativeTrayIconHandle_ = nullptr;
    QVector<ProcessEntry> closedPrograms_;
    QVector<ManagedServiceState> stoppedServices_;
};
