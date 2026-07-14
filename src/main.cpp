#include "mainwindow.h"

#include <QApplication>
#include <QCoreApplication>
#include <QIcon>
#include <QLocalServer>
#include <QLocalSocket>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace {
const QString kInstanceServerName = QStringLiteral("FUCKPecfectWorld.CS2NetworkControl");
}

int main(int argc, char *argv[])
{
#ifdef Q_OS_WIN
    using SetAppUserModelId = HRESULT (WINAPI *)(PCWSTR);
    const auto setAppUserModelId = reinterpret_cast<SetAppUserModelId>(
        GetProcAddress(GetModuleHandleW(L"shell32.dll"), "SetCurrentProcessExplicitAppUserModelID"));
    if (setAppUserModelId) {
        setAppUserModelId(L"com.fuckpecfectworld.cs2networkcontrol");
    }
#endif
    QApplication application(argc, argv);
    QCoreApplication::setOrganizationName("FUCKPecfectWorld");
    QCoreApplication::setApplicationName("FUCKPecfectWorld");
    QApplication::setQuitOnLastWindowClosed(false);
    application.setWindowIcon(QIcon(QStringLiteral(":/icons/cs_source.ico")));

    QLocalSocket existingInstance;
    existingInstance.connectToServer(kInstanceServerName, QIODevice::WriteOnly);
    if (existingInstance.waitForConnected(250)) {
        existingInstance.write("activate");
        existingInstance.waitForBytesWritten(250);
        return 0;
    }

    QLocalServer::removeServer(kInstanceServerName);
    QLocalServer instanceServer;
    if (!instanceServer.listen(kInstanceServerName)) {
        return 1;
    }

    MainWindow window;
    QObject::connect(&instanceServer, &QLocalServer::newConnection, &window, [&instanceServer, &window] {
        while (QLocalSocket *connection = instanceServer.nextPendingConnection()) {
            connection->deleteLater();
            window.showFromTray();
        }
    });

    window.show();
    window.applyNativeWindowIcon();
    return application.exec();
}
