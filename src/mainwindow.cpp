#include "mainwindow.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QCoreApplication>
#include <QCursor>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFrame>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QProcess>
#include <QStringList>
#include <QPushButton>
#include <QSettings>
#include <QSet>
#include <QSplitter>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QTextEdit>
#include <QTimer>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>
#include <string>

#ifdef Q_OS_WIN
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#endif

namespace {
constexpr int kCheckColumn = 0;
constexpr int kNameColumn = 1;
constexpr int kPidColumn = 2;
constexpr int kImpactColumn = 3;
constexpr int kReasonColumn = 4;
constexpr int kPathColumn = 5;
QString text(const char *value);
#ifdef Q_OS_WIN
constexpr UINT kNativeTrayCallbackMessage = WM_APP + 42;
constexpr UINT kNativeTrayIconId = 1;
#endif

struct ManagedServiceRule
{
    QString serviceName;
    QString displayName;
    QString reason;
    int impact = 3;
    bool defaultChecked = true;
    QStringList workerNames;
    QStringList scheduledTasks;
};

const QVector<ManagedServiceRule> &managedServiceRules()
{
    static const QVector<ManagedServiceRule> genericRules;
    return genericRules;

    static const QVector<ManagedServiceRule> rules = {
        {QStringLiteral("aTrustService"), text(u8"aTrustService（Windows 服务）"),
         text(u8"守护 aTrustAgent / Xtunnel；选择后停止服务并暂时禁用启动任务"), 3, true,
         {QStringLiteral("atrustagent.exe"), QStringLiteral("atrustxtunnel.exe")},
         {QStringLiteral("Start-aTrustService-In-Login"), QStringLiteral("Start-aTrustService-In-Runing")}},
        {QStringLiteral("SangforPWEx"), text(u8"Sangfor VPN Protect（Windows 服务）"),
         text(u8"守护 SangforPWEx / SangforUDProtectEx；正常停止服务可阻止子进程复活"), 3, true,
         {QStringLiteral("sangforpwex.exe"), QStringLiteral("sangforudprotectex.exe")}, {}},
        {QStringLiteral("SangforSP"), text(u8"Sangfor Promote（Windows 服务）"),
         text(u8"守护 SangforPromoteService；选择后停止深信服推广网络服务"), 3, true,
         {QStringLiteral("sangforpromoteservice.exe")}, {}},
        {QStringLiteral("eaio_service"), text(u8"Sangfor EAIO（Windows 服务）"),
         text(u8"深信服 EAIO 网络服务；选择后停止服务"), 3, true,
         {QStringLiteral("eaio_service.exe")}, {}}
    };
    return rules;
}

bool isManagedServiceWorker(const QString &name)
{
    const QString normalized = name.toLower();
    for (const ManagedServiceRule &rule : managedServiceRules()) {
        if (rule.workerNames.contains(normalized)) {
            return true;
        }
    }
    return false;
}
struct Rule {
    const char *executable;
    int impact;
    const char *level;
    const char *reason;
    bool defaultChecked;
};

const Rule kRules[] = {
    {"clash-verge.exe", 3, u8"高", u8"系统代理与 TUN 接管，可能改变 CS2 路由", false},
    {"verge-mihomo.exe", 3, u8"高", u8"Clash Verge 网络核心", false},
    {"mihomo.exe", 3, u8"高", u8"代理 / TUN 网络核心", true},
    {"clash.exe", 3, u8"高", u8"代理 / TUN 网络核心", true},
    {"clash-meta.exe", 3, u8"高", u8"代理 / TUN 网络核心", true},
    {"v2ray.exe", 3, u8"高", u8"代理网络核心", true},
    {"xray.exe", 3, u8"高", u8"代理网络核心", true},
    {"sing-box.exe", 3, u8"高", u8"代理 / TUN 网络核心", true},
    {"wireguard.exe", 3, u8"高", u8"VPN 隧道", true},
    {"warp-svc.exe", 3, u8"高", u8"Cloudflare WARP 隧道", true},
    {"atrustagent.exe", 3, u8"高", u8"深信服 aTrust 网络过滤", true},
    {"atrusttray.exe", 2, u8"中", u8"深信服 aTrust 客户端", true},
    {"atrustxtunnel.exe", 3, u8"高", u8"深信服 aTrust 隧道", true},
    {"easyconnect.exe", 3, u8"高", u8"深信服 SSL VPN", true},
    {"sangforpromoteservice.exe", 3, u8"高", u8"深信服网络服务", true},
    {"sangforpwex.exe", 3, u8"高", u8"深信服网络组件", true},
    {"sangforudprotectex.exe", 3, u8"高", u8"深信服网络组件", true},
    {"netch.exe", 3, u8"高", u8"网络代理或游戏加速隧道", false},
    {"sstap.exe", 3, u8"高", u8"虚拟网卡代理", true},
    {"proxifier.exe", 3, u8"高", u8"进程级代理与流量重定向", true},
    {"sockscap64.exe", 2, u8"中", u8"进程代理", true},
    {"thunder.exe", 2, u8"中", u8"下载和上传可能占用带宽", true},
    {"qbittorrent.exe", 2, u8"中", u8"P2P 上传可能造成排队延迟", true},
    {"utorrent.exe", 2, u8"中", u8"P2P 上传可能造成排队延迟", true},
    {"onedrive.exe", 2, u8"中", u8"后台同步可能占用上行带宽", false},
    {"baidunetdisk.exe", 2, u8"中", u8"网盘同步或下载可能占用带宽", false},
    {"obs64.exe", 2, u8"中", u8"直播推流会持续占用上行带宽", false},
    {"gamebar.exe", 1, u8"低", u8"Xbox 叠加层", false},
    {"gamebarftserver.exe", 1, u8"低", u8"Xbox 录制或叠加层", false},
    {"discord.exe", 1, u8"低", u8"语音和叠加层，使用语音时应保留", false},
    {"gameoverlayui.exe", 1, u8"低", u8"Steam 叠加层，默认保留", false},
    {"uu.exe", 2, u8"中", u8"游戏加速器，默认保留", false},
    {"leigod.exe", 2, u8"中", u8"游戏加速器，默认保留", false},
    {"qiyou.exe", 2, u8"中", u8"游戏加速器，默认保留", false},
};

QString text(const char *value)
{
    return QString::fromUtf8(value);
}

struct ConfiguredRule
{
    QString executable;
    int impact = 1;
    QString level;
    QString reason;
    bool defaultChecked = false;
    bool stoppable = true;
};

QString levelForImpact(int impact)
{
    if (impact >= 3) {
        return text(u8"高");
    }
    if (impact == 2) {
        return text(u8"中");
    }
    return text(u8"低");
}

QVector<ConfiguredRule> parseConfiguredRules(const QByteArray &documentBytes)
{
    const QJsonDocument document = QJsonDocument::fromJson(documentBytes);
    if (!document.isObject()) {
        return {};
    }

    QVector<ConfiguredRule> rules;
    const QJsonArray entries = document.object().value(QStringLiteral("rules")).toArray();
    rules.reserve(entries.size());
    for (const QJsonValue &value : entries) {
        const QJsonObject object = value.toObject();
        const QString executable = object.value(QStringLiteral("executable")).toString().trimmed().toLower();
        if (executable.isEmpty()) {
            continue;
        }

        ConfiguredRule rule;
        rule.executable = executable;
        rule.impact = qBound(1, object.value(QStringLiteral("impact")).toInt(1), 3);
        rule.level = levelForImpact(rule.impact);
        rule.defaultChecked = object.value(QStringLiteral("defaultSelected")).toBool(false);
        rule.stoppable = object.value(QStringLiteral("stoppable")).toBool(true);
        const QString category = object.value(QStringLiteral("category")).toString().trimmed();
        const QString reason = object.value(QStringLiteral("reason")).toString().trimmed();
        rule.reason = category.isEmpty() ? reason : category + text(u8" · ") + reason;
        rules.push_back(rule);
    }
    return rules;
}

QVector<ConfiguredRule> loadConfiguredRules()
{
    const QString externalPath = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("rules.json"));
    QFile externalFile(externalPath);
    if (externalFile.open(QIODevice::ReadOnly)) {
        const QVector<ConfiguredRule> rules = parseConfiguredRules(externalFile.readAll());
        if (!rules.isEmpty()) {
            return rules;
        }
    }

    QFile bundledFile(QStringLiteral(":/icons/default_rules.json"));
    if (bundledFile.open(QIODevice::ReadOnly)) {
        return parseConfiguredRules(bundledFile.readAll());
    }
    return {};
}

const QVector<ConfiguredRule> &configuredRules()
{
    static const QVector<ConfiguredRule> rules = loadConfiguredRules();
    return rules;
}

QString applicationStyleSheet()
{
    return QStringLiteral(R"(
        * {
            font-family: "Segoe UI Variable", "Segoe UI", "Microsoft YaHei UI";
            font-size: 14px;
        }
        QMainWindow, QWidget {
            background: #0B0B0D;
            color: #F5F5F7;
        }
        QFrame#header {
            background: #151518;
            border: 1px solid #26262B;
            border-radius: 8px;
        }
        QFrame#tableSurface, QFrame#activitySurface, QFrame#summarySurface {
            background: #121215;
            border: 1px solid #27272D;
            border-radius: 8px;
        }
        QLabel#appName {
            color: #F5F5F7;
            font-size: 19px;
            font-weight: 600;
        }
        QLabel#appTagline {
            color: #98989F;
            font-size: 12px;
            font-weight: 600;
        }
        QLabel[role="sectionTitle"] {
            color: #F5F5F7;
            font-size: 15px;
            font-weight: 600;
        }
        QLabel#summary {
            color: #C9C9D0;
            font-size: 15px;
        }
        QLabel[role="status"] {
            background: #183A2A;
            color: #66E0A3;
            border: 1px solid #24533A;
            border-radius: 8px;
            padding: 5px 9px;
            font-size: 14px;
            font-weight: 600;
        }
        QLabel[role="status"][severity="warning"] {
            background: #402D19;
            color: #F8BE68;
            border-color: #6B4B23;
        }
        QPushButton {
            min-height: 32px;
            padding: 0 12px;
            background: #242429;
            border: 1px solid #34343C;
            border-radius: 6px;
            color: #F5F5F7;
            font-weight: 500;
        }
        QPushButton:hover { background: #303037; border-color: #484852; }
        QPushButton:pressed { background: #1B1B20; }
        QPushButton[primary="true"] {
            background: #0A84FF;
            border-color: #2191FF;
            color: #FFFFFF;
            font-weight: 600;
        }
        QPushButton[primary="true"]:hover { background: #2795FF; }
        QToolButton {
            min-width: 32px;
            min-height: 32px;
            padding: 0;
            border: 1px solid transparent;
            border-radius: 6px;
            color: #C9C9D0;
            background: transparent;
        }
        QToolButton:hover { background: #2A2A30; border-color: #3A3A43; }
        QToolButton:pressed { background: #1B1B20; }
        QTableWidget {
            background: transparent;
            alternate-background-color: #17171B;
            border: none;
            gridline-color: #29292F;
            selection-background-color: #183653;
            selection-color: #FFFFFF;
            outline: none;
        }
        QTableWidget::item { padding: 7px 9px; border-bottom: 1px solid #25252B; }
        QHeaderView::section {
            background: #17171B;
            color: #94949D;
            border: none;
            border-bottom: 1px solid #2A2A30;
            padding: 10px 9px;
            font-size: 13px;
            font-weight: 600;
        }
        QCheckBox { spacing: 6px; font-size: 14px; }
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border-radius: 4px;
            border: 1px solid #5A5A64;
            background: #17171B;
        }
        QCheckBox::indicator:checked {
            border-color: #0A84FF;
            background: #0A84FF;
        }
        QTextEdit {
            background: transparent;
            border: none;
            color: #B5B5BE;
            selection-background-color: #234B70;
            font-family: "Microsoft YaHei UI", "Segoe UI";
            font-size: 13px;
            padding: 4px 8px 8px 8px;
        }
        QScrollBar:vertical {
            background: transparent;
            width: 10px;
            margin: 3px;
        }
        QScrollBar::handle:vertical {
            background: #484850;
            min-height: 28px;
            border-radius: 4px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        QMenu {
            background: #1B1B20;
            border: 1px solid #3A3A42;
            padding: 5px;
            color: #F5F5F7;
        }
        QMenu::item { padding: 7px 30px 7px 10px; border-radius: 4px; }
        QMenu::item:selected { background: #2E2E35; }
        QMenu::separator { height: 1px; background: #34343B; margin: 5px 7px; }
        QMessageBox { background: #17171B; }
    )");
}
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    applyDarkTheme();
    buildUi();
    configureTray();
    refresh();
}

void MainWindow::applyDarkTheme()
{
    qApp->setStyleSheet(applicationStyleSheet());
}

void MainWindow::buildUi()
{
    setWindowTitle(text(u8"FUCKPecfectWorld"));
    setWindowIcon(QIcon(QStringLiteral(":/icons/cs_source.ico")));
    resize(1160, 760);
    setMinimumSize(900, 620);

    auto *central = new QWidget(this);
    central->setObjectName(QStringLiteral("central"));
    auto *layout = new QVBoxLayout(central);
    layout->setContentsMargins(18, 16, 18, 18);
    layout->setSpacing(12);

    auto *header = new QFrame(central);
    header->setObjectName(QStringLiteral("header"));
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(14, 10, 12, 10);
    headerLayout->setSpacing(10);

    auto *appMark = new QLabel(header);
    appMark->setPixmap(QIcon(QStringLiteral(":/icons/cs_source_tray.png")).pixmap(34, 34));
    appMark->setFixedSize(34, 34);

    auto *brandLayout = new QVBoxLayout;
    brandLayout->setSpacing(0);
    auto *appName = new QLabel(text(u8"FUCKPecfectWorld"), header);
    appName->setObjectName(QStringLiteral("appName"));
    auto *appTagline = new QLabel(text(u8"CS2 NETWORK CONTROL"), header);
    appTagline->setObjectName(QStringLiteral("appTagline"));
    brandLayout->addWidget(appName);
    brandLayout->addWidget(appTagline);

    modeStatus_ = new QLabel(text(u8"准备就绪"), header);
    modeStatus_->setProperty("role", QStringLiteral("status"));
    modeStatus_->setProperty("severity", QStringLiteral("ready"));
    modeStatus_->setAlignment(Qt::AlignCenter);

    auto *minimizeButton = new QPushButton(text(u8"最小化到托盘"), header);
    minimizeButton->setIcon(style()->standardIcon(QStyle::SP_TitleBarMinButton));
    minimizeButton->setToolTip(text(u8"隐藏窗口，保留系统托盘图标"));

    headerLayout->addWidget(appMark);
    headerLayout->addLayout(brandLayout);
    headerLayout->addStretch();
    headerLayout->addWidget(modeStatus_);
    headerLayout->addWidget(minimizeButton);

    auto *summarySurface = new QFrame(central);
    summarySurface->setObjectName(QStringLiteral("summarySurface"));
    auto *summaryLayout = new QHBoxLayout(summarySurface);
    summaryLayout->setContentsMargins(14, 11, 14, 11);
    auto *summaryTitle = new QLabel(text(u8"扫描状态"), summarySurface);
    summaryTitle->setProperty("role", QStringLiteral("sectionTitle"));
    summary_ = new QLabel(summarySurface);
    summary_->setObjectName(QStringLiteral("summary"));
    summaryLayout->addWidget(summaryTitle);
    summaryLayout->addSpacing(14);
    summaryLayout->addWidget(summary_);
    summaryLayout->addStretch();

    auto *tableSurface = new QFrame(central);
    tableSurface->setObjectName(QStringLiteral("tableSurface"));
    auto *tableLayout = new QVBoxLayout(tableSurface);
    tableLayout->setContentsMargins(0, 0, 0, 0);
    tableLayout->setSpacing(0);

    auto *tableToolbar = new QWidget(tableSurface);
    auto *toolbarLayout = new QHBoxLayout(tableToolbar);
    toolbarLayout->setContentsMargins(14, 10, 12, 10);
    toolbarLayout->setSpacing(8);
    auto *tableTitle = new QLabel(text(u8"相关进程"), tableToolbar);
    tableTitle->setProperty("role", QStringLiteral("sectionTitle"));

    auto *refreshButton = new QToolButton(tableToolbar);
    refreshButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    refreshButton->setToolTip(text(u8"重新扫描"));
    refreshButton->setAccessibleName(text(u8"重新扫描"));

    auto *launchButton = new QPushButton(text(u8"启动 CS2"), tableToolbar);
    launchButton->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    auto *enterButton = new QPushButton(text(u8"进入 CS2 模式"), tableToolbar);
    enterButton->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
    enterButton->setProperty("primary", true);
    enterButton->setDefault(true);

    toolbarLayout->addWidget(tableTitle);
    toolbarLayout->addWidget(refreshButton);
    toolbarLayout->addStretch();
    toolbarLayout->addWidget(launchButton);
    toolbarLayout->addWidget(enterButton);

    table_ = new QTableWidget(tableSurface);
    table_->setColumnCount(6);
    table_->setHorizontalHeaderLabels({text(u8"关闭"), text(u8"进程"), text(u8"PID"), text(u8"影响"), text(u8"原因"), text(u8"路径")});
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setShowGrid(false);
    table_->verticalHeader()->setVisible(false);
    table_->verticalHeader()->setDefaultSectionSize(40);
    table_->horizontalHeader()->setStretchLastSection(false);
    table_->horizontalHeader()->setSectionResizeMode(kCheckColumn, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(kNameColumn, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(kPidColumn, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(kImpactColumn, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(kReasonColumn, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(kPathColumn, QHeaderView::Stretch);

    tableLayout->addWidget(tableToolbar);
    tableLayout->addWidget(table_, 1);

    auto *activitySurface = new QFrame(central);
    activitySurface->setObjectName(QStringLiteral("activitySurface"));
    auto *activityLayout = new QVBoxLayout(activitySurface);
    activityLayout->setContentsMargins(0, 0, 0, 0);
    activityLayout->setSpacing(0);
    auto *activityHeader = new QWidget(activitySurface);
    auto *activityHeaderLayout = new QHBoxLayout(activityHeader);
    activityHeaderLayout->setContentsMargins(14, 10, 12, 4);
    auto *activityTitle = new QLabel(text(u8"活动"), activityHeader);
    activityTitle->setProperty("role", QStringLiteral("sectionTitle"));
    auto *restoreButton = new QPushButton(text(u8"恢复已关闭程序"), activityHeader);
    restoreButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    auto *logiButton = new QPushButton(text(u8"重启 Logi Options+"), activityHeader);
    logiButton->setIcon(style()->standardIcon(QStyle::SP_ComputerIcon));
    activityHeaderLayout->addWidget(activityTitle);
    activityHeaderLayout->addStretch();
    activityHeaderLayout->addWidget(restoreButton);
    activityHeaderLayout->addWidget(logiButton);

    logView_ = new QTextEdit(activitySurface);
    logView_->setReadOnly(true);
    logView_->setMinimumHeight(106);
    logView_->setMaximumHeight(142);
    logView_->setPlaceholderText(text(u8"等待操作"));
    activityLayout->addWidget(activityHeader);
    activityLayout->addWidget(logView_);

    layout->addWidget(header);
    layout->addWidget(summarySurface);
    layout->addWidget(tableSurface, 1);
    layout->addWidget(activitySurface);
    setCentralWidget(central);

    connect(minimizeButton, &QPushButton::clicked, this, [this] { hideToTray(); });
    connect(refreshButton, &QToolButton::clicked, this, [this] { refresh(); });
    connect(enterButton, &QPushButton::clicked, this, [this] { enterCsMode(); });
    connect(launchButton, &QPushButton::clicked, this, [this] { launchCs2(); });
    connect(restoreButton, &QPushButton::clicked, this, [this] { restorePrograms(); });
    connect(logiButton, &QPushButton::clicked, this, [this] { restartLogiOptions(); });
}

void MainWindow::configureTray()
{
    if (trayIcon_) {
        return;
    }

    trayIcon_ = new QSystemTrayIcon(QIcon(QStringLiteral(":/icons/cs_source.ico")), this);
    trayIcon_->setToolTip(text(u8"FUCKPecfectWorld"));
    trayMenu_ = new QMenu(this);
    showAction_ = trayMenu_->addAction(text(u8"显示主窗口"));
    auto *scanAction = trayMenu_->addAction(text(u8"重新扫描"));
    auto *csModeAction = trayMenu_->addAction(text(u8"进入 CS2 模式"));
    auto *logiAction = trayMenu_->addAction(text(u8"重启 Logi Options+"));
    trayMenu_->addSeparator();
    auto *quitAction = trayMenu_->addAction(text(u8"退出应用"));

    trayIcon_->setContextMenu(trayMenu_);
    showNativeTrayIcon();
    QTimer::singleShot(1500, this, [this] {
        showNativeTrayIcon();
    });

    connect(showAction_, &QAction::triggered, this, [this] { showFromTray(); });
    connect(scanAction, &QAction::triggered, this, [this] { showFromTray(); refresh(); });
    connect(csModeAction, &QAction::triggered, this, [this] { showFromTray(); enterCsMode(); });
    connect(logiAction, &QAction::triggered, this, [this] { restartLogiOptions(); });
    connect(quitAction, &QAction::triggered, this, [this] { requestExit(); });
    connect(trayIcon_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
            showFromTray();
        }
    });
}
void MainWindow::showFromTray()
{
    setWindowState(windowState() & ~Qt::WindowMinimized);
    show();
    raise();
    activateWindow();
}

void MainWindow::showNativeTrayIcon()
{
#ifdef Q_OS_WIN
    const HWND windowHandle = reinterpret_cast<HWND>(winId());
    if (!windowHandle) {
        return;
    }
    if (!nativeTrayIconHandle_) {
        nativeTrayIconHandle_ = LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1), IMAGE_ICON,
                                           16, 16, LR_DEFAULTCOLOR);
    }
    if (!nativeTrayIconHandle_) {
        return;
    }

    NOTIFYICONDATAW data = {};
    data.cbSize = sizeof(data);
    data.hWnd = windowHandle;
    data.uID = kNativeTrayIconId;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = kNativeTrayCallbackMessage;
    data.hIcon = static_cast<HICON>(nativeTrayIconHandle_);
    lstrcpynW(data.szTip, L"FUCKPecfectWorld", ARRAYSIZE(data.szTip));

    BOOL registered = Shell_NotifyIconW(nativeTrayIconVisible_ ? NIM_MODIFY : NIM_ADD, &data);
    if (!registered && nativeTrayIconVisible_) {
        registered = Shell_NotifyIconW(NIM_ADD, &data);
    }
    nativeTrayIconVisible_ = registered;
    if (registered) {
        data.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &data);
    }
#endif
}

void MainWindow::hideNativeTrayIcon()
{
#ifdef Q_OS_WIN
    if (nativeTrayIconVisible_) {
        NOTIFYICONDATAW data = {};
        data.cbSize = sizeof(data);
        data.hWnd = reinterpret_cast<HWND>(winId());
        data.uID = kNativeTrayIconId;
        Shell_NotifyIconW(NIM_DELETE, &data);
        nativeTrayIconVisible_ = false;
    }
    if (nativeTrayIconHandle_) {
        DestroyIcon(static_cast<HICON>(nativeTrayIconHandle_));
        nativeTrayIconHandle_ = nullptr;
    }
#endif
}

void MainWindow::applyNativeWindowIcon()
{
#ifdef Q_OS_WIN
    const HWND windowHandle = reinterpret_cast<HWND>(winId());
    const HINSTANCE module = GetModuleHandleW(nullptr);
    if (!windowHandle || !module) {
        return;
    }

    const HICON smallIcon = static_cast<HICON>(LoadImageW(module, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                                            16, 16, LR_DEFAULTCOLOR));
    const HICON largeIcon = static_cast<HICON>(LoadImageW(module, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                                            32, 32, LR_DEFAULTCOLOR));
    if (smallIcon) {
        SendMessageW(windowHandle, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
    }
    if (largeIcon) {
        SendMessageW(windowHandle, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(largeIcon));
    }

    const BOOL useDarkTitleBar = TRUE;
    const COLORREF captionColor = RGB(21, 21, 24);
    const COLORREF captionTextColor = RGB(245, 245, 247);
    DwmSetWindowAttribute(windowHandle, 20, &useDarkTitleBar, sizeof(useDarkTitleBar));
    DwmSetWindowAttribute(windowHandle, 35, &captionColor, sizeof(captionColor));
    DwmSetWindowAttribute(windowHandle, 36, &captionTextColor, sizeof(captionTextColor));
#endif
}

void MainWindow::hideToTray()
{
    if (!trayIcon_) {
        showMinimized();
        return;
    }

    showNativeTrayIcon();
    if (!nativeTrayIconVisible_) {
        showMinimized();
        return;
    }

    hidingToTray_ = true;
    hide();
    hidingToTray_ = false;
    if (!trayTipShown_) {
        trayIcon_->showMessage(text(u8"FUCKPecfectWorld"), text(u8"应用仍在后台运行；图标可能位于任务栏右侧的上箭头内。"),
                                QSystemTrayIcon::Information, 2600);
        trayTipShown_ = true;
    }
}

void MainWindow::requestExit()
{
    close();
}

bool MainWindow::exitConfirmationDisabled() const
{
    QSettings settings;
    return settings.value(QStringLiteral("ui/skipExitConfirmation"), false).toBool();
}

void MainWindow::setExitConfirmationDisabled(bool disabled)
{
    QSettings settings;
    settings.setValue(QStringLiteral("ui/skipExitConfirmation"), disabled);
}

bool MainWindow::showExitChoice()
{
    QMessageBox dialog(this);
    dialog.setIcon(QMessageBox::Question);
    dialog.setWindowTitle(text(u8"关闭 FUCKPecfectWorld"));
    dialog.setText(text(u8"要退出应用，还是保留在系统托盘中？"));
    dialog.setInformativeText(text(u8"最小化后仍可在托盘菜单中恢复或退出。"));

    auto *dontAskAgain = new QCheckBox(text(u8"下次不再提醒，直接退出"), &dialog);
    dialog.setCheckBox(dontAskAgain);
    QPushButton *minimizeButton = nullptr;
    if (trayIcon_) {
        minimizeButton = dialog.addButton(text(u8"最小化到托盘"), QMessageBox::ActionRole);
    }
    auto *exitButton = dialog.addButton(text(u8"退出应用"), QMessageBox::DestructiveRole);
    auto *cancelButton = dialog.addButton(QMessageBox::Cancel);
    dialog.setDefaultButton(minimizeButton ? minimizeButton : exitButton);
    dialog.exec();

    if (dialog.clickedButton() == exitButton) {
        setExitConfirmationDisabled(dontAskAgain->isChecked());
        return true;
    }
    if (minimizeButton && dialog.clickedButton() == minimizeButton) {
        hideToTray();
    }
    Q_UNUSED(cancelButton)
    return false;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (!forceQuit_ && !exitConfirmationDisabled()) {
        if (!showExitChoice()) {
            event->ignore();
            return;
        }
    }

    forceQuit_ = true;
    if (trayIcon_) {
        trayIcon_->hide();
    }
    hideNativeTrayIcon();
    event->accept();
    QTimer::singleShot(0, qApp, &QCoreApplication::quit);
}

bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, long *result)
{
#ifdef Q_OS_WIN
    if (eventType == QByteArrayLiteral("windows_generic_MSG")) {
        MSG *nativeMessage = static_cast<MSG *>(message);
        if (nativeMessage->message == kNativeTrayCallbackMessage) {
            const UINT event = LOWORD(nativeMessage->lParam);
            if (event == WM_CONTEXTMENU) {
                trayMenu_->popup(QCursor::pos());
            } else if (event == WM_LBUTTONUP || event == WM_LBUTTONDBLCLK || event == NIN_SELECT || event == NIN_KEYSELECT) {
                showFromTray();
            }
            *result = 0;
            return true;
        }
    }
#else
    Q_UNUSED(eventType)
    Q_UNUSED(message)
    Q_UNUSED(result)
#endif
    return QMainWindow::nativeEvent(eventType, message, result);
}

void MainWindow::changeEvent(QEvent *event)
{
    QMainWindow::changeEvent(event);
    if (event->type() != QEvent::WindowStateChange || hidingToTray_ || !isMinimized()) {
        return;
    }

    QTimer::singleShot(0, this, [this] {
        if (isMinimized()) {
            hideToTray();
        }
    });
}

ProcessEntry MainWindow::classify(const QString &name, quint32 pid, const QString &path) const
{
    const QString normalized = name.toLower();
    for (const ConfiguredRule &rule : configuredRules()) {
        if (normalized == rule.executable) {
            return {name, pid, path, rule.impact, rule.level, rule.reason, rule.defaultChecked,
                    rule.stoppable, false, {}, {}};
        }
    }
    for (const Rule &rule : kRules) {
        if (normalized == QLatin1String(rule.executable)) {
            return {name, pid, path, rule.impact, text(rule.level), text(rule.reason), rule.defaultChecked,
                    true, false, {}, {}};
        }
    }
    return {name, pid, path, 0, {}, {}, false, true, false, {}, {}};
}

QVector<ProcessEntry> MainWindow::scanRelevantProcesses() const
{
    QVector<ProcessEntry> result;
#ifdef Q_OS_WIN
    for (const ManagedServiceRule &rule : managedServiceRules()) {
        bool serviceRunning = false;
        const quint32 servicePid = queryServiceProcessId(rule.serviceName, &serviceRunning);
        if (!serviceRunning) {
            continue;
        }

        ProcessEntry serviceEntry;
        serviceEntry.name = rule.displayName;
        serviceEntry.pid = servicePid;
        serviceEntry.path = queryProcessPath(servicePid);
        serviceEntry.impact = rule.impact;
        serviceEntry.level = text(u8"高");
        serviceEntry.reason = rule.reason;
        serviceEntry.defaultChecked = rule.defaultChecked;
        if (rule.serviceName == QStringLiteral("eaio_service")) {
            serviceEntry.reason = text(u8"EAIO 服务不接受 Windows 停止控制，无法由本工具安全关闭");
            serviceEntry.defaultChecked = false;
        }
        serviceEntry.managedService = true;
        serviceEntry.serviceName = rule.serviceName;
        serviceEntry.scheduledTasks = rule.scheduledTasks;
        result.push_back(serviceEntry);
    }

    const DWORD ownPid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return result;
    }

    PROCESSENTRY32W item = {};
    item.dwSize = sizeof(item);
    if (Process32FirstW(snapshot, &item)) {
        do {
            if (item.th32ProcessID == ownPid || item.th32ProcessID == 0) {
                continue;
            }
            const QString name = QString::fromWCharArray(item.szExeFile);
            if (isManagedServiceWorker(name)) {
                continue;
            }
            ProcessEntry entry = classify(name, item.th32ProcessID, queryProcessPath(item.th32ProcessID));
            if (entry.impact > 0) {
                result.push_back(entry);
            }
        } while (Process32NextW(snapshot, &item));
    }
    CloseHandle(snapshot);
#endif

    std::sort(result.begin(), result.end(), [](const ProcessEntry &left, const ProcessEntry &right) {
        return left.impact == right.impact
            ? left.name.compare(right.name, Qt::CaseInsensitive) < 0
            : left.impact > right.impact;
    });
    return result;
}

QString MainWindow::queryProcessPath(quint32 pid) const
{
#ifdef Q_OS_WIN
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return {};
    }

    wchar_t buffer[32768] = {};
    DWORD length = sizeof(buffer) / sizeof(buffer[0]);
    const BOOL ok = QueryFullProcessImageNameW(process, 0, buffer, &length);
    CloseHandle(process);
    if (ok) {
        return QString::fromWCharArray(buffer, static_cast<int>(length));
    }
#else
    Q_UNUSED(pid)
#endif
    return {};
}
quint32 MainWindow::queryServiceProcessId(const QString &serviceName, bool *running) const
{
    if (running) {
        *running = false;
    }
#ifdef Q_OS_WIN
    const std::wstring nativeName = serviceName.toStdWString();
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        return 0;
    }
    SC_HANDLE service = OpenServiceW(manager, nativeName.c_str(), SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(manager);
        return 0;
    }

    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    const BOOL success = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                              reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!success) {
        return 0;
    }
    if (running) {
        *running = status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING;
    }
    return status.dwProcessId;
#else
    Q_UNUSED(serviceName)
    return 0;
#endif
}

bool MainWindow::stopWindowsService(const QString &serviceName, QString *error) const
{
#ifdef Q_OS_WIN
    const std::wstring nativeName = serviceName.toStdWString();
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        *error = text(u8"无法连接服务控制管理器，Windows 错误 %1").arg(GetLastError());
        return false;
    }
    SC_HANDLE service = OpenServiceW(manager, nativeName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        *error = text(u8"无法打开服务，Windows 错误 %1").arg(GetLastError());
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded);
    if (status.dwCurrentState == SERVICE_STOPPED) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return true;
    }

    SERVICE_STATUS controlStatus = {};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &controlStatus) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        *error = text(u8"停止服务失败，Windows 错误 %1").arg(GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return false;
    }

    for (int attempt = 0; attempt < 30; ++attempt) {
        Sleep(200);
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)
            && status.dwCurrentState == SERVICE_STOPPED) {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return true;
        }
    }
    *error = text(u8"等待服务停止超时");
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return false;
#else
    Q_UNUSED(serviceName)
    *error = text(u8"当前仅支持 Windows");
    return false;
#endif
}

bool MainWindow::startWindowsService(const QString &serviceName, QString *error) const
{
#ifdef Q_OS_WIN
    const std::wstring nativeName = serviceName.toStdWString();
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        *error = text(u8"无法连接服务控制管理器，Windows 错误 %1").arg(GetLastError());
        return false;
    }
    SC_HANDLE service = OpenServiceW(manager, nativeName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        *error = text(u8"无法打开服务，Windows 错误 %1").arg(GetLastError());
        CloseServiceHandle(manager);
        return false;
    }
    const BOOL started = StartServiceW(service, 0, nullptr);
    const DWORD lastError = started ? ERROR_SUCCESS : GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!started && lastError != ERROR_SERVICE_ALREADY_RUNNING) {
        *error = text(u8"启动服务失败，Windows 错误 %1").arg(lastError);
        return false;
    }
    return true;
#else
    Q_UNUSED(serviceName)
    *error = text(u8"当前仅支持 Windows");
    return false;
#endif
}

bool MainWindow::setWindowsServiceAutoStart(const QString &serviceName, bool enabled, QString *error) const
{
    QProcess process;
    process.start(QStringLiteral("sc.exe"), {
        QStringLiteral("config"), serviceName, QStringLiteral("start="),
        enabled ? QStringLiteral("auto") : QStringLiteral("demand")
    });
    if (!process.waitForStarted(2000) || !process.waitForFinished(5000)) {
        *error = text(u8"无法修改服务启动方式");
        return false;
    }
    if (process.exitCode() != 0) {
        const QString details = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        *error = details.isEmpty() ? text(u8"修改服务启动方式失败") : details;
        return false;
    }
    return true;
}

bool MainWindow::setScheduledTaskEnabled(const QString &taskName, bool enabled, QString *error) const
{
    QProcess process;
    const QStringList arguments = {
        QStringLiteral("/Change"), QStringLiteral("/TN"), taskName,
        enabled ? QStringLiteral("/Enable") : QStringLiteral("/Disable")
    };
    process.start(QStringLiteral("schtasks.exe"), arguments);
    if (!process.waitForStarted(2000) || !process.waitForFinished(5000)) {
        *error = text(u8"无法调用任务计划程序");
        return false;
    }
    if (process.exitCode() != 0) {
        const QString details = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        *error = details.isEmpty() ? text(u8"修改计划任务失败") : details;
        return false;
    }
    return true;
}

bool MainWindow::setEaioFailureActions(bool enabled, QString *error) const
{
    QProcess process;
    const QStringList arguments = {
        QStringLiteral("failure"), QStringLiteral("eaio_service"),
        QStringLiteral("reset="), enabled ? QStringLiteral("86400") : QStringLiteral("0"),
        QStringLiteral("actions="), enabled
            ? QStringLiteral("restart/3000/restart/3000/restart/3000")
            : QString()
    };
    process.start(QStringLiteral("sc.exe"), arguments);
    if (!process.waitForStarted(2000) || !process.waitForFinished(5000)) {
        *error = text(u8"无法修改 EAIO 服务失败重启策略");
        return false;
    }
    if (process.exitCode() != 0) {
        const QString details = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        *error = details.isEmpty() ? text(u8"修改 EAIO 失败重启策略失败") : details;
        return false;
    }
    return true;
}
bool MainWindow::quiesceManagedService(const ProcessEntry &entry, QString *error)
{
    if (entry.serviceName == QStringLiteral("eaio_service")) {
        *error = text(u8"EAIO 服务被 Windows 标记为 NOT_STOPPABLE，已跳过；不会强制结束受保护服务进程");
        return false;
    }

    for (const ManagedServiceState &state : stoppedServices_) {
        if (state.serviceName == entry.serviceName) {
            return true;
        }
    }

    ManagedServiceState state;
    state.serviceName = entry.serviceName;
    state.wasRunning = true;
    for (const QString &taskName : entry.scheduledTasks) {
        QString taskError;
        if (setScheduledTaskEnabled(taskName, false, &taskError)) {
            state.disabledTasks.push_back(taskName);
        } else {
            for (const QString &disabledTask : state.disabledTasks) {
                QString ignoredError;
                setScheduledTaskEnabled(disabledTask, true, &ignoredError);
            }
            *error = text(u8"无法暂停启动任务 %1：%2").arg(taskName, taskError);
            return false;
        }
    }

    QString serviceError;
    if (entry.serviceName == QStringLiteral("eaio_service")) {
        if (!setEaioFailureActions(false, &serviceError)) {
            for (const QString &disabledTask : state.disabledTasks) {
                QString ignoredError;
                setScheduledTaskEnabled(disabledTask, true, &ignoredError);
            }
            *error = serviceError;
            return false;
        }
        state.eaioRecoverySuppressed = true;

        if (!setWindowsServiceAutoStart(entry.serviceName, false, &serviceError)) {
            QString ignoredError;
            setEaioFailureActions(true, &ignoredError);
            for (const QString &disabledTask : state.disabledTasks) {
                setScheduledTaskEnabled(disabledTask, true, &ignoredError);
            }
            *error = serviceError;
            return false;
        }
        state.eaioStartDisabled = true;

        if (!stopWindowsService(entry.serviceName, &serviceError)) {
            QString ignoredError;
            setWindowsServiceAutoStart(entry.serviceName, true, &ignoredError);
            setEaioFailureActions(true, &ignoredError);
            for (const QString &disabledTask : state.disabledTasks) {
                setScheduledTaskEnabled(disabledTask, true, &ignoredError);
            }
            *error = serviceError;
            return false;
        }
    } else if (!stopWindowsService(entry.serviceName, &serviceError)) {
        for (const QString &disabledTask : state.disabledTasks) {
            QString ignoredError;
            setScheduledTaskEnabled(disabledTask, true, &ignoredError);
        }
        *error = serviceError;
        return false;
    }

    stoppedServices_.push_back(state);
    return true;
}

bool MainWindow::stopProcess(quint32 pid, QString *error) const
{
#ifdef Q_OS_WIN
    HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (!process) {
        *error = text(u8"无法打开进程，Windows 错误 %1").arg(GetLastError());
        return false;
    }

    const BOOL stopped = TerminateProcess(process, 0);
    const DWORD lastError = stopped ? ERROR_SUCCESS : GetLastError();
    if (stopped) {
        WaitForSingleObject(process, 3000);
    }
    CloseHandle(process);
    if (!stopped) {
        *error = text(u8"终止失败，Windows 错误 %1").arg(lastError);
    }
    return stopped;
#else
    Q_UNUSED(pid)
    *error = text(u8"当前仅支持 Windows");
    return false;
#endif
}

void MainWindow::refresh()
{
    const QVector<ProcessEntry> entries = scanRelevantProcesses();
    table_->setRowCount(entries.size());
    int highCount = 0;

    for (int row = 0; row < entries.size(); ++row) {
        const ProcessEntry &entry = entries.at(row);
        highCount += entry.impact == 3 ? 1 : 0;

        auto *checkbox = new QCheckBox(table_);
        checkbox->setChecked(entry.defaultChecked);
        checkbox->setToolTip(text(u8"勾选后在进入 CS2 模式时关闭"));
        if (!entry.stoppable) {
            checkbox->setEnabled(false);
            checkbox->setToolTip(text(u8"此项仅提示，不会由本工具关闭"));
        }
        auto *checkCell = new QWidget(table_);
        auto *checkLayout = new QHBoxLayout(checkCell);
        checkLayout->setContentsMargins(0, 0, 0, 0);
        checkLayout->setAlignment(Qt::AlignCenter);
        checkLayout->addWidget(checkbox);
        table_->setCellWidget(row, kCheckColumn, checkCell);

        auto *name = new QTableWidgetItem(entry.name);
        name->setData(Qt::UserRole, entry.pid);
        name->setData(Qt::UserRole + 1, entry.path);
        name->setData(Qt::UserRole + 2, entry.managedService);
        name->setData(Qt::UserRole + 3, entry.serviceName);
        name->setData(Qt::UserRole + 4, entry.scheduledTasks);
        name->setData(Qt::UserRole + 5, entry.stoppable);
        auto *pid = new QTableWidgetItem(QString::number(entry.pid));
        auto *impact = new QTableWidgetItem(entry.level);
        auto *reason = new QTableWidgetItem(entry.reason);
        auto *path = new QTableWidgetItem(entry.path);

        const QColor foreground = entry.impact == 3 ? QColor(255, 164, 165)
                               : entry.impact == 2 ? QColor(248, 190, 104)
                                                     : QColor(174, 202, 230);
        impact->setForeground(foreground);
        impact->setTextAlignment(Qt::AlignCenter);

        table_->setItem(row, kNameColumn, name);
        table_->setItem(row, kPidColumn, pid);
        table_->setItem(row, kImpactColumn, impact);
        table_->setItem(row, kReasonColumn, reason);
        table_->setItem(row, kPathColumn, path);
    }

    summary_->setText(text(u8"发现 %1 个相关进程，其中高影响 %2 个。仅关闭已勾选项目。")
                      .arg(entries.size()).arg(highCount));
    modeStatus_->setText(highCount > 0 ? text(u8"需要处理") : text(u8"准备就绪"));
    modeStatus_->setProperty("severity", highCount > 0 ? QStringLiteral("warning") : QStringLiteral("ready"));
    modeStatus_->style()->unpolish(modeStatus_);
    modeStatus_->style()->polish(modeStatus_);
    log(text(u8"扫描完成：%1 个相关进程").arg(entries.size()));
}

void MainWindow::enterCsMode()
{
    QVector<ProcessEntry> selected;
    for (int row = 0; row < table_->rowCount(); ++row) {
        auto *checkCell = table_->cellWidget(row, kCheckColumn);
        auto *checkbox = checkCell ? checkCell->findChild<QCheckBox *>() : nullptr;
        auto *name = table_->item(row, kNameColumn);
        if (checkbox && checkbox->isChecked() && name) {
            ProcessEntry selectedEntry;
            selectedEntry.name = name->text();
            selectedEntry.pid = name->data(Qt::UserRole).toUInt();
            selectedEntry.path = name->data(Qt::UserRole + 1).toString();
            selectedEntry.managedService = name->data(Qt::UserRole + 2).toBool();
            selectedEntry.serviceName = name->data(Qt::UserRole + 3).toString();
            selectedEntry.scheduledTasks = name->data(Qt::UserRole + 4).toStringList();
            selectedEntry.stoppable = name->data(Qt::UserRole + 5).toBool();
            selected.push_back(selectedEntry);
        }
    }

    if (selected.isEmpty()) {
        QMessageBox::information(this, text(u8"没有选择"), text(u8"当前没有勾选需要关闭的进程。"));
        return;
    }

    QStringList names;
    for (const ProcessEntry &entry : selected) {
        names << QStringLiteral("%1  (PID %2)").arg(entry.name).arg(entry.pid);
    }
    if (QMessageBox::question(this, text(u8"确认进入 CS2 模式"),
                              text(u8"将立即关闭以下进程：\n\n%1\n\n不会卸载软件。是否继续？")
                              .arg(names.join(QLatin1Char('\n'))),
                              QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    int stopped = 0;
    for (const ProcessEntry &entry : selected) {
        QString error;
        if (!entry.stoppable) {
            log(text(u8"跳过 %1：该项只用于提示，不会自动关闭").arg(entry.name));
            continue;
        }
        if (entry.managedService) {
            if (quiesceManagedService(entry, &error)) {
                ++stopped;
                log(text(u8"已停止服务 %1，并暂停关联启动任务").arg(entry.serviceName));
            } else {
                log(text(u8"停止服务 %1 失败：%2").arg(entry.serviceName, error));
            }
        } else if (stopProcess(entry.pid, &error)) {
            closedPrograms_.push_back(entry);
            ++stopped;
            log(text(u8"已关闭 %1  (PID %2)").arg(entry.name).arg(entry.pid));
        } else {
            log(text(u8"关闭 %1 失败：%2").arg(entry.name, error));
        }
    }
    log(text(u8"CS2 模式完成：成功关闭 %1/%2 个进程").arg(stopped).arg(selected.size()));
    refresh();
}

void MainWindow::restorePrograms()
{
    int restoredServices = 0;
    for (const ManagedServiceState &state : stoppedServices_) {
        QString serviceError;
        if (state.eaioStartDisabled && !setWindowsServiceAutoStart(state.serviceName, true, &serviceError)) {
            log(text(u8"恢复 EAIO 自动启动失败：%1").arg(serviceError));
        }
        if (state.eaioRecoverySuppressed && !setEaioFailureActions(true, &serviceError)) {
            log(text(u8"恢复 EAIO 失败重启策略失败：%1").arg(serviceError));
        }
        if (state.wasRunning && startWindowsService(state.serviceName, &serviceError)) {
            ++restoredServices;
            log(text(u8"已启动服务 %1").arg(state.serviceName));
        } else if (state.wasRunning) {
            log(text(u8"启动服务 %1 失败：%2").arg(state.serviceName, serviceError));
        }
        for (const QString &taskName : state.disabledTasks) {
            QString taskError;
            if (setScheduledTaskEnabled(taskName, true, &taskError)) {
                log(text(u8"已恢复启动任务 %1").arg(taskName));
            } else {
                log(text(u8"恢复启动任务 %1 失败：%2").arg(taskName, taskError));
            }
        }
    }
    stoppedServices_.clear();

    QSet<QString> launched;
    int restoredPrograms = 0;
    for (const ProcessEntry &entry : closedPrograms_) {
        if (entry.path.isEmpty() || launched.contains(entry.path) || !QFileInfo::exists(entry.path)) {
            continue;
        }
        if (QProcess::startDetached(entry.path, {})) {
            launched.insert(entry.path);
            ++restoredPrograms;
            log(text(u8"已恢复 %1").arg(entry.path));
        }
    }
    closedPrograms_.clear();

    if (restoredServices == 0 && restoredPrograms == 0) {
        QMessageBox::information(this, text(u8"没有记录"), text(u8"本次运行没有已关闭且可恢复的程序或服务。"));
        return;
    }
    log(text(u8"恢复完成：启动 %1 个服务，启动 %2 个程序").arg(restoredServices).arg(restoredPrograms));
}

void MainWindow::restartLogiOptions()
{
    QVector<ProcessEntry> logi;
#ifdef Q_OS_WIN
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W item = {};
        item.dwSize = sizeof(item);
        if (Process32FirstW(snapshot, &item)) {
            do {
                const QString name = QString::fromWCharArray(item.szExeFile);
                if (name.contains(QStringLiteral("logioptionsplus"), Qt::CaseInsensitive)) {
                    logi.push_back({name, item.th32ProcessID, queryProcessPath(item.th32ProcessID), 0, {}, {}, false, true, false, {}, {}});
                }
            } while (Process32NextW(snapshot, &item));
        }
        CloseHandle(snapshot);
    }
#endif

    for (const ProcessEntry &entry : logi) {
        QString error;
        if (stopProcess(entry.pid, &error)) {
            log(text(u8"已停止 %1").arg(entry.name));
        } else {
            log(text(u8"停止 %1 失败：%2").arg(entry.name, error));
        }
    }

    const QString programFiles = qEnvironmentVariable("ProgramFiles");
    const QString localAppData = qEnvironmentVariable("LOCALAPPDATA");
    const QStringList candidates = {
        QDir(programFiles).filePath(QStringLiteral("LogiOptionsPlus/logioptionsplus_agent.exe")),
        QDir(programFiles).filePath(QStringLiteral("LogiOptionsPlus/logioptionsplus.exe")),
        QDir(localAppData).filePath(QStringLiteral("Programs/LogiOptionsPlus/logioptionsplus_agent.exe")),
        QDir(localAppData).filePath(QStringLiteral("Programs/LogiOptionsPlus/logioptionsplus.exe"))
    };
    for (const QString &path : candidates) {
        if (QFileInfo::exists(path) && QProcess::startDetached(path, {})) {
            log(text(u8"已启动 Logi Options+：%1").arg(path));
            return;
        }
    }

    QMessageBox::warning(this, text(u8"未找到 Logi Options+"),
                         text(u8"已停止相关进程，但没有在常见安装目录找到启动程序。请确认安装路径。"));
    log(text(u8"未找到 Logi Options+ 启动程序"));
}

void MainWindow::launchCs2()
{
    if (QDesktopServices::openUrl(QUrl(QStringLiteral("steam://rungameid/730")))) {
        log(text(u8"已请求 Steam 启动 CS2"));
    } else {
        QMessageBox::warning(this, text(u8"启动失败"), text(u8"无法调用 Steam。请确认 Steam 已正确安装。"));
    }
}

void MainWindow::log(const QString &message)
{
    logView_->append(QStringLiteral("[%1] %2")
                     .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")), message));
}
