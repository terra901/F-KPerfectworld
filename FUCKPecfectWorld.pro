QT += widgets network

TEMPLATE = app
TARGET = FUCKPecfectWorld
CONFIG += c++17
QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8

SOURCES += \
    src/main.cpp \
    src/mainwindow.cpp

HEADERS += \
    src/mainwindow.h

RESOURCES += \
    resources/resources.qrc

win32 {
    LIBS += -ladvapi32 -lshell32 -ldwmapi
    RC_FILE = resources/app.rc
}

DESTDIR = bin
OBJECTS_DIR = build/obj
MOC_DIR = build/moc
RCC_DIR = build/rcc
UI_DIR = build/ui
