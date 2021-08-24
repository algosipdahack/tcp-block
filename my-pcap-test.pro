TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnetfilter_queue
SOURCES += \
        bm.cpp \
        mac.cpp \
        main.cpp \
        packet.cpp \
        prepare.cpp

HEADERS += \
    bm.h \
    header.h \
    mac.h


