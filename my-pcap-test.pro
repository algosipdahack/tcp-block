TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnetfilter_queue
SOURCES += \
        bm.cpp \
        function.cpp \
        main.cpp

HEADERS += \
    bm.h \
    header.h


