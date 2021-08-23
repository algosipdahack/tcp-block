nfqnl_test : function.o nfqnl_test.o
	gcc -o nfqnl_test nfqnl_test.o function.o -lpcap
nfqnl_test.o : header.h main.cpp bm.h bm.cpp
	gcc -c -o nfqnl_test.o main.cpp bm.cpp
function.o : function.cpp header.h bm.h bm.cpp
	gcc -c -o function.o function.cpp bm.cpp
