all: main.o
	g++ -o main main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm *.o main
