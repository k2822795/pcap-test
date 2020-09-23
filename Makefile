all: main.o
	g++ -o main main.o -lpcap

main.o: main.cpp
	sudo apt-get install libnet1-dev
	g++ -c -o main.o main.cpp

clean:
	rm *.o main
