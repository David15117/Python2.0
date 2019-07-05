
all: fscan

fscan: *.cpp *.h
	g++ -g -lssl -pthread -I./ fscan.cpp sockets.cpp webforms.cpp config.cpp BasicAuth.cpp base64.cpp md5.cpp -o ../.fscan

clean:
	rm -f ../.fscan
