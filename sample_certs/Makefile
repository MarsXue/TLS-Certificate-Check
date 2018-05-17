# certcheck: certcheck.c
# 	gcc -o certcheck certcheck.c -lssl -lcrypto -I /usr/local/opt/openssl/include -L /usr/local/opt/openssl/lib

##Adapted from http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
CC = gcc
CFLAGS = -lssl -lcrypto
OBJ = certcheck.c
EXE = certcheck

##Create executable linked file from object files.
$(EXE): $(OBJ)
	gcc -Wall -o $@ $^ $(CFLAGS)

##Delete object files
clean:
	/bin/rm $(EXE)
