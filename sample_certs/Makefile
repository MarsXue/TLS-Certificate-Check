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
