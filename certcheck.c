/* * * * * * * * *
 * A TLS Certificate checking
 *
 * Command line arguments: path to test file
 *
 * created for COMP30023 Computer Systems - Assignment 2, 2018
 * by Wenqing Xue <wenqingx@student.unimelb.edu.au>
 * Login ID: wenqingx
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define SIZE 256
#define READ "r"
#define WRITE "w"
#define SLASH '/'
#define OUTPUT "output.csv"
#define FORMAT "%s,%s,%d\n"

char *get_path(int argc, char **argv);
void *open_file(char *path, char *type);

int main(int argc, char **argv) {

    // get the file path
    char *path = get_path(argc, argv);
    // open the file
    FILE *fin = open_file(path, READ);
    // get the directory path

    FILE *fout = open_file(path, WRITE);

    // read each line and validate
    char buf[SIZE], cert[SIZE], url[SIZE];
    while(fgets(buf, SIZE, fin) != NULL) {
        // get the certificate and url
        buf[strlen(buf)-1] = '\0';
        sscanf(buf, "%[^,],%[^,]", cert, url);

        printf("cert: %s \t| url: %s\n", cert, url);
        // write into the file
        fprintf(fout, FORMAT, cert, url, 0);

    }
    // close the file
    fclose(fin);
    fclose(fout);
    return 0;
}

// get the file path from input
char *get_path(int argc, char **argv) {
    char *path;
    if (argc == 2) {
        path = argv[1];
    } else {
        fprintf(stderr, "usage: ./certcheck pathToTestFile\n");
        exit(1);
    }
    return path;
}

// open the file by type from file path
void *open_file(char *path, char *type) {
    FILE *f;
    if (strcmp(type, WRITE) == 0) {
        // write mode
        char new_path[SIZE];
        int index = strlen(path) - strlen(strrchr(path, SLASH));
        strncpy(new_path, path, ++index);
        strcat(new_path, OUTPUT);
        // output csv file
        f = fopen(new_path, type);
    } else {
        // read mode
        f = fopen(path, type);
    }
    if (f == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }
    return f;
}
