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

// string size
#define SIZE 256
// read mode
#define READ "r"
// write mode
#define WRITE "w"
// star character
#define STAR '*'
// slash character
#define SLASH '/'
// valid value
#define VALID 1
// invalid value
#define INVALID 0
// output file name
#define OUTPUT "output.csv"
// output data format
#define FORMAT "%s,%s,%d\n"

/******************************* HELP FUNCTION *******************************/
int validation(char *file, char *url);
int check_common_name(X509 *cert, char *url);
int check_validate_time(X509 *cert);
int compare_time(ASN1_TIME *from, ASN1_TIME *to);
char *get_path(int argc, char **argv);
void *open_file(char *path, char *type);
void remove_char(char *str, int index);
/****************************************************************************/

int main(int argc, char **argv) {
    // get the file path
    char *path = get_path(argc, argv);
    // open the input file
    FILE *fin = open_file(path, READ);
    // get the directory path
    char directory[SIZE];
    int index = strlen(path) - strlen(strrchr(path, SLASH));
    strncpy(directory, path, ++index);
    // open the output file
    FILE *fout = open_file(directory, WRITE);
    // read and validate each line in file
    char buf[SIZE], file[SIZE], url[SIZE];
    while(fgets(buf, SIZE, fin) != NULL) {
        // get the certificate file and url
        buf[strlen(buf)-1] = '\0';
        sscanf(buf, "%[^,],%[^,]", file, url);
        // directory path + file
        char file_path[SIZE];
        strcpy(file_path, directory);
        strcat(file_path, file);

        printf("cert: %s \t| url: %s\n", file_path, url);
        // check the validation
        int result = validation(file_path, url);
        // write into the file
        fprintf(fout, FORMAT, file, url, result);
        printf("\n");
    }
    // close the files
    fclose(fin);
    fclose(fout);
    return 0;
}

// process the validation by required
int validation(char *file, char *url) {
    X509 *cert = NULL;
    BIO *certificate_bio = NULL;
    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    // Create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());
    // Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, file))) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }
    /************************************************************************/
    // validates the domain in common name
    if (!check_common_name(cert, url)) return INVALID;
    // validates the not before, not after time
    if (!check_validate_time(cert)) return INVALID;

    /************************************************************************/
    X509_free(cert);
    BIO_free_all(certificate_bio);

    return VALID;
}

// check the common name with domain name
int check_common_name(X509 *cert, char *url) {
    // get the subject common name
    X509_NAME *cert_subject = X509_get_subject_name(cert);
    char subject_cn[SIZE] = "Subject CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_subject, NID_commonName, subject_cn, SIZE);
    // validates with domain name
    if (strchr(subject_cn, STAR)) {
        int index = strlen(subject_cn) - strlen(strrchr(subject_cn, STAR));
        remove_char(subject_cn, index);
        // url does not contain subject name
        if (!strstr(url, subject_cn)) return INVALID;
    } else {
        // url and subject common name is different
        if (strcmp(subject_cn, url) != 0) return INVALID;
    }
    return VALID;
}

// check the validation time
int check_validate_time(X509 *cert) {
    // get the not valid before and after time
    ASN1_TIME *nb_time = X509_get_notBefore(cert);
    ASN1_TIME *na_time = X509_get_notAfter(cert);
    // check not before and not after time are valid
    // if (!compare_time(nb_time, NULL) || !compare_time(NULL, na_time)) {
    //     return INVALID;
    // }
    // return VALID;
    return compare_time(nb_time, NULL) && compare_time(NULL, na_time);
}

// compare the two given time structure
int compare_time(ASN1_TIME *from, ASN1_TIME *to) {
    int day, sec;
    if (ASN1_TIME_diff(&day, &sec, from, to)) {
        // positive value - from <= to
        if (day >= 0 || sec >= 0) return VALID;
    }
    return INVALID;
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
        // write mode - open required output csv file
        char n_path[SIZE];
        strcpy(n_path, path);
        strcat(n_path, OUTPUT);
        f = fopen(n_path, type);
    } else {
        // read mode - open sample input csv file
        f = fopen(path, type);
    }
    if (f == NULL) {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }
    return f;
}

// remove the specific character by index
void remove_char(char *str, int index) {
    char *src;
    for (src = str + index; *src != '\0'; *src = *(src + 1), ++src);
    *src = '\0';
}
