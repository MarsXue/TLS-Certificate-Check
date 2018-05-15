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
// slash character
#define SLASH '/'
// output file name
#define OUTPUT "output.csv"
// output data format
#define FORMAT "%s,%s,%d\n"

/******************************* HELP FUNCTION *******************************/
void validation(char *file, char *url);
char *get_path(int argc, char **argv);
void *open_file(char *path, char *type);
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
    // read each line and validate
    char buf[SIZE], file[SIZE], url[SIZE];
    while(fgets(buf, SIZE, fin) != NULL) {
        // get the certificate file and url
        buf[strlen(buf)-1] = '\0';
        sscanf(buf, "%[^,],%[^,]", file, url);

        char file_path[SIZE];
        strcpy(file_path, directory);
        strcat(file_path, file);

        printf("cert: %s \t| url: %s\n", file_path, url);
        // check the validation
        validation(file_path, url);
        printf("\n");
        // write into the file
        fprintf(fout, FORMAT, file, url, 0);
    }

    time_t t = time(NULL);
    printf("Current time: %ld\n", (long)t);
    struct tm *gmt = gmtime(&t);
    printf("GMT is: %s", asctime(gmt));

    ASN1_TIME *now_asn1time = ASN1_TIME_new();
    ASN1_TIME_set(now_asn1time, time(NULL));

    BIO *bio = NULL;
    bio = BIO_new(BIO_s_file());
    bio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio, "Set ASN1 date & time from time(): ");
    if (!ASN1_TIME_print(bio, now_asn1time)) {
        BIO_printf(bio, "Error printing ASN1 time\n");
    } else {
        BIO_printf(bio, "\n");
    }

    ASN1_TIME_free(now_asn1time);
    BIO_free_all(bio);

    // close the files
    fclose(fin);
    fclose(fout);
    return 0;
}

void validation(char *file, char *url) {
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_subject = NULL;
    // X509_CINF *cert_inf = NULL;
    // STACK_OF(X509_EXTENSION) * ext_list;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, file))) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

    //****************************************************************
    // Subject Common Name
    cert_subject = X509_get_subject_name(cert);
    char subject_cn[SIZE] = "Subject CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_subject, NID_commonName, subject_cn, SIZE);
    printf("Subject CommonName:%s\n", subject_cn);

    ASN1_TIME *cert_nb_time;
    cert_nb_time = X509_get_notBefore(cert);
    char *pstring_nb = (char*)cert_nb_time->data;

    ASN1_TIME *cert_na_time;
    cert_na_time = X509_get_notAfter(cert);
    char *pstring_na = (char*)cert_na_time->data;

    printf("Not before: %s | Not after: %s\n", pstring_nb, pstring_na);

    //****************************************************************
    X509_free(cert);
    BIO_free_all(certificate_bio);
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
        // write mode - required output csv file
        char n_path[SIZE];
        strcpy(n_path, path);
        strcat(n_path, OUTPUT);
        f = fopen(n_path, type);
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
