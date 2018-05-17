/* * * * * * * * *
 * A TLS Certificate validation using openssl library
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

// byte to bits
#define BITS 8
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
// minimum RSA key length
#define KEY_LEN 2048
// output file name
#define OUTPUT "output.csv"
// output data format
#define FORMAT "%s,%s,%d\n"
// TLS Web Server Authentication
#define TLS_WSA "TLS Web Server Authentication"

/******************************* HELP FUNCTION *******************************/
int validation(char *file, char *url);
int check_CN(X509 *cert, char *url);
int check_SAN(X509 *cert, char *url);
int check_time(X509 *cert);
int check_key_length(X509 *cert);
int check_basic_constraint(X509 *cert);
int check_TLS_WSA(X509 *cert);
int compare_time(ASN1_TIME *from, ASN1_TIME *to);
char *get_path(int argc, char **argv);
void *open_file(char *path, char *type);
void remove_char(char *str, int index);
/****************************************************************************/

int main(int argc, char **argv) {
    // get the input file path
    char *path = get_path(argc, argv);
    // open the input file
    FILE *fin = open_file(path, READ);
    // open the output file
    FILE *fout = open_file(OUTPUT, WRITE);
    // read and validate each line in file
    char buf[SIZE], file[SIZE], url[SIZE];
    while(fgets(buf, SIZE, fin) != NULL) {
        // get the certificate file and url
        buf[strlen(buf)-1] = '\0';
        sscanf(buf, "%[^,],%[^,]", file, url);
        // check the validation
        int result = validation(file, url);
        // write into the file
        fprintf(fout, FORMAT, file, url, result);
    }
    // close the files
    fclose(fin);
    fclose(fout);
    return 0;
}

// process the validation by required
// part of code is extracted from certexample
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
    /******************************************************************/
    // processing the validation
    int result = VALID;
    // validates the domain in common name
    if (!check_CN(cert, url) && !check_SAN(cert, url)) result = INVALID;
    // validates the not before, not after time
    if (!check_time(cert)) result = INVALID;
    // validates the minimum key length
    if (check_key_length(cert)) result = INVALID;
    // validates the basic constraint
    if (check_basic_constraint(cert)) result = INVALID;
    // validates the extension of extended key usage
    if (!check_TLS_WSA(cert)) result = INVALID;
    /******************************************************************/
    X509_free(cert);
    BIO_free_all(certificate_bio);

    return result;
}

// check the common name with domain name
int check_CN(X509 *cert, char *url) {
    // get the subject common name
    X509_NAME *cert_subject = X509_get_subject_name(cert);
    char subject_cn[SIZE] = "Subject CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_subject, NID_commonName, subject_cn, SIZE);
    // validates with domain name
    if (strchr(subject_cn, STAR)) {
        // check the wildcard domains
        int index = strlen(subject_cn) - strlen(strrchr(subject_cn, STAR));
        remove_char(subject_cn, index);
        // subject name does not contain wildcard domains
        if (!strstr(url, subject_cn)) return INVALID;
    } else {
        // subject common name and url are different
        if (strcmp(url, subject_cn) != 0) return INVALID;
    }
    return VALID;
}

// check the subject alternative name
int check_SAN(X509 *cert, char *url) {
    int san_names_nb = -1, result = INVALID, i;
    STACK_OF(GENERAL_NAME) *san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    san_names_nb = sk_GENERAL_NAME_num(san_names);
    // check each name within the extension
    for (i=0; i<san_names_nb; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
        if (current_name->type == GEN_DNS) {
            char *dns_name = (char *)ASN1_STRING_data(current_name->d.dNSName);
            // check the wildcard domains
            if (strchr(dns_name, STAR)) {
                int index = strlen(dns_name) - strlen(strrchr(dns_name, STAR));
                remove_char(dns_name, index);
                // subject alternative name does not contain wildcard domains
                if (strstr(url, dns_name)) result = VALID;
            } else {
                // subject alternative name and url are different
                if (strcmp(url, dns_name) == 0) result = VALID;
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return result;
}

// check the validation time
int check_time(X509 *cert) {
    // get the not valid before and after time
    ASN1_TIME *nb_time = X509_get_notBefore(cert);
    ASN1_TIME *na_time = X509_get_notAfter(cert);
    // check not before and not after time are valid
    return compare_time(nb_time, NULL) && compare_time(NULL, na_time);
}

// check the key length is 2048 bits
int check_key_length(X509 *cert) {
    EVP_PKEY *public_key = X509_get_pubkey(cert);
    RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
    int key_length = RSA_size(rsa_key);
    RSA_free(rsa_key);
    return key_length * BITS - KEY_LEN;
}

// check the basic constraint "CA:FALSE"
int check_basic_constraint(X509 *cert) {
    int ca = -1;
    BASIC_CONSTRAINTS *bs = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    // CA value: 0 for false, 255 for true
    ca = bs->ca;
    BASIC_CONSTRAINTS_free(bs);
    return ca;
}

// check the TLS WSA in extended key usage
// part of code is extracted from certexample
int check_TLS_WSA(X509 *cert) {
    char *buf = NULL;
    BUF_MEM *bptr = NULL;
    // extension of extended key usage
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));

    BIO *bio = BIO_new(BIO_s_mem());
    if(!X509V3_EXT_print(bio, ex, 0, 0)){
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    // bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
    // free the bio
    BIO_free_all(bio);
    // return VALID if buf contains TLS_WSA
    if (!strstr(buf, TLS_WSA)) return INVALID;
    return VALID;
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
        fprintf(stderr, "usage: ./certcheck [path to test file]\n");
        exit(1);
    }
    return path;
}

// open the file by type from file path
void *open_file(char *path, char *type) {
    FILE *f = fopen(path, type);
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
