#ifndef _AUTHSCANNER_
#define __AUTHSCANNER_

#define VERSION "Fast HTTP Auth Scanner v0.6"
#define _OPENSSL_SUPPORT_
#undef _OPENSSL_SUPPORT_
#define _DBG_
#undef _DBG_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>  
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>  //pthread
#include <ctype.h> //toupper

#define DWORD int
#define BOOL int
#define closesocket close
#define strnicmp strncasecmp
#define ioctlsocket ioctl
#define Sleep usleep
#define EnterCriticalSection pthread_mutex_lock
#define LeaveCriticalSection pthread_mutex_unlock

#ifdef _OPENSSL_SUPPORT_
 #include <openssl/crypto.h>
 #include <openssl/x509.h>
 #include <openssl/pem.h>
 #include <openssl/ssl.h>
 #include <openssl/err.h>
#endif

#define NO_AUTH      0
#define BASIC_AUTH   1
#define DIGEST_AUTH  2
#define NTLM_AUTH    4
#define UNKNOWN_AUTH 8
//configuration
#define MAX_USER_LIST   200
#define MAX_IGNORE_LIST 50
#define MAX_AUTH_LIST   100
#define MAX_WEBFORMS    100
#define MAX_PORTS       100
#define RETRY_COUNT     3
#define BUFFSIZE 1000

//
//puertos a auditar
struct _ports {
   int port;
   int ssl;
};

//hosts que no procesaremos
struct  _ignore {
   DWORD status;
   char server[200];
};

//Autenticacion de routers fuera del directorio raiz
struct _fakeauth {
   DWORD status;
   char  server[200];
   char  authurl[200];
   char method[10]; //GET |POST
   char postdata[200];
};

//resultado de una peticion http
struct _request {
   DWORD status;
   char server[200];
   DWORD challenge;
   char *resultado;
   DWORD len;
   long ip;
   int port;
   int ssl;
   char request[4096];
   
};

//información de un router que soporta auth por webform
struct _webform {
   char  model[200];       //Fake version
   DWORD status;            //codigo de error de la página principal
   char  server[200]; //banner del servidor Web
   char  matchstring[200]; //string de la peticion con la que machear los resultados.
   char  ValidateImage[200];
   char  authurl[200];
   char  authmethod[10];
   char  authform[1024];
   int   requireloginandpass;
   char  validauthstring[200];
   char  invalidauthstring[200];
   char  invalidauthstringalt[200]; 
};


void usage(void);
struct _request *conecta(long target,int port, int ssl, char *request);
long GetNextTarget(void);
void FreeRequest(struct _request *request);
void TryToUpdateHeader(char *oldheader,char *newheader);

DWORD IgnoreHost(struct _request *host);
BOOL IsInvalidValidStatusCode(DWORD status);
struct _request *GetHttpRequest(long ip, int port, int ssl);
int TryHttpBasicAuth(struct _request *data,struct _fakeauth *newFakeAuth);
void *Escanea( void *thread);
struct _fakeauth *CheckBasicAuth(struct _request *data, struct _fakeauth *newFakeAuth);

unsigned int Base64EncodeGetLength( unsigned long size );
unsigned int Base64DecodeGetLength( unsigned long size );
int Base64Encode( unsigned char* out, const unsigned char* in, int inlen );
int Base64Decode( char* out, const char* in, unsigned long size );

//config
int LoadUserList(void);
int LoadIgnoreList(void);
int LoadRouterAuth(void);
int LoadWebForms(void);
int LoadSingleUserList(void);
int ReadAndSanitizeInput(FILE *file, char *buffer,int len);
DWORD LoadConfigurationFiles(int argc, char *argv[]);
//webforms
int CheckWebformAuth(struct _request *data);
int TryHTTPWebformAuth(long ip, int port, int ssl,int webform);

void GenerateAuth(char *scheme, char *output, char *username, char *password);

#endif

