#include "sslscanner.h"
#include "md5.h"
extern int nUsers;
char logins[MAX_USER_LIST][40];
int nLogins=0;
extern char userpass[MAX_USER_LIST][100];
struct _webform WEBFORMS[MAX_WEBFORMS];
int nWebforms=0;//=sizeof(WEBFORMS)/sizeof(struct _webform);

//#define _DBG_

#define RAWUSER   "!!!RAWUSER!!!"
#define RAWPASS   "!!!RAWPASS!!!"
#define B64USER   "!!!B64USER!!!"
#define B64PASS   "!!!B64PASS!!!"
#define MD5USER   "!!!MD5USER!!!"
#define MD5PASS   "!!!MD5PASS!!!"
#define RAWIPAD   "!!!RAWIPAD!!!"

#define MAX_POST_LENGHT 4096

int what(char *code) {
   //devuelve un codigo de error dependiendo del formato de los datos
   if (strncmp(code,RAWUSER,13)==0) return(0);
   if (strncmp(code,RAWPASS,13)==0) return(1);
   if (strncmp(code,B64USER,13)==0) return(2);
   if (strncmp(code,B64PASS,13)==0) return(3);
   if (strncmp(code,MD5USER,13)==0) return(4);
   if (strncmp(code,MD5PASS,13)==0) return(5);
   if (strncmp(code,RAWIPAD,13)==0) return(6);
   return(-1);
}
//-------------------------------------------------------------------
#define NEEDUSER 1
#define NEEDPASS 2
void GenerateAuth(char *scheme, char *output, char *username, char *password,long ip) {
   //Generamos los datos del POST en base al scheme
   memset(output,'\0',1000);
   char *opt;
   char *where=scheme;
   char tmp[100];
   do {
      opt=strstr(where,"!!!");
      if (opt)
      {
         memset(tmp,'\0',sizeof(tmp));
         strncat(output,where,opt-where);
         switch (what(opt)) {
         case 0:
            strcat(output,username);
            break;
         case 1:
            strcat(output,password);
            break;
         case 2:
            Base64Encode((unsigned char *)tmp,(unsigned char *)username,strlen(username));
            strcat(output,tmp);
            break;
         case 3:
            Base64Encode((unsigned char *)tmp,(unsigned char *)password,strlen(password));
            strcat(output,tmp);
            break;
         case 4:
            Getmd5Hash(username,strlen(username),(unsigned char *)tmp);
            strcat(output,tmp);
            break;
         case 5:
            Getmd5Hash(password,strlen(password),(unsigned char *)tmp);
            strcat(output,tmp);
            break;
         case 6:
                struct sockaddr_in server;
                server.sin_addr.s_addr=ip;
                strcat(output,inet_ntoa(server.sin_addr));
                break;
         default: //invalid scheme
            strncat(output,opt,3);
            //opt+=3;
            opt-=10;
         }
         where=opt+13;
      } else { //copiamos el final
         strncat(output,where,strlen(where));
      }
   } while(opt!=NULL);
}



/*
char version[200];
DWORD status;
char serverbanner[];
char matchstring[200];
--------------------------
Webform - Model Fingerprint
{"D-Link Wireless adsl router", 200,"","//inserted by Edward on 2004/01/07 for user pressing "Enter" to login if "Username" and "Password"},
{"router",200,"","Please Log In to continue."},
{"ZyXEL ZyWALL Series",200,"","ZyXEL ZyWALL Series"},
{"hp LaserJet",200,"Virata-EmWeb/R6_0_1"
{"D-Link DNS-323",302,"GoAhead-Webs","Location: http://DNS323/web/login.asp"},
{"Webcam",200,"Virata-EmWeb/R6_0_1","HCNetVideo.csUrl=activex.url.value"};
{"Webcam",200,"GeoHttpServer","<TITLE>Password</TITLE>"},
{"Geovision video",200,"thttpd/2.25b 29dec2003","top.location.href = "/L3gpp.htm";"},
{"Zyxel P-661H-D1", 200,"RomPager/4.51 UPnP/1.0","<title>.:: Welcome to the Web-Based Configurator::.</title>"},
{"Zyxel P-660HW-D1",200,"RomPager/4.07 UPnP/1.0","<title>.:: Welcome to the Web-Based Configurator::.</title>"},

*/
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------

int TryHTTPWebformAuth(long ip, int port, int ssl,int webform) {
   
   char request[MAX_POST_LENGHT*2];
   char post[MAX_POST_LENGHT];
   char user[100];
   char password[100];
   char *p;
   struct sockaddr_in client;
   client.sin_addr.s_addr=ip;
   int retry=RETRY_COUNT;
   struct _request *new_data;
   char InvalidAuthString[200];
   char InvalidAuthStringalt[200];
   int iteractions;
   int login=0;
   char ipaddress[16];
   strcpy(ipaddress,inet_ntoa(client.sin_addr));

   if (WEBFORMS[webform].requireloginandpass) {
      login=1; //Our first user/password  is null
      iteractions=nUsers;
   } else iteractions=nLogins;
   
#ifdef _DBG_
   printf("Vamos a hacer %i iteraciones\n",iteractions);
#endif 
   for(login;login<iteractions ;login++) {
      if (WEBFORMS[webform].requireloginandpass)
      {
         strcpy(user,userpass[login]);
         p=strchr(userpass[login],':');
         strcpy(password,p+1);
         user[p-userpass[login]]='\0';
      } else {
         strcpy(user,logins[login]);
         strcpy(password,logins[login]);
      }
#ifdef _DBG_
      printf("TryHTTPWebformAuth::usuario: !!%s!! pass: !!%s!!\n",user,password);
#endif
      memset(post,'\0',sizeof(post));
      memset(request,'\0',sizeof(request));
      GenerateAuth(WEBFORMS[webform].authform,post,user,password,ip);
#ifdef _DBG_
      printf("\nTryHTTPWebformAuth::password: %s\nPOST VALE: %s\n\n",password,post);
#endif
      
      if (strncmp(WEBFORMS[webform].authmethod,"GET",3)==0) {
         snprintf(request,sizeof(request)-1,
                "GET %s?%s HTTP/1.0\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Connection: close\r\n\r\n",WEBFORMS[webform].authurl,post,ipaddress,VERSION);
      } else {
         snprintf(request,sizeof(request)-1,
            "%s %s HTTP/1.0\r\n",
            "Host: %s\r\n",
            "User-Agent: %s\r\n",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "Content-Length: %i\r\n\r\n",
            "%i\r\n",WEBFORMS[webform].authmethod,WEBFORMS[webform].authurl,ipaddress,VERSION,strlen(post),post);
      }
      
      
#ifdef _DBG_
      printf("TryHTTPWebformAuth::REQUEST: %s\n",request);
#endif
      do { //hacemos la peticion HTTP.. y la repetimos si es necesario
         new_data=conecta(ip,port, ssl,request);
         if (!new_data)
         {
            retry--;
         }
         else
         {
            if (IsInvalidValidStatusCode(new_data->status))
            {
               retry--;
               FreeRequest(new_data); new_data=NULL;
            }
         }
      } while ( (!new_data) && (retry) );

      if (!new_data) //Se acabaron los timeouts o los errores
      {
#ifdef _DBG_
         printf("TryHTTPWebformAuth::Error en la peticion\n");
#endif
         return(-1);
      } else {
         //avoid stupid D-Link "bug"
         for(unsigned long i=0;i<200;i++) { if (i==new_data->len) break; if (new_data->resultado[i]==0x00) new_data->resultado[i]=' '; }
#ifdef _DBG_
         printf("TryHTTPWebformAuth::devuelto: %s",new_data->resultado);
#endif
         if (strlen(WEBFORMS[webform].validauthstring)>0) {
            if (strstr(new_data->resultado,WEBFORMS[webform].validauthstring)!=NULL) {
#ifdef _DBG_
               printf("TryHTTPWebformAuth::ENCONTRADO!!!\n");
#endif
               FreeRequest(new_data);
               return(login + (WEBFORMS[webform].requireloginandpass*1024));
            }
         } else {
            GenerateAuth(WEBFORMS[webform].invalidauthstring,InvalidAuthString,user,password,ip);
            //if (strstr(new_data->resultado,WEBFORMS[webform].invalidauthstring)==NULL) {
            if (strstr(new_data->resultado,InvalidAuthString)==NULL) {
#ifdef _DBG_
               printf("TryHTTPWebformAuth::NO ENCONTRADO INVALID!!!!! OK :)\n");

#endif
              InvalidAuthStringalt[0]='\0';
#ifdef _DBG_
              printf("WEBFORMS[webform].invalidauthstringalt: %s\n",WEBFORMS[webform].invalidauthstringalt);
#endif

               GenerateAuth(WEBFORMS[webform].invalidauthstringalt,InvalidAuthStringalt,user,password,ip);
#ifdef _DBG_
               printf("InvalidAuthStringalt: %s\n",InvalidAuthStringalt);
#endif

//               GenerateAuth(WEBFORMS[webform].invalidauthstring,InvalidAuthString,user,password,ip)
               if ( ( strlen(WEBFORMS[webform].invalidauthstringalt)==0 ) || ( strstr(new_data->resultado,InvalidAuthStringalt)==NULL ) ) {
#ifdef _DBG_
                  printf("TryHTTPWebformAuth::invalidauthstringalt not found ;)\n");
                  printf("len: %i. No se encontro: !%s!\n",strlen(WEBFORMS[webform].invalidauthstringalt),WEBFORMS[webform].invalidauthstringalt);
#endif
                  FreeRequest(new_data);
                  return(login + (WEBFORMS[webform].requireloginandpass*1024));
               }
            }

         }
         //printf("Devuelto: %s\n",new_data->resultado);
         FreeRequest(new_data);
      }
   }
   return(-1);
}

//---------------------------------------------------------------------------
int CheckWebformAuth(struct _request *data) {
   //verifica en base a firmas si debemos realizar una autenticacion por webforms
   int i=0;
#ifdef _DBG_
   printf("CheckWebformAuth::verificando: %i\n",nWebforms);
#endif
   for(i;i<nWebforms;i++)
   {
      if (data->status==WEBFORMS[i].status) {
#ifdef _DBG_
         printf("data->status: %i == WEBFORMS[%i].status: %i\n",data->status,i,WEBFORMS[i].status);

printf("strlen: %i\n", strlen(data->server));
#endif
         if ( (strlen(WEBFORMS[i].server)==0) ||
              (strcmp(data->server,WEBFORMS[i].server)==0)  ||
            ( (strlen(data->server)==0) && (strcmp(WEBFORMS[i].server,"HTTP/1.0")==0)) )
         {
#ifdef _DBG_
            printf("CheckWebformAuth::vamos a verificar el string %i\n",i);
#endif
            if (strstr(data->resultado,WEBFORMS[i].matchstring)!=NULL) {

/*
               if ( (strlen(data->server)==0) || (strcmp(data->server,"HTTP/1.0")==0) ) {
                  snprintf(data->server,sizeof(data->server)-1,"(%s)",WEBFORMS[i].model);
                  data->server[sizeof(data->server)-1]='\0';
               }
*/
#ifdef _DBG_
               printf("CheckWebformAuth::match: %s\n\n",WEBFORMS[i].matchstring);
#endif
                if (strlen(WEBFORMS[i].ValidateImage)==0) {
#ifdef _DBG_
                        printf("CheckWebformAuth::ValidateImage len=0 %s\n\n",WEBFORMS[i].ValidateImage);
#endif
                        snprintf(data->server,sizeof(data->server)-1,"(%s)",WEBFORMS[i].model);
                        return(i);
                } else {
                  char image[200];
                  struct sockaddr_in server;
                  server.sin_addr.s_addr=data->ip;
                  sprintf(image,"GET %s HTTP/1.0\r\nHost: %s\r\n\r\n",WEBFORMS[i].ValidateImage,inet_ntoa(server.sin_addr));
                  struct _request *new_data=conecta(data->ip,data->port, data->ssl,image);
                  if (new_data) {
                   if ( (new_data->status==200) && (strstr(new_data->resultado,"Content-Type: image/")!=NULL) ) {
#ifdef _DBG_
        printf(" CheckWebformAuth::Validateimage: MATCH %s\n",image);
#endif
                        FreeRequest(new_data);
                        snprintf(data->server,sizeof(data->server)-1,"(%s)",WEBFORMS[i].model);
                        return(i);
                   } else {
#ifdef _DBG_
        printf(" CheckWebformAuth::Validateimage: Not found %s\n",image);
#endif
                        FreeRequest(new_data);
                   }
                  }
                }
            } else {
#ifdef _DBG_
               printf("CheckWebformAuth::no encontrado: %s\n",WEBFORMS[i].matchstring);
#endif
               //printf("datos: %s\n",data->resultado);
            }
         } else {
#ifdef _DBG_
            printf ("CheckWebformAuth No match %s - %s\n", data->server,WEBFORMS[i].server);
#endif
         }
      }
   }
#ifdef _DBG_
   printf("salimos...%i\n",i);
#endif   
   return(-1);
}




