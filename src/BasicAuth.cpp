#include "sslscanner.h"
#include "md5.h"

//#define _DBG_

extern int bruteforce;
extern int nRouterAuth;
struct          _fakeauth FakeAuth[MAX_AUTH_LIST];
extern char userpass[MAX_USER_LIST][100];
extern int  nUsers;
//-------------------------------------------------------------------


struct _fakeauth *CheckBasicAuth(struct _request *data, struct _fakeauth *newFakeAuth)  {
   //Dado el resultado de una peticion HTTP verificamos si debemos realizar una autenticacion Basic
   //Si el codigo no es 401, verificamos si podemos hacer un fingerprint del banner del servidor web
   // para identificar una url que si requiera autenticacion

//Si el host no requiere autenticacion, devolvemos NULL
//Si el host requiere autenticacion, devolvemos un puntero a la estructura
//FakeAuth que contiene información de donde y como realizar la autenticación.

   if (!bruteforce) return(NULL);
   struct _request *new_data=data;
   char tmp[4096];
   struct sockaddr_in client;
   int retry=RETRY_COUNT;
   client.sin_addr.s_addr=data->ip;

   char ipaddress[16];
   strcpy(ipaddress,inet_ntoa(client.sin_addr));


// Verificamos antes de nada la cabecera Location..

   for(int i=0;i<nRouterAuth;i++) {
      if (i!=0) { //First request is to match "GET / HTTP/1.0" and this request have been already performed
         new_data=NULL;
         if ( (FakeAuth[i].status == data->status ) &&
         ( (strncmp(data->server,FakeAuth[i].server,strlen(FakeAuth[i].server))==0) ||
            ( (strlen(data->server)==0) && (strcmp(FakeAuth[i].server," ")==0)) )

         )
         {
            
#ifdef _DBG_
            printf("verificando: %s\n",FakeAuth[i].authurl);
#endif
            memset(tmp,'\0',sizeof(tmp));
            if (strcmp(FakeAuth[i].method,"GET")==0) {        //metodo por defecto
               snprintf(tmp,sizeof(tmp)-1, "GET %s HTTP/1.0\r\n"
                  "Host: %s\r\n\r\n",FakeAuth[i].authurl,ipaddress);
            } else {
               snprintf(tmp,sizeof(tmp)-1,
                  "%s %s HTTP/1.0\r\n",
                  "Host: %s\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: %i\r\n\r\n",
                  "%s\r\n",FakeAuth[i].method,FakeAuth[i].authurl,ipaddress,strlen(FakeAuth[i].postdata),FakeAuth[i].postdata);
            }
#ifdef _DBG_
            printf("enviando: %s\n",tmp);
#endif
            //          new_data=conecta(data->ip,data->port,data->ssl,tmp);
            do { //hacemos la peticion HTTP.. y la repetimos si es necesario
               new_data=conecta(data->ip,data->port, data->ssl,tmp);
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
               return(NULL);
            }
         }
      }
      if ( (new_data) && (new_data->status==401) && (new_data->challenge!=NO_AUTH) ) {
         if (new_data->challenge & BASIC_AUTH) {
#ifdef _DBG_
            printf("Iteraccion %i Soporta basic_auth\n",i);
#endif
            if (i>0) FreeRequest(new_data);
            return(&FakeAuth[i]);
         } else {
#ifdef _DBG_
            printf("Iteraccion %i No soporta basic_auth\n",i);
#endif
            if (i!=0) FreeRequest(new_data);
            return(NULL);
         }
      }
      if (i!=0) FreeRequest(new_data);
   }
#ifdef _DBG_
   printf("CheckBasicAuth:: No fingerprinting found. Trying to parse Location: Header\n");
#endif
#define LOCATION "\nLocation:" //http://88.36.25.20/hag/pages/home.htm
   char *location=strstr(data->resultado,LOCATION);
   if (location) {
      location+=strlen(LOCATION);
      if (location[0]==' ') location++;
      char newlocation[200]="";
      char *path;
#ifdef _DBG_
      printf("CheckBasicAuth::Location header found: %s\n",location);
#endif
      if (strncmp(location,"http://",7)==0) {
         location+=7;
      } else {
         if ((location[0]!='/') &&  (location[0]!='.') )
         {
#ifdef _DBG_
            printf("Found relative URI not found:?\n");
#endif
            location=NULL;
         }
      }
      if (location) {
         location=strchr(location,'/');
         if (location)
         {
#ifdef _DBG_
            printf("new location: %s\n",location);
#endif
            //            location++;
            strncpy(newlocation,location,sizeof(newlocation)-1);
            newlocation[sizeof(newlocation)-1]='\0';
            path=strchr(newlocation,'\r');
            if (path) path[0]='\0';

            path=strchr(newlocation,'\n');
            if (path) path[0]='\0';
#ifdef _DBG_
            printf("Saltando a la ruta: %s\n",newlocation);
#endif

            snprintf(tmp, sizeof(tmp)-1,"GET %s HTTP/1.0\r\nHost: %s\r\n\r\n",newlocation,ipaddress);
            tmp[sizeof(tmp)-1]='\0';

            new_data=conecta(data->ip,data->port, data->ssl,tmp);
            if ( (new_data) && (new_data->status==401) && (new_data->challenge & BASIC_AUTH) )
            {
#ifdef _DBG_
               printf("Auth requerida!! . Creando fake auth!!\n");
#endif
               newFakeAuth->status=new_data->status;
               strncpy(newFakeAuth->server,data->server,sizeof(FakeAuth[nRouterAuth].server));
               strncpy(newFakeAuth->authurl,newlocation,sizeof(FakeAuth[nRouterAuth].authurl));
               strncpy(newFakeAuth->method,"GET",4);
               newFakeAuth->postdata[0]='\0';
               FreeRequest(new_data);
               return(newFakeAuth);
            }
            FreeRequest(new_data);
         }
      }
   }
   return(NULL);

}
//-------------------------------------------------------------------
int TryHttpBasicAuth(struct _request *data,struct _fakeauth *newFakeAuth) {
   
   //lanza un ataque de fuerza bruta con autenticacion basic contra el host y path especificados
   int retry=RETRY_COUNT; //bruteforce timeout limit...
   char request[512];
   struct _request *new_data;
   struct sockaddr_in client;
   client.sin_addr.s_addr=data->ip;
   char tmp[200];
   char ipaddress[16];
   strcpy(ipaddress,inet_ntoa(client.sin_addr));

   
   for(int login=0;login<nUsers ;login++)
   {
      memset(request,'\0',sizeof(request));
      memset(tmp,0,sizeof(tmp));
      Base64Encode((unsigned char *)tmp,(unsigned char*)userpass[login],strlen(userpass[login]));
      if (strcmp(newFakeAuth->method,"GET")==0) {        //metodo por defecto
         snprintf(request,sizeof(request)-1,
            "GET %s HTTP/1.0\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "Authorization: Basic %s\r\n\r\n",newFakeAuth->authurl,ipaddress,tmp);
         
      } else {
         snprintf(request,sizeof(request)-1,
            "%s %s HTTP/1.0\r\n",
            "Host: %s\r\n",
            "Connection: close\r\n",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "Content-Length: %i\r\n",
            "Authorization: Basic %s\r\n\r\n",
            "%s\r\n",newFakeAuth->method,newFakeAuth->authurl,ipaddress,strlen(newFakeAuth->postdata),tmp,newFakeAuth->postdata);
      }
      //      printf("probando: !%s!\n",userpass[login]);
#ifdef _DBG_
      printf("TryHttpBasicAuth::Enviando: %s",request);
#endif      
      
      do { //hacemos la peticion HTTP.. y la repetimos si es necesario
         new_data=conecta(data->ip,data->port, data->ssl,request);
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
            } else
            {
               
            }
         }
      } while ( (!new_data) && (retry) );
      
      if (!new_data) //Se acabaron los timeouts o los errores
      {
         return(-1);
      } else {
      //
         if ( (new_data->status!=401) && (new_data->status!=403) && (new_data->status!=413) && (new_data->status!=400) )  { //Add aditional checks for error 403      and 413 /
            //printf("request:\n%s",request);
            //printf(" TryHttpBasicAuth:: new_data->status = %i\n%s\n",new_data->status,new_data->resultado);
#ifdef _DBG_
            printf("request:\n%s",request);
            printf(" TryHttpBasicAuth:: new_data->status = %i\n%s\n",new_data->status,new_data->resultado);
#endif
            TryToUpdateHeader(data->server,new_data->server);
            FreeRequest(new_data);
            return(login);
         } else {
#ifdef _DBG_
            printf("return Code: %i\n", new_data->status);
#endif            
            FreeRequest(new_data);
         }
      }
   }
   return(-1);
}







