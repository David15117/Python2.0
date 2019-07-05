#include "sslscanner.h"
/*
  Funciones Necesarias para establecer la conexion HTTP y HTTPS
*/

extern int   CONN_TIMEOUT;


void GiveMeBanner(const char *buffer, char *server,int len);
DWORD IschallengeSupported(const char *buffer, int len);
DWORD GetStatusCode(const char *buffer);
//-------------------------------------------------------------------

static const char * strinstr (/*in*/ const char *   pString,int            nMax,
                             /*in*/ const char *   pSubString, int l)

    {
    char c = *pSubString ;

    while (nMax-- > 0)
    {
        while (*pString && toupper (*pString) != c)
            pString++ ;

        if (*pString == '\0')
            return NULL ;

        if (strnicmp (pString, pSubString, l) == 0)
            return pString ;
        pString++ ;
    }

    return(NULL);
    }

//-------------------------------------------------------------------
DWORD IschallengeSupported(const char *buffer, int len)
{
  const char AuthNeeded[]="WWW-Authenticate:";

  DWORD ret=0;
  char *p=(char *)buffer;
  int offset=0;

  do {
        p=( char *)strinstr(p,len-offset,AuthNeeded,17);
        if (p) {
        p+=17; while (*p==' ') p++;
         if (strnicmp (p, "basic",  5) == 0) ret+=1;
         if (strnicmp (p, "digest", 6) == 0) ret+=2;
         if (strnicmp (p, "ntlm",   4) == 0) ret+=4;
         offset=p-buffer;
        }

  } while (p!=NULL);
  return(ret);
}
//-------------------------------------------------------------------
DWORD GetStatusCode(const char *buffer)
{
   //Devuelve el codigo de error de la respuesta HTTP
   if  ((!buffer)  || (strlen(buffer)<12) || (buffer[0]!='H')  ) return(0);
   char tmp[4];
   memcpy(tmp,buffer+9,3);
   tmp[3]='\0';
   return(atoi(tmp));
}
//-------------------------------------------------------------------

void GiveMeBanner(const char *buffer, char *server,int len) {

   //devuelve el banner HTTP del servidor.
   //Si no se encuentra la header, devolvemos "HTTP/1.0"
   const char defaultserver[]= "HTTP/1.0";
   memset(server,'\0',len);
   char *banner=strstr((char *)buffer,"\nServer:");
   if (!banner) {
      strncpy(server,defaultserver,len);
   } else
   {
     banner+=8;
     while (*banner==' ') banner++;
     strncpy(server,banner,len-1);
     server[len-1]='\0';
     char *r=strchr(server,'\r'); if (r) r[0]='\0';
     r=strchr(server,'\n'); if (r) r[0]='\0';
   }
}
//-------------------------------------------------------------------
struct _request *connectssl(int sock, char *request)
{
   struct _request *data=NULL;
#ifdef _OPENSSL_SUPPORT_
   char buf[BUFFSIZE+1];
   SSL_CTX *ctx;
   SSL *ssl;
   int err=0,total=0, read_size;

      SSL_load_error_strings();
      SSL_library_init();
      //        ctx=SSL_CTX_new(SSLv2_client_method());
      ctx = SSL_CTX_new(TLSv1_client_method());
      if (!ctx)
      {
         printf("SSL_CTX_new failed\n");
         return NULL;
      }
      ssl=SSL_new(ctx);
      SSL_set_fd(ssl, sock);
      if ((err = SSL_connect(ssl)) != 1)
      {
         printf("SSL_connect failed: %s", strerror(errno));
         closesocket(sock);
         SSL_shutdown(ssl);
         SSL_free(ssl);
         SSL_CTX_free(ctx);
         return(NULL);
      }
      err=SSL_write(ssl, request, strlen(request));

      do {
        read_size=SSL_read(ssl, buf, sizeof(buf)-1);
        if(read_size > 0)
        {
            buf[read_size]='\0';
            total+=read_size;//=total+read_size;
            if (data==NULL)
            {
               data=(struct _request *)malloc(sizeof(struct _request));
               data->status=0;
               memset(data->server,'\0',sizeof(data->server));
               data->resultado=(char *)malloc(total+1);
               memcpy(data->resultado,buf,read_size);
               data->len=total;
            }
            else
            {
               data->resultado=(char *)realloc(data->resultado,total+1);
               memcpy(data->resultado+(total-read_size),buf,read_size);
            }
            data->resultado[total]='\0';
        }
      } while(read_size>0);

      SSL_shutdown(ssl);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      closesocket(sock);
      if (data) {
        data->status=GetStatusCode(data->resultado);
        data->challenge=IschallengeSupported(data->resultado,data->len);
        GiveMeBanner(data->resultado, data->server,sizeof(data->server));
      }
#endif      
      return(data);

}
/******************************************************************************/
struct _request *conecta(long target, int port, int sslport, char *request) {
   int sock;
   struct sockaddr_in webserver;
   struct timeval tv;
   //            char *resultado=NULL;
   char buf[BUFFSIZE+1];
   int total=0, read_size;
   int tmp=1;
   fd_set fdread,fds,fderr;
   struct _request *data=NULL;

   sock=socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
   memset(&webserver,0,sizeof(webserver));
   webserver.sin_family = AF_INET;
   webserver.sin_addr.s_addr = target;//inet_addr(target);
   webserver.sin_port = htons(port);

   fcntl(sock, F_SETFL, O_NONBLOCK);

   tv.tv_sec = CONN_TIMEOUT;
   tv.tv_usec = 0;
   FD_ZERO(&fds);
   FD_SET(sock, &fds);
   FD_ZERO(&fderr);
   FD_SET(sock, &fderr);
   FD_ZERO(&fdread);
   FD_SET(sock, &fdread);


   connect(sock,( struct sockaddr *)&webserver,sizeof(webserver));
   if  (select(sock+1,NULL,&fds,NULL,&tv)<=0) {
#ifdef _DBG_
      printf("Unable to connect to %i (%s):%i\n",target,inet_ntoa(webserver.sin_addr),port);
#endif
      closesocket(sock); //timeout
      return(NULL);
   }
#ifdef _DBG_
   printf("hemos conectado...\n");
#endif
   //printf("Conectado.. enviando %s",request);
   if (sslport) {
     tmp=0;
   fcntl(sock, F_SETFL, O_NONBLOCK);
     data=connectssl(sock,request);
     if (data) {
        data->ip=target;
        data->port=port;
        data->ssl=sslport;
        strncpy(data->request,request,sizeof(data->request));
     }
     return(data);
   }
   send(sock,request,strlen(request),0);

   tv.tv_sec = CONN_TIMEOUT;
   tv.tv_usec = 0;


   while (select(sock+1,&fdread,NULL,&fderr,&tv)>0)
   {
      if (FD_ISSET(sock,&fdread))
      {
         read_size=recv (sock, buf, sizeof (buf)-1,0);
         if(read_size > 0)
         {
            //printf("leidos: %i\n",read_size);
            buf[read_size]='\0';
            total+=read_size;//=total+read_size;
            if (data==NULL)
            {
               data=(struct _request *)malloc(sizeof(struct _request));
               data->status=0;
               memset(data->server,'\0',sizeof(data->server));
               data->resultado=(char *)malloc(total+1);
               memcpy(data->resultado,buf,read_size);
               data->len=total;
               data->ip=target;
               data->port=port;
               data->ssl=sslport;
               strncpy(data->request,request,sizeof(data->request));              
            }
            else
            {
               data->resultado=(char *)realloc(data->resultado,total+1);
               memcpy(data->resultado+(total-read_size),buf,read_size);
               data->len=total;
            }
            data->resultado[total]='\0';
         } else {
            closesocket(sock);
            if (data)
            {
               data->status=GetStatusCode(data->resultado);
               data->challenge=IschallengeSupported(data->resultado,data->len);
               GiveMeBanner(data->resultado, data->server,sizeof(data->server));
            }
            return(data);
         }
      }
      if (FD_ISSET(sock,&fderr)) {
         closesocket(sock);
         if (data)
         {
            data->status=GetStatusCode(data->resultado);
            data->challenge=IschallengeSupported(data->resultado,data->len);
            GiveMeBanner(data->resultado, data->server,sizeof(data->server));
         }
         return(data);
      }
      FD_ZERO(&fds);
      FD_SET(sock, &fds);

      FD_ZERO(&fdread);
      FD_SET(sock, &fdread);
   }

   //if ( (!resultado) && (err!=0)) printf("error con la ip %s\n",target);
   //printf("%s: saliendo... (leidos: %i bytes)\n",target,total);
   closesocket(sock);
   if (data) {
      data->status=GetStatusCode(data->resultado);
      data->challenge=IschallengeSupported(data->resultado,data->len);
      GiveMeBanner(data->resultado, data->server,sizeof(data->server));
   }
   return(data);
}
/******************************************************************************/

