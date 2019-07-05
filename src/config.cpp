//514 Fast HTTP Auth Scanner.
// Load Configuration
#include "sslscanner.h"


extern int             nUsers;
extern int             nIgnoreList;
extern int             nRouterAuth;
extern int             nWebforms;
extern int             nLogins;
extern char            userpass[MAX_USER_LIST][100];
extern struct          _ignore IgnoreList[MAX_IGNORE_LIST];
extern struct          _fakeauth FakeAuth[MAX_AUTH_LIST];
extern struct          _webform WEBFORMS[MAX_WEBFORMS];
extern char            logins[MAX_USER_LIST][40];
extern FILE*           LogFile;
extern FILE            *ipfile;
extern int             bruteforce;
extern struct          _ports ports[MAX_PORTS];
extern int             nports;
extern int             MAX_THREADS;
extern int             CONN_TIMEOUT;
extern unsigned long currentip;
extern unsigned long endip;
extern int FullUserList;
//------------------------------------------------------------------------------
int ReadAndSanitizeInput(FILE *file, char *buffer,int len) {
//read a line from a file stream, and removes '\r' and '\n'
//if the line is not a comment, true is returned
   fgets(buffer,len,file);
   buffer[len-1]='\0';
   if ( (strlen(buffer)>5) && buffer[0]!='#'  && buffer[0]!=';'  ) {
     char *p=buffer+strlen(buffer)-1;
     while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
     return(1);
   }
   return(0);
}
/******************************************************************************/
void ValidateLine(char *source,char *dst) {
 int j=0;
 for (unsigned int i=0;i<strlen(source);i++) {
       if (source[i]=='\\') {
         switch (source[i+1]) {
           case 'r':
            source[i+1]='\r';
           break;
           case 'n':
            source[i+1]='\n';
            break;
           case 't':
            source[i+1]='\t';
            break;
           default:
            dst[j]=source[i];
            j++;
           break;
         }
       } else {
          dst[j]=source[i];
          j++;
       }
  }
}
//------------------------------------------------------------------------------
int LoadWebForms(void)
{
 FILE *webforms=fopen("configs/webforms.ini","r");
 nWebforms=0;
 if (webforms) {
   char line[512];
   char tmp[512];

   int i;
   for(i=0;i<MAX_WEBFORMS;i++) memset((char *)&WEBFORMS[i],'\0',sizeof(struct _webform));
   while( (!feof(webforms)) && (nWebforms<MAX_WEBFORMS) )
   {
    //fgets(tmp,sizeof(tmp),webforms);

    //if ( (strlen(tmp)>6) && (tmp[0]!='#') && (tmp[0]!=';'))
    if (ReadAndSanitizeInput(webforms,tmp,sizeof(tmp)))
    {
        memset(line,'\0',sizeof(line));
        ValidateLine(tmp,line);

        if (strncmp(line,"Model=",6)==0)           
                strncpy(WEBFORMS[nWebforms].model,line+6,sizeof(WEBFORMS[nWebforms].model));
        if (strncmp(line,"status=",7)==0)
                WEBFORMS[nWebforms].status=atoi(line+7);
        if (strncmp(line,"server=",7)==0) {
                strncpy(WEBFORMS[nWebforms].server,line+7,sizeof(WEBFORMS[nWebforms].server));
        }
        if (strncmp(line,"Matchstring=",12)==0)
                strncpy(WEBFORMS[nWebforms].matchstring,line+12,sizeof(WEBFORMS[nWebforms].matchstring));
        if (strncmp(line,"ValidateImage=",14)==0)
                strncpy(WEBFORMS[nWebforms].ValidateImage,line+14,sizeof(WEBFORMS[nWebforms].ValidateImage));
        if (strncmp(line,"authurl=",8)==0)
                strncpy(WEBFORMS[nWebforms].authurl,line+8,sizeof(WEBFORMS[nWebforms].authurl));
        if (strncmp(line,"authmethod=",11)==0)
                strncpy(WEBFORMS[nWebforms].authmethod,line+11,sizeof(WEBFORMS[nWebforms].authmethod));
        if (strncmp(line,"requireloginandpass=",20)==0)
                WEBFORMS[nWebforms].requireloginandpass=atoi(line+20);
        if (strncmp(line,"authform=",9)==0)
                strncpy(WEBFORMS[nWebforms].authform,line+9,sizeof(WEBFORMS[nWebforms].authform));
        if (strncmp(line,"validauthstring=",16)==0) {
                strncpy(WEBFORMS[nWebforms].validauthstring,line+16,sizeof(WEBFORMS[nWebforms].validauthstring));
        }
        if (strncmp(line,"invalidauthstring=",18)==0) {
                strncpy(WEBFORMS[nWebforms].invalidauthstring,line+18,sizeof(WEBFORMS[nWebforms].invalidauthstring));
                nWebforms++;
        }
        if (strncmp(line,"invalidauthstringalt=",21)==0) {
                strncpy(WEBFORMS[nWebforms-1].invalidauthstringalt,line+21,sizeof(WEBFORMS[nWebforms].invalidauthstringalt));
        }
    }
   }
 }
 return(nWebforms);
}

//------------------------------------------------------------------------------
int LoadUserList(void) {
 FILE *userlist;
 char *p;
 char user[200];

 if (FullUserList) {
         userlist=fopen("configs/UserListMulti.ini","r");
 } else {
         userlist=fopen("configs/UserListMulti-simple.ini","r");
 }
 if (userlist) {
   while( (!feof(userlist)) && (nUsers<MAX_USER_LIST) )
   {
    memset(user,'\0',sizeof(user));
    fgets(user,sizeof(user)-1,userlist);
    if ( (strlen(user)>1) && (user[0]!='#') )
    {
      p=user+strlen(user)-1;
      while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
      strncpy(userpass[nUsers],user,sizeof(userpass[nUsers]));
      nUsers++;
    }
   }
   fclose(userlist);
 }
 return(nUsers);
}

/******************************************************************************/
int LoadSingleUserList(void) {
 FILE *userlist;
 char *p;
 char user[200];

 userlist=fopen("configs/UserListSingle.ini","r");
 if (userlist) {
   while( (!feof(userlist)) && (nLogins<MAX_USER_LIST) )
   {

    memset(user,'\0',sizeof(user));
    fgets(user,sizeof(user)-1,userlist);
    if ( (strlen(user)>1) && (user[0]!='#') )
    {

      p=user+strlen(user)-1;
      while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
      strncpy(&logins[nLogins][0],user,sizeof(logins[nLogins])-1);
      nLogins++;
    }
   }
   fclose(userlist);
 }

 return(nLogins);
}
/******************************************************************************/

/******************************************************************************/
int LoadIgnoreList(void) {
 FILE *ignore;
 char *p;
 char line[512];

 ignore=fopen("configs/IgnoreList.ini","r");
 if (ignore) {
   while (!feof(ignore))
   {
    if ( ReadAndSanitizeInput(ignore,line,sizeof(line)) )
    {
      p=strchr(line,' ');
      if (p) {
        p[0]='\0';
//        printf("bloque: %s-%s\n",line,p+1);
        IgnoreList[nIgnoreList].status=atoi(line);
        strcpy(IgnoreList[nIgnoreList].server,p+1);
        nIgnoreList++;
      }
    } 
   }
   fclose(ignore);
 }
 return(nIgnoreList);
}
/******************************************************************************/
int LoadRouterAuth(void) {
 FILE *RouterAuth;
 char line[200];
 char *p;

 RouterAuth=fopen("configs/RouterAuth.ini","r");

 if (RouterAuth) {
  while (!feof(RouterAuth)) {
    fgets(line,sizeof(line)-1,RouterAuth);
    if ( (strlen(line)>5) && line[0]!='#' ) {
      p=line+strlen(line)-1;
      while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
     p=strtok(line,"|");
     FakeAuth[nRouterAuth].status=atoi(p);
     p=strtok(NULL,"|");
     strcpy(FakeAuth[nRouterAuth].server,p);
     if ( (strlen(p)==1) && (p[0]=='*') ) FakeAuth[nRouterAuth].server[0]='\0';
     p=strtok(NULL,"|");
     strcpy(FakeAuth[nRouterAuth].authurl,p);
     p=strtok(NULL,"|");
     strcpy(FakeAuth[nRouterAuth].method,p);
     p=strtok(NULL,"|");
     if (p) strcpy(FakeAuth[nRouterAuth].postdata,p);
     nRouterAuth++;
    }
  }
  fclose(RouterAuth);
 }
 return(nRouterAuth);
}
/******************************************************************************/



void usage(void) {
   printf("\nUsage: fscan.exe  <parameters>\n");
   printf("  --threads <threads>                   (Number of threads.  default 10)\n");
   printf("  --timeout <timeout>                   (Connection Timeout. default 10)\n");
   printf("  --logfile <logfile>                   (Save results to <logfile>)\n");
   printf("  --ipfile  <ipfile>                    (load ips from <ipfile>)\n");
   printf("  --hosts   <ip1[-ip2]>                 (ex: --hosts 192.168.1.1-192.168.10.1)\n");
   printf("  --bruteforce   <0|1>                  (Bruteforce (enabled by default) )\n");
   printf("  --fulluserlist <0|1>                  (Test all users (slowest)\n");
#ifdef _OPENSSL_SUPPORT_
   printf("  --sslports <port>[,<port>,<port>,..]  (example -P 443,1443)\n");
#endif
   printf("  --ports <port>[,<port>,<port>,..]     (example -p 80,81,82,8080)\n\n");


   printf(" Example:\n");
#ifdef _OPENSSL_SUPPORT_
   printf(" fscan.exe --ports 80 --sslports 443,1433 --hosts 192.168.0.1-192.168.1.254  --threads 200\n\n");
#else
   printf(" fscan.exe --ports 80,81 --hosts 192.168.0.1-192.168.1.254  --threads 200\n\n");
#endif
   exit(1);

}
//-----------------------------------------------------------------------------

DWORD LoadConfigurationFiles(int argc, char *argv[]){
   int i;
   char *p;
   struct sockaddr_in ip1,ip2;
   int nhosts=0;
   char dbg[512];

   if (argc<3) usage();
   for (i=1;i<argc-1;i++) {
      if ( argv[i][0]=='-')  {
        if (strcmp( argv[i],"--logfile")==0) {
            LogFile=fopen(argv[i+1],"a+");
            i++;

        } else
        if (strcmp( argv[i],"--bruteforce")==0) {
            bruteforce=atoi(argv[i+1]);
            i++;
        } else
        if (strcmp( argv[i],"--fulluserlist")==0) {
            FullUserList=atoi(argv[i+1]);
            i++;
        } else
        if (strcmp( argv[i],"--ports")==0) {
            p=strtok(argv[i+1],",");
            while (p!=NULL) {
               ports[nports].port=atoi(p);
               ports[nports].ssl=0;
               p=strtok(NULL,",");
               nports++;
            }
            i++;
        } else
#ifdef _OPENSSL_SUPPORT_
        if (strcmp( argv[i],"--sslports")==0) {
            p=strtok(argv[i+1],",");
            while (p!=NULL) {
               ports[nports].port=atoi(p);
               ports[nports].ssl=1;
               p=strtok(NULL,",");
               nports++;
            }
            i++;
        } else
#endif
        if (strcmp( argv[i],"--timeout")==0) {
            CONN_TIMEOUT=atoi(argv[i+1]);
            i++;
        } else
        if (strcmp( argv[i],"--threads")==0) {
            MAX_THREADS=atoi(argv[i+1]);
            i++;
        } else
        if (strcmp( argv[i],"--ipfile")==0) {
            ipfile=fopen(argv[i+1],"r");
            if (ipfile) {
               printf("[+] Loaded ips from %s\n",argv[i+1]);
            } else {
               printf("[-] Unable to load ips from %s\n",argv[i+1]);
               usage();
            }
            i++;
        } else
        if (strcmp( argv[i],"--hosts")==0) {
            p=strtok(argv[i+1],"-");
            ip1.sin_addr.s_addr = inet_addr(p);
            currentip=ntohl(ip1.sin_addr.s_addr);
            p=strtok(NULL,"-");
            if (!p) {
                endip=currentip+1;
                ip2.sin_addr.s_addr=htonl(endip);
                nhosts=1;
            } else {
                ip2.sin_addr.s_addr = inet_addr(p);
                endip=ntohl(ip2.sin_addr.s_addr);
                if (endip==currentip) endip++;
                nhosts=endip-currentip;
                if ( nhosts <0) {
                        printf(" Invalid ip range %s  - %s\n",inet_ntoa(ip1.sin_addr),p);
                        usage();
                }
            }
            i++;
        } else {
           printf("Invalid parameter %s\n",argv[i]);
           usage();
        }
     }
  }
    i=LoadUserList();
   if (!i) {
      printf("[-] UserList file not found\n");
      return(1);
   } else {
      printf("[+] Loaded %i user/pass combinations\n",i);
   }
   i=LoadIgnoreList();
   if (!i) {
      printf("[-] Unable to load Ignore List\n");
      return(1);
   } else {
      printf("[+] Loaded %i ignored webservers\n",i);
   }

   i=LoadRouterAuth();
   if (!i) {
      printf("[-] Unable to load Router Auth engine\n");
      return(1);
   } else {
      printf("[+] Loaded %i Router authentication schemes\n",i);
   }
   i=LoadWebForms();
   if (!i) {
      printf("[-] Unable to load Webforms auth engine\n");
      return(1);
   } else {
      printf("[+] Loaded %i webform authentication schemes\n",i);
   }
   i=LoadSingleUserList();
   if (!i) {
      printf("[-] Unable to load Single login file\n");
      return(1);
   } else {
      printf("[+] Loaded %i Single Users\n",i);
   }

   if ( (!nports) || ( (nhosts==0) && (ipfile==NULL) )  ) usage();

   /*if (ipfile) {
      sprintf(dbg,"[+] Scanning hosts from ip file\n",nhosts);
   } else {
      sprintf(dbg,"[+] Scanning %i hosts  (%s  - %s)\n",nhosts,inet_ntoa(ip1.sin_addr),p);
   }*/
   //printf("%s",dbg);
   if (LogFile) { fwrite(dbg,1,strlen(dbg),LogFile); }
   //sprintf(dbg,"[+] Scanning %i ports - bruteforce is %s\n",nports,bruteforce ? "active" : "Inactive");
   //printf("%s",dbg);
   if (LogFile) { fwrite(dbg,1,strlen(dbg),LogFile); }
   printf("\n");

   return(0);
}
