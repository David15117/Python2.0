#include "sslscanner.h"

pthread_mutex_t CSip;
pthread_mutex_t CSThreads;
pthread_mutexattr_t mutexattr;
pthread_mutexattr_t secondmutexattr;

unsigned long currentip=0, endip=0;

int             MAX_THREADS=10;
int             CONN_TIMEOUT=10;
char            userpass[MAX_USER_LIST][100];
extern char     logins[MAX_USER_LIST][40];
struct          _ports ports[MAX_PORTS];
struct          _ignore IgnoreList[MAX_IGNORE_LIST];
FILE            *ipfile=NULL;
int             CurrentIp=0;
int             FullUserList=0;
int             ShowAll=0; //Report all webservers or webservers that report 401 error code
int             UseIgnoreList=1; //Ignore default webservers (non routers)
int             bruteforce=1;  //Yeah! try to discover default passwords
int             IgnoreNotGuesedPasswords=0;
int             nports=0;
int             nUsers=0;
int             nIgnoreList=0;
int             nRouterAuth=0;
FILE*           LogFile=NULL;
int             ThreadsActivos=0;


long GetNextTarget(void)
{
	//Devuelve el siguiente registro a analizar
	EnterCriticalSection(&CSip);
 
	if (ipfile) {
		if (feof(ipfile)) {
			LeaveCriticalSection(&CSip);
			return(0);
		} else {
			char line[512];
			if ( ReadAndSanitizeInput(ipfile,line,sizeof(line)) ){
				struct sockaddr_in ip;
				if (line[0]==' ') { //read logfiles
					line[17]='\0';
					ip.sin_addr.s_addr = inet_addr(line+1);
				} else {
					line[16]='\0';
					ip.sin_addr.s_addr = inet_addr(line);
				}
				LeaveCriticalSection(&CSip);
				return(ip.sin_addr.s_addr);
			} else{
				LeaveCriticalSection(&CSip);
				return(0);
			}
		}
	} else {
		unsigned long ret=(long)currentip++;
		LeaveCriticalSection(&CSip);
		if (ret<endip) {
			return((long)htonl(ret));
		} else {
			return(0);
		}
	}
}

void FreeRequest(struct _request *request) {
	// liberar a memoria usada pelo request
	if (request) {
		if (request->resultado)
		{
			free(request->resultado);
			request->resultado=NULL;
		}
		free(request);
	}
}

DWORD IgnoreHost(struct _request *host) {
	// checa se precisa ignorar esse host
	if ( (host==NULL) || (host->resultado==NULL) ) return(1);
	if  (UseIgnoreList)  {
		for(int i=0;i<  nIgnoreList;i++) {
			if (strncmp(host->server,IgnoreList[i].server,strlen(IgnoreList[i].server))==0) {
				if ( (IgnoreList[i].status==0) ||(IgnoreList[i].status==host->status) ) {
					return(1);
				}
			}
		}
	}
	return(0);
}

BOOL IsInvalidValidStatusCode(DWORD status) {
	return ( (status<100) || (status>510) );
}

void TryToUpdateHeader(char *oldheader,char *newheader) {
	if(( (strlen(oldheader)==0) || (strncmp(oldheader,"HTTP/1.0",8)==0)  ) &&
		 (strlen(newheader)!=0) && (strncmp(newheader,"HTTP/1.0",8)!=0)  ) {
#ifdef _DBG_
		printf("Updating Server Header: %s -> %s\n",oldheader,newheader);
#endif
		strncpy(oldheader,newheader,200);
	}
}

struct _request *GetHttpRequest(long ip, int port, int ssl) {
	//realiza una peticion http contra el servidor seleccionado
	//si la peticion HEAD no necesita autenticacion (error 401) forzamos una segunda peticion GET
	//Necesario para saber si debemos realizar un ataque de fuerza bruta contra la pagina de inicio
	char GET[200]="GET / HTTP/1.0\r\n\r\n";
	char dbg[512];
	struct _request *GETdata;
	struct sockaddr_in client;
	client.sin_addr.s_addr=ip;
   
	GETdata=conecta(ip,port,ssl,GET);
	if (GETdata)
	{
#ifdef _DBG_
		printf("GetHttpRequest::send: %s\n",GET);
		printf("GetHttpRequest::result %s: (%i bytes) %s\n",inet_ntoa(client.sin_addr),GETdata->len,GETdata->resultado);
#endif
		if ( (strncmp(GETdata->server,"HTTP/",5)==0) || (strlen(GETdata->server)==0) ) {
			char HEAD[200];
			sprintf(HEAD,"HEAD / HTTP/1.0\r\nConnection: close\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",inet_ntoa(client.sin_addr),VERSION);
			struct _request *HEADdata=conecta(ip,port,ssl,HEAD);
			if (HEADdata) {
				TryToUpdateHeader(GETdata->server,HEADdata->server);
				FreeRequest(HEADdata);
			}
		}
      
		if(IsInvalidValidStatusCode(GETdata->status)) //Verificamos que se trate de un servidor Web
		{
			FreeRequest(GETdata);
			return(NULL);
		}
 
		if(IgnoreHost(GETdata))  //Ignoramos Host. Lo mostramos si esta configurado
		{
			memset(dbg,0,sizeof(dbg));
			snprintf(dbg,sizeof(dbg)-1," %-15s%5i %3i %20s %s\n",inet_ntoa(client.sin_addr),port,GETdata->status,"                    ",GETdata->server);
			if((LogFile) && (ShowAll)) { fwrite(dbg,1,strlen(dbg),LogFile); fflush(LogFile); }
			if(ShowAll) printf("%s",dbg);
			FreeRequest(GETdata);
			return(NULL);
		}
	}
	return(GETdata);
}

void *Escanea(void *thread)
{
	int i;
	int login;
	struct sockaddr_in client;
	struct _request *data;
	char password[28]="                   ";
	const char unknownpass[]=   "not:found";//NoTfOuNd:nOtFoUnD ";
	char dbg[512];
   
	pthread_mutex_lock (&CSThreads);
	ThreadsActivos++;
	pthread_mutex_unlock (&CSThreads);         
   
	struct _fakeauth newFakeAuth,*AuthNeeded;
   
	while((client.sin_addr.s_addr=GetNextTarget())!=0)
	{
		for (i=0;i<nports;i++)
		{
			memset(password,' ',sizeof(password)-1); password[sizeof(password)-1]='\0';password[20]='\0';
			data=GetHttpRequest(client.sin_addr.s_addr,ports[i].port, ports[i].ssl);
 
			if (data)
			{
				// memset(path,'\0',sizeof(path));
				AuthNeeded=CheckBasicAuth(data,&newFakeAuth);
				if(AuthNeeded!=NULL)
				{
					login=TryHttpBasicAuth(data,AuthNeeded);
					if (login>=0) memcpy(password,userpass[login],strlen(userpass[login]));
					else memcpy(password,unknownpass,9);
				} else {
					int ret=CheckWebformAuth(data);
					if (ret>=0)
					{
						login=TryHTTPWebformAuth(client.sin_addr.s_addr,ports[i].port, ports[i].ssl,ret);
						if (login>=0)
						{
#ifdef _DBG_
							printf("login found: %i\n",login);
#endif
							if (login>=1024) memcpy(password,userpass[login-1024],strlen(userpass[login-1024]));
							else memcpy(password,logins[login],strlen(logins[login]));
						} else memcpy(password,unknownpass,9);
					}
				}
            
				//guardamos el log..
				memset(dbg,0,sizeof(dbg));
				snprintf(dbg,sizeof(dbg)-1," %-15s%5i %3i %20s %s\n",inet_ntoa(client.sin_addr),ports[i].port,data->status,password,data->server);
				if (LogFile) { fwrite(dbg,1,strlen(dbg),LogFile); fflush(LogFile);}
				//if((IgnoreNotGuesedPasswords==0) || ((IgnoreNotGuesedPasswords==1) && logins>=  ))
				//if((IgnoreNotGuesedPasswords==0) && logins != NULL )
				//if(logins != NULL)
					printf("%s",dbg);
				FreeRequest(data);
			}
		}
	}
 
	pthread_mutex_lock(&CSThreads);
	ThreadsActivos--;
	pthread_mutex_unlock(&CSThreads);
	pthread_exit(NULL);
	return NULL;
}

int main(int argc, char *argv[]){
	int i;
	char *p;
	struct sockaddr_in ip1,ip2;
	char dbg[512];

	pthread_t e_th;
   
	if(LoadConfigurationFiles(argc,argv)==1) exit(1);

	pthread_mutexattr_settype(&mutexattr,PTHREAD_MUTEX_RECURSIVE); // Set the mutex as recursive
	pthread_mutex_init(&CSip, &mutexattr);  // create the mutex with the attributes set
	pthread_mutex_init(&CSThreads, &secondmutexattr);
	pthread_mutexattr_destroy(&mutexattr);

	printf(" Server          Port status password          banner\n");
	for(i=0;i<MAX_THREADS;i++) {
		pthread_create(&e_th, NULL, Escanea, (void *)i);
	}

	Sleep(100); while(ThreadsActivos>0) { Sleep(500); }
	if(LogFile) fclose(LogFile);
	printf("scan Finished\n");   
	return(1);
}
