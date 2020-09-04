#ifndef RECEIVER_H
#define RECEIVER_H

//#include "libssh2_config.h"
#include "fx.h"
//#include "/data/projects/scanner/ipworksssh/include/ipworksssh.h"
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

using namespace std;
using namespace fx;
using namespace boost;


#define NORMAL "\033[0m"
#define BOLD (char)27 << "[1m"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define RESET "\033[0m"

#define FUCKYOU SIG_IGN

#endif

