#ifndef FX_H
#define FX_H
#include <sstream>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
using namespace std;
namespace patch
{
template < typename T >
string to_string(const T& n)
{
    ostringstream stm ;
    stm << n ;
    return stm.str() ;
}
}

static pthread_mutex_t foo_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t trim_mutex = PTHREAD_MUTEX_INITIALIZER;
/* feature extensions */
namespace fx
{
static char* trim(char* str)
{
    char *dst;
    int i=0;
    pthread_mutex_lock(&trim_mutex);
    dst=(char*)malloc(strlen(str)+111);
    memset(dst, 0, strlen(str));
    while (str[i])
    {
        if (str[i]=='\n'||str[i]=='\r')
            dst[i]=0x20;
        else if (isascii(str[i]))
            dst[i]=str[i];
        i++;
    }
    dst[i+1]=0;
    strcpy(str, dst);
    free(dst);
    pthread_mutex_unlock(&trim_mutex);
    return str;
}
static char* fmterr(int err = NULL)
{
    static char szInternal[255] = {0};
    if (!err)
        err = errno;
    sprintf(szInternal, "%s", strerror(errno));
    return szInternal;
}
#ifdef FRELEASE
static void deb(char *msg, ...) {};
#else
static void deb(char *msg, ...)
{

    va_list ap;
    char string[8192];
    char stringout[8192];
    pthread_mutex_lock(&foo_mutex);
    va_start(ap, msg);
    vsprintf(string,  msg, ap);
    va_end(ap);
    snprintf(stringout, 8192, "%s",   string);
    fprintf(stderr, stringout);
    pthread_mutex_unlock(&foo_mutex);
}
static void fdeb(char *msg, ...)
{
    static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
    va_list ap;
    char string[8192];
    char stringout[8192];
    pthread_mutex_lock(&file_mutex);
    va_start(ap, msg);
    vsprintf(string,  msg, ap);
    va_end(ap);
    snprintf(stringout, 8192, "%s",   string);
    FILE *fp;
    fp = fopen("log.txt", "a+");
    fwrite(stringout, strlen(stringout), 1, fp);
    fclose(fp);
    pthread_mutex_unlock(&file_mutex);
}
#endif
static string RandomString(int size)
{
    char letters[] = "-./_QWERTYUIOPASDFGH"
                     "JKLZZXCVBNM";
    string str;
    // size=10000;
    if (size<=0)
        return "";
    str.resize(size+1);
    char *ptrStr=(char*)str.c_str();
    while (size >= 0)
    {
        char letter;
        letter=letters[rand()%(sizeof(letters)-1)];
        //while(size >= 0 && rand()%2==1)
        // ptrStr[size--] = letter;
        //if(size>=0)
        ptrStr[size--] = letter;
    }
    return str;
}
}
#endif

