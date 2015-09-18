#include "../../receiver.h"


void BusSignalFunction(int sign)
{
   static unsigned TotalSignalRecieved;
   deb(KRED "[bus/abort signal recieved #%4d]\r\n" RESET,
      TotalSignalRecieved++);
 //  sleep(2);
   abort();
   //signal(sign, SIG_IGN);
}

void FinishProgram(int sign)
{
   deb(KRED "[" RESET "\r\n\tFinishProgram signal recieved, w8 and bye " KRED "]" RESET "\r\n" );
}