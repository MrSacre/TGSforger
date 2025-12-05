#ifndef SOURCE_H
#define SOURCE_H

#define STATUS_SUCCESS 0x00000000

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <cstdlib>
#include <windows.h>
#include <ntsecapi.h>

#pragma comment(lib, "ws2_32.lib")

#pragma comment(lib, "Secur32.lib")

int ForgeTicket(PCWCH SPN,BOOL isLocal, SOCKET c);

#endif