#pragma once

#ifdef _WIN32 // _WIN32 is defined for both 32-bit and 64-bit Windows systems
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOGDI
// winsock2.h must be included before windows.h to prevent
// redefinition errors from the older winsock.h that windows.h
// would otherwise pull in.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#define WINDOWS_SPECIFIC_MACRO // This expands to nothing on non-Windows systems
#endif
