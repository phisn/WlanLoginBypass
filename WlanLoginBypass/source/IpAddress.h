#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>

#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class IpAddress
{
public:
	IpAddress() = default;
	IpAddress(const char* address)
	{
	}

	IpAddress(IPAddr address)
		:
		address(address)
	{
	}

	bool setIpAddress(
		const std::string address)
	{
		// InetPtonA();
		return true;
	}

	std::string toString()
	{
		// 3 x 255 (numbers) + 4 (dots) + 1 (zero)
		std::string result(3 * 4 + 4 + 1, '\0');

		InetNtopA(
			AF_INET, 
			&address, 
			(char*) result.c_str(), 
			3 * 4 + 4 + 1
		);
		 
		return result;
	}

private:
	IPAddr address = NULL;
};
