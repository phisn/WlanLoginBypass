#pragma once

#include <IpAddress.h>
#include <MacAddress.h>

#include <iostream>
#include <string>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <iphlpapi.h>
#include <IcmpAPI.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

class Client
{
public:
	Client(
		const IpAddress ipAddress,
		const MacAddress macAddress)
		:
		ipAddress(ipAddress),
		macAddress(macAddress)
	{
	}

	bool validateClient()
	{
		/*
		IPAddr address;
		InetPtonA(AF_INET, ipAddress.c_str(), &address);

		if (int result = InetPtonA(
				AF_INET, 
				ipAddress.c_str(),
				&address)
			; result != 1)
		{
			if (result == 0)
			{
				std::cout << "Got invalid IPAddress" << std::endl;
				return false;
			}
			else
			{
				std::cout << "Got error '" << WSAGetLastError() << "'" << std::endl;

				return false;
			}
		}
		*/
	}

	IpAddress getIpAddress() const
	{
		return ipAddress;
	}

	MacAddress getMacAddress() const
	{
		return macAddress;
	}

private:
	const IpAddress ipAddress;
	const MacAddress macAddress;
};

static bool operator<(const Client& client1, const Client& client2)
{
	return client1.getMacAddress() < client2.getMacAddress(); // ignore ip
}

static bool operator>(const Client& client1, const Client& client2)
{
	return client1.getMacAddress() > client2.getMacAddress(); // ignore ip
}
