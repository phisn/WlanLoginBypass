#pragma once

#include <Adapter.h>
#include <Client.h>

#include <set>

#include <Windows.h>
#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")

class ClientTester
{
public:
	ClientTester(Adapter* const adapter)
		:
		adapter(adapter)
	{
	}

	bool testClients(const std::set<Client> clients)
	{
		for (const Client& client : clients)
		{
			if (Adapter::CMA_RESULT result = adapter->changeMacAddress(
					client.getMacAddress()); result.code != Adapter::CMA_RESULT::SUCCESS)
			{
				std::cout << "Failed to aquire MAC-Address: ";

				if (result.code == Adapter::CMA_RESULT::NOT_FOUND)
				{
					std::cout << "(Adapter not found)" << std::endl;
				}
				else
				{
					std::cout << "(Status Code: " << result.status << ")" << std::endl;
				}
			}

			adapter->restart();

			if (int result = testConnection(); result)
			{
				if (result != WSAEHOSTUNREACH)
				{
					std::cout << "Failed to connect to the internet: " << result << std::endl;
				}
			}
			else
			{
				return true;
			}
		}

		return false;
	}

	int testConnection()
	{
		SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);

		if (sock == SOCKET_ERROR)
		{
			return WSAGetLastError();
		}

		SOCKADDR_IN sockaddr;

		sockaddr.sin_addr.S_un.S_addr = MAKELONG(
			MAKEWORD(8, 8),
			MAKEWORD(8, 8));
		sockaddr.sin_family = AF_INET;
		sockaddr.sin_port = htons(53);

		if (connect(sock, (SOCKADDR*)&sockaddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
		{
			return WSAGetLastError();
		}

		closesocket(sock);

		return 0;
	}

private:
	Adapter* const adapter;
};

