#pragma once

#include <Adapter.h>
#include <Client.h>

#include <set>

#include <Windows.h>
#include <WinSock2.h>

#include <thread>

#pragma comment(lib, "ws2_32.lib")

class ClientTester
{
public:
	ClientTester(Adapter* const adapter)
		:
		adapter(adapter)
	{
	}

	// -1 = fatal | 0 = success | 1 failed
	int testClients(const std::set<Client> clients)
	{
		for (const Client& client : clients)
		{
			if (Adapter::GRK_RESULT result = adapter->changeMacAddress(
					client.getMacAddress()); result.code != Adapter::GRK_RESULT::SUCCESS)
			{
				std::cout << "Failed to aquire MAC-Address: ";

				if (result.code == Adapter::GRK_RESULT::NOT_FOUND)
				{
					std::cout << "(Adapter not found)" << std::endl;
				}
				else
				{
					std::cout << "(Status Code: " << result.status << ")" << std::endl;
				}

				return -1;
			}

			if (!adapter->restartDevice())
			{
				std::cout << "Failed to restart adapter" << std::endl;

				return -1;
			}

			if (int result = testConnection(); result)
			{
				if (result != WSAEHOSTUNREACH)
				{
					std::cout << "Failed to connect to the internet (" << result << ")" << std::endl;

					return -1;
				}
			}
			else
			{
				std::cout << std::endl << "Successfully aquired internet connection as " << std::endl;
				std::cout << " - IP:  " << client.getIpAddress().toString() << std::endl;
				std::cout << " - MAC: " << client.getMacAddress().toString() << std::endl;

				return 0;
			}
		}

		return 1;
	}

	int testConnection()
	{
		SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);

	RETRY_1:
		if (sock == SOCKET_ERROR)
		{
			const int result = WSAGetLastError();

			if (result == 0x2743)
			{
				std::this_thread::sleep_for(
					std::chrono::seconds(1)
				);

				goto RETRY_1;
			}

			return result;
		}

		SOCKADDR_IN sockaddr;

		sockaddr.sin_addr.S_un.S_addr = MAKELONG(
			MAKEWORD(8, 8),
			MAKEWORD(8, 8));
		sockaddr.sin_family = AF_INET;
		sockaddr.sin_port = htons(53);

	RETRY_2:
		if (connect(sock, (SOCKADDR*)&sockaddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
		{
			const int result = WSAGetLastError();

			if (result == 0x2743)
			{
				std::this_thread::sleep_for(
					std::chrono::seconds(1)
				);

				goto RETRY_2;
			}

			closesocket(sock);

			return result;
		}

		closesocket(sock);

		return 0;
	}

private:
	Adapter* const adapter;
};

