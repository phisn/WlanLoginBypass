#pragma once

#include <Windows.h>

#include <chrono>
#include <thread>

#include <ClientFinder.h>
#include <ClientTester.h>

class Application
{
	static DWORD WINAPI static_runner(void* const data)
	{
		((Application* const) data)->clientFinder.run();
		
		return 0;
	}

public:
	Application(Adapter* const adapter)
		:
		adapter(adapter),
		clientTester(adapter)
	{
	}

	bool initialize()
	{
		if (Adapter::GRK_RESULT result = adapter->resetMacAddress()
			; result.code != Adapter::GRK_RESULT::SUCCESS)
		{
			if (result.code == Adapter::GRK_RESULT::FAILED)
			{
				std::cout << "Failed to reset MAC (" << result.status << ")" << std::endl;
			}
			else
			{
				std::cout << "Failed to find MAC" << std::endl;
			}

			return false;
		}

		if (!createClientFinder())
		{
			return false;
		}

		std::cout << "Starting initialize sleep (30 sec)" << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(30));

		if (DWORD exitCode; !GetExitCodeThread(clientFinderThread, &exitCode) || exitCode != STILL_ACTIVE)
		{
			std::cout << "ClientFinder thread failed (" << exitCode << ")" << std::endl;

			return false;
		}

		return true;
	}

	int run()
	{
		while (true)
		{
			std::set<Client> clients = clientFinder.stripClients();

			if (clients.size() == 0)
			{
				std::cout << "No clients found, waiting (5 sec)" << std::endl;

				std::this_thread::sleep_for(
					std::chrono::seconds(5)
				);

				continue;
			}

			std::cout << "Testing " << clients.size() << " clients" << std::endl;

			switch (
				clientTester.testClients(std::move(clients)) 
				)
			{
			case -1:

				return 0x0001'0000;
			case 0:
				if (!hibernate())
				{
					return 0x0002'0000;
				}

				break;
			case 1:
				break;
			}
		}

		return 0;
	}

private:
	bool createClientFinder()
	{
		const std::pair<std::string, bool> result = adapter->toPcapDevice();

		if (!result.second)
		{
			return false;
		}

		if (!clientFinder.initialize(result.first))
		{
			return false;
		}

		DWORD threadId;
		clientFinderThread = CreateThread(
			NULL,
			NULL,
			static_runner,
			(void*) this,
			0,
			&threadId);

		if (clientFinderThread == NULL)
		{
			std::cout << "Failed to start ClientFinder thread (" << GetLastError() << ")" << std::endl;

			return false;
		}

		return true;
	}

	bool hibernate()
	{
		std::cout << std::endl << "suspending ..." << std::endl;

		clientFinder.stop();
		if (DWORD result = WaitForSingleObject(clientFinderThread, 1000 * 5)
			; result != WAIT_OBJECT_0)
		{
			DWORD threadExitCode;
			GetExitCodeThread(clientFinderThread, &threadExitCode);

			std::cout << "Failed to await thread (result: " << result 
				<< " : exitcode: " << threadExitCode << ")" << std::endl;

			return false;
		}

		while (true)
		{
			std::this_thread::sleep_for(
				std::chrono::seconds(5)
			);

			if (clientTester.testConnection() != 0)
			{
				std::cout << "Internet connection lost, resuming ..." << std::endl << std::endl;

				break;
			}
		}

		if (!createClientFinder())
		{
			return false;
		}

		return true;
	}

	Adapter* const adapter;
	ClientTester clientTester;
	ClientFinder clientFinder;
	HANDLE clientFinderThread;
};
