#include <Windows.h>

#include "Adapter.h"
#include "ClientFinder.h"

#include <chrono>
#include <iostream>
#include <thread>

int SelectAdapter(Adapter* outputAdapter)
{
	std::vector<Adapter> adapters = Adapter::GetAll();

	if (adapters.size() == 0)
	{
		std::cout << "No adapters found!" << std::endl;

		return 1;
	}
}

bool HasInternetConnection()
{
	return false;
}

struct HijackResult
{
	enum Type
	{
		WinError,
		Failed,
		Success		
	} type;

	int code;
} TryHijackClient(
	Adapter* const adapter,
	Client* const client)
{
	return { };
}

bool TryHijackAll(
	Adapter* const adapter,
	std::vector<Client>& clients)
{
	for (Client& client : clients)
	{
		HijackResult result = TryHijackClient(adapter, &client);

		if (result.type == HijackResult::Success)
		{
			return true;
		}

		if (result.type == HijackResult::WinError)
		{
			// ...
		}
	}

	return false;
}

int main()
{
	/*Adapter adapter;
	if (int result = SelectAdapter(&adapter); result)
	{
		return result;
	}*/

	Adapter adapter = Adapter::GetAll()[3];
	ClientFinder clientFinder( adapter.toPcapDevice() );
	std::thread th([&]() { clientFinder(); });

	std::this_thread::sleep_for(std::chrono::seconds(30));

	clientFinder.stop();
	th.join();
	clientFinder.print();

/*	std::thread clientFinderThread = std::thread(clientFinder);
	clientFinderThread.join();*/
	/*
	while (true)
	{
		std::vector<Client> clients = clientFinder.getClients();

		// remove all clients from previous iteration

		if (clients.size() == 0)
		{
			if ( !clientThread.is_not_dead() )
			{
				// ...
			]

			std::this_thread::sleep_for(
				std::chrono::seconds(1)
			);

			continue;
		}

		std::cout << "Testing " << clients.size() << " Clients" << std::endl;

		if ( !TryHijackAll(&adapter, clients) )
		{
			continue;
		}

		std::cout << "Aquired Internetconnection" << std::endl;

		do
		{
			std::this_thread::sleep_for(
				std::chrono::minutes(1) // TODO: increase?
			);

		} while (HasInternetConnection());

		std::cout << "Internetconnection lost, retry" << std::endl;
	}*/
}