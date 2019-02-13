#include <ClientFinder.h> // must be before adapter
#include <ClientTester.h>
#include <Adapter.h>

#define INIT_SOCKET_FAILED 1
#define INCORRECT_ADAPTER_SELECTION 2
#define PCAP_ADAPTER_NOT_FOUND 3

bool initSocket()
{
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) == SOCKET_ERROR)
	{
		std::cout << "Failed to initialize socket libary (" << WSAGetLastError() << ")" << std::endl;

		return false;
	}

	return true;
}

bool selectAdapter(Adapter* const adapter)
{
	const std::vector<Adapter> adapters = Adapter::GetAll();

	// prepare cout width
	int adapterNameLength = 0;
	const int adapterCountLength = log10(adapters.size()) + 1;

	for (const Adapter& adapter : adapters)
	{
		const int currentAdapterNameLength = strlen(adapter.getAdapterInfo()->Description);

		if (currentAdapterNameLength > adapterNameLength)
		{
			adapterNameLength = currentAdapterNameLength;
		}
	}

	// print all adapters
	std::cout << std::endl;
	for (int i = 0; i < adapters.size(); ++i)
	{
		std::cout.width(adapterCountLength); // iterator
		std::cout << i + 1 << " : ";

		// mac address
		std::cout.fill('0');

		int j = 0;
		while (true)
		{
			std::cout.width(2);
			std::cout << std::hex << (int) adapters[i].getAdapterInfo()->Address[j];

			if (++j >= adapters[i].getAdapterInfo()->AddressLength)
			{
				break;
			}

			std::cout << ":";
		}

		std::cout << " : ";

		// reset fill
		std::cout.fill(' ');

		// name / description
		std::cout.width(adapterNameLength);
		std::cout << std::left << adapters[i].getAdapterInfo()->Description << " : ";

		// print adapter type
		switch (adapter->getAdapterInfo()->Type)
		{
		case 1:
			std::cout << "Unkown type";

			break;
		case 6:
			std::cout << "Ethernet network interface";

			break;
		case 9:
			std::cout << "IF_TYPE_ISO88025_TOKENRING";

			break;
		case 23:
			std::cout << "PPP network interface";

			break;
		case 24:
			std::cout << "Loopback network interface";

			break;
		case 28:
			std::cout << "ATM network interface";

			break;
		case 71:
			std::cout << "IEEE 802.11 wireless network interface";

			break;
		}

		std::cout << std::endl;
	}

	// select adapter
	std::cout << std::endl << "Select your desired adapter (1 - " << adapters.size() << "): ";
	
	int selection;
	std::cin >> selection;

	// make space
	std::cout << std::endl;

	if (selection > 0 && selection <= adapters.size())
	{
		*adapter = adapters[selection - 1];

		return true;
	}
	else
	{
		std::cout << "Incorrect selection" << std::endl;

		return false;
	}
}

int main()
{
	std::cout << "Initializing components..." << std::endl;
	if (!initSocket())
	{
		return INIT_SOCKET_FAILED;
	}

	Adapter adapter;
	if (!selectAdapter(&adapter))
	{
		return INCORRECT_ADAPTER_SELECTION;
	}

	return 0;
	
	adapter.resetMacAddress();
	std::pair<std::string, bool> result;

	if (!result.second)
	{
		return PCAP_ADAPTER_NOT_FOUND;
	}

	ClientFinder clientFinder(result.first);
	std::thread clientFinderThread(
		std::ref(clientFinder)
	);

	std::cout << "Starting initialize sleep (30 sec)" << std::endl;
	std::this_thread::sleep_for(
		std::chrono::seconds(30)
	);


}