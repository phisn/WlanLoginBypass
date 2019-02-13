#include <ClientFinder.h> // must be before adapter
#include <ClientTester.h>
#include <Adapter.h>

int main()
{
	WSADATA wsad;

	WSAStartup(MAKEWORD(2, 2), &wsad);

	Adapter adapter = Adapter::GetAll()[3];
	ClientTester ct(&adapter);

	std::cout << ct.testConnection() << WSAGetLastError() << std::endl;

/*	ClientFinder clientFinder(adapter.toPcapDevice());
	std::thread th([&]() { clientFinder(); });
	th.join();*/
}