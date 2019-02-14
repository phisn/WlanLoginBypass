#pragma once

#include <Client.h>
#include <MacAddress.h>

#include <Windows.h>

#include <iostream>
#include <mutex>
#include <set>
#include <vector>
#include <pcap.h>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

#define CONVERT_TO_PTR(type, val) (*(type*)(val))

#define REVERSE_TO_08_PTR(val) CONVERT_TO_PTR(char, val)
#define REVERSE_TO_16_PTR(val) MAKEWORD(REVERSE_TO_08_PTR(val + 1), REVERSE_TO_08_PTR(val))
#define REVERSE_TO_32_PTR(val) MAKELONG(REVERSE_TO_16_PTR(val + 2), REVERSE_TO_16_PTR(val))

#define PROTO_TYPE_ARP	0x0806
#define PROTO_TYPE_IP	0x0800

#define DEF_PROTO_OFFSET 12
#define ARP_PROTO_OFFSET 16

#define DEF_MACTARGET_OFFSET 0
#define DEF_MACSOURCE_OFFSET 6

#define IP_IPSOURCE_OFFSET 26 // propably wrong
#define IP_IPTARGET_OFFSET 30

#define ARP_IPSOURCE_OFFSET 28
#define ARP_IPTARGET_OFFSET 38

class ClientFinder
{
	static void __cdecl static_runner(
		u_char* const clientFinder,
		const pcap_pkthdr* const packetHeader,
		const u_char* const packetData)
	{
		((ClientFinder*) clientFinder)->packetHandler(packetHeader, packetData);
	}

public:
	~ClientFinder()
	{
		if (captureHandle)
		{
			stop();
		}
	}

	bool initialize(const std::string networkDevice)
	{
		{	char errorBuffer[PCAP_ERRBUF_SIZE] = "";
			captureHandle = pcap_open_live(
				networkDevice.c_str(),
				66536,
				0,
				1000,
				errorBuffer);

			if (errorBuffer[0])
			{
				if (captureHandle == NULL)
				{
					std::cout << "Failed to call pcap_open_live (" << errorBuffer << ")" << std::endl;

					return false;
				}
				else
				{
					std::cout << "Warning: " << errorBuffer << std::endl;
				}
			}
		} // deallocate errorBuffer

		bpf_program compiledFilter;
		if (pcap_compile(
				captureHandle, 
				&compiledFilter, 
				"arp or rarp or ip or vlan", 
				FALSE, 0) 
			== PCAP_ERROR)
		{
			std::cout << "Failed to call pcap_compile (" << pcap_geterr(captureHandle) << ")" << std::endl;

			return false;
		}

		if (pcap_setfilter(
				captureHandle, 
				&compiledFilter) 
			== PCAP_ERROR)
		{
			std::cout << "Failed to call pcap_setfilter (" << pcap_geterr(captureHandle) << ")" << std::endl;

			return false;
		}
		
		return true;
	}

	void run()
	{
		pcap_loop(captureHandle, -1, static_runner, (u_char*) this);
	}

	void stop()
	{
		pcap_breakloop(captureHandle);
		pcap_close(captureHandle);

		clients.clear();
	}
	
	std::set<Client> stripClients()
	{
		std::lock_guard<std::mutex> lock(clientMutex);
		return std::move(clients);
	}

private:
	void packetHandler(
		const pcap_pkthdr* const packetHeader,
		const u_char* const packetData)
	{
		std::lock_guard<std::mutex> lock(clientMutex);
		std::pair<decltype(clients)::iterator, bool> result = { };

		switch (REVERSE_TO_16_PTR(packetData + DEF_PROTO_OFFSET))
		{
		case PROTO_TYPE_IP:
			result = 
			clients.emplace(
				IpAddress(CONVERT_TO_PTR(
					IPAddr,
					packetData + IP_IPSOURCE_OFFSET)),
				MacAddress(
					packetData + DEF_MACSOURCE_OFFSET)
			);

			break;
		case PROTO_TYPE_ARP:
			if (REVERSE_TO_16_PTR(packetData + ARP_PROTO_OFFSET) == PROTO_TYPE_IP)
			{
				result = 
				clients.emplace(
					IpAddress(CONVERT_TO_PTR(
						IPAddr,
						packetData + ARP_IPSOURCE_OFFSET)),
					MacAddress(
						packetData + DEF_MACSOURCE_OFFSET)
				);
			}
			else
			{
				result = 
				clients.emplace(
					IpAddress(),
					MacAddress(packetData + DEF_MACSOURCE_OFFSET)
				);
			}

			break;
		default:
			std::cout << "Invalid protocol (" << REVERSE_TO_16_PTR(packetData + DEF_PROTO_OFFSET) << ")" << std::endl;

			return;
		}

		if (result.second)
		{
			std::cout << "Found => IP: " << result.first->getIpAddress().toString() << "  MAC: " << result.first->getMacAddress().toString() << ";" << std::endl;
		}
	}

	pcap_t* captureHandle = NULL;

	std::mutex clientMutex;
	std::set<Client> clients;
};
