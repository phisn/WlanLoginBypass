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

#define CONVERT_PTR(type, val) (*(type*)(val))

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
	const std::string networkDevice;
public:

	ClientFinder(
		const std::string networkDevice)
		:
		networkDevice(networkDevice)
	{
		current = this;
	}

	void operator()()
	{
		std::cout << networkDevice << std::endl;

		captureHandle = pcap_open_live(
			networkDevice.c_str(),
			66536, 
			0,
			1000,
			errorBuffer);
		
		if (errorBuffer[0])
		{
			std::cout << errorBuffer << std::endl;

			if (captureHandle == NULL)
			{
				return;
			}
		}

		bpf_program compiledFilter; //  or rarp or ip or vlan"
		if (pcap_compile(captureHandle, &compiledFilter, "arp or rarp or ip or vlan", FALSE, 0) == -1)
		{
			std::cout << pcap_geterr(captureHandle) << std::endl;
			return;
		}

		if (pcap_setfilter(captureHandle, &compiledFilter) == -1)
		{
			std::cout << pcap_geterr(captureHandle) << std::endl;
			return;
		}

		if (int result = pcap_loop(captureHandle, -1, packetHandler, NULL); result < 0)
		{
			std::cout << result << " : " << pcap_geterr(captureHandle) << std::endl;
			return;
		}
	}

	void stop()
	{
		pcap_breakloop(captureHandle);
	}
	
	void print()
	{
		for (const Client& client : clients)
		{
			std::cout << "MAC: '" << client.getMacAddress().toString() << "' IP: '" << client.getIpAddress().toString() << "'" << std::endl;
			/*std::cout << "RAW: " << std::endl;
		
			
			for (int i = 0; i < client.getSize(); ++i)
			{
				std::cout.width(3);
				std::cout.fill('0');
				std::cout << (int) client.getRaw()[i] << " ";
				
				if ((i + 1) % 16 == 0)
				{
					std::cout << std::endl;
					continue;
				}

				if ((i + 1) % 8 == 0)
				{
					std::cout << "  ";
				}
			}
			std::cout << std::endl;
			std::cout << std::endl;
			std::cout << std::endl;*/
		}
	}

	std::set<Client> getClients()
	{
		std::lock_guard<std::mutex> lock(clientMutex);
		return std::move(clients);
	}

private:
	static ClientFinder* current;
	static void packetHandler(
		u_char* user,
		const pcap_pkthdr* packetHeader,
		const u_char* packetData)
	{
		short result = MAKEWORD(CONVERT_PTR(char, packetData + DEF_PROTO_OFFSET + 1), CONVERT_PTR(char, packetData + DEF_PROTO_OFFSET));
		switch (result)
		{
		case PROTO_TYPE_IP:
			current->clients.emplace(
				IpAddress(CONVERT_PTR(
					IPAddr,
					packetData + IP_IPSOURCE_OFFSET)),
				MacAddress(
					packetData + DEF_MACSOURCE_OFFSET)
			);

			break;
		case PROTO_TYPE_ARP:
			if (CONVERT_PTR(short, packetData + ARP_PROTO_OFFSET) == PROTO_TYPE_IP)
			{
				current->clients.emplace(
					IpAddress(CONVERT_PTR(
						IPAddr,
						packetData + ARP_IPSOURCE_OFFSET)),
					MacAddress(
						packetData + DEF_MACSOURCE_OFFSET)
				);
			}
			else
			{
				current->clients.emplace(
					IpAddress(),
					MacAddress(packetData + DEF_MACSOURCE_OFFSET)
				);
			}

			break;
		}

		std::cout << std::hex << "(0x0" << result << std::dec << ") Size: " << packetHeader->len << " : " << packetHeader->caplen << std::endl;
	}

	pcap_t* captureHandle;
	char errorBuffer[PCAP_ERRBUF_SIZE] = "";

	std::mutex clientMutex;
	std::set<Client> clients;
};
