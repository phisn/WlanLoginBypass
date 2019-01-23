#pragma once

#include "Client.h"
#include "MACAddress.h"

#include <Windows.h>

#include <iostream>
#include <mutex>
#include <set>
#include <vector>
#include <pcap.h>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

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
		for (const MACAddress& mac : macs)
		{
			std::cout << mac.toString() << std::endl;
		}
	}

	std::vector<Client> getClients()
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
		current->macs.insert(MACAddress((unsigned char*) packetData + 6));
	}

	pcap_t* captureHandle;
	char errorBuffer[PCAP_ERRBUF_SIZE] = "";

	std::mutex clientMutex;
	std::vector<Client> clients;

	std::set<MACAddress> macs;
};
