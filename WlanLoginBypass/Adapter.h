#pragma once

#include "MACAddress.h"

#include <Windows.h>
#include <iphlpapi.h>

#include <iostream>
#include <string>
#include <vector>

#include <pcap.h>

#pragma comment(lib, "iphlpapi.lib")

#define REG_NEWORK_PATH_W L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
#define REG_ADAPTER_ID_A "NetCfgInstanceId"
#define REG_ADAPTER_NETADDRESS_A "NetworkAddress"

class Adapter
{
public:
	static std::vector<Adapter> GetAll()
	{
		std::vector<Adapter> result;

		ULONG len = 0;
		if (GetAdaptersInfo(NULL, &len) == ERROR_BUFFER_OVERFLOW)
		{
			PIP_ADAPTER_INFO adapters = (PIP_ADAPTER_INFO) new char[len];

			if (GetAdaptersInfo(adapters, &len) == NO_ERROR)
			{
				PIP_ADAPTER_INFO adapter = adapters;

				do
				{
					result.emplace_back(adapter);

				} while (adapter = adapter->Next);
			}

			delete[] (char*) adapters;
		}

		return result;
	}

	Adapter() = default;
	Adapter(PIP_ADAPTER_INFO adapterInfo)
	{
		memcpy(&info, adapterInfo, sizeof(IP_ADAPTER_INFO));
	}
	
	std::string toPcapDevice() const
	{
		char errorBuffer[PCAP_ERRBUF_SIZE] = "";

		pcap_if_t* networkDevice;
		if (pcap_findalldevs(
				&networkDevice,
				errorBuffer)
			== -1)
		{
			std::cout << errorBuffer << std::endl;
			return "\1Failed";
		}

		do
		{
			if (strstr(networkDevice->name, info.AdapterName) != NULL)
			{
				std::string result = networkDevice->name;
				pcap_freealldevs(networkDevice);
				
				return result;
			}

		} while (networkDevice = networkDevice->next);

		return "\1Not Found";
	}

	struct CMA_RESULT
	{
		enum
		{
			SUCCESS,
			NOT_FOUND,
			FAILED // see status
		} code;

		LSTATUS status;

	} changeMacAddress(const MACAddress macAddress)
	{
		CMA_RESULT result;
		HKEY networkKey;
		
		result.status = RegOpenKeyExW(
			HKEY_LOCAL_MACHINE,
			REG_NEWORK_PATH_W,
			0,
			KEY_ALL_ACCESS,
			&networkKey);
		if (result.status != ERROR_SUCCESS)
		{
			result.code = CMA_RESULT::FAILED;
			goto FAILED_INTRO;
		}

		DWORD adapterKeyNameSize;
		result.status = RegQueryInfoKeyW(
			networkKey,
			NULL, 
			NULL, NULL, NULL,
			&adapterKeyNameSize,
			NULL, NULL, NULL, 
			NULL, NULL, NULL);
		if (result.status != ERROR_SUCCESS)
		{
			result.code = CMA_RESULT::FAILED;
			goto FAILED_INTRO;
		}

		{	wchar_t* adapterKeyName = new wchar_t[adapterKeyNameSize];
			ZeroMemory(adapterKeyName, adapterKeyNameSize * sizeof(wchar_t));

			int adapterKeyIndex = 0;
			while (true)
			{
				result.status = RegEnumKeyW(
					networkKey,
					adapterKeyIndex++,
					adapterKeyName,
					adapterKeyNameSize);
				if (result.status != ERROR_SUCCESS)
				{
					result.code = CMA_RESULT::FAILED;
					goto FAILED_POST_ADAPTERKEYNAME;
				}

				bool adapterFound = false;
				HKEY adapterKey;
				result.status = RegOpenKeyExW(
					networkKey,
					adapterKeyName,
					0,
					KEY_ALL_ACCESS,
					&adapterKey);
				if (result.status != ERROR_SUCCESS)
				{
					continue;
				}

				DWORD adapterIdSize = NULL;
				DWORD adapterIdType = NULL;
				result.status = RegQueryValueExA(
					adapterKey,
					REG_ADAPTER_ID_A,
					NULL,
					&adapterIdType,
					NULL,
					&adapterIdSize);

				if (result.status != ERROR_SUCCESS ||
					adapterIdSize < 0 ||
					adapterIdType != REG_SZ)
				{
					goto FAILED_POST_ADAPTERKEY;
				}

				{	char* adapterID = new char[adapterIdSize];
					ZeroMemory(adapterID, adapterIdSize);

					result.status = RegQueryValueExA(
						adapterKey,
						REG_ADAPTER_ID_A,
						NULL,
						&adapterIdType,
						(PBYTE)adapterID,
						&adapterIdSize);

					if (result.status != ERROR_SUCCESS)
					{
						goto FAILED_POST_ADAPTERID;
					}

					adapterFound = memcmp(
						adapterID,
						info.AdapterName,
						adapterIdSize) == 0;

					if (!adapterFound)
					{
						goto FAILED_POST_ADAPTERID;
					}

					result.status = RegSetValueExA(
						adapterKey,
						REG_ADAPTER_NETADDRESS_A,
						NULL,
						REG_SZ,
						(const BYTE*) macAddress.toString().c_str(),
						18);

				FAILED_POST_ADAPTERID:
					delete[] adapterID;
				}

			FAILED_POST_ADAPTERKEY:
				RegCloseKey(adapterKey);

				if (adapterFound)
				{
					result.code = CMA_RESULT::SUCCESS;
					goto SUCCESS_ADAPTER_CHANGED;
				}
			}

			if (result.status != ERROR_NO_MORE_ITEMS)
			{
				result.code = CMA_RESULT::FAILED;

				goto FAILED_POST_ADAPTERKEYNAME;
			}

			result.code = CMA_RESULT::NOT_FOUND;
		
		SUCCESS_ADAPTER_CHANGED: FAILED_POST_ADAPTERKEYNAME:
			delete[] adapterKeyName;
		}

	FAILED_INTRO:
		return result;
	}

	void print()
	{
		std::cout << info.Description << std::endl;
		std::cout << info.AdapterName << std::endl;
		
		int i = 0;
		while (true)
		{
			std::cout.fill('0');
			std::cout.width(2);

			std::cout << std::hex << (int) info.Address[i];

			if (++i >= info.AddressLength)
			{
				break;
			}

			std::cout << ":";
		}

		std::cout << std::endl;
	}

private:
	IP_ADAPTER_INFO info;
};

