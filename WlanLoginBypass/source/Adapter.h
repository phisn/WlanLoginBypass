#pragma once

#include <MacAddress.h>

#include <Windows.h>

#include <iphlpapi.h>
#include <NetCon.h>

#include <iostream>
#include <string>
#include <vector>
#include <utility>

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
	
	std::pair<std::string, bool> toPcapDevice() const
	{
		char errorBuffer[PCAP_ERRBUF_SIZE] = "";

		pcap_if_t* networkDevice;
		if (pcap_findalldevs(
				&networkDevice,
				errorBuffer)
			== -1)
		{
			return { errorBuffer, false };
		}

		do
		{
			if (strstr(networkDevice->name, info.AdapterName) != NULL)
			{
				std::string result = networkDevice->name;
				pcap_freealldevs(networkDevice);
				
				return { result, true };
			}

		} while (networkDevice = networkDevice->next);

		return { "Not found as PCAP device", false };
	}

	bool restartDevice()
	{
		bool successfullyRestarted = false;

		INetConnectionManager* netConnectionManager;
		if (HRESULT result = CoCreateInstance(
				CLSID_ConnectionManager,
				NULL,
				CLSCTX_LOCAL_SERVER | CLSCTX_NO_CODE_DOWNLOAD,
				IID_INetConnectionManager,
				(void**) &netConnectionManager);
			result != S_OK)
		{
			std::cout << "Failed to create NetConnectionManger (" << result << ")" << std::endl;

			return false;
		}

		IEnumNetConnection* enumNetConnection;
		if (HRESULT result = netConnectionManager->EnumConnections(
				NCME_DEFAULT,
				&enumNetConnection);
			FAILED(result))
		{
			std::cout << "Failed to EnumConnections (" << result << ")" << std::endl;

			// goto NET_ENUM_CONNECTIONS_FAILED;
		}

		{	std::wstring wAdapterName(
				info.Description,
				info.Description + strlen(info.Description)
			);

			while (true)
			{
				NETCON_PROPERTIES* connectionProperties;
				INetConnection* connection;

				unsigned long ulCount;
				if (HRESULT result = enumNetConnection->Next(
						1,
						&connection,
						&ulCount);
					FAILED(result))
				{
					std::cout << "Failed to get next EnumNetConnection (" << result << ")" << std::endl;

					break;
				}

				if (ulCount != 1)
				{
					std::cout << "Invalid ulCount" << std::endl;

					break;
				}

				if (HRESULT result = connection->GetProperties(
						&connectionProperties);
					FAILED(result))
				{
					std::cout << "Failed to get ConnectionProperties (" << result << ")" << std::endl;

					break;
				}

				const bool isCorrectAdapter = wcscmp(
					connectionProperties->pszwDeviceName,
					wAdapterName.c_str()
				) == 0;

				CoTaskMemFree(connectionProperties->pszwName);
				CoTaskMemFree(connectionProperties->pszwDeviceName);
				CoTaskMemFree(connectionProperties);

				if (isCorrectAdapter)
				{
					if (HRESULT result = connection->Disconnect(); FAILED(result))
					{
						std::cout << "Failed to disconnect adapter (" << result << ")" << std::endl;
						
						goto FAILED_DIS_CONNECT;
					}

					if (HRESULT result = connection->Connect(); FAILED(result))
					{
						std::cout << "Failed to connect adapter (" << result << ")" << std::endl;

						goto FAILED_DIS_CONNECT;
					}

					successfullyRestarted = true;
				}

			FAILED_DIS_CONNECT:
				connection->Release();

				if (isCorrectAdapter)
				{
					break;
				}
			}
		}

		enumNetConnection->Release();
	NET_ENUM_CONNECTIONS_FAILED:
		netConnectionManager->Release();

		return successfullyRestarted;
	}

	struct GRK_RESULT
	{
		enum
		{
			SUCCESS,
			NOT_FOUND,
			FAILED // see status
		} code;

		LSTATUS status;

	};
	
	GRK_RESULT changeMacAddress(const MacAddress macAddress)
	{
		std::pair<const HKEY, GRK_RESULT> result = getAdapterRegistryKey();

		if (result.second.code == GRK_RESULT::SUCCESS)
		{
			std::cout << "Setting to " << macAddress.toString() << std::endl;
			
			result.second.status = RegSetValueExA(
				result.first,
				REG_ADAPTER_NETADDRESS_A,
				NULL,
				REG_SZ,
				(const BYTE*) macAddress.toString().c_str(),
				18);
			if (result.second.status != ERROR_SUCCESS)
			{
				result.second.code = GRK_RESULT::FAILED;
			}

			RegCloseKey(result.first);
		}

		return result.second;
	}

	GRK_RESULT resetMacAddress()
	{
		std::pair<const HKEY, GRK_RESULT> result = getAdapterRegistryKey();

		if (result.second.code == GRK_RESULT::SUCCESS)
		{
			result.second.status = RegDeleteValueA(
				result.first,
				REG_ADAPTER_NETADDRESS_A
			);

			if (result.second.status != ERROR_SUCCESS)
			{
				if (result.second.status == ERROR_FILE_NOT_FOUND)
				{
					result.second.status = ERROR_SUCCESS;
				}
				else
				{
					result.second.code = GRK_RESULT::FAILED;
				}
			}

			RegCloseKey(result.first);
		}

		return result.second;
	}

	std::pair<HKEY, GRK_RESULT> getAdapterRegistryKey()
	{
		GRK_RESULT resultGRK;
		HKEY resultKey = NULL;
		HKEY networkKey;

		resultGRK.status = RegOpenKeyExW(
			HKEY_LOCAL_MACHINE,
			REG_NEWORK_PATH_W,
			0,
			KEY_ALL_ACCESS,
			&networkKey);
		if (resultGRK.status != ERROR_SUCCESS)
		{
			resultGRK.code = GRK_RESULT::FAILED;
			goto FAILED_INTRO;
		}

		DWORD adapterKeyNameSize;
		resultGRK.status = RegQueryInfoKeyW(
			networkKey,
			NULL,
			NULL, NULL, NULL,
			&adapterKeyNameSize,
			NULL, NULL, NULL,
			NULL, NULL, NULL);
		if (resultGRK.status != ERROR_SUCCESS)
		{
			resultGRK.code = GRK_RESULT::FAILED;
			goto FAILED_INTRO;
		}

		{	wchar_t* adapterKeyName = new wchar_t[adapterKeyNameSize];
		ZeroMemory(adapterKeyName, adapterKeyNameSize * sizeof(wchar_t));

		int adapterKeyIndex = 0;
		while (true)
		{
			resultGRK.status = RegEnumKeyW(
				networkKey,
				adapterKeyIndex++,
				adapterKeyName,
				adapterKeyNameSize);
			if (resultGRK.status != ERROR_SUCCESS)
			{
				resultGRK.code = GRK_RESULT::FAILED;
				goto FAILED_POST_ADAPTERKEYNAME;
			}

			bool adapterFound = false;
			HKEY adapterKey;
			resultGRK.status = RegOpenKeyExW(
				networkKey,
				adapterKeyName,
				0,
				KEY_ALL_ACCESS,
				&adapterKey);
			if (resultGRK.status != ERROR_SUCCESS)
			{
				continue;
			}

			DWORD adapterIdSize = NULL;
			DWORD adapterIdType = NULL;
			resultGRK.status = RegQueryValueExA(
				adapterKey,
				REG_ADAPTER_ID_A,
				NULL,
				&adapterIdType,
				NULL,
				&adapterIdSize);

			if (resultGRK.status != ERROR_SUCCESS ||
				adapterIdSize < 0 ||
				adapterIdType != REG_SZ)
			{
				goto FAILED_POST_ADAPTERKEY;
			}

			{	char* adapterID = new char[adapterIdSize];
			ZeroMemory(adapterID, adapterIdSize);

			resultGRK.status = RegQueryValueExA(
				adapterKey,
				REG_ADAPTER_ID_A,
				NULL,
				&adapterIdType,
				(PBYTE)adapterID,
				&adapterIdSize);

			if (resultGRK.status != ERROR_SUCCESS)
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

			std::cout << info.AdapterName << " : " << adapterID << " : " << adapterKey << std::endl;

			resultKey = adapterKey;
		FAILED_POST_ADAPTERID:
			delete[] adapterID;
			}

		FAILED_POST_ADAPTERKEY:
			if (resultKey != adapterKey)
			{
				RegCloseKey(adapterKey);
			}

			if (adapterFound)
			{
				resultGRK.code = GRK_RESULT::SUCCESS;
				goto SUCCESS_ADAPTER_CHANGED;
			}
		}

		if (resultGRK.status != ERROR_NO_MORE_ITEMS)
		{
			resultGRK.code = GRK_RESULT::FAILED;

			goto FAILED_POST_ADAPTERKEYNAME;
		}

		resultGRK.code = GRK_RESULT::NOT_FOUND;

	SUCCESS_ADAPTER_CHANGED: FAILED_POST_ADAPTERKEYNAME:
		delete[] adapterKeyName;
		}

	FAILED_INTRO:
		return { resultKey, resultGRK };
	}

	const IP_ADAPTER_INFO* getAdapterInfo() const
	{
		return &info;
	}

private:
	IP_ADAPTER_INFO info;
};

