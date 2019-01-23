#pragma once

#include <string>
#include <sstream>

class MACAddress
{
	typedef unsigned char BYTE;
public:
	MACAddress(const char* strAddress)
		:
		MACAddress(
			std::string(strAddress)
		)
	{
	}

	MACAddress(const std::string strAddress)
	{
		int iter = 0;
		for (const char ch : strAddress)
			if ( isHex(ch) )
			{
				address[iter++] = ch;
			}
	}

	MACAddress(const BYTE* rawAddress)
	{
		memcpy(address, rawAddress, 6);
	}

	std::string toString(const char delimiter = '-') const
	{
		std::stringstream result;

		int i = 0;
		while (true)
		{
			result.width(2);
			result.fill('0');
			result << std::hex << (int) address[i];

			if (++i < 6)
			{
				result << delimiter;
			}
			else
			{
				break;
			}
		}

		return result.str();
	}

	const BYTE* raw() const
	{
		return address;
	}

	bool operator<(const MACAddress& mac)
	{
		return memcmp(address, mac.address, 6) < 0;
	}

	bool operator>(const MACAddress& mac)
	{
		return memcmp(address, mac.address, 6) > 0;
	}

private:
	bool isHex(wchar_t ch)
	{
		return 
			ch >= '0' && ch <= '9' ||
			ch >= 'A' && ch <= 'F' ||
			ch >= 'a' && ch <= 'f';
	}

	BYTE address[6];
};

static bool operator<(const MACAddress& mac1, const MACAddress& mac2)
{
	return memcmp(mac1.raw(), mac2.raw(), 6) < 0;
}

static bool operator>(const MACAddress& mac1, const MACAddress& mac2)
{
	return memcmp(mac1.raw(), mac2.raw(), 6) > 0;
}
