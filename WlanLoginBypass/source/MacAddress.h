#pragma once

#include <string>
#include <sstream>

class MacAddress
{
	typedef unsigned char BYTE;
public:
	MacAddress(const char* strAddress)
		:
		MacAddress(
			std::string(strAddress)
		)
	{
	}

	MacAddress(const std::string strAddress)
	{
		int iter = 0;
		for (const char ch : strAddress)
			if ( isHex(ch) )
			{
				address[iter++] = ch;
			}
	}

	MacAddress(const BYTE* rawAddress)
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

static bool operator<(const MacAddress& mac1, const MacAddress& mac2)
{
	return memcmp(mac1.raw(), mac2.raw(), 6) < 0;
}

static bool operator>(const MacAddress& mac1, const MacAddress& mac2)
{
	return memcmp(mac1.raw(), mac2.raw(), 6) > 0;
}

