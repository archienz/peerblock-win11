/*
	Copyright (C) 2004-2005 Cory Nelson

	This software is provided 'as-is', without any express or implied
	warranty.  In no event will the authors be held liable for any damages
	arising from the use of this software.

	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:

	1. The origin of this software must not be misrepresented; you must not
		claim that you wrote the original software. If you use this software
		in a product, an acknowledgment in the product documentation would be
		appreciated but is not required.
	2. Altered source versions must be plainly marked as such, and must not be
		misrepresented as being the original software.
	3. This notice may not be removed or altered from any source distribution.

*/

#include "stdafx.h"
#include <p2p/list.hpp>
using namespace std;

static void v6_prefix_bounds(unsigned char addr[16], unsigned prefix, unsigned char start[16], unsigned char end[16]) {
	memcpy(start, addr, 16);
	memcpy(end, addr, 16);
	if (prefix > 128) prefix = 128;
	for (unsigned i = 0; i < 16; ++i) {
		unsigned bit0 = i * 8;
		if (bit0 + 8 <= prefix) continue;
		if (bit0 >= prefix) { start[i] = 0; end[i] = 0xFF; continue; }
		unsigned keep = prefix - bit0;
		unsigned char mask = (unsigned char)(0xFFu << (8 - keep));
		start[i] &= mask;
		end[i] |= (unsigned char)~mask;
	}
}

static void PushIps(set<unsigned int> &iplist, const IP_ADDR_STRING *ips) {
	for(; ips; ips=ips->Next) {
		if(ips->IpAddress.String[0]) {
			unsigned short ip1, ip2, ip3, ip4;

			if(sscanf(ips->IpAddress.String, "%hu.%hu.%hu.%hu", &ip1, &ip2, &ip3, &ip4)==4) {
				union {
					unsigned int ip;
					unsigned char ipb[4];
				};

				ipb[0]=(unsigned char)ip4;
				ipb[1]=(unsigned char)ip3;
				ipb[2]=(unsigned char)ip2;
				ipb[3]=(unsigned char)ip1;

				if(ip) iplist.insert(ip);
			}
		}
	}
}

void GetLocalIps(set<unsigned int> &ips, unsigned int types) {
	ULONG buflen=0;

	if(GetAdaptersInfo(NULL, &buflen)==ERROR_BUFFER_OVERFLOW) {
		IP_ADAPTER_INFO *info=(IP_ADAPTER_INFO*)malloc(buflen);

		if(GetAdaptersInfo(info, &buflen)==ERROR_SUCCESS) {
			for(IP_ADAPTER_INFO *iter=info; iter!=NULL; iter=iter->Next) {
				if(types&LOCALIP_GATEWAY) PushIps(ips, &iter->GatewayList);
				if(iter->DhcpEnabled && types&LOCALIP_DHCP) PushIps(ips, &iter->DhcpServer);
			}
		}
		free(info);
	}

	if(types&LOCALIP_ADAPTER || types&LOCALIP_DNS) {
		buflen=0;
		DWORD flags=GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_FRIENDLY_NAME|GAA_FLAG_SKIP_MULTICAST;

		if((types&LOCALIP_ADAPTER) == 0) flags|=GAA_FLAG_SKIP_UNICAST;
		if((types&LOCALIP_DNS) == 0) flags|=GAA_FLAG_SKIP_DNS_SERVER;

		if(GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &buflen)==ERROR_BUFFER_OVERFLOW) {
			IP_ADAPTER_ADDRESSES *addresses=(IP_ADAPTER_ADDRESSES*)malloc(buflen);

			if(GetAdaptersAddresses(AF_INET, flags, NULL, addresses, &buflen)==ERROR_SUCCESS) {
				const IP_ADAPTER_ADDRESSES *iter;

				for(iter=addresses; iter!=NULL; iter=iter->Next) {
					if(types&LOCALIP_ADAPTER) {
						const IP_ADAPTER_UNICAST_ADDRESS *i;

						for(i=iter->FirstUnicastAddress; i!=NULL; i=i->Next)
							ips.insert(ntohl(((const sockaddr_in*)i->Address.lpSockaddr)->sin_addr.s_addr));
					}
					if(types&LOCALIP_DNS) {
						const IP_ADAPTER_DNS_SERVER_ADDRESS *i;

						for(i=iter->FirstDnsServerAddress; i!=NULL; i=i->Next)
							ips.insert(ntohl(((const sockaddr_in*)i->Address.lpSockaddr)->sin_addr.s_addr));
					}
				}
			}

			free(addresses);
		}
	}
}

void GetLocalIps6(set<p2p::ip6> &ips, unsigned int types) {
	ULONG buflen = 0;
	DWORD flags = GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_FRIENDLY_NAME|GAA_FLAG_SKIP_MULTICAST;
	if ((types & LOCALIP_ADAPTER) == 0) flags |= GAA_FLAG_SKIP_UNICAST;
	if ((types & LOCALIP_DNS) == 0) flags |= GAA_FLAG_SKIP_DNS_SERVER;

	if (GetAdaptersAddresses(AF_INET6, flags, NULL, NULL, &buflen) != ERROR_BUFFER_OVERFLOW)
		return;

	IP_ADAPTER_ADDRESSES *addresses = (IP_ADAPTER_ADDRESSES*)malloc(buflen);
	if (!addresses) return;

	if (GetAdaptersAddresses(AF_INET6, flags, NULL, addresses, &buflen) == ERROR_SUCCESS) {
		for (IP_ADAPTER_ADDRESSES *iter = addresses; iter; iter = iter->Next) {
			if (types & LOCALIP_ADAPTER) {
				for (IP_ADAPTER_UNICAST_ADDRESS *i = iter->FirstUnicastAddress; i; i = i->Next) {
					if (i->Address.lpSockaddr && i->Address.lpSockaddr->sa_family == AF_INET6) {
						p2p::ip6 v;
						memcpy(v.b, &((sockaddr_in6*)i->Address.lpSockaddr)->sin6_addr, 16);
						ips.insert(v);
					}
				}
			}
			if (types & LOCALIP_DNS) {
				for (IP_ADAPTER_DNS_SERVER_ADDRESS *i = iter->FirstDnsServerAddress; i; i = i->Next) {
					if (i->Address.lpSockaddr && i->Address.lpSockaddr->sa_family == AF_INET6) {
						p2p::ip6 v;
						memcpy(v.b, &((sockaddr_in6*)i->Address.lpSockaddr)->sin6_addr, 16);
						ips.insert(v);
					}
				}
			}
		}
	}
	free(addresses);
}

void AddWellKnownLocalIPv6(p2p::list &allow) {
	unsigned char z[16] = {0};
	unsigned char start[16], end[16];
	p2p::range6 r;

	z[0] = 0xFE; z[1] = 0x80;
	v6_prefix_bounds(z, 10, start, end);
	r = p2p::range6(L"IPv6 link-local");
	memcpy(r.start.b, start, 16);
	memcpy(r.end.b, end, 16);
	allow.insert(r);

	memset(z, 0, 16);
	z[0] = 0xFC;
	v6_prefix_bounds(z, 7, start, end);
	r = p2p::range6(L"IPv6 unique-local");
	memcpy(r.start.b, start, 16);
	memcpy(r.end.b, end, 16);
	allow.insert(r);

	memset(z, 0, 16);
	z[15] = 1;
	r = p2p::range6(L"IPv6 loopback");
	memcpy(r.start.b, z, 16);
	memcpy(r.end.b, z, 16);
	allow.insert(r);
}
