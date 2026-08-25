/*
	Copyright (C) 2004-2005 Cory Nelson
	PeerBlock modifications copyright (C) 2010 PeerBlock, LLC

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
#ifdef _WIN32
#include <ws2tcpip.h>
#endif
#include <cstring>
using namespace std;

inline static unsigned int make_ip(unsigned int a, unsigned int b, unsigned int c, unsigned int d) {
	return ((a<<24) | (b<<16) | (c<<8) | d);
}

static wstring name_to_wide(const string &name) {
	wstring w;
	w.reserve(name.size());
	copy(name.begin(), name.end(), back_inserter(w));
	return w;
}

static bool parse_v4_range(const char *s, unsigned int *start, unsigned int *end) {
	unsigned int sa, sb, sc, sd, ea, eb, ec, ed;
	if (sscanf(s, "%u.%u.%u.%u-%u.%u.%u.%u",
			&sa, &sb, &sc, &sd, &ea, &eb, &ec, &ed) != 8)
		return false;
	if (sa>255 || sb>255 || sc>255 || sd>255 || ea>255 || eb>255 || ec>255 || ed>255)
		return false;
	unsigned int a = make_ip(sa, sb, sc, sd);
	unsigned int b = make_ip(ea, eb, ec, ed);
	*start = min(a, b);
	*end = max(a, b);
	return true;
}

static bool parse_v4_cidr(const char *s, unsigned int *start, unsigned int *end) {
	unsigned int a, b, c, d, p;
	if (sscanf(s, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &p) != 5)
		return false;
	if (a>255 || b>255 || c>255 || d>255 || p>32)
		return false;
	unsigned int ip = make_ip(a, b, c, d);
	unsigned int mask = (p == 0) ? 0 : (0xFFFFFFFFu << (32 - p));
	*start = ip & mask;
	*end = ip | (~mask);
	return true;
}

static bool parse_v6_addr(const char *s, unsigned char out[16]) {
	sockaddr_in6 sa;
	int len = sizeof(sa);
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	if (WSAStringToAddressA((char*)s, AF_INET6, NULL, (sockaddr*)&sa, &len) == 0) {
		memcpy(out, &sa.sin6_addr, 16);
		return true;
	}
	return false;
}

static void v6_prefix_bounds(unsigned char addr[16], unsigned prefix, unsigned char start[16], unsigned char end[16]) {
	memcpy(start, addr, 16);
	memcpy(end, addr, 16);
	if (prefix > 128)
		prefix = 128;
	for (unsigned i = 0; i < 16; ++i) {
		unsigned bit0 = i * 8;
		if (bit0 + 8 <= prefix) {
			continue;
		}
		if (bit0 >= prefix) {
			start[i] = 0;
			end[i] = 0xFF;
			continue;
		}
		unsigned keep = prefix - bit0;
		unsigned char mask = (unsigned char)(0xFFu << (8 - keep));
		start[i] &= mask;
		end[i] |= (unsigned char)~mask;
	}
}

namespace p2p {
void list::_load_p2p(istream &stream) {
	string line;
	while(getline(stream, line)) {
		boost::trim(line);
		if (line.empty() || line[0]=='#' || line[0]==';')
			continue;

		string::size_type bracket = line.find(":[");
		if (bracket != string::npos) {
			string name = line.substr(0, bracket);
			string rest = line.substr(bracket + 1);
			boost::trim(name);

			string::size_type slash = rest.find("]/");
			string::size_type dash = rest.find("]-[");
			if (slash != string::npos && rest.size() > 2 && rest[0]=='[') {
				string addr = rest.substr(1, slash - 1);
				unsigned prefix = 0;
				if (sscanf(rest.c_str() + slash + 2, "%u", &prefix) != 1 || prefix > 128)
					continue;
				unsigned char raw[16], startb[16], endb[16];
				if (!parse_v6_addr(addr.c_str(), raw))
					continue;
				v6_prefix_bounds(raw, prefix, startb, endb);
				range6 r6(name_to_wide(name));
				memcpy(r6.start.b, startb, 16);
				memcpy(r6.end.b, endb, 16);
				this->insert(r6);
				continue;
			}
			if (dash != string::npos && rest.size() > 2 && rest[0]=='[') {
				string a1 = rest.substr(1, dash - 1);
				string a2 = rest.substr(dash + 3);
				if (!a2.empty() && a2[a2.size()-1]==']')
					a2.erase(a2.size()-1);
				unsigned char s[16], e[16];
				if (!parse_v6_addr(a1.c_str(), s) || !parse_v6_addr(a2.c_str(), e))
					continue;
				range6 r6(name_to_wide(name));
				if (memcmp(s, e, 16) <= 0) {
					memcpy(r6.start.b, s, 16);
					memcpy(r6.end.b, e, 16);
				} else {
					memcpy(r6.start.b, e, 16);
					memcpy(r6.end.b, s, 16);
				}
				this->insert(r6);
				continue;
			}
			continue;
		}

		string::size_type i=line.rfind(':');
		if(i==string::npos) continue;

		string name(line.c_str(), i);
		string spec = line.substr(i+1);
		boost::trim(name);

		unsigned int start, end;
		if (parse_v4_cidr(spec.c_str(), &start, &end) ||
			parse_v4_range(spec.c_str(), &start, &end)) {
			range r(name_to_wide(name), start, end);
			this->insert(r);
		}
	}
}

void list::_save_p2p(ostream &stream) const {
	for(list::const_iterator iter=this->begin(); iter!=this->end(); ++iter) {
		string name;
		name.reserve(iter->name.size());

		for(wstring::size_type i=0; i<iter->name.size(); i++)
			name+=(char)iter->name[i];

		stream
				<< name
				<< ':'
				<< (int)iter->start.ipb[3] << '.'
				<< (int)iter->start.ipb[2] << '.'
				<< (int)iter->start.ipb[1] << '.'
				<< (int)iter->start.ipb[0]
				<< '-'
				<< (int)iter->end.ipb[3] << '.'
				<< (int)iter->end.ipb[2] << '.'
				<< (int)iter->end.ipb[1] << '.'
				<< (int)iter->end.ipb[0]
				<< endl;
	}
	for (list::const_iterator6 iter = this->begin6(); iter != this->end6(); ++iter) {
		string name;
		name.reserve(iter->name.size());
		for (wstring::size_type i = 0; i < iter->name.size(); i++)
			name += (char)iter->name[i];
		char a1[64] = {0}, a2[64] = {0};
		DWORD n1 = sizeof(a1), n2 = sizeof(a2);
		sockaddr_in6 s1 = {0}, s2 = {0};
		s1.sin6_family = AF_INET6;
		s2.sin6_family = AF_INET6;
		memcpy(&s1.sin6_addr, iter->start.b, 16);
		memcpy(&s2.sin6_addr, iter->end.b, 16);
		WSAAddressToStringA((sockaddr*)&s1, sizeof(s1), NULL, a1, &n1);
		WSAAddressToStringA((sockaddr*)&s2, sizeof(s2), NULL, a2, &n2);
		stream << name << ":[" << a1 << "]-[" << a2 << "]" << endl;
	}
}
}
