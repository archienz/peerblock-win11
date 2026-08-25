#ifndef __P2P_IP6_HPP__
#define __P2P_IP6_HPP__

#include <cstring>

namespace p2p {
struct ip6 {
	unsigned char b[16];

	ip6() { std::memset(b, 0, 16); }

	bool operator<(const ip6 &o) const { return std::memcmp(b, o.b, 16) < 0; }
	bool operator>(const ip6 &o) const { return std::memcmp(b, o.b, 16) > 0; }
	bool operator<=(const ip6 &o) const { return std::memcmp(b, o.b, 16) <= 0; }
	bool operator>=(const ip6 &o) const { return std::memcmp(b, o.b, 16) >= 0; }
	bool operator==(const ip6 &o) const { return std::memcmp(b, o.b, 16) == 0; }
	bool operator!=(const ip6 &o) const { return std::memcmp(b, o.b, 16) != 0; }
};

inline ip6 ip6_min(const ip6 &a, const ip6 &b) { return (a < b) ? a : b; }
inline ip6 ip6_max(const ip6 &a, const ip6 &b) { return (a > b) ? a : b; }
}

#endif
