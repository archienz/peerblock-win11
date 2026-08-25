/*
	PeerBlock security hardening - WinHTTP download helper
*/

#pragma once

#include <winsock2.h>
#include <windows.h>
#include <time.h>
#include <string>
#include "tstring.h"

struct PbHttpResult {
	long status;
	DWORD winerr;
	bool transport_ok;
	char err[256];
};

tstring PbUpgradeToHttps(const tstring &url);

inline bool PbUrlIsHttps(const tstring &url)
{
	return url.size() >= 8 && _tcsnicmp(url.c_str(), _T("https://"), 8) == 0;
}

PbHttpResult PbHttpsGet(
	const tstring &url,
	FILE *file,
	std::string *body,
	time_t ifModifiedSince,
	const char *userAgent,
	const tstring &proxy,
	bool socksProxy,
	void (*allowAddr)(void *ctx, sockaddr *addr, int addrlen),
	void *allowCtx,
	int (*progressFn)(void *ctx, double pct),
	void *progressCtx,
	size_t maxBytes,
	bool *abortFlag);
