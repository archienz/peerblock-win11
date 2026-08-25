/*
	PeerBlock security hardening - HTTPS downloads via WinHTTP / Schannel.
	Replaces cleartext libcurl 7.22.0 (no TLS backend).
*/

#include "stdafx.h"
#include "secure_http.h"

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

using namespace std;

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 0x00000200
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif
#ifndef WINHTTP_OPTION_REDIRECT_POLICY
#define WINHTTP_OPTION_REDIRECT_POLICY 88
#endif
#ifndef WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP
#define WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP 2
#endif

tstring PbUpgradeToHttps(const tstring &url)
{
	tstring u = url;
	if (u.size() >= 7) {
		tstring p = u.substr(0, 7);
		for (tstring::size_type i = 0; i < p.size(); ++i)
			p[i] = (TCHAR)_totlower(p[i]);
		if (p == _T("http://"))
			u.replace(0, 4, _T("https"));
	}
	return u;
}

static void SetErr(PbHttpResult *r, const char *msg, DWORD err)
{
	r->transport_ok = false;
	r->winerr = err;
	r->status = 0;
	_snprintf_s(r->err, _TRUNCATE, "%s (%lu)", msg, err);
}

static void AllowHost(const wchar_t *host, INTERNET_PORT port,
	void (*allowAddr)(void*, sockaddr*, int), void *allowCtx)
{
	ADDRINFOW hints = {0};
	ADDRINFOW *res = NULL;
	wchar_t portstr[16];

	if (!allowAddr || !host)
		return;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	swprintf_s(portstr, L"%u", port);

	if (GetAddrInfoW(host, portstr, &hints, &res) != 0)
		return;

	for (ADDRINFOW *p = res; p; p = p->ai_next) {
		if (p->ai_addr && p->ai_addrlen >= sizeof(sockaddr_in))
			allowAddr(allowCtx, p->ai_addr, (int)p->ai_addrlen);
	}
	FreeAddrInfoW(res);
}

static bool FormatHttpDate(time_t t, wchar_t *buf, size_t cch)
{
	struct tm gmt;
	if (gmtime_s(&gmt, &t) != 0)
		return false;
	return wcsftime(buf, cch, L"%a, %d %b %Y %H:%M:%S GMT", &gmt) != 0;
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
	bool *abortFlag)
{
	PbHttpResult result;
	memset(&result, 0, sizeof(result));

	if (socksProxy && !proxy.empty()) {
		SetErr(&result, "SOCKS5 proxies are not supported (WinHTTP); use an HTTP proxy or a direct connection", ERROR_NOT_SUPPORTED);
		return result;
	}

	tstring secureUrl = PbUpgradeToHttps(url);
	if (!PbUrlIsHttps(secureUrl)) {
		SetErr(&result, "only HTTPS URLs are allowed", ERROR_ACCESS_DENIED);
		return result;
	}

	URL_COMPONENTS uc;
	memset(&uc, 0, sizeof(uc));
	uc.dwStructSize = sizeof(uc);
	wchar_t host[256] = {0};
	wchar_t path[2048] = {0};
	wchar_t extra[1024] = {0};
	uc.lpszHostName = host;
	uc.dwHostNameLength = _countof(host);
	uc.lpszUrlPath = path;
	uc.dwUrlPathLength = _countof(path);
	uc.lpszExtraInfo = extra;
	uc.dwExtraInfoLength = _countof(extra);

	if (!WinHttpCrackUrl(secureUrl.c_str(), 0, 0, &uc)) {
		SetErr(&result, "WinHttpCrackUrl", GetLastError());
		return result;
	}

	if (uc.nScheme != INTERNET_SCHEME_HTTPS) {
		SetErr(&result, "refusing non-HTTPS URL", ERROR_ACCESS_DENIED);
		return result;
	}

	if (uc.nPort == 0)
		uc.nPort = INTERNET_DEFAULT_HTTPS_PORT;

	wstring object = path;
	object += extra;

	wstring ua;
	if (userAgent && userAgent[0]) {
		int n = MultiByteToWideChar(CP_UTF8, 0, userAgent, -1, NULL, 0);
		if (n > 0) {
			ua.resize(n);
			MultiByteToWideChar(CP_UTF8, 0, userAgent, -1, &ua[0], n);
			if (!ua.empty() && ua[ua.size()-1] == 0)
				ua.resize(ua.size()-1);
		}
	}
	if (ua.empty())
		ua = L"PeerBlock";

	DWORD access = WINHTTP_ACCESS_TYPE_NO_PROXY;
	const wchar_t *proxyName = WINHTTP_NO_PROXY_NAME;
	wstring proxyBuf;
	if (!proxy.empty() && !socksProxy) {
		access = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
		proxyBuf = proxy;
		proxyName = proxyBuf.c_str();
	}

	HINTERNET session = WinHttpOpen(ua.c_str(), access, proxyName, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!session) {
		SetErr(&result, "WinHttpOpen", GetLastError());
		return result;
	}

	DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 |
		WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
		WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
	WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

#ifdef WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS
	{
		DWORD redirects = 5;
		WinHttpSetOption(session, WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS, &redirects, sizeof(redirects));
	}
#endif

	DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
	WinHttpSetOption(session, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));

	AllowHost(host, uc.nPort, allowAddr, allowCtx);

	HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
	if (!connect) {
		SetErr(&result, "WinHttpConnect", GetLastError());
		WinHttpCloseHandle(session);
		return result;
	}

	HINTERNET request = WinHttpOpenRequest(connect, L"GET", object.c_str(), NULL,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!request) {
		SetErr(&result, "WinHttpOpenRequest", GetLastError());
		WinHttpCloseHandle(connect);
		WinHttpCloseHandle(session);
		return result;
	}

	DWORD securityFlags = 0;
	WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

	if (ifModifiedSince) {
		wchar_t date[64];
		if (FormatHttpDate(ifModifiedSince, date, _countof(date))) {
			wstring hdr = L"If-Modified-Since: ";
			hdr += date;
			hdr += L"\r\n";
			WinHttpAddRequestHeaders(request, hdr.c_str(), (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD);
		}
	}

	if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
		SetErr(&result, "WinHttpSendRequest", GetLastError());
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(connect);
		WinHttpCloseHandle(session);
		return result;
	}

	if (!WinHttpReceiveResponse(request, NULL)) {
		SetErr(&result, "WinHttpReceiveResponse", GetLastError());
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(connect);
		WinHttpCloseHandle(session);
		return result;
	}

	DWORD status = 0, statusSize = sizeof(status);
	if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
		SetErr(&result, "WinHttpQueryHeaders", GetLastError());
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(connect);
		WinHttpCloseHandle(session);
		return result;
	}

	result.status = (long)status;
	result.transport_ok = true;

	DWORD contentLen = 0, contentLenSize = sizeof(contentLen);
	BOOL haveLen = WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &contentLen, &contentLenSize, WINHTTP_NO_HEADER_INDEX);

	size_t total = 0;
	for (;;) {
		if (abortFlag && *abortFlag)
			break;

		DWORD avail = 0;
		if (!WinHttpQueryDataAvailable(request, &avail)) {
			SetErr(&result, "WinHttpQueryDataAvailable", GetLastError());
			break;
		}
		if (avail == 0)
			break;

		if (avail > 65536)
			avail = 65536;

		if (maxBytes && total + avail > maxBytes) {
			SetErr(&result, "download exceeded size limit", ERROR_BUFFER_OVERFLOW);
			break;
		}

		vector<char> buf(avail);
		DWORD read = 0;
		if (!WinHttpReadData(request, &buf[0], avail, &read)) {
			SetErr(&result, "WinHttpReadData", GetLastError());
			break;
		}
		if (read == 0)
			break;

		if (file) {
			if (fwrite(&buf[0], 1, read, file) != read) {
				SetErr(&result, "fwrite", ERROR_WRITE_FAULT);
				break;
			}
		}
		else if (body) {
			body->append(&buf[0], read);
		}

		total += read;
		if (progressFn && haveLen && contentLen > 0) {
			double pct = min(100.0, (double)total * 100.0 / (double)contentLen);
			progressFn(progressCtx, pct);
		}
	}

	if (progressFn)
		progressFn(progressCtx, 100.0);

	WinHttpCloseHandle(request);
	WinHttpCloseHandle(connect);
	WinHttpCloseHandle(session);
	return result;
}
