/*
	Original code copyright (C) 2004-2005 Cory Nelson
	PeerBlock modifications copyright (C) 2009-2010 PeerBlock, LLC
	Based on the original work by Tim Leonard

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

#include <wdm.h>
#include <ntddk.h>
#include <stdlib.h>
#include <string.h>
#include "internal.h"

PBINTERNAL *g_internal;

BOOLEAN PbSafeULongMult(ULONG a, ULONG b, ULONG *out)
{
	ULONGLONG r;

	if (!out)
		return FALSE;

	r = (ULONGLONG)a * (ULONGLONG)b;
	if (r > 0xFFFFFFFFUI64)
		return FALSE;

	*out = (ULONG)r;
	return TRUE;
}

BOOLEAN PbSafeULongAdd(ULONG a, ULONG b, ULONG *out)
{
	ULONGLONG r;

	if (!out)
		return FALSE;

	r = (ULONGLONG)a + (ULONGLONG)b;
	if (r > 0xFFFFFFFFUI64)
		return FALSE;

	*out = (ULONG)r;
	return TRUE;
}

BOOLEAN PbValidateRangesBuffer(const PBRANGES *ranges, ULONG inputlen)
{
	ULONG body, needed;

	if (ranges == NULL || inputlen < FIELD_OFFSET(PBRANGES, ranges))
		return FALSE;

	if (ranges->count > PB_MAX_RANGES)
		return FALSE;

	if (!PbSafeULongMult(ranges->count, sizeof(PBIPRANGE), &body))
		return FALSE;

	if (!PbSafeULongAdd(FIELD_OFFSET(PBRANGES, ranges), body, &needed))
		return FALSE;

	return inputlen >= needed;
}

BOOLEAN PbValidateRanges6Buffer(const PBRANGES6 *ranges, ULONG inputlen)
{
	ULONG body, needed;

	if (ranges == NULL || inputlen < FIELD_OFFSET(PBRANGES6, ranges))
		return FALSE;

	if (ranges->count > PB_MAX_RANGES)
		return FALSE;

	if (!PbSafeULongMult(ranges->count, sizeof(PBIP6RANGE), &body))
		return FALSE;

	if (!PbSafeULongAdd(FIELD_OFFSET(PBRANGES6, ranges), body, &needed))
		return FALSE;

	return inputlen >= needed;
}

BOOLEAN PbValidatePortsBuffer(const VOID *ports, ULONG inputlen, USHORT *count_out)
{
	if (!count_out)
		return FALSE;

	if (inputlen == 0) {
		*count_out = 0;
		return TRUE;
	}

	if (ports == NULL || (inputlen % sizeof(USHORT)) != 0)
		return FALSE;

	if ((inputlen / sizeof(USHORT)) > PB_MAX_PORTS)
		return FALSE;

	*count_out = (USHORT)(inputlen / sizeof(USHORT));
	return TRUE;
}

const PBIPRANGE* inranges(const PBIPRANGE *ranges, int count, ULONG ip) {
	const PBIPRANGE *iter = ranges;
	const PBIPRANGE *last = ranges + count;

	while(0 < count) {
		int count2 = count >> 1;
		const PBIPRANGE *mid = iter + count2;

		if(mid->start < ip) {
			iter = mid + 1;
			count -= count2 + 1;
		}
		else {
			count = count2;
		}
	}

	if(iter != last) {
		if(iter->start != ip) --iter;
	}
	else {
		--iter;
	}

	return (iter >= ranges && iter->start <= ip && ip <= iter->end) ? iter : NULL;
}

static int ip6cmp(const unsigned char *a, const unsigned char *b)
{
	return memcmp(a, b, 16);
}

const PBIP6RANGE* inranges6(const PBIP6RANGE *ranges, int count, const UCHAR ip[16])
{
	const PBIP6RANGE *iter = ranges;
	const PBIP6RANGE *last = ranges + count;

	if (!ranges || count <= 0 || !ip)
		return NULL;

	while (count > 0) {
		int count2 = count >> 1;
		const PBIP6RANGE *mid = iter + count2;
		if (ip6cmp(mid->start, ip) < 0) {
			iter = mid + 1;
			count -= count2 + 1;
		}
		else {
			count = count2;
		}
	}

	if (iter != last) {
		if (ip6cmp(iter->start, ip) != 0)
			--iter;
	}
	else {
		--iter;
	}

	if (iter >= ranges && ip6cmp(iter->start, ip) <= 0 && ip6cmp(ip, iter->end) <= 0)
		return iter;
	return NULL;
}

void SetRanges(const PBRANGES *ranges, int block)
{
	PBIPRANGE *nranges, *oldranges;
	ULONG ncount, labelsid, nbytes;
	KIRQL irq;

	DbgPrint("pbfilter:  > SetRanges\n");
	if(ranges && ranges->count > 0)
	{
		DbgPrint("pbfilter:    found some ranges\n");
		ncount = ranges->count;
		labelsid = ranges->labelsid;

		if (ncount > PB_MAX_RANGES ||
			!PbSafeULongMult(ncount, sizeof(PBIPRANGE), &nbytes))
		{
			DbgPrint("pbfilter:    ERROR: SetRanges() count overflow or too large\n");
			return;
		}

		DbgPrint("pbfilter:    allocating memory from nonpaged pool");
		nranges = ExAllocatePoolWithTag(PB_POOL_TYPE, nbytes, '02GP');
		if (nranges == NULL)
		{
			DbgPrint("pbfilter:    ERROR: SetRanges() can't allocate nranges memory from NonPagedPool!!");
			DbgPrint("  count:[%d], size:[%d]\n", ranges->count, sizeof(PBIPRANGE));
			return;
		}

		DbgPrint("pbfilter:    copying ranges into driver\n");
		RtlCopyMemory(nranges, ranges->ranges, nbytes);
		DbgPrint("pbfilter:    done setting up new ranges\n");
	}
	else
	{
		DbgPrint("pbfilter:    no ranges specified\n");
		ncount = 0;
		labelsid = 0xFFFFFFFF;
		nranges = NULL;
	}

	DbgPrint("pbfilter:    acquiring rangeslock...\n");
	KeAcquireSpinLock(&g_internal->rangeslock, &irq);
	DbgPrint("pbfilter:    ...rangeslock acquired\n");

	if(block)
	{
		DbgPrint("pbfilter:    block list\n");
		oldranges = g_internal->blockedcount ? g_internal->blockedranges : NULL;

		g_internal->blockedcount = ncount;
		g_internal->blockedranges = nranges;
		g_internal->blockedlabelsid = labelsid;
	}
	else
	{
		DbgPrint("pbfilter:    allow list\n");
		oldranges = g_internal->allowedcount ? g_internal->allowedranges : NULL;

		g_internal->allowedcount = ncount;
		g_internal->allowedranges = nranges;
		g_internal->allowedlabelsid = labelsid;
	}

	DbgPrint("pbfilter:    releasing rangeslock...\n");
	KeReleaseSpinLock(&g_internal->rangeslock, irq);
	DbgPrint("pbfilter:    ...rangeslock released\n");

	if(oldranges) {
		DbgPrint("pbfilter:    freeing oldranges\n");
		ExFreePoolWithTag(oldranges, '02GP');
	}
	DbgPrint("pbfilter:  < SetRanges\n");
}

void SetRanges6(const PBRANGES6 *ranges, int block)
{
	PBIP6RANGE *nranges, *oldranges;
	ULONG ncount, labelsid, nbytes;
	KIRQL irq;

	if (ranges && ranges->count > 0) {
		ncount = ranges->count;
		labelsid = ranges->labelsid;
		if (ncount > PB_MAX_RANGES ||
			!PbSafeULongMult(ncount, sizeof(PBIP6RANGE), &nbytes))
			return;
		nranges = ExAllocatePoolWithTag(PB_POOL_TYPE, nbytes, '62GP');
		if (nranges == NULL)
			return;
		RtlCopyMemory(nranges, ranges->ranges, nbytes);
	}
	else {
		ncount = 0;
		labelsid = 0xFFFFFFFF;
		nranges = NULL;
	}

	KeAcquireSpinLock(&g_internal->rangeslock, &irq);
	if (block) {
		oldranges = g_internal->blocked6count ? g_internal->blocked6ranges : NULL;
		g_internal->blocked6count = ncount;
		g_internal->blocked6ranges = nranges;
		g_internal->blocked6labelsid = labelsid;
	}
	else {
		oldranges = g_internal->allowed6count ? g_internal->allowed6ranges : NULL;
		g_internal->allowed6count = ncount;
		g_internal->allowed6ranges = nranges;
		g_internal->allowed6labelsid = labelsid;
	}
	KeReleaseSpinLock(&g_internal->rangeslock, irq);

	if (oldranges)
		ExFreePoolWithTag(oldranges, '62GP');
}

void SetDestinationPorts(const USHORT *ports, USHORT count)
{
	USHORT *oldports = NULL;
	USHORT *nports = NULL;
	ULONG nbytes;
	KIRQL irq;

	if (ports && count > 0) {
		if (count > PB_MAX_PORTS ||
			!PbSafeULongMult(count, sizeof(USHORT), &nbytes))
		{
			DbgPrint("pbfilter:    ERROR: SetDestinationPorts() count overflow\n");
			return;
		}

		nports = (USHORT*) ExAllocatePoolWithTag(PB_POOL_TYPE, nbytes, 'PDBP');
		if (nports == NULL)
		{
			DbgPrint("pbfilter:    ERROR: SetDestinationPorts() can't allocate nports memory from NonPagedPool!!\n");
			return;
		}
		RtlCopyMemory(nports, ports, nbytes);
	}
	else {
		nports = NULL;
		count = 0;
	}

	KeAcquireSpinLock(&g_internal->destinationportslock, &irq);
	oldports = g_internal->destinationports;
	g_internal->destinationports = nports;
	g_internal->destinationportcount = count;
	KeReleaseSpinLock(&g_internal->destinationportslock, irq);

	if (oldports) {
		ExFreePoolWithTag(oldports, 'PDBP');
	}
}

void SetSourcePorts(const USHORT *ports, USHORT count)
{
	USHORT *oldports = NULL;
	USHORT *nports = NULL;
	ULONG nbytes;
	KIRQL irq;

	if (ports && count > 0) {
		if (count > PB_MAX_PORTS ||
			!PbSafeULongMult(count, sizeof(USHORT), &nbytes))
		{
			DbgPrint("pbfilter:    ERROR: SetSourcePorts() count overflow\n");
			return;
		}

		nports = (USHORT*) ExAllocatePoolWithTag(PB_POOL_TYPE, nbytes, 'PSBP');
		if (nports == NULL)
		{
			DbgPrint("pbfilter:    ERROR: SetSourcePorts() can't allocate nports memory from NonPagedPool!!\n");
			return;
		}
		RtlCopyMemory(nports, ports, nbytes);
	}
	else {
		nports = NULL;
		count = 0;
	}

	KeAcquireSpinLock(&g_internal->sourceportslock, &irq);
	oldports = g_internal->sourceports;
	g_internal->sourceports = nports;
	g_internal->sourceportcount = count;
	KeReleaseSpinLock(&g_internal->sourceportslock, irq);

	if (oldports) {
		ExFreePoolWithTag(oldports, 'PSBP');
	}
}

int __cdecl CompareUShort(const void * a, const void * b)
{
	return ( *(USHORT*)a - *(USHORT*)b );
}

int SourcePortAllowed(USHORT port) {
	KIRQL irq;
	int allowed = 0;

	KeAcquireSpinLock(&g_internal->sourceportslock, &irq);
	if (g_internal->sourceports && g_internal->sourceportcount > 0) {
		allowed = (int)bsearch(&port, g_internal->sourceports, g_internal->sourceportcount, sizeof(USHORT), CompareUShort);
	}
	KeReleaseSpinLock(&g_internal->sourceportslock, irq);
	return allowed;
}

int DestinationPortAllowed(USHORT port) {
	KIRQL irq;
	int allowed = 0;

	KeAcquireSpinLock(&g_internal->destinationportslock, &irq);
	if (g_internal->destinationports && g_internal->destinationportcount > 0) {
		allowed = (int)bsearch(&port, g_internal->destinationports, g_internal->destinationportcount, sizeof(USHORT), CompareUShort);
	}
	KeReleaseSpinLock(&g_internal->destinationportslock, irq);
	return allowed;
}

int HttpPortBlocked(ULONG protocol, USHORT port)
{
	if (!g_internal || (g_internal->flags & PB_FLAG_BLOCK_HTTP) == 0)
		return 0;
	if (port != 80 && port != 443)
		return 0;
	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
		return 1;
	return 0;
}
