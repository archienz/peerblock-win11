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

#define NDIS60 1

#include <stddef.h>
#include <wdm.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include "internal.h"

static __inline BOOLEAN PbIsActive(VOID)
{
	return g_internal && g_internal->block && !g_internal->shutting_down;
}

static VOID PbContinue(const FWPS_FILTER0* filter, FWPS_CLASSIFY_OUT0* classifyOut)
{
	if (filter && (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)) {
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
	classifyOut->actionType = FWP_ACTION_CONTINUE;
}

static VOID PbBlock(FWPS_CLASSIFY_OUT0* classifyOut)
{
	classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	classifyOut->actionType = FWP_ACTION_BLOCK;
}

static ULONG CheckRanges(PBNOTIFICATION *pbn, ULONG ip) {
	const PBIPRANGE *range = {0};
	KIRQL irq;
	ULONG action = 2;

	KeAcquireSpinLock(&g_internal->rangeslock, &irq);

	if(g_internal->allowedcount) {
		range = inranges(g_internal->allowedranges, g_internal->allowedcount, ip);
		if(range) {
			pbn->label = range->label;
			pbn->labelsid = g_internal->allowedlabelsid;
			action = 1;
		}
	}

	if(!range) {
		if(g_internal->blockedcount) {
			range = inranges(g_internal->blockedranges, g_internal->blockedcount, ip);
			if(range) {
				pbn->label = range->label;
				pbn->labelsid = g_internal->blockedlabelsid;
				action = 0;
			}
		}
		else {
			range = NULL;
		}
	}

	KeReleaseSpinLock(&g_internal->rangeslock, irq);

	return action;
}

static ULONG CheckRanges6(PBNOTIFICATION *pbn, const UCHAR ip[16]) {
	const PBIP6RANGE *range = NULL;
	KIRQL irq;
	ULONG action = 2;

	KeAcquireSpinLock(&g_internal->rangeslock, &irq);

	if (g_internal->allowed6count) {
		range = inranges6(g_internal->allowed6ranges, (int)g_internal->allowed6count, ip);
		if (range) {
			pbn->label = range->label;
			pbn->labelsid = g_internal->allowed6labelsid;
			action = 1;
		}
	}

	if (!range && g_internal->blocked6count) {
		range = inranges6(g_internal->blocked6ranges, (int)g_internal->blocked6count, ip);
		if (range) {
			pbn->label = range->label;
			pbn->labelsid = g_internal->blocked6labelsid;
			action = 0;
		}
	}

	KeReleaseSpinLock(&g_internal->rangeslock, irq);
	return action;
}

static void FillAddrs(PBNOTIFICATION *pbn, ULONG srcAddr, const IN6_ADDR *srcAddr6, USHORT srcPort, ULONG destAddr, const IN6_ADDR *destAddr6, USHORT destPort)
{
	if(!srcAddr6) {
		pbn->source.addr4.sin_family = AF_INET;
		pbn->source.addr4.sin_addr.s_addr = NTOHL(srcAddr);
		pbn->source.addr4.sin_port = NTOHS(srcPort);
	}
	else {
		pbn->source.addr6.sin6_family = AF_INET6;
		pbn->source.addr6.sin6_addr = *srcAddr6;
		pbn->source.addr6.sin6_port = NTOHS(srcPort);
	}

	if(!destAddr6) {
		pbn->dest.addr4.sin_family = AF_INET;
		pbn->dest.addr4.sin_addr.s_addr = NTOHL(destAddr);
		pbn->dest.addr4.sin_port = NTOHS(destPort);
	}
	else {
		pbn->dest.addr6.sin6_family = AF_INET6;
		pbn->dest.addr6.sin6_addr = *destAddr6;
		pbn->dest.addr6.sin6_port = NTOHS(destPort);
	}
}

static ULONG RealClassifyV4Connect(ULONG protocol, ULONG localAddr, const IN6_ADDR *localAddr6, USHORT localPort, ULONG remoteAddr, const IN6_ADDR *remoteAddr6, USHORT remotePort) {
	PBNOTIFICATION pbn = {0};

	if(protocol == IPPROTO_TCP && (DestinationPortAllowed(remotePort) || SourcePortAllowed(localPort))) {
		pbn.action = 2;
	}
	else {
		pbn.action = CheckRanges(&pbn, remoteAddr);
	}

	pbn.protocol = protocol;
	FillAddrs(&pbn, localAddr, localAddr6, localPort, remoteAddr, remoteAddr6, remotePort);

	Notification_Send(&g_internal->queue, &pbn);
	return pbn.action;
}

static NTSTATUS ClassifyV4Connect(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
								  VOID* packet, const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut)
{
	ULONG protocol, localAddr, remoteAddr;
	USHORT localPort, remotePort;

	if(!PbIsActive()) {
		PbContinue(filter, classifyOut);
		return STATUS_SUCCESS;
	}

	protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16;
	localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
	remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

	if(!RealClassifyV4Connect(protocol, localAddr, NULL, localPort, remoteAddr, NULL, remotePort)) {
		PbBlock(classifyOut);
		return STATUS_SUCCESS;
	}

	PbContinue(filter, classifyOut);
	return STATUS_SUCCESS;
}

static ULONG RealClassifyV4Accept(ULONG protocol, ULONG localAddr, const IN6_ADDR *localAddr6, USHORT localPort, ULONG remoteAddr, const IN6_ADDR *remoteAddr6, USHORT remotePort) {
	PBNOTIFICATION pbn = {0};

	if (protocol == IPPROTO_TCP && (DestinationPortAllowed(remotePort) || SourcePortAllowed(localPort))) {
		pbn.action = 2;
	}
	else {
		pbn.action = CheckRanges(&pbn, remoteAddr);
	}

	pbn.protocol = protocol;

	FillAddrs(&pbn, remoteAddr, remoteAddr6, remotePort, localAddr, localAddr6, localPort);

	Notification_Send(&g_internal->queue, &pbn);
	return pbn.action;
}

static NTSTATUS ClassifyV4Accept(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
								 VOID* packet, const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut)
{
	ULONG protocol, localAddr, remoteAddr;
	USHORT localPort, remotePort;

	if(!PbIsActive()) {
		PbContinue(filter, classifyOut);
		return STATUS_SUCCESS;
	}

	protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint16;
	localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
	localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
	remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
	remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;

	if(!RealClassifyV4Accept(protocol, localAddr, NULL, localPort, remoteAddr, NULL, remotePort)) {
		PbBlock(classifyOut);
		return STATUS_SUCCESS;
	}

	PbContinue(filter, classifyOut);
	return STATUS_SUCCESS;
}

static NTSTATUS ClassifyV6Connect(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
								  VOID* packet, const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut)
{
	const IN6_ADDR *localAddr, *remoteAddr;
	const FAKEV6ADDR *fakeremoteAddr;
	ULONG protocol;
	USHORT localPort, remotePort;
	int action;

	if(!PbIsActive()) {
		PbContinue(filter, classifyOut);
		return STATUS_SUCCESS;
	}

	if(!inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16 ||
	   !inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16) {
		PbContinue(filter, classifyOut);
		return STATUS_SUCCESS;
	}

	protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint16;
	localAddr = (const IN6_ADDR *)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16;
	remoteAddr = (const IN6_ADDR *)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
	localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
	remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
	fakeremoteAddr = (const FAKEV6ADDR*)remoteAddr;

	{
		PBNOTIFICATION pbn = {0};
		if (protocol == IPPROTO_TCP && (DestinationPortAllowed(remotePort) || SourcePortAllowed(localPort)))
			action = 2;
		else
			action = (int)CheckRanges6(&pbn, (const UCHAR*)remoteAddr);

		if (action == 2) {
			if (fakeremoteAddr->teredo.prefix == 0x0000120) {
				ULONG realRemoteAddr = ~NTOHL(fakeremoteAddr->teredo.clientip);
				action = (int)CheckRanges(&pbn, realRemoteAddr);
			}
			else if (fakeremoteAddr->sixtofour.prefix == 0x0220) {
				ULONG realRemoteAddr = NTOHL(fakeremoteAddr->sixtofour.clientip);
				action = (int)CheckRanges(&pbn, realRemoteAddr);
			}
			else if (g_internal->flags & PB_FLAG_BLOCK_UNKNOWN_V6) {
				action = 0;
			}
		}

		pbn.protocol = protocol;
		pbn.action = action;
		pbn.source.addr6.sin6_family = AF_INET6;
		pbn.source.addr6.sin6_addr = *localAddr;
		pbn.source.addr6.sin6_port = (USHORT)NTOHS((USHORT)localPort);
		pbn.dest.addr6.sin6_family = AF_INET6;
		pbn.dest.addr6.sin6_addr = *remoteAddr;
		pbn.dest.addr6.sin6_port = (USHORT)NTOHS((USHORT)remotePort);
		Notification_Send(&g_internal->queue, &pbn);
	}

	if(!action) {
		PbBlock(classifyOut);
		return STATUS_SUCCESS;
	}

	PbContinue(filter, classifyOut);
	return STATUS_SUCCESS;
}

static NTSTATUS ClassifyV6Accept(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
								 VOID* packet, const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut)
{
	const IN6_ADDR *localAddr, *remoteAddr;
	const FAKEV6ADDR *fakeremoteAddr;
	ULONG protocol;
	USHORT localPort, remotePort;
	int action;

	if(!PbIsActive()) {
		PbContinue(filter, classifyOut);
		return STATUS_SUCCESS;
	}

	if(!inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16 ||
	   !inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16) {
		PbContinue(filter, classifyOut);
		return STATUS_SUCCESS;
	}

	protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint16;
	localAddr = (const IN6_ADDR *)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16;
	remoteAddr = (const IN6_ADDR *)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
	localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
	remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
	fakeremoteAddr = (const FAKEV6ADDR*)remoteAddr;

	{
		PBNOTIFICATION pbn = {0};
		if (protocol == IPPROTO_TCP && (DestinationPortAllowed(remotePort) || SourcePortAllowed(localPort)))
			action = 2;
		else
			action = (int)CheckRanges6(&pbn, (const UCHAR*)remoteAddr);

		if (action == 2) {
			if (fakeremoteAddr->teredo.prefix == 0x0000120) {
				ULONG realRemoteAddr = ~NTOHL(fakeremoteAddr->teredo.clientip);
				action = (int)CheckRanges(&pbn, realRemoteAddr);
			}
			else if (fakeremoteAddr->sixtofour.prefix == 0x0220) {
				ULONG realRemoteAddr = NTOHL(fakeremoteAddr->sixtofour.clientip);
				action = (int)CheckRanges(&pbn, realRemoteAddr);
			}
			else if (g_internal->flags & PB_FLAG_BLOCK_UNKNOWN_V6) {
				action = 0;
			}
		}

		pbn.protocol = protocol;
		pbn.action = action;
		pbn.source.addr6.sin6_family = AF_INET6;
		pbn.source.addr6.sin6_addr = *remoteAddr;
		pbn.source.addr6.sin6_port = (USHORT)NTOHS((USHORT)remotePort);
		pbn.dest.addr6.sin6_family = AF_INET6;
		pbn.dest.addr6.sin6_addr = *localAddr;
		pbn.dest.addr6.sin6_port = (USHORT)NTOHS((USHORT)localPort);
		Notification_Send(&g_internal->queue, &pbn);
	}

	if(!action) {
		PbBlock(classifyOut);
		return STATUS_SUCCESS;
	}

	PbContinue(filter, classifyOut);
	return STATUS_SUCCESS;
}

static NTSTATUS NTAPI NullNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID *filterKey, const FWPS_FILTER0 *filter)
{
	return STATUS_SUCCESS;
}

static NTSTATUS InstallCallouts(PDEVICE_OBJECT device)
{
	FWPS_CALLOUT0 c = {0};
	NTSTATUS ret;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > Entering InstallCallouts()\n");
	c.notifyFn = NullNotify;

	// IPv4 connect filter.

	c.calloutKey = PBWFP_CONNECT_CALLOUT_V4;
	c.classifyFn = ClassifyV4Connect;

	ret = FwpsCalloutRegister0(device, &c, &g_internal->connect4);
	if(!NT_SUCCESS(ret)) return ret;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    Installed V4 connect callout: %d\n", ret);

	// IPv4 accept filter.

	c.calloutKey = PBWFP_ACCEPT_CALLOUT_V4;
	c.classifyFn = ClassifyV4Accept;

	ret = FwpsCalloutRegister0(device, &c, &g_internal->accept4);
	if(!NT_SUCCESS(ret)) goto fail;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    Installed V4 accept callout: %d\n", ret);

	// IPv6 connect filter.

	c.calloutKey = PBWFP_CONNECT_CALLOUT_V6;
	c.classifyFn = ClassifyV6Connect;

	ret = FwpsCalloutRegister0(device, &c, &g_internal->connect6);
	if(!NT_SUCCESS(ret)) goto fail;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    Installed V6 connect callout: %d\n", ret);

	// IPv6 accept filter.

	c.calloutKey = PBWFP_ACCEPT_CALLOUT_V6;
	c.classifyFn = ClassifyV6Accept;

	ret = FwpsCalloutRegister0(device, &c, &g_internal->accept6);
	if(!NT_SUCCESS(ret)) goto fail;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    Installed V6 accept callout: %d\n", ret);

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < Leaving InstallCallouts()\n");
	return ret;

fail:
	if (g_internal->connect4) {
		FwpsCalloutUnregisterById0(g_internal->connect4);
		g_internal->connect4 = 0;
	}
	if (g_internal->accept4) {
		FwpsCalloutUnregisterById0(g_internal->accept4);
		g_internal->accept4 = 0;
	}
	if (g_internal->connect6) {
		FwpsCalloutUnregisterById0(g_internal->connect6);
		g_internal->connect6 = 0;
	}
	if (g_internal->accept6) {
		FwpsCalloutUnregisterById0(g_internal->accept6);
		g_internal->accept6 = 0;
	}
	return ret;
}



static NTSTATUS Driver_OnCreate(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);
	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > Entering Driver_OnCreate()\n");
	if (g_internal) {
		InterlockedExchange(&g_internal->shutting_down, 0);
	}
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    completing IRP\n");
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < Leaving Driver_OnCreate()\n");
	return STATUS_SUCCESS;
}

static NTSTATUS Driver_OnCleanup(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);
	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > Entering Driver_OnCleanup()\n");

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    resetting internal block/allow lists\n");
	if (g_internal) {
		InterlockedExchange(&g_internal->block, 0);
		InterlockedExchange(&g_internal->shutting_down, 1);
		SetRanges(NULL, 0);
		SetRanges(NULL, 1);
		SetRanges6(NULL, 0);
		SetRanges6(NULL, 1);
		SetDestinationPorts(NULL, 0);
		SetSourcePorts(NULL, 0);
		ResetNotificationQueue(&g_internal->queue);
	}

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    completing IRP\n");
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < Leaving Driver_OnCleanup()\n");
	return STATUS_SUCCESS;
}

static NTSTATUS Driver_OnDeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
	PIO_STACK_LOCATION irpstack;
	ULONG controlcode;
	NTSTATUS status;

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	irpstack = IoGetCurrentIrpStackLocation(irp);
	controlcode = irpstack->Parameters.DeviceIoControl.IoControlCode;

	switch(controlcode)
	{
	case IOCTL_PEERBLOCK_HOOK:
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > IOCTL_PEERBLOCK_HOOK\n");
		if(irp->AssociatedIrp.SystemBuffer != NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength == sizeof(int))
		{
			int hook = *(int*)irp->AssociatedIrp.SystemBuffer;
			DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    setting block\n");
			InterlockedExchange(&g_internal->block, hook ? 1 : 0);
		}
		else
		{
			DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "pbfilter:  * ERROR: IOCTL_PEERBLOCK_HOOK, invalid parameter\n");
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < IOCTL_PEERBLOCK_HOOK\n");
		break;

	case IOCTL_PEERBLOCK_SETRANGES:
	{
		PBRANGES *ranges;
		ULONG inputlen;

		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > IOCTL_PEERBLOCK_SETRANGES\n");
		ranges = irp->AssociatedIrp.SystemBuffer;
		inputlen = irpstack->Parameters.DeviceIoControl.InputBufferLength;

		if(PbValidateRangesBuffer(ranges, inputlen))
		{
			DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    setting ranges\n");
			SetRanges(ranges, ranges->block);
		}
		else
		{
			DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "pbfilter:  * ERROR: IOCTL_PEERBLOCK_SETRANGES, invalid parameter\n");
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < IOCTL_PEERBLOCK_SETRANGES\n");
	}
	break;

	case IOCTL_PEERBLOCK_GETNOTIFICATION:
		return Notification_Recieve(&g_internal->queue, irp);

	case IOCTL_PEERBLOCK_SETDESTINATIONPORTS:
	{
		USHORT *ports;
		USHORT count;

		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > IOCTL_PEERBLOCK_SETDESTINATIONPORTS\n");
		ports = irp->AssociatedIrp.SystemBuffer;
		if (!PbValidatePortsBuffer(ports, irpstack->Parameters.DeviceIoControl.InputBufferLength, &count)) {
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		else {
			SetDestinationPorts(ports, count);
		}
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < IOCTL_PEERBLOCK_SETDESTINATIONPORTS\n");

	}
	break;

	case IOCTL_PEERBLOCK_SETSOURCEPORTS:
	{
		USHORT *ports;
		USHORT count;

		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > IOCTL_PEERBLOCK_SETSOURCEPORTS\n");
		ports = irp->AssociatedIrp.SystemBuffer;
		if (!PbValidatePortsBuffer(ports, irpstack->Parameters.DeviceIoControl.InputBufferLength, &count)) {
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		else {
			SetSourcePorts(ports, count);
		}
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < IOCTL_PEERBLOCK_SETSOURCEPORTS\n");

	}
	break;

	case IOCTL_PEERBLOCK_SETRANGES6:
	{
		PBRANGES6 *ranges6 = irp->AssociatedIrp.SystemBuffer;
		ULONG inputlen = irpstack->Parameters.DeviceIoControl.InputBufferLength;
		if (PbValidateRanges6Buffer(ranges6, inputlen))
			SetRanges6(ranges6, ranges6->block);
		else
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	}
	break;

	case IOCTL_PEERBLOCK_SETFLAGS:
		if (irp->AssociatedIrp.SystemBuffer != NULL &&
			irpstack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ULONG))
			InterlockedExchange(&g_internal->flags, *(LONG*)irp->AssociatedIrp.SystemBuffer);
		else
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		break;

	default:
		irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
	}

	status = irp->IoStatus.Status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

static void Driver_OnUnload(PDRIVER_OBJECT driver)
{
	UNICODE_STRING devlink;
	NTSTATUS status;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > Entering Driver_OnUnload()\n");

	if (g_internal) {
		InterlockedExchange(&g_internal->block, 0);
		InterlockedExchange(&g_internal->shutting_down, 1);
	}

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    unregistering callouts\n");

	if(g_internal && g_internal->connect4) {
		status = FwpsCalloutUnregisterById0(g_internal->connect4);
		g_internal->connect4 = 0;
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    unregistered V4 connect: %d\n", status);
	}

	if(g_internal && g_internal->accept4) {
		status = FwpsCalloutUnregisterById0(g_internal->accept4);
		g_internal->accept4 = 0;
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    unregistered V4 accept: %d\n", status);
	}

	if(g_internal && g_internal->connect6) {
		status = FwpsCalloutUnregisterById0(g_internal->connect6);
		g_internal->connect6 = 0;
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    unregistered V6 connect: %d\n", status);
	}

	if(g_internal && g_internal->accept6) {
		status = FwpsCalloutUnregisterById0(g_internal->accept6);
		g_internal->accept6 = 0;
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    unregistered V6 accept: %d\n", status);
	}

	if (g_internal) {
		SetRanges(NULL, 0);
		SetRanges(NULL, 1);
		SetRanges6(NULL, 0);
		SetRanges6(NULL, 1);
		SetDestinationPorts(NULL, 0);
		SetSourcePorts(NULL, 0);
		DestroyNotificationQueue(&g_internal->queue);
	}

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    deleting devobj\n");

	RtlInitUnicodeString(&devlink, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&devlink);
	if (driver->DeviceObject) {
		IoDeleteDevice(driver->DeviceObject);
	}
	g_internal = NULL;

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < Leaving Driver_OnUnload()\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registrypath)
{
	UNICODE_STRING devicename;
	PDEVICE_OBJECT device = NULL;
	NTSTATUS status;

	//DbgBreakPoint();

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  > Entering DriverEntry()\n");
	RtlInitUnicodeString(&devicename, NT_DEVICE_NAME);

	{
		UNICODE_STRING sddl;
		RtlInitUnicodeString(&sddl, PB_DEVICE_SDDL);
		status = IoCreateDeviceSecure(driver, sizeof(PBINTERNAL), &devicename, FILE_DEVICE_PEERBLOCK,
			FILE_DEVICE_SECURE_OPEN, TRUE, &sddl, NULL, &device);
	}

	if(NT_SUCCESS(status))
	{
		UNICODE_STRING devicelink;

		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    created driver\n");
		RtlInitUnicodeString(&devicelink, DOS_DEVICE_NAME);
		status = IoCreateSymbolicLink(&devicelink, &devicename);
		if (!NT_SUCCESS(status)) {
			IoDeleteDevice(device);
			return status;
		}

		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    setting up functions\n");
		driver->MajorFunction[IRP_MJ_CREATE] =
			driver->MajorFunction[IRP_MJ_CLOSE] = Driver_OnCreate;
		driver->MajorFunction[IRP_MJ_CLEANUP] = Driver_OnCleanup;
		driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_OnDeviceControl;
		driver->DriverUnload = Driver_OnUnload;

		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    initializing internal data\n");

		device->Flags |= DO_BUFFERED_IO;

		g_internal = device->DeviceExtension;
		RtlZeroMemory(g_internal, sizeof(PBINTERNAL));

		KeInitializeSpinLock(&g_internal->rangeslock);
		KeInitializeSpinLock(&g_internal->destinationportslock);
		KeInitializeSpinLock(&g_internal->sourceportslock);
		InitNotificationQueue(&g_internal->queue);

		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    installing callouts...\n");
		status = InstallCallouts(device);
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:    ...callouts installed\n");
	}

	if(!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "pbfilter:  * ERROR [%d] encountered - unloading driver\n", status);
		if (device || driver->DeviceObject) {
			Driver_OnUnload(driver);
		}
	}

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "pbfilter:  < Leaving DriverEntry()\n");
	return status;
}
