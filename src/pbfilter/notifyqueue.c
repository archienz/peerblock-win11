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
#include "internal.h"

typedef struct __pb_notifynode {
	LIST_ENTRY entry;
	PBNOTIFICATION notification;
} PBNOTIFYNODE;

static NOTIFICATION_QUEUE* CsqQueue(PIO_CSQ csq)
{
	return CONTAINING_RECORD(csq, NOTIFICATION_QUEUE, csq);
}

static VOID NTAPI CsqInsertIrp(PIO_CSQ csq, PIRP irp)
{
	InsertTailList(&CsqQueue(csq)->irp_list, &irp->Tail.Overlay.ListEntry);
}

static VOID NTAPI CsqRemoveIrp(PIO_CSQ csq, PIRP irp)
{
	UNREFERENCED_PARAMETER(csq);
	RemoveEntryList(&irp->Tail.Overlay.ListEntry);
}

static PIRP NTAPI CsqPeekNextIrp(PIO_CSQ csq, PIRP irp, PVOID peekContext)
{
	NOTIFICATION_QUEUE *queue = CsqQueue(csq);
	PLIST_ENTRY next;

	UNREFERENCED_PARAMETER(peekContext);

	next = irp ? irp->Tail.Overlay.ListEntry.Flink : queue->irp_list.Flink;
	if (next == &queue->irp_list)
		return NULL;

	return CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
}

static VOID NTAPI CsqAcquireLock(PIO_CSQ csq, PKIRQL irql)
{
	KeAcquireSpinLock(&CsqQueue(csq)->lock, irql);
}

static VOID NTAPI CsqReleaseLock(PIO_CSQ csq, KIRQL irql)
{
	KeReleaseSpinLock(&CsqQueue(csq)->lock, irql);
}

static VOID NTAPI CsqCompleteCanceledIrp(PIO_CSQ csq, PIRP irp)
{
	UNREFERENCED_PARAMETER(csq);
	irp->IoStatus.Status = STATUS_CANCELLED;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static VOID DrainNotifications(NOTIFICATION_QUEUE *queue)
{
	while (!IsListEmpty(&queue->notification_list)) {
		PBNOTIFYNODE *notifynode = (PBNOTIFYNODE*)RemoveHeadList(&queue->notification_list);
		ExFreeToNPagedLookasideList(&queue->lookaside, notifynode);
	}
	queue->queued = 0;
}

void InitNotificationQueue(NOTIFICATION_QUEUE *queue)
{
	DbgPrint("pbfilter:  > Entering InitNotificationQueue()\n");
	InitializeListHead(&queue->irp_list);
	InitializeListHead(&queue->notification_list);
	ExInitializeNPagedLookasideList(&queue->lookaside, NULL, NULL, 0, sizeof(PBNOTIFYNODE), '02GP', 0);
	KeInitializeSpinLock(&queue->lock);
	queue->queued = 0;
	IoCsqInitialize(&queue->csq,
		CsqInsertIrp, CsqRemoveIrp, CsqPeekNextIrp,
		CsqAcquireLock, CsqReleaseLock, CsqCompleteCanceledIrp);
	queue->initialized = TRUE;
	DbgPrint("pbfilter:  < Leaving InitNotificationQueue()\n");
}

void ResetNotificationQueue(NOTIFICATION_QUEUE *queue)
{
	PIRP irp;
	KIRQL irq;

	if (!queue->initialized)
		return;

	KeAcquireSpinLock(&queue->lock, &irq);
	DrainNotifications(queue);
	KeReleaseSpinLock(&queue->lock, irq);

	while ((irp = IoCsqRemoveNextIrp(&queue->csq, NULL)) != NULL) {
		irp->IoStatus.Status = STATUS_CANCELLED;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
}

void DestroyNotificationQueue(NOTIFICATION_QUEUE *queue)
{
	DbgPrint("pbfilter:  > Entering DestroyNotificationQueue()\n");

	if (!queue->initialized) {
		DbgPrint("pbfilter:  < Leaving DestroyNotificationQueue() (not initialized)\n");
		return;
	}

	ResetNotificationQueue(queue);

	DbgPrint("pbfilter:    deleting non-paged lookaside list\n");
	ExDeleteNPagedLookasideList(&queue->lookaside);
	queue->initialized = FALSE;
	DbgPrint("pbfilter:  < Leaving DestroyNotificationQueue()\n");
}

void Notification_Send(NOTIFICATION_QUEUE *queue, const PBNOTIFICATION *notification)
{
	PIRP irp;
	KIRQL irq;

	if (!queue->initialized || !notification)
		return;

	irp = IoCsqRemoveNextIrp(&queue->csq, NULL);
	if (irp) {
		PBNOTIFICATION *irpnotification = irp->AssociatedIrp.SystemBuffer;
		if (irpnotification) {
			RtlCopyMemory(irpnotification, notification, sizeof(PBNOTIFICATION));
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(PBNOTIFICATION);
		}
		else {
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return;
	}

	KeAcquireSpinLock(&queue->lock, &irq);
	if (queue->queued < 64) {
		PBNOTIFYNODE *notifynode = ExAllocateFromNPagedLookasideList(&queue->lookaside);
		if (notifynode) {
			InitializeListHead(&notifynode->entry);
			RtlCopyMemory(&notifynode->notification, notification, sizeof(PBNOTIFICATION));
			InsertTailList(&queue->notification_list, &notifynode->entry);
			++queue->queued;
		}
	}
	KeReleaseSpinLock(&queue->lock, irq);
}

NTSTATUS Notification_Recieve(NOTIFICATION_QUEUE *queue, PIRP irp)
{
	PIO_STACK_LOCATION irpstack = IoGetCurrentIrpStackLocation(irp);
	KIRQL irq;

	if (!queue->initialized) {
		irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_DEVICE_NOT_READY;
	}

	if (irpstack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(PBNOTIFICATION) ||
		irp->AssociatedIrp.SystemBuffer == NULL)
	{
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_BUFFER_TOO_SMALL;
	}

	KeAcquireSpinLock(&queue->lock, &irq);

	if (!IsListEmpty(&queue->notification_list))
	{
		PBNOTIFYNODE *notifynode = (PBNOTIFYNODE*)RemoveHeadList(&queue->notification_list);
		PBNOTIFICATION *notification = irp->AssociatedIrp.SystemBuffer;

		RtlCopyMemory(notification, &notifynode->notification, sizeof(PBNOTIFICATION));
		ExFreeToNPagedLookasideList(&queue->lookaside, notifynode);
		--queue->queued;

		KeReleaseSpinLock(&queue->lock, irq);

		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = sizeof(PBNOTIFICATION);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	KeReleaseSpinLock(&queue->lock, irq);

	IoCsqInsertIrp(&queue->csq, irp, NULL);
	return STATUS_PENDING;
}
