
#include "stdafx.h"


#include <windows.h>
#include <stdio.h>

#include "packet_trace.h"
#include "kernel_trace.h"

class MyPacketListener : public PacketTraceListener {
public:
	virtual void OnPacket(uint32_t tv_sec, uint32_t tv_ns, int caplen, const unsigned char *data, uint32_t pid) {
		printf("packet ts:%lu pid:%5d caplen:%5d\n", tv_sec, pid, caplen);
	}
};

class MyKernelListener : public KernelTraceListener {
public:
	virtual void OnProcessStart(LARGE_INTEGER ts, uint32_t pid) {
		printf("NEW pid:%5d\n", pid);
	}
	virtual void OnProcessEnd(LARGE_INTEGER ts, uint32_t pid) {
		printf("END pid:%5d\n", pid);
	}
};

static DWORD WINAPI PacketTraceThreadFunc( LPVOID lpParam )
{
	if (lpParam == 0L) return 1;

	PacketTraceSession *packetTraceSession = (PacketTraceSession*)lpParam;
	packetTraceSession->Run();

	return 0;
}

static DWORD WINAPI KernelTraceThreadFunc( LPVOID lpParam )
{
	if (lpParam == 0L) return 1;

	KernelTraceSession *kernelTraceSession = (KernelTraceSession*)lpParam;
	kernelTraceSession->Run();

	return 0;
}


void wmain(void)
{
	MyPacketListener* packetListener = new MyPacketListener();
	PacketTraceSession* packetTraceSession = PacketTraceInstance();
	if (0L == packetTraceSession) return;

	MyKernelListener* kernelListener = new MyKernelListener();
	KernelTraceSession* kernelTraceSession = KernelTraceInstance();

	packetTraceSession->SetListener(packetListener);
	kernelTraceSession->SetListener(kernelListener);

	//packetTraceSession->HookNDISTrace();

	DWORD dwThreadIdPacket=0;
	DWORD dwThreadIdKernel=0;

	CreateThread(NULL, 0, PacketTraceThreadFunc, packetTraceSession, 0, &dwThreadIdPacket);
	CreateThread(NULL, 0, KernelTraceThreadFunc, kernelTraceSession, 0, &dwThreadIdKernel);

	printf("press a key to stop\n");
	getc(stdin);

}

