// Example to demonstrate simultaneous realtime ETW sessions for Kernel and NDIS Packet Capture.
// NOTE: This needs to run with elevated "Debug" privilege to establish ETW session.
// NOTE: Invoke a command-line similar to the following as Administrator to start capture.
//
//   netsh.exe trace start capture=yes report=no correlation=no PacketTruncateBytes=98 maxSize=16m
//
// References:
//  https://stackoverflow.com/questions/9470135/how-to-consume-real-time-etw-events-from-the-microsoft-windows-ndis-packetcaptur
//
// Alex Malone, Ziften Technologies, Inc.

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

//-------------------------------------------------------------------------
// Function for packet trace thread.  It will call Run(), which
// calls ProcessTrace() Windows API call.
//-------------------------------------------------------------------------
static DWORD WINAPI PacketTraceThreadFunc( LPVOID lpParam )
{
	PacketTraceSession *packetTraceSession = (PacketTraceSession*)lpParam;
	packetTraceSession->Run();
	return 0;
}

//-------------------------------------------------------------------------
// Function for kernel trace thread.  It will call Run(), which
// calls ProcessTrace() Windows API call.
//-------------------------------------------------------------------------
static DWORD WINAPI KernelTraceThreadFunc( LPVOID lpParam )
{
	KernelTraceSession *kernelTraceSession = (KernelTraceSession*)lpParam;
	kernelTraceSession->Run();
	return 0;
}


void wmain(void)
{
	// create instances of our trace session classes.  The xxInstance() calls
	// perform some setup:
	//     StartTrace(), EnableTraceEx2(), OpenTrace()
	// If there are failures along the way, NULL pointer is returned.

	MyPacketListener* packetListener = new MyPacketListener();
	PacketTraceSession* packetTraceSession = PacketTraceInstance();
	KernelTraceSession* kernelTraceSession = KernelTraceInstance();

	if (0L == packetTraceSession || 0L == kernelTraceSession) {
		printf("Error: could not create a trace. packet:0x%x kernel:0x%x\n", packetTraceSession, kernelTraceSession);
		return;
	}

	packetTraceSession->SetListener(packetListener);

	//packetTraceSession->HookNDISTrace();

	DWORD dwThreadIdPacket=0;
	DWORD dwThreadIdKernel=0;

	HANDLE packetTraceThread = CreateThread(NULL, 0, PacketTraceThreadFunc, packetTraceSession, 0, &dwThreadIdPacket);
	HANDLE kernelTraceThread = CreateThread(NULL, 0, KernelTraceThreadFunc, kernelTraceSession, 0, &dwThreadIdKernel);

	printf("press a key to stop\n");
	getc(stdin);

	// set a flag in each of our Trace Session classes, so that next time
	// BufferCallback() are called, they return false.  This will instruct ETW
	// to stop sending events.

	packetTraceSession->Stop();
	kernelTraceSession->Stop();

	// Give it a second...

	Sleep(1000);

	// Finally, terminate the threads

	TerminateThread(packetTraceThread, 0);
	TerminateThread(kernelTraceThread, 0);
}

