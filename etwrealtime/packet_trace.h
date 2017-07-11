#ifndef _PACKET_TRACE_H_
#define _PACKET_TRACE_H_

#include <stdint.h>

class PacketTraceListener
{
public:
	virtual void OnPacket(uint32_t tv_sec, uint32_t tv_ns, int caplen, const unsigned char *data, uint32_t pid)=0;
};

class PacketTraceSession
{
public:
	/*
	 * Run()
	 * Will block until SetStopFlag is called, so this should be called from a dedicated thread.
	 */
	virtual void Run()=0;

	virtual void Stop()=0;

	virtual void HookNDISTrace()=0;

	virtual void SetListener(PacketTraceListener* listener)=0;
};

PacketTraceSession* PacketTraceInstance();

#endif // _PACKET_TRACE_H_
