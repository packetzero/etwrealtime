#ifndef _PACKET_TRACE_H_
#define _PACKET_TRACE_H_

#include <stdint.h>

// Abstract class (e.g. Interface) that should be implemented if you want to receive packets

class PacketTraceListener
{
public:
	virtual void OnPacket(uint32_t tv_sec, uint32_t tv_ns, int caplen, const unsigned char *data, uint32_t pid)=0;
};

// High-level abstraction of packet trace session

class PacketTraceSession
{
public:
	/*
	 * Run()
	 * Will block until Stop() is called, so this should be called from a dedicated thread.
	 */
	virtual void Run()=0;

	/**
	 * Sets a flag, so that next time ETW calls our internal BufferCallback() we will
	 * return FALSE.
	 */
	virtual void Stop()=0;

	/**
	 * Register your listener implementation to receive packets.
	 */
	virtual void SetListener(PacketTraceListener* listener)=0;

	/**
	 * TODO: Not working, this invokes the command-line to run
	 *  netsh.exe trace start capture=yes report=no correlation=no PacketTruncateBytes=98 maxSize=16m
	 */
	virtual void HookNDISTrace()=0;
};

/**
 * PacketTraceSession is a singleton.  Will return existing instance or
 * create a new one before return.
 *
 * Returns NULL if setup failed, instance otherwise.
 */
PacketTraceSession* PacketTraceInstance();

#endif // _PACKET_TRACE_H_
