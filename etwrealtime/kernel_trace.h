#ifndef _KERNEL_TRACE_H_
#define _KERNEL_TRACE_H_

#include <stdint.h>
#include <windows.h>

class KernelTraceListener
{
public:
	virtual void OnProcessStart(LARGE_INTEGER ts, uint32_t pid)=0;
	virtual void OnProcessEnd(LARGE_INTEGER ts, uint32_t pid)=0;
};

class KernelTraceSession
{
public:
	/*
	 * Run()
	 * Will block until SetStopFlag is called, so this should be called from a dedicated thread.
	 */
	virtual void Run()=0;

	virtual void Stop()=0;

	virtual void SetListener(KernelTraceListener* listener)=0;

};

KernelTraceSession* KernelTraceInstance();


#endif // _KERNEL_TRACE_H_