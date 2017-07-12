#ifndef _KERNEL_TRACE_H_
#define _KERNEL_TRACE_H_

#include <stdint.h>
#include <windows.h>

class KernelTraceSession
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

};

/**
 * KernelTraceSession is a singleton.  Will return existing instance or
 * create a new one before return.
 *
 * Returns NULL if setup failed, instance otherwise.
 */
KernelTraceSession* KernelTraceInstance();


#endif // _KERNEL_TRACE_H_