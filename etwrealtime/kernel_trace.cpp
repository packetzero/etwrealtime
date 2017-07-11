#include "stdafx.h"

#include "kernel_trace.h"
#include "utils.h"

//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include <guiddef.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>

#include <vector>		// stdlibc++
#include <string>

#pragma comment(lib, "tdh.lib")

class KernelTraceSessionImpl;

KernelTraceSessionImpl* gKernelTraceSession=0L;


class KernelTraceSessionImpl : public KernelTraceSession
{
public:
	/*
	 * constructor
	 */
	KernelTraceSessionImpl(): m_stopFlag(false), m_startTraceHandle(0L), m_listener(0L) {}

	virtual void Run();
	virtual void Stop() { m_stopFlag = true; }
	virtual void SetListener(KernelTraceListener* listener) { m_listener = listener; }

	bool Setup();
	void OnRecordEvent(PEVENT_RECORD pEvent);
	BOOL OnBuffer(PEVENT_TRACE_LOGFILE pBuffer);

private:


	bool         m_stopFlag;
	TRACEHANDLE  m_startTraceHandle;
	KernelTraceListener* m_listener;
};


//---------------------------------------------------------------------
// Run()
// Will block until SetStopFlag is called, so this should be called from a dedicated thread.
//---------------------------------------------------------------------
void KernelTraceSessionImpl::Run()
{
	m_stopFlag = false;

	// Process Trace - blocks until BufferCallback returns FALSE, or

	ULONG status = ProcessTrace(&m_startTraceHandle, 1, 0, 0);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
    {
        wprintf(L"ProcessTrace failed with %lu\n", status);
		CloseTrace(m_startTraceHandle);
    }
}

DEFINE_GUID ( /* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */
    ProcessProviderGuid,
    0x3d6fa8d0,
    0xfe05,
    0x11d0,
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
  );

//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void KernelTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent)
{
    DWORD status = ERROR_SUCCESS;
    HRESULT hr = S_OK;
    PTRACE_EVENT_INFO pInfo = NULL;
    LPWSTR pStringGuid = NULL;
	
	PrintEventMeta(pEvent);


}

//---------------------------------------------------------------------
// Called from StaticEventBufferCallback(), which is called by
// ETW loop in ProcessSession().
//
// The only reason we implement this is to signal to ETW
// to terminate this session's ProcessSession() loop.
//---------------------------------------------------------------------
BOOL KernelTraceSessionImpl::OnBuffer(PEVENT_TRACE_LOGFILE buf)
{
	if (m_stopFlag) return FALSE;	// I'm done. Stop sending and exit ProcessSession()

	return TRUE;// keep sending me events!
}

// some made-up guid to associate with our session
static const GUID myGuid = 
{ 0x10101010, 0x2345, 0x0abcd, { 0xAA, 0x22, 0x71, 0x00, 0x11, 0x00, 0x00, 0xFF } };


//---------------------------------------------------------------------
// Called from Setup()
//---------------------------------------------------------------------
static bool StartTraceSession(std::wstring mySessionName, DWORD dwEnableFlags, TRACEHANDLE &traceSessionHandle)
{
	std::vector<unsigned char>	vecEventTraceProps;	//EVENT_TRACE_PROPERTIES || name

	vecEventTraceProps.resize ( sizeof(EVENT_TRACE_PROPERTIES) + (mySessionName.length()+1)*sizeof(mySessionName[0]) );
	PEVENT_TRACE_PROPERTIES petp = (PEVENT_TRACE_PROPERTIES) &vecEventTraceProps[0];
	petp->Wnode.BufferSize = (ULONG)vecEventTraceProps.size();

	petp->Wnode.Guid = SystemTraceControlGuid;	// For kernel trace, have to use shared one

	petp->Wnode.ClientContext = 1;	//use QPC for timestamp resolution
	petp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	petp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	petp->FlushTimer = 1;
	petp->LogFileNameOffset = 0;
	petp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	petp->EnableFlags = dwEnableFlags;

	// Call StartTrace() to setup a realtime ETW context associated with myGuid + mySessionName
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364117(v=vs.85).aspx

	ULONG status = ::StartTrace ( &traceSessionHandle, mySessionName.c_str(), petp );
	if ( ERROR_ALREADY_EXISTS == status )
	{
		// might not have flags / settings you want.
		return true;
	}
	else if (status != ERROR_SUCCESS )
	{
		printf("StartTraceW returned %ul\n", status);
		traceSessionHandle = 0L;
		return false;
	} else {
			// Enable Trace

		status = EnableTraceEx2(traceSessionHandle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

		// TODO: check status
	}
	return true;
}

//---------------------------------------------------------------------
//---------------------------------------------------------------------
static VOID WINAPI StaticRecordEventCallback(PEVENT_RECORD pEvent)
{
	if (0L == gKernelTraceSession) return;
	gKernelTraceSession->OnRecordEvent(pEvent);
}

//---------------------------------------------------------------------
//---------------------------------------------------------------------
static BOOL WINAPI StaticBufferEventCallback(PEVENT_TRACE_LOGFILE buf)
{
	if (0L == gKernelTraceSession) return FALSE;
	return gKernelTraceSession->OnBuffer(buf);
}

//---------------------------------------------------------------------
// Establish a session.
// Returns true on success, false otherwise.
//---------------------------------------------------------------------
bool KernelTraceSessionImpl::Setup()
{
	std::wstring mySessionName = L"NT Kernel Logger";

	// This is where you wask for Process information, TCP, etc.  Look at StartTraceW() docs.
	DWORD kernelTraceOptions = EVENT_TRACE_FLAG_PROCESS;

	ULONG status = StartTraceSession(mySessionName, kernelTraceOptions, this->m_startTraceHandle);
	
	if (status == false) //this->m_startTraceHandle == 0L)
		return false;

    // Identify the log file from which you want to consume events
    // and the callbacks used to process the events and buffers.

    EVENT_TRACE_LOGFILE trace;
    TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
    ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = (LPWSTR)mySessionName.c_str();
    trace.LogFileName = (LPWSTR) NULL;
	//trace.Context = this; // passes to EventRecordCallback, but only works in Vista+
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK) (StaticRecordEventCallback);
	trace.BufferCallback = (PEVENT_TRACE_BUFFER_CALLBACK)(StaticBufferEventCallback);
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	
	// Open Trace

    this->m_startTraceHandle = OpenTrace(&trace);
    if (INVALID_PROCESSTRACE_HANDLE == this->m_startTraceHandle)
    {
		DWORD err = GetLastError();
        wprintf(L"KernelTraceSession: OpenTrace() failed with %lu\n", err);	// lookup in winerror.h
        goto cleanup;
    }

	return true;

cleanup:
	CloseTrace(this->m_startTraceHandle);
	return false;
}


//---------------------------------------------------------------------
// KernelTraceCreate()
// KernelTraceSession is a singleton.  Will return existing instance or
// create a new one before return.
//
// Returns NULL if setup failed, instance otherwise.
//---------------------------------------------------------------------
KernelTraceSession* KernelTraceInstance() {

	if (gKernelTraceSession != 0L) return gKernelTraceSession;

	KernelTraceSessionImpl* obj = new KernelTraceSessionImpl();
	
	if (obj->Setup() == false) {
		printf("KernelTraceSession Setup failed\n");
		delete obj;
		return 0L;
	}

	gKernelTraceSession = obj;

	return obj;
}
