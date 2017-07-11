#include "stdafx.h"

//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include "packet_trace.h"
#include <guiddef.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>

#include <vector>		// stdlibc++
#include <string>

#pragma comment(lib, "tdh.lib")

class PacketTraceSessionImpl;

PacketTraceSessionImpl* gPacketTraceSession=0L;

// Gleaned from running "logman query providers" :
//
DEFINE_GUID ( /* 2ed6006e-4729-4609-b423-3ee7bcd678ef */
    NDISProviderGuid,
    0x2ed6006e,
    0x4729,
    0x4609,
    0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef
  );

class PacketTraceSessionImpl : public PacketTraceSession
{
public:
	/*
	 * constructor
	 */
	PacketTraceSessionImpl(): m_stopFlag(false), m_userPropLen(0), m_startTraceHandle(0L), m_listener(0L) {}

	virtual void Run();
	virtual void Stop() { m_stopFlag = true; }
	virtual void HookNDISTrace();
	virtual void SetListener(PacketTraceListener* listener) { m_listener = listener; }


	bool Setup();
	void OnRecordEvent(PEVENT_RECORD pEvent);
	BOOL OnBuffer(PEVENT_TRACE_LOGFILE pBuffer);

private:

	DWORD GetUserPropLen(PEVENT_RECORD pEvent);
	void GetTimestamp(LARGE_INTEGER ts, uint32_t &tv_sec, uint32_t &tv_ns);

	bool         m_stopFlag;
	int          m_userPropLen;
	TRACEHANDLE  m_startTraceHandle;
	PacketTraceListener* m_listener;
};

static LARGE_INTEGER gTimestampAdjust;


//---------------------------------------------------------------------
// Run()
// Will block until SetStopFlag is called, so this should be called from a dedicated thread.
//---------------------------------------------------------------------
void PacketTraceSessionImpl::Run()
{
	m_stopFlag = false;

	// 100-nanoseconds = milliseconds * 10000  (year 1601 to 1970)
	gTimestampAdjust.QuadPart = 11644473600000 * 10000;

	// Process Trace - blocks until BufferCallback returns FALSE, or

	ULONG status = ProcessTrace(&m_startTraceHandle, 1, 0, 0);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
    {
        wprintf(L"ProcessTrace failed with %lu\n", status);
		CloseTrace(m_startTraceHandle);
    }
}

void PacketTraceSessionImpl::GetTimestamp(LARGE_INTEGER ts, uint32_t &tv_sec, uint32_t &tv_ns)
{
	// removes the diff between 1970 and 1601
	uint64_t QuadPart = ts.QuadPart - gTimestampAdjust.QuadPart;

	tv_sec = (uint32_t)(QuadPart / 10000000);
	tv_ns = (uint32_t)(QuadPart % 10000000)*100;
}


//---------------------------------------------------------------------
// The packet capture trace requires that monitoring filters are placed
// on NDIS devices. The easiest way to accomplish this is using the
// following elevated command-line:
//
//   netsh trace start capture=yes ..
//
// TODO: If a new network device is plugged in or enabled, does
//    this need to be called again?
//
// Get info on parameters:
//   netsh trace start help
//---------------------------------------------------------------------
void PacketTraceSessionImpl::HookNDISTrace()
{
	// only capture headers

	std::wstring args=L"trace start capture=yes report=no correlation=no PacketTruncateBytes=98  maxSize=16m";

	// args += " persistent=yes";

	//system(cmdstr.c_str());

	CreateProcess(L"\\Windows\\System32\\netsh.exe", (LPWSTR)args.c_str(), NULL, NULL, false, 0, NULL, NULL, NULL, NULL);
}

//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
// If there's network traffic and you are not seeing this get
// called, look at HookNDISTrace()
//---------------------------------------------------------------------
void PacketTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent)
{
    DWORD status = ERROR_SUCCESS;
    HRESULT hr = S_OK;
    PTRACE_EVENT_INFO pInfo = NULL;
    LPWSTR pStringGuid = NULL;


	if (IsEqualGUID(pEvent->EventHeader.ProviderId, NDISProviderGuid )) {
		if (m_userPropLen == 0) {
			status = GetUserPropLen(pEvent);
		}
		int packetBytesCaptured = pEvent->UserDataLength - m_userPropLen;
		if (packetBytesCaptured > 0) {
			uint32_t tv_sec, tv_ns;
			GetTimestamp(pEvent->EventHeader.TimeStamp, tv_sec, tv_ns);

			//printf("%d caplen=%d\n", pEvent->EventHeader.TimeStamp.LowPart ,packetBytesCaptured);

			unsigned char *packetBytes = (unsigned char *)pEvent->UserData + m_userPropLen;

			if (0L != m_listener)
				m_listener->OnPacket(tv_sec, tv_ns, packetBytesCaptured, packetBytes, pEvent->EventHeader.ProcessId);
		}
	}
}

//---------------------------------------------------------------------
// Called from StaticEventBufferCallback(), which is called by
// ETW loop in ProcessSession().
//
// The only reason we implement this is to signal to ETW
// to terminate this session's ProcessSession() loop.
//---------------------------------------------------------------------
BOOL PacketTraceSessionImpl::OnBuffer(PEVENT_TRACE_LOGFILE buf)
{
	if (m_stopFlag) return FALSE;	// I'm done. Stop sending and exit ProcessSession()

	return TRUE;// keep sending me events!
}

// some made-up guid to associate with our session
static const GUID myGuid = 
{ 0x10101010, 0x2345, 0x0abcd, { 0xAA, 0x22, 0x71, 0x00, 0x00, 0x00, 0x00, 0xFF } };


//---------------------------------------------------------------------
// Called from Setup()
//---------------------------------------------------------------------
static bool StartTraceSession(std::wstring mySessionName, DWORD dwEnableFlags, TRACEHANDLE &traceSessionHandle)
{
	std::vector<unsigned char>	vecEventTraceProps;	//EVENT_TRACE_PROPERTIES || name

	vecEventTraceProps.resize ( sizeof(EVENT_TRACE_PROPERTIES) + (mySessionName.length()+1)*sizeof(mySessionName[0]) );
	PEVENT_TRACE_PROPERTIES petp = (PEVENT_TRACE_PROPERTIES) &vecEventTraceProps[0];
	petp->Wnode.BufferSize = (ULONG)vecEventTraceProps.size();

	petp->Wnode.Guid = myGuid;	// We could set a random guid here, but StartTrace will create for us if not supplied
	
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

		status = EnableTraceEx2(traceSessionHandle, &NDISProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

		// TODO: check status
	}
	return true;
}

//---------------------------------------------------------------------
//---------------------------------------------------------------------
static VOID WINAPI StaticRecordEventCallback(PEVENT_RECORD pEvent)
{
	if (0L == gPacketTraceSession) return;
	gPacketTraceSession->OnRecordEvent(pEvent);
}

//---------------------------------------------------------------------
//---------------------------------------------------------------------
static BOOL WINAPI StaticBufferEventCallback(PEVENT_TRACE_LOGFILE buf)
{
	if (0L == gPacketTraceSession) return FALSE;
	return gPacketTraceSession->OnBuffer(buf);
}

//---------------------------------------------------------------------
// Establish a session.
// Returns true on success, false otherwise.
//---------------------------------------------------------------------
bool PacketTraceSessionImpl::Setup()
{
	std::wstring mySessionName = L"Example NDIS Packet Trace Session";

	ULONG status = StartTraceSession(mySessionName, 0, this->m_startTraceHandle);
	
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
        wprintf(L"PacketTraceSession: OpenTrace() failed with %lu\n", err);	// lookup in winerror.h
        goto cleanup;
    }

	return true;

cleanup:
	CloseTrace(this->m_startTraceHandle);
	return false;
}

DWORD PacketTraceSessionImpl::GetUserPropLen(PEVENT_RECORD pEvent)
{
	PTRACE_EVENT_INFO pInfo=0L;

    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;

    // Retrieve the required buffer size for the event metadata.

    status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pInfo = (TRACE_EVENT_INFO*) malloc(BufferSize);
        if (pInfo == NULL)
        {
            wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the event metadata.

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
    }

    if (ERROR_SUCCESS == status)
    {
		int proplen = 0;
		for (uint32_t i=0;i < pInfo->PropertyCount;i++) {
		    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
				continue; // buffer, defined by previous property length
			proplen += pInfo->EventPropertyInfoArray[i].length;
		}
		if (proplen > 0)
			m_userPropLen = proplen;
		free(pInfo);
    }

cleanup:

    return status;
}

//---------------------------------------------------------------------
// PacketTraceInstance()
// PacketTraceSession is a singleton.  Will return existing instance or
// create a new one before return.
//
// Returns NULL if setup failed, instance otherwise.
//---------------------------------------------------------------------
PacketTraceSession* PacketTraceInstance() {

	if (gPacketTraceSession != 0L) return gPacketTraceSession;

	PacketTraceSessionImpl* obj = new PacketTraceSessionImpl();
	
	if (obj->Setup() == false) {
		printf("PacketTraceSession Setup failed\n");
		delete obj;
		return 0L;
	}

	gPacketTraceSession = obj;

	return obj;
}
