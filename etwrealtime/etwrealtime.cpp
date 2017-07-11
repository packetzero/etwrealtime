// To receive NDIS Packet capture events, you need to enable using:
// netsh trace start capture=yes report=no persistent=yes correlation=no PacketTruncateBytes=98  
// netsh trace show capturefilterhelp

#include "stdafx.h"

//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <guiddef.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>

#pragma comment(lib, "tdh.lib")

static const GUID GUID_NULL = 
{ 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

// some made-up guid to associate with our session
static const GUID myGuid = 
{ 0x10101010, 0x2345, 0x0abcd, { 0xAA, 0x22, 0x71, 0x00, 0x00, 0x00, 0x00, 0xFF } };


// Strings that represent the source of the event metadata.

WCHAR* pSource[] = {L"XML instrumentation manifest", L"WMI MOF class", L"WPP TMF file"};

// Handle to the trace file that you opened.

//TRACEHANDLE g_hTrace = 0;  


// Prototypes

void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
DWORD GetUserPropLen(PEVENT_RECORD pEvent);
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);
DWORD PrintPropertyMetadata(TRACE_EVENT_INFO* pInfo, DWORD i, USHORT indent);

#include <vector>
#include <string>


// From "logman query providers"
//
// Microsoft-Windows-NDIS                   {CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}
// Microsoft-Windows-NDIS-PacketCapture     {2ED6006E-4729-4609-B423-3EE7BCD678EF}
//  
DEFINE_GUID ( /* 2ed6006e-4729-4609-b423-3ee7bcd678ef */
    NDISProviderGuid,
    0x2ed6006e,
    0x4729,
    0x4609,
    0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef
  );

//std::wstring	gNdisTraceSessionName;	//a name for this session
//TRACEHANDLE		gTraceSessionHandle;			//the trace handle



ULONG StartTraceSession(bool bIsKernelLoggerSession, std::wstring mySessionName, DWORD dwEnableFlags, TRACEHANDLE &traceSessionHandle)
{
	std::vector<unsigned char>	gVecEventTraceProps;	//EVENT_TRACE_PROPERTIES || names

	gVecEventTraceProps.resize ( sizeof(EVENT_TRACE_PROPERTIES) + (mySessionName.length()+1)*sizeof(mySessionName[0]) );
	PEVENT_TRACE_PROPERTIES petp = (PEVENT_TRACE_PROPERTIES) &gVecEventTraceProps[0];
	petp->Wnode.BufferSize = (ULONG)gVecEventTraceProps.size();

	if (bIsKernelLoggerSession)
		petp->Wnode.Guid = SystemTraceControlGuid;
	else
		petp->Wnode.Guid = myGuid;
	
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
	}
	else if (status != ERROR_SUCCESS )
	{
		printf("StartTraceW returned %ul\n", status);
		traceSessionHandle = 0L;
	}
	return status;
}

void wmain(void)
{
    ULONG status = ERROR_SUCCESS;
    EVENT_TRACE_LOGFILE trace;
    TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

	// Start trace

	TRACEHANDLE myNdisTraceSessionHandle=0L;
	std::wstring myNdisSessionName = L"NDIS session";
	status = StartTraceSession(false, myNdisSessionName, 0, myNdisTraceSessionHandle);

	//StartTraceSession(myGuid, 0);
	if (myNdisTraceSessionHandle == 0L) return;

	status = EnableTraceEx2(myNdisTraceSessionHandle, &NDISProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

    // Identify the log file from which you want to consume events
    // and the callbacks used to process the events and buffers.

    ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = (LPWSTR)myNdisSessionName.c_str();
    trace.LogFileName = (LPWSTR) NULL;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK) (ProcessEvent);
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	

    TRACEHANDLE hTrace = OpenTrace(&trace);
    if (INVALID_PROCESSTRACE_HANDLE == hTrace)
    {
		DWORD err = GetLastError();
        wprintf(L"OpenTrace failed with %lu\n", err);	// lookup in winerror.h
        goto cleanup;
    }

    status = ProcessTrace(&hTrace, 1, 0, 0);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
    {
        wprintf(L"ProcessTrace failed with %lu\n", status);
        goto cleanup;
    }

cleanup:

    if (INVALID_PROCESSTRACE_HANDLE != hTrace)
    {
        status = CloseTrace(hTrace);
    }
}

const int CAPLEN=92;
int gUserPropLen=0;

VOID WINAPI ProcessEvent(PEVENT_RECORD pEvent)
{
    DWORD status = ERROR_SUCCESS;
    HRESULT hr = S_OK;
    PTRACE_EVENT_INFO pInfo = NULL;
    LPWSTR pStringGuid = NULL;


    // Skips the event if it is the event trace header. Log files contain this event
    // but real-time sessions do not. The event contains the same information as 
    // the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open 
    // the trace. 

    if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
        pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
    {
        return; // Skip this event.
    }
	else if (IsEqualGUID(pEvent->EventHeader.ProviderId, NDISProviderGuid )) {
		if (gUserPropLen == 0) {
			status = GetUserPropLen(pEvent);
		}
		int packetBytesCaptured = pEvent->UserDataLength - gUserPropLen;
		if (packetBytesCaptured <= 0) {
			return;
		} else {
			printf("%d caplen=%d\n", pEvent->EventHeader.TimeStamp.LowPart ,packetBytesCaptured);
			unsigned char *packetBytes = (unsigned char *)pEvent->UserData + gUserPropLen;
			return;
		}
	}
	else
    {
        // Process the event. This example does not process the event data but
        // instead prints the metadata that describes each event.

        status = GetEventInformation(pEvent, pInfo);

        if (ERROR_SUCCESS != status)
        {
            wprintf(L"GetEventInformation failed with %lu\n", status);
            goto cleanup;
        }

        wprintf(L"Decoding source: %s\n", pSource[pInfo->DecodingSource]);

        if (DecodingSourceWPP == pInfo->DecodingSource)
        {
            // This example is not rendering WPP metadata.
            goto cleanup;
        }

        if (pInfo->ProviderNameOffset > 0)
        {
            wprintf(L"Provider name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->ProviderNameOffset));
        }

        hr = StringFromCLSID(pInfo->ProviderGuid, &pStringGuid);
        if (FAILED(hr))
        {
            wprintf(L"StringFromCLSID(ProviderGuid) failed with 0x%x\n", hr);
            status = hr;
            goto cleanup;
        }

        wprintf(L"\nProvider GUID: %s\n", pStringGuid);
        CoTaskMemFree(pStringGuid);
        pStringGuid = NULL;

        if (!IsEqualGUID(pInfo->EventGuid, GUID_NULL))
        {
            hr = StringFromCLSID(pInfo->EventGuid, &pStringGuid);
            if (FAILED(hr))
            {
                wprintf(L"StringFromCLSID(EventGuid) failed with 0x%x\n", hr);
                status = hr;
                goto cleanup;
            }

            wprintf(L"\nEvent GUID: %s\n", pStringGuid);
            CoTaskMemFree(pStringGuid);
            pStringGuid = NULL;
        }


        if (DecodingSourceXMLFile == pInfo->DecodingSource)
        {
            wprintf(L"Event ID: %hu\n", pInfo->EventDescriptor.Id);
        }

        wprintf(L"Version: %d\n", pInfo->EventDescriptor.Version);

        if (pInfo->ChannelNameOffset > 0)
        {
            wprintf(L"Channel name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->ChannelNameOffset));
        }

        if (pInfo->LevelNameOffset > 0)
        {
            wprintf(L"Level name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->LevelNameOffset));
        }
        else
        {
            wprintf(L"Level: %hu\n", pInfo->EventDescriptor.Level);
        }

        if (DecodingSourceXMLFile == pInfo->DecodingSource)
        {
            if (pInfo->OpcodeNameOffset > 0)
            {
                wprintf(L"Opcode name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->OpcodeNameOffset));
            }
        }
        else
        {
            wprintf(L"Type: %hu\n", pInfo->EventDescriptor.Opcode);
        }

        if (DecodingSourceXMLFile == pInfo->DecodingSource)
        {
            if (pInfo->TaskNameOffset > 0)
            {
                wprintf(L"Task name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->TaskNameOffset));
            }
        }
        else
        {
            wprintf(L"Task: %hu\n", pInfo->EventDescriptor.Task);
        }

        wprintf(L"Keyword mask: 0x%x\n", pInfo->EventDescriptor.Keyword);
        if (pInfo->KeywordsNameOffset)
        {
            LPWSTR pKeyword = (LPWSTR)((PBYTE)(pInfo) + pInfo->KeywordsNameOffset);

            for (; *pKeyword != 0; pKeyword += (wcslen(pKeyword) + 1))
                wprintf(L"  Keyword name: %s\n", pKeyword);
        }

        if (pInfo->EventMessageOffset > 0)
        {
            wprintf(L"Event message: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->EventMessageOffset));
        }

        if (pInfo->ActivityIDNameOffset > 0)
        {
            wprintf(L"Activity ID name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->ActivityIDNameOffset));
        }

        if (pInfo->RelatedActivityIDNameOffset > 0)
        {
            wprintf(L"Related activity ID name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->RelatedActivityIDNameOffset));
        }

        wprintf(L"Number of top-level properties: %lu\n", pInfo->TopLevelPropertyCount);

        wprintf(L"Total number of properties: %lu\n", pInfo->PropertyCount);

        // Print the metadata for all the top-level properties. Metadata for all the 
        // top-level properties come before structure member properties in the 
        // property information array.

        if (pInfo->TopLevelPropertyCount > 0)
        {
            wprintf(L"\nThe following are the user data properties defined for this event:\n");

            for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
            {
                status = PrintPropertyMetadata(pInfo, i, 0);
                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"Printing metadata for top-level properties failed.\n");
                    goto cleanup;
                }
            }
        }
        else
        {
            wprintf(L"\nThe event does not define any user data properties.\n");
        }

        wprintf(L"\n");
    }

cleanup:

    if (pInfo)
    {
        free(pInfo);
    }

    if (ERROR_SUCCESS != status)
    {
        //CloseTrace(g_hTrace);
    }
}

DWORD GetUserPropLen(PEVENT_RECORD pEvent)
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
		for (int i=0;i < pInfo->PropertyCount;i++) {
		    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
				continue; // buffer, defined by previous property length
			proplen += pInfo->EventPropertyInfoArray[i].length;
		}
		if (proplen > 0)
			gUserPropLen = proplen;
		free(pInfo);
    }

cleanup:

    return status;
}

DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo)
{
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

    if (ERROR_SUCCESS != status)
    {
        wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
    }

cleanup:

    return status;
}


// Print the metadata for each property.

DWORD PrintPropertyMetadata(TRACE_EVENT_INFO* pinfo, DWORD i, USHORT indent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD j = 0;
    DWORD lastMember = 0;  // Last member of a structure

    // Print property name.

    wprintf(L"%*s%s", indent, L"", (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[i].NameOffset));


    // If the property is an array, the property can define the array size or it can
    // point to another property whose value defines the array size. The PropertyParamCount
    // flag tells you where the array size is defined.

    if ((pinfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        j = pinfo->EventPropertyInfoArray[i].countPropertyIndex;
        wprintf(L" (array size is defined by %s)", (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[j].NameOffset));
    }
    else
    {
        if (pinfo->EventPropertyInfoArray[i].count > 1)
            wprintf(L" (array size is %lu)", pinfo->EventPropertyInfoArray[i].count);
    }


    // If the property is a buffer, the property can define the buffer size or it can
    // point to another property whose value defines the buffer size. The PropertyParamLength
    // flag tells you where the buffer size is defined.

    if ((pinfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
    {
        j = pinfo->EventPropertyInfoArray[i].lengthPropertyIndex;
        wprintf(L" (size is defined by %s)", (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[j].NameOffset));
    }
    else
    {
        // Variable length properties such as structures and some strings do not have
        // length definitions.

        if (pinfo->EventPropertyInfoArray[i].length > 0)
            wprintf(L" (size is %lu bytes)", pinfo->EventPropertyInfoArray[i].length);
        else
            wprintf(L" (size  is unknown)");
    }

    wprintf(L"\n");


    // If the property is a structure, print the members of the structure.

    if ((pinfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
    {
        wprintf(L"%*s(The property is a structure and has the following %hu members:)\n", 4, L"",
            pinfo->EventPropertyInfoArray[i].structType.NumOfStructMembers);

        lastMember = pinfo->EventPropertyInfoArray[i].structType.StructStartIndex + 
            pinfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

        for (j = pinfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < lastMember; j++)
        {
            PrintPropertyMetadata(pinfo, j, 4);
        }
    }
    else
    {
        // You can use InType to determine the data type of the member and OutType
        // to determine the output format of the data.

        if (pinfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset)
        {
            // You can pass the name to the TdhGetEventMapInformation function to 
            // retrieve metadata about the value map.

            wprintf(L"%*s(Map attribute name is %s)\n", indent, L"", 
                (PWCHAR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset));
        }
    }

    return status;
}

/*
0x00732010  0a 00 00 00 0a 00 00 00 5c 00 00 00 d4 ae 52 a1 3e 83 00 0c 29 26 26 11 08 00 45 00 00 4e 14 4d 40 00 80 06 00 00 0a 00 14 c9 36 d7 aa 09 c7 aa 01 bb c2 7e f3 2f 46 54 25 2f 50 18 80  ........\...Ô®R¡>ƒ..)&&...E..N.M@.€......É6×ª.Çª.»Â~ó/FT%/P.€
0x0073204D  00 ff e9 00 00 17 03 03 00 21 00 00 00 00 00 00 00 04 10 ff a7 47 51 67 87 5d 8b 40 b3 84 f2 c5 04 8b 9b 9b 94 c7 11 fc 72 da fc b8 00 13 c0 00 00 00 00 98 13 00 00 d0 12 00 00 c9 91  .ÿé......!.........ÿ§GQg.].@..òÅ....”Ç.ürÚü¸..À....˜...Ð...É‘
0x0073208A  59 9c 07 00 00 00 6e 00 d6 2e 29 47 09 46 b4 23 3e e7 bc d6 78 ef e9 03 00 10 04 00 00 00 01 00 00 c0 01 06 00 80 01 00 00 00 00 00 00 00 23 d6 02 00 00 00 00 00 00 00 00 00 00 00 00  Yœ....n.Ö.)G.F´#>ç.Öxïé..........À...€........#Ö.............
0x007320C7  00 0a 00 00 00 0a 00 00 00 5c 00 00 00 d4 ae 52 a1 3e 83 00 0c 29 26 26 11 08 00 45 00 00 4e 14 4e 40 00 80 06 00 00 0a 00 14 c9 36 d7 aa 09 c7 ab 01 bb 2d e0 b3 0e 30 25 37 4d 50 18  .........\...Ô®R¡>ƒ..)&&...E..N.N@.€......É6×ª.Ç«.»-à..0%7MP.
0x00732104  7f d2 ff e9 00 00 17 03 03 00 21 00 00 00 00 00 00 00 02 80 c0 91 bd bd a6 65 6f 84 26 65 1a 80 8a 12 0f 06 02 28 a1 db 7c 26 ed 9c b8 02 13 c0 00 00 00 00 98 13 00 00 d0 12 00 00 23  .Òÿé......!........€À‘..¦eo.&e.€Š....(¡Û|&íœ¸..À....˜...Ð...#
0x00732141  96 59 9c 07 00 00 00 6e 00 d6 2e 29 47 09 46 b4 23 3e e7 bc d6 78 ef e9 03 00 10 04 00 00 00 01 00 00 c0 02 06 00 80 02 00 00 00 00 00 00 00 24 d6 02 00 00 00 00 00 00 00 00 00 00 00  –Yœ....n.Ö.)G.F´#>ç.Öxïé..........À...€........$Ö............
0x0073217E  00 00 0a 00 00 00 0a 00 00 00 5c 02 00 00 00 0c 29 26 26 11 d4 ae 52 a1 3e 83 08 00 45 00 02 4e 29 18 40 00 2c 06 23 e9 36 d7 aa 09 0a 00 14 c9 01 bb c7 aa 46 54 25 2f c2 7e f3 2f 50  ..........\.....)&&.Ô®R¡>ƒ..E..N).@.,.#é6×ª....É.»ÇªFT%/Â~ó/P


MiniportIfIndex (size is 4 bytes)
LowerIfIndex (size is 4 bytes)
FragmentSize (size is 4 bytes)

0x00732010  

0a 00 00 00 MiniportIfIndex
0a 00 00 00 LowerIfIndex
5c 00 00 00 FragmentSize     (92 = caplen)

d4 ae 52 a1 3e 83
00 0c 29 26 26 11
08 00  // IPV4
45 00 00 4e 14 4d 40 00 80 06 00 00 0a 00 14 c9 36 d7 aa 09 c7 aa 01 bb c2 7e f3 2f 46 54 25 2f 50 18 80  ........\...Ô®R¡>ƒ..)&&...E..N.M@.€......É6×ª.Çª.»Â~ó/FT%/P.€
0x0073204D  00 ff e9 00 00 17 03 03 00 21 00 00 00 00 00 00 00 04 10 ff a7 47 51 67 87 5d 8b 40 b3 84 f2 c5 04 8b 9b 9b 94 c7 11 fc 72 da fc b8 00 13 c0 00 00 00 00 98 13 00 00 d0 12 00 00 c9 91  .ÿé......!.........ÿ§GQg.].@..òÅ....”Ç.ürÚü¸..À....˜...Ð...É‘
0x0073208A  59 9c 07 00 00 00 6e 00 d6 2e 29 47 09 46 b4 23 3e e7 bc d6 78 ef e9 03 00 10 04 00 00 00 01 00 00 c0 01 06 00 80 01 00 00 00 00 00 00 00 23 d6 02 00 00 00 00 00 00 00 00 00 00 00 00  Yœ....n.Ö.)G.F´#>ç.Öxïé..........À...€........#Ö.............
0x007320C7  00 0a 00 00 00 0a 00 00 00 5c 00 00 00 d4 ae 52 a1 3e 83 00 0c 29 26 26 11 08 00 45 00 00 4e 14 4e 40 00 80 06 00 00 0a 00 14 c9 36 d7 aa 09 c7 ab 01 bb 2d e0 b3 0e 30 25 37 4d 50 18  .........\...Ô®R¡>ƒ..)&&...E..N.N@.€......É6×ª.Ç«.»-à..0%7MP.
0x00732104  7f d2 ff e9 00 00 17 03 03 00 21 00 00 00 00 00 00 00 02 80 c0 91 bd bd a6 65 6f 84 26 65 1a 80 8a 12 0f 06 02 28 a1 db 7c 26 ed 9c b8 02 13 c0 00 00 00 00 98 13 00 00 d0 12 00 00 23  .Òÿé......!........€À‘..¦eo.&e.€Š....(¡Û|&íœ¸..À....˜...Ð...#
0x00732141  96 59 9c 07 00 00 00 6e 00 d6 2e 29 47 09 46 b4 23 3e e7 bc d6 78 ef e9 03 00 10 04 00 00 00 01 00 00 c0 02 06 00 80 02 00 00 00 00 00 00 00 24 d6 02 00 00 00 00 00 00 00 00 00 00 00  –Yœ....n.Ö.)G.F´#>ç.Öxïé..........À...€........$Ö............
0x0073217E  00 00 0a 00 00 00 0a 00 00 00 5c 02 00 00 00 0c 29 26 26 11 d4 ae 52 a1 3e 83 08 00 45 00 02 4e 29 18 40 00 2c 06 23 e9 36 d7 aa 09 0a 00 14 c9 01 bb c7 aa 46 54 25 2f c2 7e f3 2f 50  ..........\.....)&&.Ô®R¡>ƒ..E..N).@.,.#é6×ª....É.»ÇªFT%/Â~ó/P


0x011A2148  
0a 00 00 00
0a 00 00 00
66 00 00 00 
33 33 00 00 00 fb 
98 01 a7 b1 7d c9
86 dd // ipv6
60 07 21 89 00 30 11 ff fe 80 00 00 00 00 00 00 04 17 cd 8e bc 86 52 97 ff 02 00 00 00 00 00 00 00 00 00  ........f...33...û˜.§±}É.Ý`.!..0.ÿþ€........ÍŽ..R—ÿ..........
0x011A2185  00 00 00 00 fb 14 e9 14 e9 00 30 ac 61 00 00 00 00 00 01 00 00 00 00 00 00 0b 5f 67 6f 6f 67 6c 65 63 61 73 74 04 5f 74 63 70 05 6c 6f 63 61 6c 00 00 0c 00 01 ff ff ff ff ff ff 00 00  ....û.é.é.0¬a............._googlecast._tcp.local.....ÿÿÿÿÿÿ..
0x011A21C2  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  .............................................................

*/