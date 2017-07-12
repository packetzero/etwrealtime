# Windows Event Trace (ETW) Example

This is a simple Win32 console application that demonstrates the use of 
simultaneous realtime sessions of the standard NT kernel logger and
NDIS packet capture (Win7+).

# Elevated privileges required
Processes that make use of ETW require debugging privileges.

# Packet Capture
Requires that you run a netsh command-line for wiring up NDIS monitoring.  Notice that I ask for truncated packets... full packet capture without specialized hardware is too much load, and will lead to dropped events.  The first 98 bytes of packets are enough to get the layer headers for IPV4 and IPV6.

`netsh.exe trace start capture=yes report=no correlation=no PacketTruncateBytes=98  maxSize=16m`

# Delayed Events and Flood of Events at Start
After trace sessions have been established for a while, and you restart your application (e.g. this example), you will get a flood of events.  This is because ETW is buffered.  It appears that ETW will send you everything it has buffered up, and once caught-up, new events.  You need to plan for this, and ignore buffered events.

Additionally, consider that events such as packets are not really 'real time'.  There is a delay of several seconds between an action (a packet sent on wire or new process start) and the event to be reported to your application.

# References
- [Stackoverflow Discussion on NDIS ETW](https://stackoverflow.com/questions/9470135/how-to-consume-real-time-etw-events-from-the-microsoft-windows-ndis-packetcaptur?rq=1)
- [MS Message Analyzer](https://blogs.technet.microsoft.com/messageanalyzer/)

Thank you,


Alex Malone, Ziften Technologies Inc.

