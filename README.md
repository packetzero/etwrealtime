# Windows Event Trace (ETW) Example

This is a simple Win32 console application that demonstrates the use of 
simultaneous realtime sessions of the standard NT kernel logger and
NDIS packet capture (Win7+).

# Elevated privileges required
Processes that make use of ETW require debugging privileges.

# Packet Capture
Requires that you run a netsh command-line for wiring up NDIS monitoring.

`netsh.exe trace start capture=yes report=no correlation=no PacketTruncateBytes=98  maxSize=16m`

