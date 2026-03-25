# Midterm Project: tasklist/taskkill Recreation in C++

## Overview
This project recreates selected functionality of the Windows `tasklist` and `taskkill` utilities in C++. The project was completed for a digital forensics midterm and focuses on both functionality and defensive detection. My implementation supports the required `tasklist` options `/V` and `/SVC`, and the required `taskkill` options `/PID`, `/IM`, `/F`, `/S`, `/U`, and `/T`.

The goal of this project was to:
1. Write C++ code that returns equivalent results to the assigned binaries
2. Compile and run the tools successfully
3. Demonstrate their behavior through live testing
4. Show how defenders could detect their use using a monitoring tool

---

## Files Included
- `my_tasklist.cpp` - recreates selected `tasklist` functionality
- `my_taskkill.cpp` - recreates selected `taskkill` functionality
- `my_tasklist.exe` - compiled binary
- `my_taskkill.exe` - compiled binary

---

## Supported Functionality

### my_tasklist
This tool supports:
- `my_tasklist.exe`
- `my_tasklist.exe /V`
- `my_tasklist.exe /SVC`

#### Description
- `my_tasklist.exe` lists currently running processes
- `my_tasklist.exe /V` displays verbose process details such as PID, session ID, threads, working set size, username, and creation time when available
- `my_tasklist.exe /SVC` shows services associated with running processes

---

### my_taskkill
This tool supports:
- `my_taskkill.exe /PID <pid>`
- `my_taskkill.exe /IM <image.exe>`
- `my_taskkill.exe /PID <pid> /F`
- `my_taskkill.exe /IM <image.exe> /F`
- `my_taskkill.exe /PID <pid> /F /T`
- `my_taskkill.exe /S <system> /U <domain\\user> /PID <pid> /F`
- `my_taskkill.exe /S <system> /U <domain\\user> /IM <image.exe> /F`

#### Description
- `/PID` terminates a process by PID
- `/IM` terminates a process by image name
- `/F` forces process termination
- `/T` terminates the target process and any child processes in its process tree
- `/S` specifies a remote system
- `/U` specifies the user context for remote WMI-based termination

Note: In my implementation, `/S` and `/U` use WMI for remote termination. Local testing of remote functionality against the same machine may fail due to WMI authentication behavior and environment-specific restrictions.

---

## Build Instructions

### Requirements
- Windows
- Visual Studio
- Visual Studio Developer Command Prompt
- Desktop development with C++ tools installed

### Compile `my_tasklist.cpp`
```developer command prompt
cl /EHsc /W4 /DUNICODE /D_UNICODE my_tasklist.cpp /link advapi32.lib wtsapi32.lib psapi.lib

### Compile `my_taskkill.cpp`
```developer command prompt
cl /EHsc /W4 /DUNICODE /D_UNICODE my_taskkill.cpp /link advapi32.lib wbemuuid.lib ole32.lib oleaut32.lib