	/**
	 * @file kc.h
	 * @brief Declaration of KernelCap structs and constants for the HAC library.
	 * @author Jack (jakcron)
	 * @version 0.1
	 * @date 2022/06/28
	 **/
#pragma once
#include <pietendo/hac/define/types.h>
#include <bitset>

namespace pie { namespace hac {
	
namespace kc
{
	enum class KernelCapId
	{
		Invalid = 0,
		ThreadInfo = 3,
		EnableSystemCalls = 4,
		MemoryMap = 6,
		IoMemoryMap = 7,
		MemoryRegionMap = 10,
		EnableInterrupts = 11,
		MiscParams = 13,
		KernelVersion = 14,
		HandleTableSize = 15,
		MiscFlags = 16,
		Stubbed = 32
	};

	enum class ProgramType
	{
		System,
		Application,
		Applet
	};

	enum class MiscFlagsBit
	{
		EnableDebug,
		ForceDebug
	};

	using MiscFlags = std::bitset<16>;

	enum class MemoryPermission : bool
	{
		Rw,
		Ro
	};

	enum class MappingType : bool
	{
		Io,
		Static
	};

	enum class RegionType : byte_t
	{
		NoMapping,
		KernelTraceBuffer,
		OnMemoryBootImage,
		DTB
	};

	enum class SystemCallId : byte_t
	{
		Unknown0                       = 0,
		SetHeapSize                    = 1,
		SetMemoryPermission            = 2,
		SetMemoryAttribute             = 3,
		MapMemory                      = 4,
		UnmapMemory                    = 5,
		QueryMemory                    = 6,
		ExitProcess                    = 7,
		CreateThread                   = 8,
		StartThread                    = 9,
		ExitThread                     = 10,
		SleepThread                    = 11,
		GetThreadPriority              = 12,
		SetThreadPriority              = 13,
		GetThreadCoreMask              = 14,
		SetThreadCoreMask              = 15,
		GetCurrentProcessorNumber      = 16,
		SignalEvent                    = 17,
		ClearEvent                     = 18,
		MapSharedMemory                = 19,
		UnmapSharedMemory              = 20,
		CreateTransferMemory           = 21,
		CloseHandle                    = 22,
		ResetSignal                    = 23,
		WaitSynchronization            = 24,
		CancelSynchronization          = 25,
		ArbitrateLock                  = 26,
		ArbitrateUnlock                = 27,
		WaitProcessWideKeyAtomic       = 28,
		SignalProcessWideKey           = 29,
		GetSystemTick                  = 30,
		ConnectToNamedPort             = 31,
		SendSyncRequestLight           = 32,
		SendSyncRequest                = 33,
		SendSyncRequestWithUserBuffer  = 34,
		SendAsyncRequestWithUserBuffer = 35,
		GetProcessId                   = 36,
		GetThreadId                    = 37,
		Break                          = 38,
		OutputDebugString              = 39,
		ReturnFromException            = 40,
		GetInfo                        = 41,
		FlushEntireDataCache           = 42,
		FlushDataCache                 = 43,
		MapPhysicalMemory              = 44,
		UnmapPhysicalMemory            = 45,
		GetDebugFutureThreadInfo       = 46,
		GetLastThreadInfo              = 47,
		GetResourceLimitLimitValue     = 48,
		GetResourceLimitCurrentValue   = 49,
		SetThreadActivity              = 50,
		GetThreadContext3              = 51,
		WaitForAddress                 = 52,
		SignalToAddress                = 53,
		SynchronizePreemptionState     = 54,
		Unknown55                      = 55,
		Unknown56                      = 56,
		Unknown57                      = 57,
		Unknown58                      = 58,
		Unknown59                      = 59,
		KernelDebug                    = 60,
		ChangeKernelTraceState         = 61, /* DumpInfo [1.0.0-3.0.2] */
		Unknown62                      = 62,
		Unknown63                      = 63,
		CreateSession                  = 64,
		AcceptSession                  = 65,
		ReplyAndReceiveLight           = 66,
		ReplyAndReceive                = 67,
		ReplyAndReceiveWithUserBuffer  = 68,
		CreateEvent                    = 69,
		Unknown70                      = 70,
		Unknown71                      = 71,
		MapPhysicalMemoryUnsafe        = 72,
		UnmapPhysicalMemoryUnsafe      = 73,
		SetUnsafeLimit                 = 74,
		CreateCodeMemory               = 75,
		ControlCodeMemory              = 76,
		SleepSystem                    = 77,
		ReadWriteRegister              = 78,
		SetProcessActivity             = 79,
		CreateSharedMemory             = 80,
		MapTransferMemory              = 81,
		UnmapTransferMemory            = 82,
		CreateInterruptEvent           = 83,
		QueryPhysicalAddress           = 84,
		QueryIoMapping                 = 85,
		CreateDeviceAddressSpace       = 86,
		AttachDeviceAddressSpace       = 87,
		DetachDeviceAddressSpace       = 88,
		MapDeviceAddressSpaceByForce   = 89,
		MapDeviceAddressSpaceAligned   = 90,
		MapDeviceAddressSpace          = 91,
		UnmapDeviceAddressSpace        = 92,
		InvalidateProcessDataCache     = 93,
		StoreProcessDataCache          = 94,
		FlushProcessDataCache          = 95,
		DebugActiveProcess             = 96,
		BreakDebugProcess              = 97,
		TerminateDebugProcess          = 98,
		GetDebugEvent                  = 99,
		ContinueDebugEvent             = 100,
		GetProcessList                 = 101,
		GetThreadList                  = 102,
		GetDebugThreadContext          = 103,
		SetDebugThreadContext          = 104,
		QueryDebugProcessMemory        = 105,
		ReadDebugProcessMemory         = 106,
		WriteDebugProcessMemory        = 107,
		SetHardwareBreakPoint          = 108,
		GetDebugThreadParam            = 109,
		Unknown110                     = 110,
		GetSystemInfo                  = 111,
		CreatePort                     = 112,
		ManageNamedPort                = 113,
		ConnectToPort                  = 114,
		SetProcessMemoryPermission     = 115,
		MapProcessMemory               = 116,
		UnmapProcessMemory             = 117,
		QueryProcessMemory             = 118,
		MapProcessCodeMemory           = 119,
		UnmapProcessCodeMemory         = 120,
		CreateProcess                  = 121,
		StartProcess                   = 122,
		TerminateProcess               = 123,
		GetProcessInfo                 = 124,
		CreateResourceLimit            = 125,
		SetResourceLimitLimitValue     = 126,
		CallSecureMonitor              = 127
	};

	static const uint32_t kMaxSystemCallNum = ((1 << 3) * 24);
	static const uint32_t kMaxSystemCallId = kMaxSystemCallNum - 1;
	using SystemCallIds = std::bitset<kMaxSystemCallNum>;
}

}} // namespace pie::hac