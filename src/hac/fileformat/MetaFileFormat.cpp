#include <pietendo/hac/fileformat/MetaFileFormat.h>

#include <pietendo/hac/AccessControlInfoUtil.h>
#include <pietendo/hac/FileSystemAccessUtil.h>
#include <pietendo/hac/KernelCapabilityUtil.h>
#include <pietendo/hac/MetaUtil.h>

#include <tc/io/IOUtil.h>

#include <fmt/core.h>

pie::hac::MetaFileFormat::MetaFileFormat() :
	mModuleName("pie::hac::MetaFileFormat"),
	mFile()
{
}

pie::hac::MetaFileFormat::MetaFileFormat(const std::shared_ptr<tc::io::IStream>& base, const KeyBag& keycfg) :
	MetaFileFormat()
{
	mFile = base;
	mKeyCfg = keycfg;

	if (mFile == nullptr)
	{
		throw tc::Exception(mModuleName, "No file reader set.");
	}
	if (mFile->canRead() == false || mFile->canSeek() == false)
	{
		throw tc::NotSupportedException(mModuleName, "Input stream requires read/seek permissions.");
	}

	// check if file_size is greater than 20MB, don't import.
	size_t file_size = tc::io::IOUtil::castInt64ToSize(mFile->length());
	if (file_size > (0x100000 * 20))
	{
		throw tc::Exception(mModuleName, "File too large.");
	}

	// read meta
	tc::ByteData scratch = tc::ByteData(file_size);
	mFile->seek(0, tc::io::SeekOrigin::Begin);
	mFile->read(scratch.data(), scratch.size());

	mMeta.fromBytes(scratch.data(), scratch.size());
}

void pie::hac::MetaFileFormat::validate()
{
	validateAcidSignature(mMeta.getAccessControlInfoDesc(), mMeta.getAccessControlInfoDescKeyGeneration());
	validateAciFromAcid(mMeta.getAccessControlInfo(), mMeta.getAccessControlInfoDesc());
}

const pie::hac::Meta& pie::hac::MetaFileFormat::getMeta() const
{
	return mMeta;
}

void pie::hac::MetaFileFormat::validateAcidSignature(const pie::hac::AccessControlInfoDesc& acid, byte_t key_generation)
{
	try {
		if (mKeyCfg.acid_sign_key.find(key_generation) == mKeyCfg.acid_sign_key.end())
		{
			throw tc::Exception("Failed to load rsa public key");
		}

		acid.validateSignature(mKeyCfg.acid_sign_key.at(key_generation));
	}
	catch (tc::Exception& e) {
		fmt::print("[WARNING] ACID Signature: FAIL ({:s})\n", e.error());
	}
	
}

void pie::hac::MetaFileFormat::validateAciFromAcid(const pie::hac::AccessControlInfo& aci, const pie::hac::AccessControlInfoDesc& acid)
{
	// check Program ID
	if (acid.getProgramIdRestrict().min > 0 && aci.getProgramId() < acid.getProgramIdRestrict().min)
	{
		fmt::print("[WARNING] ACI ProgramId: FAIL (Outside Legal Range)\n");
	}
	else if (acid.getProgramIdRestrict().max > 0 && aci.getProgramId() > acid.getProgramIdRestrict().max)
	{
		fmt::print("[WARNING] ACI ProgramId: FAIL (Outside Legal Range)\n");
	}

	auto fs_access = aci.getFileSystemAccessControl().getFsAccess();
	auto desc_fs_access = acid.getFileSystemAccessControl().getFsAccess();
	for (size_t i = 0; i < fs_access.size(); i++)
	{
		bool rightFound = false;
		for (size_t j = 0; j < desc_fs_access.size() && rightFound == false; j++)
		{
			if (fs_access[i] == desc_fs_access[j])
				rightFound = true;
		}

		if (rightFound == false)
		{
			fmt::print("[WARNING] ACI/FAC FsaRights: FAIL ({:s} not permitted)\n", pie::hac::FileSystemAccessUtil::getFsAccessFlagAsString(fs_access[i]));
		}
	}

	for (size_t i = 0; i < aci.getFileSystemAccessControl().getContentOwnerIdList().size(); i++)
	{
		bool rightFound = false;
		for (size_t j = 0; j < acid.getFileSystemAccessControl().getContentOwnerIdList().size() && rightFound == false; j++)
		{
			if (aci.getFileSystemAccessControl().getContentOwnerIdList()[i] == acid.getFileSystemAccessControl().getContentOwnerIdList()[j])
				rightFound = true;
		}

		if (rightFound == false)
		{

			fmt::print("[WARNING] ACI/FAC ContentOwnerId: FAIL (0x{:016x} not permitted)\n", aci.getFileSystemAccessControl().getContentOwnerIdList()[i]);
		}
	}

	for (size_t i = 0; i < aci.getFileSystemAccessControl().getSaveDataOwnerIdList().size(); i++)
	{
		bool rightFound = false;
		for (size_t j = 0; j < acid.getFileSystemAccessControl().getSaveDataOwnerIdList().size() && rightFound == false; j++)
		{
			if (aci.getFileSystemAccessControl().getSaveDataOwnerIdList()[i] == acid.getFileSystemAccessControl().getSaveDataOwnerIdList()[j])
				rightFound = true;
		}

		if (rightFound == false)
		{

			fmt::print("[WARNING] ACI/FAC SaveDataOwnerId: FAIL (0x{:016x} ({:d}) not permitted)\n", aci.getFileSystemAccessControl().getSaveDataOwnerIdList()[i].id, (uint32_t)aci.getFileSystemAccessControl().getSaveDataOwnerIdList()[i].access_type);
		}
	}

	// check SAC
	for (size_t i = 0; i < aci.getServiceAccessControl().getServiceList().size(); i++)
	{
		bool rightFound = false;
		for (size_t j = 0; j < acid.getServiceAccessControl().getServiceList().size() && rightFound == false; j++)
		{
			if (aci.getServiceAccessControl().getServiceList()[i] == acid.getServiceAccessControl().getServiceList()[j])
				rightFound = true;
		}

		if (rightFound == false)
		{
			fmt::print("[WARNING] ACI/SAC ServiceList: FAIL ({:s}{:s} not permitted)\n", aci.getServiceAccessControl().getServiceList()[i].getName(), (aci.getServiceAccessControl().getServiceList()[i].isServer()? " (Server)" : ""));
		}
	}

	// check KC
	// check thread info
	if (aci.getKernelCapabilities().getThreadInfo().getMaxCpuId() != acid.getKernelCapabilities().getThreadInfo().getMaxCpuId())
	{
		fmt::print("[WARNING] ACI/KC ThreadInfo/MaxCpuId: FAIL ({:d} not permitted)\n", aci.getKernelCapabilities().getThreadInfo().getMaxCpuId());
	}
	if (aci.getKernelCapabilities().getThreadInfo().getMinCpuId() != acid.getKernelCapabilities().getThreadInfo().getMinCpuId())
	{
		fmt::print("[WARNING] ACI/KC ThreadInfo/MinCpuId: FAIL ({:d} not permitted)\n", aci.getKernelCapabilities().getThreadInfo().getMinCpuId());
	}
	if (aci.getKernelCapabilities().getThreadInfo().getMaxPriority() != acid.getKernelCapabilities().getThreadInfo().getMaxPriority())
	{
		fmt::print("[WARNING] ACI/KC ThreadInfo/MaxPriority: FAIL ({:d} not permitted)\n", aci.getKernelCapabilities().getThreadInfo().getMaxPriority());
	}
	if (aci.getKernelCapabilities().getThreadInfo().getMinPriority() != acid.getKernelCapabilities().getThreadInfo().getMinPriority())
	{
		fmt::print("[WARNING] ACI/KC ThreadInfo/MinPriority: FAIL ({:d} not permitted)\n", aci.getKernelCapabilities().getThreadInfo().getMinPriority());
	}
	// check system calls
	auto syscall_ids = aci.getKernelCapabilities().getSystemCalls().getSystemCallIds();
	auto desc_syscall_ids = acid.getKernelCapabilities().getSystemCalls().getSystemCallIds();
	for (size_t i = 0; i < syscall_ids.size(); i++)
	{
		if (syscall_ids.test(i) && desc_syscall_ids.test(i) == false)
		{
			fmt::print("[WARNING] ACI/KC SystemCallList: FAIL ({:s} not permitted)\n", pie::hac::KernelCapabilityUtil::getSystemCallIdAsString(pie::hac::kc::SystemCallId(i)));
		}
	}
	// check memory maps
	for (size_t i = 0; i < aci.getKernelCapabilities().getMemoryMaps().getMemoryMaps().size(); i++)
	{
		bool rightFound = false;
		for (size_t j = 0; j < acid.getKernelCapabilities().getMemoryMaps().getMemoryMaps().size() && rightFound == false; j++)
		{
			if (aci.getKernelCapabilities().getMemoryMaps().getMemoryMaps()[i] == acid.getKernelCapabilities().getMemoryMaps().getMemoryMaps()[j])
				rightFound = true;
		}

		if (rightFound == false)
		{
			auto map = aci.getKernelCapabilities().getMemoryMaps().getMemoryMaps()[i];

			fmt::print("[WARNING] ACI/KC MemoryMap: FAIL ({:s} not permitted)\n", formatMappingAsString(map));
		}
	}
	for (size_t i = 0; i < aci.getKernelCapabilities().getMemoryMaps().getIoMemoryMaps().size(); i++)
	{
		bool rightFound = false;
		for (size_t j = 0; j < acid.getKernelCapabilities().getMemoryMaps().getIoMemoryMaps().size() && rightFound == false; j++)
		{
			if (aci.getKernelCapabilities().getMemoryMaps().getIoMemoryMaps()[i] == acid.getKernelCapabilities().getMemoryMaps().getIoMemoryMaps()[j])
				rightFound = true;
		}

		if (rightFound == false)
		{
			auto map = aci.getKernelCapabilities().getMemoryMaps().getIoMemoryMaps()[i];

			fmt::print("[WARNING] ACI/KC IoMemoryMap: FAIL ({:s} not permitted)\n", formatMappingAsString(map));
		}
	}
	// check interupts
	for (size_t i = 0; i < aci.getKernelCapabilities().getInterupts().getInteruptList().size(); i++)
	{
		bool rightFound = false;
		for (size_t j = 0; j < acid.getKernelCapabilities().getInterupts().getInteruptList().size() && rightFound == false; j++)
		{
			if (aci.getKernelCapabilities().getInterupts().getInteruptList()[i] == acid.getKernelCapabilities().getInterupts().getInteruptList()[j])
				rightFound = true;
		}

		if (rightFound == false)
		{
			fmt::print("[WARNING] ACI/KC InteruptsList: FAIL (0x{:x} not permitted)\n", aci.getKernelCapabilities().getInterupts().getInteruptList()[i]);
		}
	}
	// check misc params
	if (aci.getKernelCapabilities().getMiscParams().getProgramType() != acid.getKernelCapabilities().getMiscParams().getProgramType())
	{
		fmt::print("[WARNING] ACI/KC ProgramType: FAIL ({:d} not permitted)\n", (uint32_t)aci.getKernelCapabilities().getMiscParams().getProgramType());
	}
	// check kernel version
	uint32_t aciKernelVersion = (uint32_t)aci.getKernelCapabilities().getKernelVersion().getVerMajor() << 16 |  (uint32_t)aci.getKernelCapabilities().getKernelVersion().getVerMinor();
	uint32_t acidKernelVersion =  (uint32_t)acid.getKernelCapabilities().getKernelVersion().getVerMajor() << 16 |  (uint32_t)acid.getKernelCapabilities().getKernelVersion().getVerMinor();
	if (aciKernelVersion < acidKernelVersion)
	{
		fmt::print("[WARNING] ACI/KC RequiredKernelVersion: FAIL ({:d}.{:d} not permitted)\n", aci.getKernelCapabilities().getKernelVersion().getVerMajor(), aci.getKernelCapabilities().getKernelVersion().getVerMinor());
	}
	// check handle table size
	if (aci.getKernelCapabilities().getHandleTableSize().getHandleTableSize() > acid.getKernelCapabilities().getHandleTableSize().getHandleTableSize())
	{
		fmt::print("[WARNING] ACI/KC HandleTableSize: FAIL (0x{:x} too large)\n", aci.getKernelCapabilities().getHandleTableSize().getHandleTableSize());
	}
	// check misc flags
	auto misc_flags = aci.getKernelCapabilities().getMiscFlags().getMiscFlags();
	auto desc_misc_flags = acid.getKernelCapabilities().getMiscFlags().getMiscFlags();
	for (size_t i = 0; i < misc_flags.size(); i++)
	{
		if (misc_flags.test(i) && desc_misc_flags.test(i) == false)
		{
			fmt::print("[WARNING] ACI/KC MiscFlag: FAIL ({:s} not permitted)\n", pie::hac::KernelCapabilityUtil::getMiscFlagsBitAsString(pie::hac::kc::MiscFlagsBit(i)));
		}		
	}
}

std::string pie::hac::MetaFileFormat::formatMappingAsString(const pie::hac::MemoryMappingHandler::sMemoryMapping& map) const
{
	return fmt::format("0x{:016x} - 0x{:016x} (perm={:s}) (type={:s})", ((uint64_t)map.addr << 12), (((uint64_t)(map.addr + map.size) << 12) - 1), pie::hac::KernelCapabilityUtil::getMemoryPermissionAsString(map.perm), pie::hac::KernelCapabilityUtil::getMappingTypeAsString(map.type));
}