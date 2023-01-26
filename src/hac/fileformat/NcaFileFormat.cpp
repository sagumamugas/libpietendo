#include <pietendo/hac/fileformat/NcaFileFormat.h>
#include <pietendo/hac/fileformat/MetaFileFormat.h>
//#include "util.h"

#include <pietendo/hac/ContentArchiveUtil.h>
#include <pietendo/hac/AesKeygen.h>
#include <pietendo/hac/HierarchicalSha256Stream.h>
#include <pietendo/hac/HierarchicalIntegrityStream.h>
#include <pietendo/hac/BKTREncryptedStream.h>
#include <pietendo/hac/PartitionFsSnapshotGenerator.h>
#include <pietendo/hac/RomFsSnapshotGenerator.h>
#include <pietendo/hac/CombinedFsSnapshotGenerator.h>

#include <fmt/core.h>

pie::hac::NcaFileFormat::NcaFileFormat() :
	mModuleName("pie::hac::NcaFileFormat"),
	mBaseStream(),
	mFileSystem()
{
}

pie::hac::NcaFileFormat::NcaFileFormat(const std::shared_ptr<tc::io::IStream>& base, const KeyBag& keycfg) :
	NcaFileFormat()
{
	mBaseStream = base;
	mKeyCfg = keycfg;
	// import header
	importHeader();

	// determine keys
	generateNcaBodyEncryptionKeys();

	// import/generate fs header data
	generatePartitionConfiguration();

	// process partition
	processPartitions();
}

const pie::hac::NcaFileFormat::sKeys& pie::hac::NcaFileFormat::getContentKey() const {
	return mContentKey;
}

const pie::hac::ContentArchiveHeader& pie::hac::NcaFileFormat::getHeader() const
{
	return mHdr;
}

const pie::hac::NcaFileFormat::sPartitionInfo& pie::hac::NcaFileFormat::getPartition(size_t index) const
{
	return mPartitions[index];
}

const std::shared_ptr<tc::io::IFileSystem>& pie::hac::NcaFileFormat::getFileSystem() const
{
	return mFileSystem;
}

void pie::hac::NcaFileFormat::importHeader()
{
	if (mBaseStream == nullptr)
	{
		throw tc::Exception(mModuleName, "No file reader set.");
	}
	if (mBaseStream->canRead() == false || mBaseStream->canSeek() == false)
	{
		throw tc::NotSupportedException(mModuleName, "Input stream requires read/seek permissions.");
	}

	// read header block
	if (mBaseStream->length() < tc::io::IOUtil::castSizeToInt64(sizeof(pie::hac::sContentArchiveHeaderBlock)))
	{
		throw tc::Exception(mModuleName, "Corrupt NCA: File too small.");
	}
	mBaseStream->seek(0, tc::io::SeekOrigin::Begin);
	mBaseStream->read((byte_t*)(&mHdrBlock), sizeof(pie::hac::sContentArchiveHeaderBlock));

	// decrypt header block
	if (mKeyCfg.nca_header_key.isNull())
	{
		throw tc::Exception(mModuleName, "Failed to decrypt NCA header. (nca_header_key could not be loaded)");
	}
	pie::hac::ContentArchiveUtil::decryptContentArchiveHeader((byte_t*)&mHdrBlock, (byte_t*)&mHdrBlock, mKeyCfg.nca_header_key.get());

	// generate header hash
	tc::crypto::GenerateSha256Hash(mHdrHash.data(), (byte_t*)&mHdrBlock.header, sizeof(pie::hac::sContentArchiveHeader));

	// proccess main header
	mHdr.fromBytes((byte_t*)&mHdrBlock.header, sizeof(pie::hac::sContentArchiveHeader));
}

void pie::hac::NcaFileFormat::generateNcaBodyEncryptionKeys()
{
	// create zeros key
	KeyBag::aes128_key_t zero_aesctr_key;
	memset(zero_aesctr_key.data(), 0, zero_aesctr_key.size());
	
	// get key data from header
	byte_t masterkey_rev = pie::hac::AesKeygen::getMasterKeyRevisionFromKeyGeneration(mHdr.getKeyGeneration());
	byte_t keak_index = mHdr.getKeyAreaEncryptionKeyIndex();

	// process key area
	sKeys::sKeyAreaKey kak;
	for (size_t i = 0; i < mHdr.getKeyArea().size(); i++)
	{
		if (mHdr.getKeyArea()[i] != zero_aesctr_key)
		{
			kak.index = (byte_t)i;
			kak.enc = mHdr.getKeyArea()[i];
			kak.decrypted = false;
			// key[0-3]
			if (i < 4 && mKeyCfg.nca_key_area_encryption_key[keak_index].find(masterkey_rev) != mKeyCfg.nca_key_area_encryption_key[keak_index].end())
			{
				kak.decrypted = true;
				pie::hac::AesKeygen::generateKey(kak.dec.data(), kak.enc.data(), mKeyCfg.nca_key_area_encryption_key[keak_index][masterkey_rev].data());
			}
			// key[KeyBankIndex_AesCtrHw]
			else if (i == pie::hac::nca::KeyBankIndex_AesCtrHw && mKeyCfg.nca_key_area_encryption_key_hw[keak_index].find(masterkey_rev) != mKeyCfg.nca_key_area_encryption_key_hw[keak_index].end())
			{
				kak.decrypted = true;
				pie::hac::AesKeygen::generateKey(kak.dec.data(), kak.enc.data(), mKeyCfg.nca_key_area_encryption_key_hw[keak_index][masterkey_rev].data());
			}
			else
			{
				kak.decrypted = false;
			}
			mContentKey.kak_list.push_back(kak);
		}
	}

	// clear content key
	mContentKey.aes_ctr = tc::Optional<pie::hac::detail::aes128_key_t>();

	// if this has a rights id, the key needs to be sourced from a ticket
	if (mHdr.hasRightsId() == true)
	{
		KeyBag::aes128_key_t tmp_key;
		if (mKeyCfg.external_content_keys.find(mHdr.getRightsId()) != mKeyCfg.external_content_keys.end())
		{
			mContentKey.aes_ctr = mKeyCfg.external_content_keys[mHdr.getRightsId()];
		}
		else if (mKeyCfg.fallback_content_key.isSet())
		{
			mContentKey.aes_ctr = mKeyCfg.fallback_content_key.get();
		}
		else if (mKeyCfg.fallback_enc_content_key.isSet())
		{
			tmp_key = mKeyCfg.fallback_enc_content_key.get();
			if (mKeyCfg.etik_common_key.find(masterkey_rev) != mKeyCfg.etik_common_key.end())
			{
				pie::hac::AesKeygen::generateKey(tmp_key.data(), tmp_key.data(), mKeyCfg.etik_common_key[masterkey_rev].data());
				mContentKey.aes_ctr = tmp_key;
			}
		}
	}
	// otherwise used decrypt key area
	else
	{
		for (size_t i = 0; i < mContentKey.kak_list.size(); i++)
		{
			if (mContentKey.kak_list[i].index == pie::hac::nca::KeyBankIndex_AesCtr && mContentKey.kak_list[i].decrypted)
			{
				mContentKey.aes_ctr = mContentKey.kak_list[i].dec;
			}
		}
	}

	// if the keys weren't generated, check if the keys were supplied by the user
	if (mContentKey.aes_ctr.isNull())
	{
		if (mKeyCfg.fallback_content_key.isSet())
		{
			mContentKey.aes_ctr = mKeyCfg.fallback_content_key.get();
		}
	}
}

void pie::hac::NcaFileFormat::generatePartitionConfiguration()
{
	for (size_t i = 0; i < mHdr.getPartitionEntryList().size(); i++)
	{
		// get reference to relevant structures
		const pie::hac::ContentArchiveHeader::sPartitionEntry& partition = mHdr.getPartitionEntryList()[i];
		pie::hac::sContentArchiveFsHeader& fs_header = mHdrBlock.fs_header[partition.header_index];

		// output structure
		sPartitionInfo& info = mPartitions[partition.header_index];

		// validate header hash
		pie::hac::detail::sha256_hash_t fs_header_hash;
		tc::crypto::GenerateSha256Hash(fs_header_hash.data(), (const byte_t*)&mHdrBlock.fs_header[partition.header_index], sizeof(pie::hac::sContentArchiveFsHeader));
		if (fs_header_hash != partition.fs_header_hash)
		{
			throw tc::Exception(mModuleName, fmt::format("NCA FS Header [{:d}] Hash: FAIL", partition.header_index));
		}

		if (fs_header.version.unwrap() != pie::hac::nca::kDefaultFsHeaderVersion)
		{
			throw tc::Exception(mModuleName, fmt::format("NCA FS Header [{:d}] Version({:d}): UNSUPPORTED", partition.header_index, fs_header.version.unwrap()));
		}

		// setup AES-CTR 
		pie::hac::ContentArchiveUtil::getNcaPartitionAesCtr(&fs_header, info.aes_ctr.data());

		// save partition configinfo
		info.offset = partition.offset;
		info.size = partition.size;
		info.format_type = (pie::hac::nca::FormatType)fs_header.format_type;
		info.hash_type = (pie::hac::nca::HashType)fs_header.hash_type;
		info.enc_type = (pie::hac::nca::EncryptionType)fs_header.encryption_type;
		info.metadata_hash_type = (pie::hac::nca::MetaDataHashType)fs_header.meta_data_hash_type;

		if (info.hash_type == pie::hac::nca::HashType_HierarchicalSha256)
		{
			info.hierarchicalsha256_hdr.fromBytes(fs_header.hash_info.data(), fs_header.hash_info.size());
		}	
		else if (info.hash_type == pie::hac::nca::HashType_HierarchicalIntegrity)
		{
			info.hierarchicalintegrity_hdr.fromBytes(fs_header.hash_info.data(), fs_header.hash_info.size());
		}

		// create reader
		try 
		{
			// handle partition encryption and partition compaction (sparse layer)
			if (fs_header.sparse_info.generation.unwrap() != 0)
			{
				throw tc::Exception("SparseStorage: Not currently supported.");
			}
			else
			{
				// create raw partition
				info.raw_reader = std::make_shared<tc::io::SubStream>(tc::io::SubStream(mBaseStream, info.offset, info.size));

				// handle encryption if required reader based on encryption type
				if (info.enc_type == pie::hac::nca::EncryptionType_None)
				{
					// no encryption so do nothing
					info.decrypt_reader = info.raw_reader;
				}
				else if (info.enc_type == pie::hac::nca::EncryptionType_AesCtr)
				{
					if (mContentKey.aes_ctr.isNull())
						throw tc::Exception(mModuleName, "AES-CTR Key was not determined");

					// get partition key
					pie::hac::detail::aes128_key_t partition_key = mContentKey.aes_ctr.get();

					// get partition counter
					pie::hac::detail::aes_iv_t partition_ctr = info.aes_ctr;
					tc::crypto::IncrementCounterAes128Ctr(partition_ctr.data(), info.offset>>4);

					// create decryption stream
					info.decrypt_reader = std::make_shared<tc::crypto::Aes128CtrEncryptedStream>(tc::crypto::Aes128CtrEncryptedStream(info.raw_reader, partition_key, partition_ctr));

				}
				else if (info.enc_type == pie::hac::nca::EncryptionType_AesCtrEx)
				{
					if (mContentKey.aes_ctr.isNull())
						throw tc::Exception(mModuleName, "AES-CTR Key was not determined");

					// get partition key
					pie::hac::detail::aes128_key_t partition_key = mContentKey.aes_ctr.get();

					// get partition counter
					pie::hac::detail::aes_iv_t partition_ctr = info.aes_ctr;
					tc::crypto::IncrementCounterAes128Ctr(partition_ctr.data(), info.offset >> 4);

					if (mNcaBase->mHdr.getProgramId() != mHdr.getProgramId()) {
						throw tc::Exception(mModuleName, "Invalid base nca. ProgramID diferent.");
					}
					std::shared_ptr<tc::io::IStream> base_reader;
					for (auto& partition_base : mNcaBase->mPartitions) {
						if (partition_base.format_type == pie::hac::nca::FormatType::FormatType_RomFs && partition_base.raw_reader != nullptr)
						{
							base_reader = partition_base.decrypt_reader;
						}
					}
					if (base_reader == nullptr) {
						throw tc::Exception(mModuleName, "Cannot determine RomFs from base nca.");
					}

					// create decryption stream
					info.decrypt_reader = std::make_shared<pie::hac::BKTREncryptedStream>(pie::hac::BKTREncryptedStream(info.raw_reader, partition_key, partition_ctr, fs_header.patch_info, base_reader));
				}
				else if (info.enc_type == pie::hac::nca::EncryptionType_AesXts)
				{
					throw tc::Exception(mModuleName, fmt::format("EncryptionType({:s}): UNSUPPORTED", pie::hac::ContentArchiveUtil::getEncryptionTypeAsString(info.enc_type)));
				}
				else
				{
					throw tc::Exception(mModuleName, fmt::format("EncryptionType({:s}): UNKNOWN", pie::hac::ContentArchiveUtil::getEncryptionTypeAsString(info.enc_type)));
				}
			}

			// filter out unrecognised hash types, and hash based readers
			switch (info.hash_type)
			{
			case (pie::hac::nca::HashType_None):
				break;
			case (pie::hac::nca::HashType_HierarchicalSha256):
				info.reader = std::make_shared<pie::hac::HierarchicalSha256Stream>(pie::hac::HierarchicalSha256Stream(info.decrypt_reader, info.hierarchicalsha256_hdr));
				break;
			case (pie::hac::nca::HashType_HierarchicalIntegrity):
				info.reader = std::make_shared<pie::hac::HierarchicalIntegrityStream>(pie::hac::HierarchicalIntegrityStream(info.decrypt_reader, info.hierarchicalintegrity_hdr));
				break;
			default:
				throw tc::Exception(mModuleName, fmt::format("HashType({:s}): UNKNOWN", pie::hac::ContentArchiveUtil::getHashTypeAsString(info.hash_type)));
			}

			// filter out unrecognised format types
			switch (info.format_type)
			{
			case (pie::hac::nca::FormatType_PartitionFs):
				info.fs_snapshot = pie::hac::PartitionFsSnapshotGenerator(info.reader);
				info.fs_reader = std::make_shared<tc::io::VirtualFileSystem>(tc::io::VirtualFileSystem(info.fs_snapshot));
				break;
			case (pie::hac::nca::FormatType_RomFs):
				info.fs_snapshot = pie::hac::RomFsSnapshotGenerator(info.reader);
				info.fs_reader = std::make_shared<tc::io::VirtualFileSystem>(tc::io::VirtualFileSystem(info.fs_snapshot));
				break;
			default:
				throw tc::Exception(mModuleName, fmt::format("FormatType({:s}): UNKNOWN", pie::hac::ContentArchiveUtil::getFormatTypeAsString(info.format_type)));
			}
		}
		catch (const tc::Exception& e)
		{
			info.fail_reason = std::string(e.error());
		}
	}
}

void pie::hac::NcaFileFormat::validate()
{
	// validate signature[0]
	if (mKeyCfg.nca_header_sign0_key.find(mHdr.getSignatureKeyGeneration()) != mKeyCfg.nca_header_sign0_key.end())
	{
		if (tc::crypto::VerifyRsa2048PssSha256(mHdrBlock.signature_main.data(), mHdrHash.data(), mKeyCfg.nca_header_sign0_key[mHdr.getSignatureKeyGeneration()]) == false)
		{
			fmt::print("[WARNING] NCA Header Main Signature: FAIL\n");
		}
	}
	else
	{
		fmt::print("[WARNING] NCA Header Main Signature: FAIL (could not load header key)\n");
	}
	

	// validate signature[1]
	if (mHdr.getContentType() == pie::hac::nca::ContentType_Program)
	{
		try {
			if (mPartitions[pie::hac::nca::ProgramContentPartitionIndex_Code].format_type == pie::hac::nca::FormatType_PartitionFs)
			{
				if (mPartitions[pie::hac::nca::ProgramContentPartitionIndex_Code].fs_reader != nullptr)
				{
					std::shared_ptr<tc::io::IStream> npdm_file;
					try {
						mPartitions[pie::hac::nca::ProgramContentPartitionIndex_Code].fs_reader->openFile(tc::io::Path(kNpdmExefsPath), tc::io::FileMode::Open, tc::io::FileAccess::Read, npdm_file);
					}
					catch (tc::io::FileNotFoundException&) {
						throw tc::Exception(fmt::format("\"{:s}\" not present in ExeFs", kNpdmExefsPath));
					}

					pie::hac::MetaFileFormat npdm(npdm_file, mKeyCfg);
					npdm.validate();

					if (tc::crypto::VerifyRsa2048PssSha256(mHdrBlock.signature_acid.data(), mHdrHash.data(), npdm.getMeta().getAccessControlInfoDesc().getContentArchiveHeaderSignature2Key()) == false)
					{
						throw tc::Exception("Bad signature");
					}
				}
				else
				{
					throw tc::Exception("ExeFs was not mounted");
				}
			}
			else
			{
				throw tc::Exception("No ExeFs partition");
			}
		}
		catch (tc::Exception& e) {
			fmt::print("[WARNING] NCA Header ACID Signature: FAIL ({:s})\n", e.error());
		}
	}
}

void pie::hac::NcaFileFormat::processPartitions()
{
	std::vector<pie::hac::CombinedFsSnapshotGenerator::MountPointInfo> mount_points;

	for (size_t i = 0; i < mHdr.getPartitionEntryList().size(); i++)
	{
		uint32_t index = mHdr.getPartitionEntryList()[i].header_index;
		struct sPartitionInfo& partition = mPartitions[index];

		// if the reader is null, skip
		if (partition.fs_reader == nullptr)
		{
			fmt::print("[WARNING] NCA Partition {:d} not readable.", index);
			if (partition.fail_reason.empty() == false)
			{
				fmt::print(" ({:s})", partition.fail_reason);
			}
			fmt::print("\n");
			continue;
		}

		std::string mount_point_name;
		/*
		if (mHdr.getContentType() == pie::hac::nca::ContentType_Program)
		{
			mount_point_name = pie::hac::ContentArchiveUtil::getProgramContentParititionIndexAsString((pie::hac::nca::ProgramContentPartitionIndex)index);
		}
		else
		*/
		{
			mount_point_name = fmt::format("{:d}", index);
		}

		mount_points.push_back( { mount_point_name, partition.fs_snapshot } );
	}

	tc::io::VirtualFileSystem::FileSystemSnapshot fs_snapshot = pie::hac::CombinedFsSnapshotGenerator(mount_points);

	std::shared_ptr<tc::io::IFileSystem> nca_fs = std::make_shared<tc::io::VirtualFileSystem>(tc::io::VirtualFileSystem(fs_snapshot));
	/*
	mFsProcess.setInputFileSystem(nca_fs);
	mFsProcess.setFsFormatName("ContentArchive");
	mFsProcess.setFsRootLabel(getContentTypeForMountStr(mHdr.getContentType()));
	mFsProcess.process();
	*/
}

std::string pie::hac::NcaFileFormat::getContentTypeForMountStr(pie::hac::nca::ContentType cont_type) const
{
	std::string str;

	switch (cont_type)
	{
		case (pie::hac::nca::ContentType_Program):
			str = "program";
			break;
		case (pie::hac::nca::ContentType_Meta):
			str = "meta";
			break;
		case (pie::hac::nca::ContentType_Control):
			str = "control";
			break;
		case (pie::hac::nca::ContentType_Manual):
			str = "manual";
			break;
		case (pie::hac::nca::ContentType_Data):
			str = "data";
			break;
		case (pie::hac::nca::ContentType_PublicData):
			str = "publicdata";
			break;
		default:
			str = "";
			break;
	}

	return str;
}