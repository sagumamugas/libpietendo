#pragma once
#include <tc/io/IStream.h>

#include <pietendo/hac/KeyBag.h>

#include <tc/types.h>
#include <tc/Optional.h>

#include <pietendo/hac/ContentArchiveHeader.h>
#include <pietendo/hac/HierarchicalIntegrityHeader.h>
#include <pietendo/hac/HierarchicalSha256Header.h>

namespace pie { namespace hac {

class NcaFileFormat
{
public: // Internal structures

	// crypto
	struct sKeys
	{
		struct sKeyAreaKey
		{
			byte_t index;
			bool decrypted;
			KeyBag::aes128_key_t enc;
			KeyBag::aes128_key_t dec;

			void operator=(const sKeyAreaKey& other)
			{
				index = other.index;
				decrypted = other.decrypted;
				enc = other.enc;
				dec = other.dec;
			}

			bool operator==(const sKeyAreaKey& other) const
			{
				return (index == other.index) \
					&& (decrypted == other.decrypted) \
					&& (enc == other.enc) \
					&& (dec == other.dec);
			}

			bool operator!=(const sKeyAreaKey& other) const
			{
				return !(*this == other);
			}
		};
		std::vector<sKeyAreaKey> kak_list;

		tc::Optional<pie::hac::detail::aes128_key_t> aes_ctr;
	} mContentKey;

	struct SparseInfo
	{

	};

	// raw partition data
	struct sPartitionInfo
	{
		std::shared_ptr<tc::io::IStream> raw_reader;
		std::shared_ptr<tc::io::IStream> decrypt_reader;
		std::shared_ptr<tc::io::IStream> reader;
		tc::io::VirtualFileSystem::FileSystemSnapshot fs_snapshot;
		std::shared_ptr<tc::io::IFileSystem> fs_reader;
		std::string fail_reason;
		int64_t offset;
		int64_t size;

		// meta data
		pie::hac::nca::FormatType format_type;
		pie::hac::nca::HashType hash_type;
		pie::hac::nca::EncryptionType enc_type;
		pie::hac::nca::MetaDataHashType metadata_hash_type;

		// hash meta data
		pie::hac::HierarchicalIntegrityHeader hierarchicalintegrity_hdr;
		pie::hac::HierarchicalSha256Header hierarchicalsha256_hdr;

		// crypto metadata
		pie::hac::detail::aes_iv_t aes_ctr;

		// sparse metadata
		SparseInfo sparse_info;
	};

public:
	NcaFileFormat();

	NcaFileFormat(const std::shared_ptr<tc::io::IStream>& file, const KeyBag& keycfg);

	void validate();

	// post process() get FS out
	const std::shared_ptr<tc::io::IFileSystem>& getFileSystem() const;

	const pie::hac::ContentArchiveHeader& getHeader() const;

	const sPartitionInfo& getPartition(size_t index) const;

	const sKeys& getContentKey() const;

	void processPartitions();
private:
	const std::string kNpdmExefsPath = "/main.npdm";

	std::string mModuleName;

	// user options
	std::shared_ptr<tc::io::IStream> mBaseStream;
	KeyBag mKeyCfg;

	std::shared_ptr<NcaFileFormat> mNcaBase;

	// fs processing
	std::shared_ptr<tc::io::IFileSystem> mFileSystem;

	// nca data
	pie::hac::sContentArchiveHeaderBlock mHdrBlock;
	pie::hac::detail::sha256_hash_t mHdrHash;
	pie::hac::ContentArchiveHeader mHdr;

	
	std::array<sPartitionInfo, pie::hac::nca::kPartitionNum> mPartitions;

	void importHeader();
	void generateNcaBodyEncryptionKeys();
	void generatePartitionConfiguration();
	void validateNcaSignatures();

	std::string getContentTypeForMountStr(pie::hac::nca::ContentType cont_type) const;
};

}} // namespace pie::hac