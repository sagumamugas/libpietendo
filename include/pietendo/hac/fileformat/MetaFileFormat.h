#pragma once
#include <tc/io/IStream.h>
#include <pietendo/hac/KeyBag.h>
#include <pietendo/hac/Meta.h>

namespace pie { namespace hac {

class MetaFileFormat 
{
public:
	MetaFileFormat();
	MetaFileFormat(const std::shared_ptr<tc::io::IStream>& base, const KeyBag& keycfg);

	void validate();

	const pie::hac::Meta& getMeta() const;

private:
	std::string mModuleName;

	std::shared_ptr<tc::io::IStream> mFile;
	KeyBag mKeyCfg;

	pie::hac::Meta mMeta;

	void validateAcidSignature(const pie::hac::AccessControlInfoDesc& acid, byte_t key_generation);
	void validateAciFromAcid(const pie::hac::AccessControlInfo& aci, const pie::hac::AccessControlInfoDesc& acid);

	std::string formatMappingAsString(const pie::hac::MemoryMappingHandler::sMemoryMapping& map) const;
};

} } // namespace pie::hac