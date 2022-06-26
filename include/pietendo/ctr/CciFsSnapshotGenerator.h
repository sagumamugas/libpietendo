#pragma once
#include <tc/io/VirtualFileSystem.h>

namespace pie { namespace ctr {

struct CciFsShapshotGenerator : public tc::io::VirtualFileSystem::FileSystemSnapshot
{
public:
	CciFsShapshotGenerator(const std::shared_ptr<tc::io::IStream>& stream);
private:
	CciFsShapshotGenerator();

	std::shared_ptr<tc::io::IStream> mBaseStream;
	size_t mCurDir;

	void addFile(const std::string& name, int64_t offset, int64_t size);
};

}} // namespace pie::ctr