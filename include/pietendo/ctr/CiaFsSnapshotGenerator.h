#pragma once
#include <tc/io/VirtualFileSystem.h>

namespace pie { namespace ctr {

struct CiaFsSnapshotGenerator : public tc::io::VirtualFileSystem::FileSystemSnapshot
{
public:
	CiaFsSnapshotGenerator(const std::shared_ptr<tc::io::IStream>& stream);
private:
	CiaFsSnapshotGenerator();

	std::shared_ptr<tc::io::IStream> mBaseStream;
	size_t mCurDir;

	void addFile(const std::string& name, int64_t offset, int64_t size);
};

}} // namespace pie::ctr