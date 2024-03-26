/*
 * Copyright (c) 2006-2014 Apple Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

//
// macho++ - Mach-O object file helpers
//
#include "macho++.h"
#include <security_utilities/alloc.h>
#include <security_utilities/memutils.h>
#include <security_utilities/endian.h>
#include <mach-o/dyld.h>
#include <list>
#include <algorithm>
#include <iterator>

namespace Security {

/* Maximum number of archs a fat binary can have */
static const int MAX_ARCH_COUNT = 100;
/* Maximum power of 2 that a mach-o can be aligned by */
static const int MAX_ALIGN = 30;

//
// Architecture values
//
Architecture::Architecture(const fat_arch &arch)
	: pair<cpu_type_t, cpu_subtype_t>(arch.cputype, arch.cpusubtype)
{
}

Architecture::Architecture(const char *name)
{
	if (const NXArchInfo *nxa = NXGetArchInfoFromName(name)) {
		this->first = nxa->cputype;
		this->second = nxa->cpusubtype;
	} else {
		this->first = this->second = none;
	}
}


//
// The local architecture.
//
// We take this from ourselves - the architecture of our main program Mach-O binary.
// There's the NXGetLocalArchInfo API, but it insists on saying "i386" on modern
// x86_64-centric systems, and lies to ppc (Rosetta) programs claiming they're native ppc.
// So let's not use that.
//
Architecture Architecture::local()
{
	return MainMachOImage().architecture();
}


//
// Translate between names and numbers
//
const char *Architecture::name() const
{
	if (const NXArchInfo *info = NXGetArchInfoFromCpuType(cpuType(), cpuSubtype()))
		return info->name;
	else
		return NULL;
}

std::string Architecture::displayName() const
{
	if (const char *s = this->name())
		return s;
	char buf[20];
	snprintf(buf, sizeof(buf), "(%d:%d)", cpuType(), cpuSubtype());
	return buf;
}
	

//
// Compare architectures.
// This is asymmetrical; the second argument provides for some templating.
//
bool Architecture::matches(const Architecture &templ) const
{
	if (first != templ.first)
		return false;	// main architecture mismatch
	if (templ.second == CPU_SUBTYPE_MULTIPLE)
		return true;	// subtype wildcard
	// match subtypes, ignoring feature bits
	return ((second ^ templ.second) & ~CPU_SUBTYPE_MASK) == 0;
}


//
// MachOBase contains knowledge of the Mach-O object file format,
// but abstracts from any particular sourcing. It must be subclassed,
// and the subclass must provide the file header and commands area
// during its construction. Memory is owned by the subclass.
//
MachOBase::~MachOBase()
{ /* virtual */ }

// provide the Mach-O file header, somehow
void MachOBase::initHeader(const mach_header *header)
{
	mHeader = header;
	switch (mHeader->magic) {
	case MH_MAGIC:
		mFlip = false;
		m64 = false;
		break;
	case MH_CIGAM:
		mFlip = true;
		m64 = false;
		break;
	case MH_MAGIC_64:
		mFlip = false;
		m64 = true;
		break;
	case MH_CIGAM_64:
		mFlip = true;
		m64 = true;
		break;
	default:
		secinfo("macho", "%p: unrecognized header magic (%x)", this, mHeader->magic);
		UnixError::throwMe(ENOEXEC);
	}
}

// provide the Mach-O commands section, somehow
void MachOBase::initCommands(const load_command *commands)
{
	mCommands = commands;
	mEndCommands = LowLevelMemoryUtilities::increment<load_command>(commands, flip(mHeader->sizeofcmds));
	if (mCommands + 1 > mEndCommands)	// ensure initial load command core available
		UnixError::throwMe(ENOEXEC);
}


size_t MachOBase::headerSize() const
{
	return m64 ? sizeof(mach_header_64) : sizeof(mach_header);
}

size_t MachOBase::commandSize() const
{
	return flip(mHeader->sizeofcmds);
}


//
// Create a MachO object from an open file and a starting offset.
// We load (only) the header and load commands into memory at that time.
// Note that the offset must be relative to the start of the containing file
// (not relative to some intermediate container).
//
MachO::MachO(FileDesc fd, size_t offset, size_t length)
	: FileDesc(fd), mOffset(offset), mLength(length), mSuspicious(false)
{
	if (mOffset == 0)
		mLength = fd.fileSize();
	size_t size = fd.read(&mHeaderBuffer, sizeof(mHeaderBuffer), mOffset);
	if (size != sizeof(mHeaderBuffer))
		UnixError::throwMe(ENOEXEC);
	this->initHeader(&mHeaderBuffer);
	size_t cmdSize = this->commandSize();
	mCommandBuffer = (load_command *)malloc(cmdSize);
	if (!mCommandBuffer)
		UnixError::throwMe();
	if (fd.read(mCommandBuffer, cmdSize, this->headerSize() + mOffset) != cmdSize)
		UnixError::throwMe(ENOEXEC);
	this->initCommands(mCommandBuffer);
	/* If we do not know the length, we cannot do a verification of the mach-o structure */
	if (mLength != 0)
		this->validateStructure();
}

void MachO::validateStructure()
{
	bool isValid = false;

	/* There should be either an LC_SEGMENT, an LC_SEGMENT_64, or an LC_SYMTAB
	 load_command and that + size must be equal to the end of the arch */
	for (const struct load_command *cmd = loadCommands(); cmd != NULL; cmd = nextCommand(cmd)) {
		uint32_t cmd_type = flip(cmd->cmd);
		struct segment_command *seg = NULL;
		struct segment_command_64 *seg64 = NULL;
		struct symtab_command *symtab = NULL;

		if (cmd_type ==  LC_SEGMENT) {
			if(flip(cmd->cmdsize) < sizeof(struct segment_command)) {
				UnixError::throwMe(ENOEXEC);
			}
			seg = (struct segment_command *)cmd;
			if (strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) == 0) {
				isValid = flip(seg->fileoff) + flip(seg->filesize) == this->length();
				secinfo("macho", "32-bit linkedit is%s valid", isValid ?"":" NOT");
				break;
			}
		} else if (cmd_type == LC_SEGMENT_64) {
			if(flip(cmd->cmdsize) < sizeof(struct segment_command_64)) {
				UnixError::throwMe(ENOEXEC);
			}
			seg64 = (struct segment_command_64 *)cmd;
			if (strncmp(seg64->segname, SEG_LINKEDIT, sizeof(seg64->segname)) == 0) {
				isValid = flip(seg64->fileoff) + flip(seg64->filesize) == this->length();
				secinfo("macho", "64-bit linkedit is%s valid", isValid ?"":" NOT");
				break;
			}
		/* PPC binaries have a SYMTAB section */
		} else if (cmd_type == LC_SYMTAB) {
			if(flip(cmd->cmdsize) < sizeof(struct symtab_command)) {
				UnixError::throwMe(ENOEXEC);
			}
			symtab = (struct symtab_command *)cmd;
			isValid = flip(symtab->stroff) + flip(symtab->strsize) == this->length();
			secinfo("macho", "symtab is%s valid", isValid ?"":" NOT");
			break;
		}
	}

	if (!isValid) {
		secerror("STRICT VALIDATION ERROR: invalid structure");
		mSuspicious = true;
	}
}

MachO::~MachO()
{
	::free(mCommandBuffer);
}


//
// Create a MachO object that is (entirely) mapped into memory.
// The caller must ensire that the underlying mapping persists
// at least as long as our object.
//
MachOImage::MachOImage(const void *address)
{
	this->initHeader((const mach_header *)address);
	this->initCommands(LowLevelMemoryUtilities::increment<const load_command>(address, this->headerSize()));
}


//
// Locate the Mach-O image of the main program
//
MainMachOImage::MainMachOImage()
	: MachOImage(mainImageAddress())
{
}

const void *MainMachOImage::mainImageAddress()
{
	return _dyld_get_image_header(0);
}


//
// Return various header fields
//
Architecture MachOBase::architecture() const
{
	return Architecture(flip(mHeader->cputype), flip(mHeader->cpusubtype));
}

uint32_t MachOBase::type() const
{
	return flip(mHeader->filetype);
}

uint32_t MachOBase::flags() const
{
	return flip(mHeader->flags);
}


//
// Iterate through load commands
//
const load_command *MachOBase::nextCommand(const load_command *command) const
{
	using LowLevelMemoryUtilities::increment;
	/* Do not try and increment by 0, or it will loop forever */
	if (flip(command->cmdsize) == 0)
		UnixError::throwMe(ENOEXEC);
	command = increment<const load_command>(command, flip(command->cmdsize));
	if (command >= mEndCommands)	// end of load commands
		return NULL;
	if (increment(command, sizeof(load_command)) > mEndCommands
		|| increment(command, flip(command->cmdsize)) > mEndCommands)
		UnixError::throwMe(ENOEXEC);
	return command;
}


//
// Find a specific load command, by command number.
// If there are multiples, returns the first one found.
//
const load_command *MachOBase::findCommand(uint32_t cmd) const
{
	for (const load_command *command = loadCommands(); command; command = nextCommand(command))
		if (flip(command->cmd) == cmd)
			return command;
	return NULL;
}


//
// Locate a segment command, by name
//	
const segment_command *MachOBase::findSegment(const char *segname) const
{
	for (const load_command *command = loadCommands(); command; command = nextCommand(command)) {
		switch (flip(command->cmd)) {
		case LC_SEGMENT:
		case LC_SEGMENT_64:
			{
				if(flip(command->cmdsize) < sizeof(struct segment_command)) {
					UnixError::throwMe(ENOEXEC);
				}
				const segment_command *seg = reinterpret_cast<const segment_command *>(command);
				if (!strncmp(seg->segname, segname, sizeof(seg->segname)))
					return seg;
				break;
			}
		default:
			break;
		}
	}
	return NULL;
}

const section *MachOBase::findSection(const char *segname, const char *sectname) const
{
	using LowLevelMemoryUtilities::increment;
	if (const segment_command *seg = findSegment(segname)) {
		if (is64()) {
			if(flip(seg->cmdsize) < sizeof(segment_command_64)) {
				UnixError::throwMe(ENOEXEC);
			}
			const segment_command_64 *seg64 = reinterpret_cast<const segment_command_64 *>(seg);
			if (sizeof(*seg64) + (seg64->nsects * sizeof(section_64)) > flip(seg64->cmdsize))		// too many segments; doesn't fit (malformed Mach-O)
				return NULL;    
			const section_64 *sect = increment<const section_64>(seg64 + 1, 0);
			for (unsigned n = flip(seg64->nsects); n > 0; n--, sect++) {
				if (!strncmp(sect->sectname, sectname, sizeof(sect->sectname)))
					return reinterpret_cast<const section *>(sect);
			}
		} else {
			if (sizeof(*seg) + (seg->nsects * sizeof(section)) > flip(seg->cmdsize))		// too many segments; doesn't fit (malformed Mach-O)
				return NULL;
			const section *sect = increment<const section>(seg + 1, 0);
			for (unsigned n = flip(seg->nsects); n > 0; n--, sect++) {
				if (!strncmp(sect->sectname, sectname, sizeof(sect->sectname)))
					return sect;
			}
		}
	}
	return NULL;
}


//
// Translate a union lc_str into the string it denotes.
// Returns NULL (no exceptions) if the entry is corrupt.
//
const char *MachOBase::string(const load_command *cmd, const lc_str &str) const
{
	size_t offset = flip(str.offset);
	const char *sp = LowLevelMemoryUtilities::increment<const char>(cmd, offset);
	if (offset + strlen(sp) + 1 > flip(cmd->cmdsize))	// corrupt string reference
		return NULL;
	return sp;
}


//
// Figure out where the Code Signing information starts in the Mach-O binary image.
// The code signature is at the end of the file, and identified
// by a specially-named section. So its starting offset is also the end
// of the signable part.
// Note that the offset returned is relative to the start of the Mach-O image.
// Returns zero if not found (usually indicating that the binary was not signed).
//
const linkedit_data_command *MachOBase::findCodeSignature() const
{
	if (const load_command *cmd = findCommand(LC_CODE_SIGNATURE)) {
		if(flip(cmd->cmdsize) < sizeof(linkedit_data_command)) {
			UnixError::throwMe(ENOEXEC);
		}
		return reinterpret_cast<const linkedit_data_command *>(cmd);
	}
	return NULL;		// not found
}

size_t MachOBase::signingOffset() const
{
	if (const linkedit_data_command *lec = findCodeSignature())
		return flip(lec->dataoff);
	else
		return 0;
}

size_t MachOBase::signingLength() const
{
	if (const linkedit_data_command *lec = findCodeSignature())
		return flip(lec->datasize);
	else
		return 0;
}

const linkedit_data_command *MachOBase::findLibraryDependencies() const
{
	if (const load_command *cmd = findCommand(LC_DYLIB_CODE_SIGN_DRS)) {
		if(flip(cmd->cmdsize) < sizeof(linkedit_data_command)) {
			UnixError::throwMe(ENOEXEC);
		}
		return reinterpret_cast<const linkedit_data_command *>(cmd);
	}
	return NULL;		// not found
}
	
const version_min_command *MachOBase::findMinVersion() const
{
	for (const load_command *command = loadCommands(); command; command = nextCommand(command))
		switch (flip(command->cmd)) {
		case LC_VERSION_MIN_MACOSX:
		case LC_VERSION_MIN_IPHONEOS:
		case LC_VERSION_MIN_WATCHOS:
		case LC_VERSION_MIN_TVOS:
			if(flip(command->cmdsize) < sizeof(version_min_command)) {
				UnixError::throwMe(ENOEXEC);
			}
			return reinterpret_cast<const version_min_command *>(command);
		}
	return NULL;
}

const build_version_command *MachOBase::findBuildVersion() const
{
	for (const load_command *command = loadCommands(); command; command = nextCommand(command)) {
		if (flip(command->cmd) == LC_BUILD_VERSION) {
			if(flip(command->cmdsize) < sizeof(build_version_command)) {
				UnixError::throwMe(ENOEXEC);
			}
			return reinterpret_cast<const build_version_command *>(command);
		}
	}
	return NULL;
}

bool MachOBase::version(uint32_t *platform, uint32_t *minVersion, uint32_t *sdkVersion) const
{
	const build_version_command *bc = findBuildVersion();

	if (bc != NULL) {
		if (platform != NULL) { *platform = flip(bc->platform); }
		if (minVersion != NULL) { *minVersion = flip(bc->minos); }
		if (sdkVersion != NULL) { *sdkVersion = flip(bc->sdk); }
		return true;
	}

	const version_min_command *vc = findMinVersion();
	if (vc != NULL) {
		uint32_t pf;
		switch (flip(vc->cmd)) {
		case LC_VERSION_MIN_MACOSX:
			pf = PLATFORM_MACOS;
			break;
		case LC_VERSION_MIN_IPHONEOS:
			pf = PLATFORM_IOS;
			break;
		case LC_VERSION_MIN_WATCHOS:
			pf = PLATFORM_WATCHOS;
			break;
		case LC_VERSION_MIN_TVOS:
			pf = PLATFORM_TVOS;
			break;
		default:
			// Old style load command, but we don't know what platform to map to.
			pf = 0;
		}

		if (platform != NULL) { *platform = pf; }
		if (minVersion != NULL) { *minVersion = flip(vc->version); }
		if (sdkVersion != NULL) { *sdkVersion = flip(vc->sdk); }
		return true;
	}

	return false;
}

//
// Return the signing-limit length for this Mach-O binary image.
// This is the signingOffset if present, or the full length if not.
//
size_t MachO::signingExtent() const
{
	if (size_t offset = signingOffset())
		return offset;
	else
		return length();
}


//
// I/O operations
//
void MachO::seek(size_t offset)
{
	FileDesc::seek(mOffset + offset);
}

CFDataRef MachO::dataAt(size_t offset, size_t size)
{
	CFMallocData buffer(size);
	if (this->read(buffer, size, mOffset + offset) != size)
		UnixError::throwMe();
	return buffer;
}

//
// Fat (aka universal) file wrappers.
// The offset is relative to the start of the containing file.
//
Universal::Universal(FileDesc fd, size_t offset /* = 0 */, size_t length /* = 0 */)
	: FileDesc(fd), mBase(offset), mLength(length), mMachType(0), mSuspicious(false)
{
	union {
		fat_header header;		// if this is a fat file
		mach_header mheader;	// if this is a thin file
	} unionHeader;

	if (fd.read(&unionHeader, sizeof(unionHeader), offset) != sizeof(unionHeader))
		UnixError::throwMe(ENOEXEC);
	switch (unionHeader.header.magic) {
	case FAT_MAGIC:
	case FAT_CIGAM:
		{
			//
			// Hack alert.
			// Under certain circumstances (15001604), mArchCount under-counts the architectures
			// by one, and special testing is required to validate the extra-curricular entry.
			// We always read an extra entry; in the situations where this might hit end-of-file,
			// we are content to fail.
			//
			mArchCount = ntohl(unionHeader.header.nfat_arch);

			if (mArchCount > MAX_ARCH_COUNT)
				UnixError::throwMe(ENOEXEC);

			size_t archSize = sizeof(fat_arch) * (mArchCount + 1);
			mArchList = (fat_arch *)malloc(archSize);
			if (!mArchList)
				UnixError::throwMe();
			if (fd.read(mArchList, archSize, mBase + sizeof(unionHeader.header)) != archSize) {
				::free(mArchList);
				UnixError::throwMe(ENOEXEC);
			}
			for (fat_arch *arch = mArchList; arch <= mArchList + mArchCount; arch++) {
				n2hi(arch->cputype);
				n2hi(arch->cpusubtype);
				n2hi(arch->offset);
				n2hi(arch->size);
				n2hi(arch->align);
			}
			const fat_arch *last_arch = mArchList + mArchCount;
			if (last_arch->cputype == (CPU_ARCH_ABI64 | CPU_TYPE_ARM)) {
				mArchCount++;
			}
			secinfo("macho", "%p is a fat file with %d architectures",
				this, mArchCount);

			/* A Mach-O universal file has padding of no more than "page size"
			 * between the header and slices. This padding must be zeroed out or the file
			   is not valid */
			std::list<struct fat_arch *> sortedList;
			for (unsigned i = 0; i < mArchCount; i++)
				sortedList.push_back(mArchList + i);

			sortedList.sort(^ bool (const struct fat_arch *arch1, const struct fat_arch *arch2) { return arch1->offset < arch2->offset; });

			const size_t universalHeaderEnd = mBase + sizeof(unionHeader.header) + (sizeof(fat_arch) * mArchCount);
			size_t prevHeaderEnd = universalHeaderEnd;
			size_t prevArchSize = 0, prevArchStart = 0;

			for (auto iterator = sortedList.begin(); iterator != sortedList.end(); ++iterator) {
				auto ret = mSizes.insert(std::pair<size_t, size_t>((*iterator)->offset, (*iterator)->size));
				if (ret.second == false) {
					::free(mArchList);
					secerror("Error processing fat file: Two architectures have the same size");
					MacOSError::throwMe(errSecInternalError); // Something is wrong if the same size was encountered twice
				}

				size_t gapSize = (*iterator)->offset - prevHeaderEnd;

				/* The size of the padding after the universal cannot be calculated to a fixed size */
				if (prevHeaderEnd != universalHeaderEnd) {
					if (((*iterator)->align > MAX_ALIGN) || gapSize >= (1 << (*iterator)->align)) {
						secerror("STRICT VALIDATION ERROR: the size of the padding after the universal cannot be calculated to a fixed size");
						mSuspicious = true;
						break;
					}
				}

				// validate gap bytes in tasty page-sized chunks
				CssmAutoPtr<uint8_t> gapBytes(Allocator::standard().malloc<uint8_t>(PAGE_SIZE));
				size_t off = 0;
				while (off < gapSize) {
					size_t want = min(gapSize - off, (size_t)PAGE_SIZE);
					size_t got = fd.read(gapBytes, want, prevHeaderEnd + off);
					if (got == 0) {
						secerror("STRICT VALIDATION ERROR: failed to read expected gap bytes");
						mSuspicious = true;
						break;
					}
					off += got;
					for (size_t x = 0; x < got; x++) {
						if (gapBytes[x] != 0) {
							secerror("STRICT VALIDATION ERROR: non-zero gap byte found");
							mSuspicious = true;
							break;
						}
					}
					if (mSuspicious) {
						break;
					}
				}
				if (off != gapSize) {
					secerror("STRICT VALIDATION ERROR: gap size does not match expected (%zu != %zu)", off, gapSize);
					mSuspicious = true;
				}
				if (mSuspicious) {
					break;
				}

				prevHeaderEnd = (*iterator)->offset + (*iterator)->size;
				prevArchSize = (*iterator)->size;
				prevArchStart = (*iterator)->offset;
			}

			/* If there is anything extra at the end of the file, reject this */
			if (!mSuspicious && (prevArchStart + prevArchSize != fd.fileSize())) {
				secerror("STRICT VALIDATION ERROR: Extra data after the last slice in a universal file (expected %zu found %zu)", prevArchStart+prevArchSize, fd.fileSize());
				mSuspicious = true;
			}

			break;
		}
	case MH_MAGIC:
	case MH_MAGIC_64:
		mArchList = NULL;
		mArchCount = 0;
		mThinArch = Architecture(unionHeader.mheader.cputype, unionHeader.mheader.cpusubtype);
		secinfo("macho", "%p is a thin file (%s)", this, mThinArch.name());
		break;
	case MH_CIGAM:
	case MH_CIGAM_64:
		mArchList = NULL;
		mArchCount = 0;
		mThinArch = Architecture(flip(unionHeader.mheader.cputype), flip(unionHeader.mheader.cpusubtype));
		secinfo("macho", "%p is a thin file (%s)", this, mThinArch.name());
		break;
	default:
		UnixError::throwMe(ENOEXEC);
	}
}

Universal::~Universal()
{
	::free(mArchList);
}

size_t Universal::lengthOfSlice(size_t offset) const
{
	auto ret = mSizes.find(offset);
	if (ret == mSizes.end())
		MacOSError::throwMe(errSecInternalError);
	return ret->second;
}

//
// Get the "local" architecture from the fat file
// Throws ENOEXEC if not found.
//
MachO *Universal::architecture() const
{
	if (isUniversal())
		return findImage(bestNativeArch());
	else
		return new MachO(*this, mBase, mLength);
}

size_t Universal::archOffset() const
{
	if (isUniversal())
		return mBase + findArch(bestNativeArch())->offset;
	else
		return mBase;
}


//
// Get the specified architecture from the fat file
// Throws ENOEXEC if not found.
//
MachO *Universal::architecture(const Architecture &arch) const
{
	if (isUniversal())
		return findImage(arch);
	else if (mThinArch.matches(arch))
		return new MachO(*this, mBase, mLength);
	else
		UnixError::throwMe(ENOEXEC);
}

size_t Universal::archOffset(const Architecture &arch) const
{
	if (isUniversal())
		return mBase + findArch(arch)->offset;
	else if (mThinArch.matches(arch))
		return 0;
	else
		UnixError::throwMe(ENOEXEC);
}

size_t Universal::archLength(const Architecture &arch) const
{
	if (isUniversal())
		return mBase + findArch(arch)->size;
	else if (mThinArch.matches(arch))
		return this->fileSize();
	else
		UnixError::throwMe(ENOEXEC);
}

//
// Get the architecture at a specified offset from the fat file.
// Throws an exception of the offset does not point at a Mach-O image.
//
MachO *Universal::architecture(size_t offset) const
{
	if (isUniversal())
		return make(new MachO(*this, offset, lengthOfSlice(offset)));
	else if (offset == mBase)
		return new MachO(*this);
	else
		UnixError::throwMe(ENOEXEC);
}


//
// Locate an architecture from the fat file's list.
// Throws ENOEXEC if not found.
//
const fat_arch *Universal::findArch(const Architecture &target) const
{
	assert(isUniversal());
	const fat_arch *end = mArchList + mArchCount;
	// First match should be for all fields, including capabilities.
	for (const fat_arch *arch = mArchList; arch < end; ++arch) {
		if (arch->cputype == target.cpuType() &&
			arch->cpusubtype == target.cpuSubtypeFull()) {
			return arch;
		}
	}
	// Second, look for the a valid type match, ignoring capabilities.
	for (const fat_arch *arch = mArchList; arch < end; ++arch) {
		if (arch->cputype == target.cpuType() &&
			(arch->cpusubtype & ~CPU_SUBTYPE_MASK) == target.cpuSubtype()) {
			return arch;
		}
	}
	// Third, prioritize match for generic model of main architecture.
	for (const fat_arch *arch = mArchList; arch < end; ++arch) {
		if (arch->cputype == target.cpuType() &&
			(arch->cpusubtype & ~CPU_SUBTYPE_MASK) == 0) {
			return arch;
		}
	}
	// Finally, try just matching any subarchitecture of the main architecture (questionable).
	for (const fat_arch *arch = mArchList; arch < end; ++arch) {
		if (arch->cputype == target.cpuType()) {
			return arch;
		}
	}
	// No match, return an error.
	UnixError::throwMe(ENOEXEC);
}

MachO *Universal::findImage(const Architecture &target) const
{
	const fat_arch *arch = findArch(target);
	return make(new MachO(*this, mBase + arch->offset, arch->size));
}
	
MachO* Universal::make(MachO* macho) const
{
	unique_ptr<MachO> mo(macho);				// safe resource
	uint32_t type = mo->type();
	if (type == 0)							// not a recognized Mach-O type
		UnixError::throwMe(ENOEXEC);
	if (mMachType && mMachType != type)		// inconsistent members
		UnixError::throwMe(ENOEXEC);
	mMachType = type;						// record
	return mo.release();
}


//
// Find the best-matching architecture for this fat file.
// We pick the native architecture if it's available.
// If it contains exactly one architecture, we take that.
// Otherwise, we throw.
//
Architecture Universal::bestNativeArch() const
{
	if (isUniversal()) {
		// ask the NXArch API for our native architecture
		const Architecture native = Architecture::local();
		if (fat_arch *match = NXFindBestFatArch(native.cpuType(), native.cpuSubtype(), mArchList, mArchCount))
			return *match;
		// if the system can't figure it out, pick (arbitrarily) the first one
		return mArchList[0];
	} else
		return mThinArch;
}

//
// List all architectures from the fat file's list.
//
void Universal::architectures(Architectures &archs) const
{
	if (isUniversal()) {
		for (unsigned n = 0; n < mArchCount; n++)
			archs.insert(mArchList[n]);
	} else {
		unique_ptr<MachO> macho(architecture());
		archs.insert(macho->architecture());
	}
}

//
// Quickly guess the Mach-O type of a file.
// Returns type zero if the file isn't Mach-O or Universal.
// Always looks at the start of the file, and does not change the file pointer.
//
uint32_t Universal::typeOf(FileDesc fd)
{
	mach_header header;
	int max_tries = 3;
	if (fd.read(&header, sizeof(header), 0) != sizeof(header))
		return 0;
	while (max_tries > 0) {
		switch (header.magic) {
		case MH_MAGIC:
		case MH_MAGIC_64:
			return header.filetype;
		case MH_CIGAM:
		case MH_CIGAM_64:
			return flip(header.filetype);
		case FAT_MAGIC:
		case FAT_CIGAM:
			{
				const fat_arch *arch1 =
					LowLevelMemoryUtilities::increment<fat_arch>(&header, sizeof(fat_header));
				if (fd.read(&header, sizeof(header), ntohl(arch1->offset)) != sizeof(header))
					return 0;
				max_tries--;
				continue;
			}
		default:
			return 0;
		}
	}
	return 0;
}

//
// Strict validation
//
bool Universal::isSuspicious() const
{
	if (mSuspicious)
		return true;
	Universal::Architectures archList;
	architectures(archList);
	for (Universal::Architectures::const_iterator it = archList.begin(); it != archList.end(); ++it) {
		unique_ptr<MachO> macho(architecture(*it));
		if (macho->isSuspicious())
			return true;
	}
	return false;
}


} // Security
