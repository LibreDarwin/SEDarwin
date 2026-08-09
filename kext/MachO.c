/*-
 * SEDarwin policy kext - in-memory Mach-O header inspection.
 *
 * Pure parsing: given a buffer holding the first bytes of a Mach-O image
 * (thin or fat), report CPU type/subtype, number of load commands and whether
 * an LC_CODE_SIGNATURE is present. No vnode or file I/O happens here.
 *
 * M0 exercises the parser at load time against a synthetic header in
 * sebsd_macho_selftest() (called from policy initbsd); the exec path does NOT
 * read files back out of the framework-provided vnode, because doing so inside
 * mpo_vnode_check_exec would re-enter the VFS under the exec path's locks. A
 * later milestone can feed this parser from a lock-free reader.
 */

#include "kernel.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>

static int
sebsd_macho_thin(const void *data, size_t len, struct sebsd_macho_info *info)
{
	const struct mach_header_64 *mh = (const struct mach_header_64 *)data;

	if (len < sizeof(struct mach_header_64)) {
		return -1;
	}
	if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) {
		return -1;
	}

	info->m_fat = 0;
	info->m_cputype = mh->cputype;
	info->m_cpusubtype = mh->cpusubtype;
	info->m_ncmds = mh->ncmds;

	{
		const struct load_command *lc;
		uint32_t i;
		size_t off = sizeof(struct mach_header_64);

		for (i = 0; i < mh->ncmds; i++) {
			if (off + sizeof(struct load_command) > len) {
				break;
			}
			lc = (const struct load_command *)
			    ((const uint8_t *)data + off);
			if (lc->cmdsize < sizeof(struct load_command) ||
			    off + lc->cmdsize > len) {
				break;
			}
			if (lc->cmd == LC_CODE_SIGNATURE) {
				info->m_codesign = 1;
			}
			off += lc->cmdsize;
		}
	}
	return 0;
}

static int
sebsd_macho_fat(const void *data, size_t len, struct sebsd_macho_info *info)
{
	const struct fat_header *fh = (const struct fat_header *)data;
	const struct fat_arch *fa;
	uint32_t narch;
	uint32_t i;

	if (len < sizeof(struct fat_header)) {
		return -1;
	}
	if (fh->magic != FAT_MAGIC && fh->magic != FAT_CIGAM) {
		return -1;
	}

	narch = ntohl(fh->nfat_arch);
	if (len < sizeof(struct fat_header) + narch * sizeof(struct fat_arch)) {
		return -1;
	}

	info->m_fat = 1;
	info->m_ncmds = (int)narch;
	info->m_codesign = 0;

	fa = (const struct fat_arch *)((const uint8_t *)data +
	    sizeof(struct fat_header));
	for (i = 0; i < narch; i++) {
		if (fa[i].cputype == CPU_TYPE_ARM64) {
			info->m_cputype = (int)fa[i].cputype;
			info->m_cpusubtype = (int)(fa[i].cpusubtype &
			    ~CPU_SUBTYPE_MASK);
			break;
		}
	}
	return 0;
}

int
sebsd_macho_info(const void *data, size_t len,
    struct sebsd_macho_info *info)
{
	const uint32_t *magic = (const uint32_t *)data;
	int error;

	if (data == NULL || len < 4 || info == NULL) {
		return -1;
	}

	info->m_cputype = 0;
	info->m_cpusubtype = 0;
	info->m_ncmds = 0;
	info->m_fat = 0;
	info->m_codesign = 0;

	if (*magic == FAT_MAGIC || *magic == FAT_CIGAM) {
		error = sebsd_macho_fat(data, len, info);
	} else {
		error = sebsd_macho_thin(data, len, info);
	}
	return error;
}

void
sebsd_macho_selftest(void)
{
	/*
	 * A synthetic 64-bit thin binary: one header plus a single
	 * LC_CODE_SIGNATURE load command. Built by hand so the parser is
	 * exercised against a known-good image without touching the filesystem.
	 */
	struct mach_header_64 hdr = {
		.magic = MH_MAGIC_64,
		.cputype = CPU_TYPE_ARM64,
		.cpusubtype = CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_LIB64,
		.filetype = MH_EXECUTE,
		.ncmds = 1,
		.sizeofcmds = sizeof(struct linkedit_data_command),
		.flags = MH_NOUNDEFS | MH_TWOLEVEL,
		.reserved = 0,
	};
	struct linkedit_data_command cs = {
		.cmd = LC_CODE_SIGNATURE,
		.cmdsize = sizeof(cs),
		.dataoff = 0x1000,
		.datasize = 0x400,
	};
	struct {
		struct mach_header_64 hdr;
		struct linkedit_data_command cs;
	} image;
	struct sebsd_macho_info info;

	memset(&image, 0, sizeof(image));
	memcpy(&image.hdr, &hdr, sizeof(hdr));
	memcpy(&image.cs, &cs, sizeof(cs));

	if (sebsd_macho_info(&image, sizeof(image), &info) != 0) {
		sebsd_log("macho selftest: FAILED to parse synthetic image");
		return;
	}
	sebsd_log("macho selftest: fat=%d cputype=0x%x cpusubtype=0x%x "
	    "ncmds=%d codesign=%d", info.m_fat, info.m_cputype,
	    info.m_cpusubtype, info.m_ncmds, info.m_codesign);
}
