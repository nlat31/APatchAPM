//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#include <cstdio>
#include "ElfRebuilder.h"
#include "FDebug.h"


#ifdef __LP64__
#define ADDRESS_FORMAT "ll"
#else
#define ADDRESS_FORMAT ""
#endif

ElfRebuilder::ElfRebuilder(ObElfReader *elf_reader) {
    elf_reader_ = elf_reader;
}

bool ElfRebuilder::RebuildPhdr() {
    FLOGD("=============LoadDynamicSectionFromBaseSource==========RebuildPhdr=========================");

    auto phdr = (Elf_Phdr*)elf_reader_->loaded_phdr();
    for(auto i = 0; i < elf_reader_->phdr_count(); i++) {
        phdr->p_filesz = phdr->p_memsz;     // expend filesize to memsiz
        // p_paddr and p_align is not used in load, just ignore it.
        // fix file offset.
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_offset = phdr->p_vaddr;     // elf has been loaded.
        phdr++;
    }
    FLOGD("=====================RebuildPhdr End======================");
    return true;
}

bool ElfRebuilder::RebuildShdr() {
    FLOGD("=======================RebuildShdr=========================");
    // rebuilding shdr, link information
    auto base = si.load_bias;
    shstrtab.push_back('\0');

    // empty shdr
    if(true) {
        Elf_Shdr shdr = {0};
        shdrs.push_back(shdr);
    }

    // gen .dynsym
    if(si.symtab != nullptr) {
        sDYNSYM = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynsym");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNSYM;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.symtab - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;   // calc sh_size later(pad to next shdr)
        shdr.sh_link = 0;   // link to dynstr later
//        shdr.sh_info = 1;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x10;
#endif

        shdrs.push_back(shdr);
    }

    // gen .dynstr
    if(si.strtab != nullptr) {
        sDYNSTR = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynstr");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.strtab - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.strtabsize;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .hash
    if(si.hash != nullptr) {
        sHASH = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".hash");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_HASH;

        shdr.sh_addr = si.hash - base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO 32bit, 64bit?
        shdr.sh_size = (si.nbucket + si.nchain) * sizeof(Elf_Addr) + 2 * sizeof(Elf_Addr);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .rel.dyn
    if(si.rel != nullptr && si.rel_count) {
        sRELDYN = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rel.dyn");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.rel - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO fix size 32bit 64bit?
        shdr.sh_size = si.rel_count * sizeof(Elf_Rel);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;
#endif

        shdrs.push_back(shdr);
    }

    // gen .rela.dyn
    if(si.plt_type == DT_RELA && si.rel != nullptr && si.rel_count) {
        sRELADYN = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rela.dyn");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_RELA;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.rel - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO fix size 32bit 64bit?
        shdr.sh_size = si.rel_count * sizeof(Elf_Rela);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0xC;
#endif

        shdrs.push_back(shdr);
    }

    // gen .rel.plt
    if(si.plt_rel != nullptr && si.plt_rel_count) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rel.plt");
        shstrtab.push_back('\0');

        shdr.sh_type = (si.plt_type == DT_RELA) ? SHT_RELA : SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.plt_rel - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO fix size 32bit 64bit?
        shdr.sh_size = si.plt_rel_count * ((si.plt_type == DT_RELA) ? sizeof(Elf_Rela) : sizeof(Elf_Rel));
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;
#endif

        shdrs.push_back(shdr);
    }

    // gen .plt
    if(si.plt_got != nullptr) {
        sPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = (uintptr_t)si.plt_got - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;  // fixed later
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 16;
        shdr.sh_entsize = 16;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 4;
#endif

        shdrs.push_back(shdr);
    }

    // gen .text
    if(si.min_load != 0 && si.max_load != 0) {
        sTEXTTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".text");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = si.min_load;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.max_load - si.min_load;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 16;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .ARM.exidx
    if(si.ARM_exidx != nullptr && si.ARM_exidx_count) {
        sARMEXIDX = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".ARM.exidx");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_ARM_EXIDX;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.ARM_exidx - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.ARM_exidx_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .fini_array
    if(si.fini_array != nullptr && si.fini_array_count) {
        sFINIARRAY = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".fini_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_FINI_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.fini_array - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.fini_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .init_array
    if(si.init_array != nullptr && si.init_array_count) {
        sINITARRAY = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".init_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_INIT_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.init_array - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.init_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .dynamic
    if(si.dynamic != nullptr) {
        sDYNAMIC = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynamic");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNAMIC;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.dynamic - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.dynamic_count * sizeof(Elf_Dyn);
        shdr.sh_link = sDYNSTR;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x10;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;
#endif

        shdrs.push_back(shdr);
    }

    // gen .got
    if(si.plt_got != nullptr) {
        sGOT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".got");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.plt_got - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;  // fixed later
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .data
    if(si.max_load != 0) {
        sDATA = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".data");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = si.max_load;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;  // fixed later
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __LP64__
        shdr.sh_addralign = 8;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .bss
    {
        sBSS = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".bss");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_NOBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = 0;
        shdr.sh_offset = 0;
        shdr.sh_size = 0;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // gen .shstrtab
    {
        sSHSTRTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".shstrtab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = 0;
        shdr.sh_addr = 0;
        shdr.sh_offset = 0; // fixed later
        shdr.sh_size = shstrtab.length();
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0;

        shdrs.push_back(shdr);
    }

    // fix sh_link for dynsym
    if (sDYNSYM != 0 && sDYNSTR != 0) {
        shdrs[sDYNSYM].sh_link = sDYNSTR;
    }

    // fix for size
    for (size_t i = 0; i + 1 < shdrs.size(); i++) {
        auto& cur = shdrs[i];
        auto& nxt = shdrs[i + 1];
        if (cur.sh_size == 0 && nxt.sh_offset > cur.sh_offset) {
            cur.sh_size = nxt.sh_offset - cur.sh_offset;
        }
    }

    FLOGD("=====================RebuildShdr End======================");
    return true;
}

bool ElfRebuilder::ReadSoInfo() {
    FLOGD("=======================ReadSoInfo=========================");
    si.phdr = elf_reader_->loaded_phdr();
    si.phnum = elf_reader_->phdr_count();
    si.base = elf_reader_->load_start();
    si.size = elf_reader_->load_size();
    si.load_bias = elf_reader_->load_bias();
    si.entry = elf_reader_->record_ehdr()->e_entry;

    Elf_Addr min_vaddr, max_vaddr;
    phdr_table_get_load_size(si.phdr, si.phnum, &min_vaddr, &max_vaddr);
    si.min_load = min_vaddr;
    si.max_load = max_vaddr;

    phdr_table_get_dynamic_section(si.phdr, si.phnum, si.load_bias, &si.dynamic, &si.dynamic_count, &si.dynamic_flags);
    if (si.dynamic == nullptr) {
        FLOGE("No valid dynamic phdr data");
        return false;
    }

    for (Elf_Dyn* d = si.dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_HASH:
                si.hash = reinterpret_cast<uint8_t*>(si.load_bias + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                si.strtab = reinterpret_cast<const char*>(si.load_bias + d->d_un.d_ptr);
                FLOGD("string table found at %" ADDRESS_FORMAT "x", d->d_un.d_ptr);
                break;
            case DT_SYMTAB:
                si.symtab = reinterpret_cast<Elf_Sym*>(si.load_bias + d->d_un.d_ptr);
                FLOGD("symbol table found at %" ADDRESS_FORMAT "x", d->d_un.d_ptr);
                break;
            case DT_JMPREL:
                si.plt_rel = reinterpret_cast<Elf_Rel*>(si.load_bias + d->d_un.d_ptr);
                FLOGD("%s plt_rel (DT_JMPREL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                si.plt_rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                FLOGD("%s plt_rel_count (DT_PLTRELSZ) %zu", si.name, si.plt_rel_count);
                break;
            case DT_REL:
                si.rel = reinterpret_cast<Elf_Rel*>(si.load_bias + d->d_un.d_ptr);
                FLOGD("%s rel (DT_REL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si.rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                FLOGD("%s rel_size (DT_RELSZ) %zu", si.name, si.rel_count);
                break;
            case DT_INIT:
                si.init_func = reinterpret_cast<void*>(si.load_bias + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI:
                si.fini_func = reinterpret_cast<void*>(si.load_bias + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                si.init_array = reinterpret_cast<void**>(si.load_bias + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                si.init_array_count = d->d_un.d_val / sizeof(Elf_Addr);
                FLOGD("%s constructors (DT_INIT_ARRAYSZ) %zu", si.name, si.init_array_count);
                break;
            case DT_FINI_ARRAY:
                si.fini_array = reinterpret_cast<void**>(si.load_bias + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                si.fini_array_count = d->d_un.d_val / sizeof(Elf_Addr);
                FLOGD("%s destructors (DT_FINI_ARRAYSZ) %zu", si.name, si.fini_array_count);
                break;
            case DT_PREINIT_ARRAY:
                si.preinit_array = reinterpret_cast<void*>(si.load_bias + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_PREINIT_ARRAY) found at %" ADDRESS_FORMAT "d", si.name, d->d_un.d_ptr);
                break;
            case DT_PREINIT_ARRAYSZ:
                si.preinit_array_count = d->d_un.d_val / sizeof(Elf_Addr);
                FLOGD("%s constructors (DT_PREINIT_ARRAYSZ) %zu", si.name, si.preinit_array_count);
                break;
            case DT_PLTGOT:
                si.plt_got = reinterpret_cast<Elf_Addr*>(si.load_bias + d->d_un.d_ptr);
                break;
            case DT_STRSZ:
                si.strtabsize = d->d_un.d_val;
                break;
            case DT_PLTREL:
                si.plt_type = d->d_un.d_val;
                break;
            case DT_SONAME:
                if (si.strtab != nullptr) {
                    si.name = si.strtab + d->d_un.d_val;
                    FLOGD("soname %s", si.name);
                }
                break;
            default:
                FLOGD("Unused DT entry: type 0x%08" ADDRESS_FORMAT "x arg 0x%08" ADDRESS_FORMAT "x", d->d_tag, d->d_un.d_val);
                break;
        }
    }
    FLOGD("=======================ReadSoInfo End=========================");
    return true;
}

bool ElfRebuilder::RebuildFin() {
    FLOGD("=======================try to finish file rebuild =========================");
    auto load_size = si.max_load - si.min_load;
    rebuild_size = load_size + shstrtab.length() +
                   shdrs.size() * sizeof(Elf_Shdr);
    rebuild_data = new uint8_t[rebuild_size];
    memcpy(rebuild_data, (void*)si.load_bias, load_size);
    // pad with shstrtab
    memcpy(rebuild_data + load_size, shstrtab.c_str(), shstrtab.length());
    // pad with shdrs
    auto shdr_off = load_size + shstrtab.length();
    memcpy(rebuild_data + (int)shdr_off, (void*)&shdrs[0],
           shdrs.size() * sizeof(Elf_Shdr));
    auto ehdr = *elf_reader_->record_ehdr();
    ehdr.e_type = ET_DYN;
#ifdef __LP64__
    ehdr.e_machine = 183;
#else
    ehdr.e_machine = 40;
#endif
    ehdr.e_shnum = shdrs.size();
    ehdr.e_shoff = (Elf_Addr)shdr_off;
    ehdr.e_shstrndx = sSHSTRTAB;
    memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));

    FLOGD("=======================End=========================");
    return true;
}

template <bool isRela>
void ElfRebuilder::relocate(uint8_t * base, Elf_Rel* rel, Elf_Addr dump_base) {
    if(rel == nullptr) return ;
#ifndef __LP64__
    auto type = ELF32_R_TYPE(rel->r_info);
    auto sym = ELF32_R_SYM(rel->r_info);
#else
    auto type = ELF64_R_TYPE(rel->r_info);
    auto sym = ELF64_R_SYM(rel->r_info);
#endif
    auto prel = reinterpret_cast<Elf_Addr *>(base + rel->r_offset);
    uintptr_t offset = reinterpret_cast<uintptr_t>(prel) - reinterpret_cast<uintptr_t>(base);
    if (offset > elf_reader_->dump_so_size_) {
        return;
    }
    switch (type) {
        // I don't known other so info, if i want to fix it, I must dump other so file
        case R_386_RELATIVE:
        case R_ARM_RELATIVE:{
            *prel = *prel - dump_base;
            break;
        }
        case 0x402:{
            auto syminfo = si.symtab[sym];
            if (syminfo.st_value != 0) {
                *prel = syminfo.st_value;
            } else {
                auto load_size = si.max_load - si.min_load;
                *prel = load_size + external_pointer;
                external_pointer += sizeof(*prel);
            }
            break;
        }
        default:
            break;
    }
    if (isRela){
        Elf_Rela* rela = (Elf_Rela*)rel;
        switch (type){
            case 0x403:
                *prel = rela->r_addend;
                break;
            default:
                break;
        }
    }
};

bool ElfRebuilder::RebuildRelocs() {
    if(elf_reader_->dump_so_base_ == 0) return true;
    FLOGD("=======================RebuildRelocs=========================");
    if (si.plt_type == DT_REL) {
        auto rel = si.rel;
        for (auto i = 0; i < si.rel_count; i++, rel++){
            relocate<false>(si.load_bias, rel, elf_reader_->dump_so_base_);
        }
        rel = si.plt_rel;
        for (auto i = 0; i < si.plt_rel_count; i++, rel++){
            relocate<false>(si.load_bias, rel, elf_reader_->dump_so_base_);
        }
    } else {
        auto rel = (Elf_Rela*)si.plt_rela;
        for (auto i = 0; i <si.plt_rela_count; i++, rel ++) {
            relocate<true>(si.load_bias, (Elf_Rel*)rel, elf_reader_->dump_so_base_);
        }
        rel = (Elf_Rela*) si.plt_rel;
        for (auto i = 0; i < si.plt_rel_count; i++, rel++){
            relocate<true>(si.load_bias, (Elf_Rel*)rel, elf_reader_->dump_so_base_);
        }
    }
    FLOGD("=======================RebuildRelocs End=======================");
    return true;
}

bool ElfRebuilder::Rebuild() {
    if (!ReadSoInfo()) return false;
    if (!RebuildPhdr()) return false;
    if (!RebuildRelocs()) return false;
    if (!RebuildShdr()) return false;
    if (!RebuildFin()) return false;
    return true;
}

