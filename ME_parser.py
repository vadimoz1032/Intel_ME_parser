import idaapi
import idautils
import idc

import json
import os

def get_string(ea, len):
	i = 1
	str = ""
	while(i <= len):
		if (get_wide_byte(ea) == 0):
			break
		str += chr(get_wide_byte(ea))
		i += 1
		ea += 1
	return str


#--------------------------------------------------------------------------------------
#CREATE ME_Flash_Partiton_Table

add_struc(get_first_struc_idx(), "ME_Flash_Partiton_Table", 0)
index_ME_Flash_Partiton_Table = get_struc_id("ME_Flash_Partiton_Table")

add_struc_member(index_ME_Flash_Partiton_Table, "ROM_bytepass_instruction",	0,		0x002400,	-1,	16)
add_struc_member(index_ME_Flash_Partiton_Table, "signature",				0X10,	0x5000c400,	 0,	4)
add_struc_member(index_ME_Flash_Partiton_Table, "NumEntries",				0X14,	0x20200400,	-1,	4)
add_struc_member(index_ME_Flash_Partiton_Table, "version",					0X18,	0x000400,	-1,	1)
add_struc_member(index_ME_Flash_Partiton_Table, "EntryType",				0X19,	0x000400,	-1,	1)
add_struc_member(index_ME_Flash_Partiton_Table, "HeaderLen",				0X1A,	0x000400,	-1,	1)
add_struc_member(index_ME_Flash_Partiton_Table, "CheckSum",					0X1B,	0x000400,	-1,	1)
add_struc_member(index_ME_Flash_Partiton_Table, "FlashCycleLifetime",		0X1C,	0x10000400,	-1,	2)
add_struc_member(index_ME_Flash_Partiton_Table, "FlashCycleLimit",			0X1E,	0x10000400,	-1,	2)
add_struc_member(index_ME_Flash_Partiton_Table, "UMASize",					0X20,	0x30000400,	-1,	8)
add_struc_member(index_ME_Flash_Partiton_Table, "Extra_ver",				0X28,	0x10200400,	-1,	8)

#--------------------------------------------------------------------------------------
#CREATE ME_FPT_Entry

add_struc(get_next_struc_idx(index_ME_Flash_Partiton_Table), "ME_FPT_Entry", 0)
index_ME_FPT_Entry = get_struc_id("ME_FPT_Entry")

add_struc_member(index_ME_FPT_Entry, "Name",			0,		0x5000c400,	0,	4)
add_struc_member(index_ME_FPT_Entry, "Owner",			0X4,	0x50000400,	0,	4)
add_struc_member(index_ME_FPT_Entry, "Offset",			0X8,	0x20000400,	-1,	4)
add_struc_member(index_ME_FPT_Entry, "Size",			0XC,	0x20000400,	-1,	4)
add_struc_member(index_ME_FPT_Entry, "TokensOnStart",	0X10,	0x20000400,	-1,	4)
add_struc_member(index_ME_FPT_Entry, "MaxTokens",		0X14,	0x20000400,	-1,	4)
add_struc_member(index_ME_FPT_Entry, "ScratchSectors",	0X18,	0x20000400,	-1,	4)
add_struc_member(index_ME_FPT_Entry, "Flags",			0X1C,	0x20000400,	-1,	4)

#--------------------------------------------------------------------------------------
#CREATE ME_CPD_Entry

add_struc(get_next_struc_idx(index_ME_FPT_Entry), "ME_CPD_Entry", 0)
index_ME_CPD_Entry = get_struc_id("ME_CPD_Entry")

add_struc_member(index_ME_CPD_Entry, "Name",	0,	    0x5000c400,	 0,	12)
add_struc_member(index_ME_CPD_Entry, "Offset",	0XC,	0x20000400,	-1,	4)
add_struc_member(index_ME_CPD_Entry, "Size",	0X10,	0x20000400,	-1,	4)
add_struc_member(index_ME_CPD_Entry, "Flags",	0X14,	0x20000400,	-1,	4)
#-------------------------------------------------------------------------------------
#CREATE ME_CPD_Header

add_struc(get_next_struc_idx(index_ME_CPD_Entry), "ME_CPD_Header", 0)
index_ME_CPD_Header = get_struc_id("ME_CPD_Header")

add_struc_member(index_ME_CPD_Header, "signature",		0,		0x5000c400,	 0,	4)
add_struc_member(index_ME_CPD_Header, "NamModules",		0X4,	0x20000400,	-1,	4)
add_struc_member(index_ME_CPD_Header, "HeaderVersion",	0X8,	0x000400,	-1,	1)
add_struc_member(index_ME_CPD_Header, "EntryVersion",	0X9,	0x000400,	-1,	1)
add_struc_member(index_ME_CPD_Header, "HeaderLength",	0XA,	0x000400,	-1,	1)
add_struc_member(index_ME_CPD_Header, "CheckSum",		0XB,	0x000400,	-1,	1)
add_struc_member(index_ME_CPD_Header, "PartitionName",	0XC,	0x5000c400,	 0,	4)
#---------------------------------------------------------------------------------------
#ME_Manifest_Header

add_struc(get_next_struc_idx(index_ME_CPD_Entry), "ME_Manifest_Header", 0)
index_ME_Manifest_Header = get_struc_id("ME_Manifest_Header")

add_struc_member(index_ME_Manifest_Header, "HeaderType",	0,		0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "HeaderSubType",	0X2,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "HeaderLength",	0X4,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "HeaderVersion",	0X8,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "Flags",			0XC,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "VenId",			0X10,	0x20100400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "Date",			0X14,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "Size",			0X18,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "aMn2",			0X1C,	0x5000c400,  0,	4)
add_struc_member(index_ME_Manifest_Header, "BuildTAg",		0X20,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "Major",			0X24,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "Minor",			0X26,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "Hotfix",		0X28,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "Build",			0X2A,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "SVN",			0X2C,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "MEU_Major",		0X30,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "MEU_Minor",		0X32,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "MEU_Hotfix",	0X34,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "MEU_Build",		0X36,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "MEU_Man_ver",	0X38,	0x10000400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "MEU_Man_Res",	0X3A,	0x10100400,	-1,	2)
add_struc_member(index_ME_Manifest_Header, "Reserved",		0X3C,	0x20000400,	-1,	60)
add_struc_member(index_ME_Manifest_Header, "PublicKeySize",	0X78,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "ExponentSize",	0X7C,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "RsaPubKey",		0X80,	0x2000040e0,-1,	256)
add_struc_member(index_ME_Manifest_Header, "RsaExponent",	0X180,	0x20000400,	-1,	4)
add_struc_member(index_ME_Manifest_Header, "RsaSig",		0X184,	0x20000400,	-1,	256)

#-----------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_01
add_struc(get_next_struc_idx(index_ME_Manifest_Header), "CSE_Ext_01", 0)
index_CSE_Ext_01 = get_struc_id("CSE_Ext_01")

add_struc_member(index_CSE_Ext_01, "TAG",			0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_01 ,"size",			0X4,	0x20100400,	-1,	4)
add_struc_member(index_CSE_Ext_01 ,"Reserved",		0X8,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_01 ,"ModuleCount",	0XC,	0x20100400,	-1,	4)

#----------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_0F
add_struc(get_next_struc_idx(index_CSE_Ext_01), "CSE_Ext_0F", 0)
index_CSE_Ext_0F = get_struc_id("CSE_Ext_0F")

add_struc_member(index_CSE_Ext_0F, "Tag",			0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0F, "Size",			0X4,	0x20100400,	-1,	4)
add_struc_member(index_CSE_Ext_0F, "PartitionName",	0X8,	0x5000c400,	 0,	4)
add_struc_member(index_CSE_Ext_0F, "VCN",			0XC,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0F, "UsageBitmap",	0X10,	0x000400,	-1,	16)
add_struc_member(index_CSE_Ext_0F, "ARBSVN",		0X20,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0F, "Reserved",		0X24,	0x20000400,	-1,	16)

#----------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_00
add_struc(get_next_struc_idx(index_CSE_Ext_0F), "CSE_Ext_00", 0)
index_CSE_Ext_00 = get_struc_id("CSE_Ext_00")

add_struc_member(index_CSE_Ext_00, "TAG",				0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_00, "Size",				0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_00, "MinUmaSize",		0X8,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_00, "ChipsetVersion",	0XC,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_00, "IMGDefualtHash",	0X10,	0x20000400,	-1,	32)
add_struc_member(index_CSE_Ext_00, "PageTableUMASize",	0X30,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_00, "Reserved0",			0X34,	0x30000400,	-1,	8)
add_struc_member(index_CSE_Ext_00, "Reserved1",			0X3C,	0x20000400,	-1,	4)

#-----------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_00_Mod
add_struc(get_next_struc_idx(index_CSE_Ext_00), "CSE_Ext_00_Mod", 0)
index_CSE_Ext_00_Mod = get_struc_id("CSE_Ext_00_Mod")

add_struc_member(index_CSE_Ext_00_Mod, "Name",		0,		0x5000c400,	0,	4)
add_struc_member(index_CSE_Ext_00_Mod, "Version",	0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_00_Mod, "UserID",	0X8,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_00_Mod, "GroupID",	0XA,	0x10000400,	-1,	2)

#------------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_0C
add_struc(get_next_struc_idx(index_CSE_Ext_00_Mod), "CSE_Ext_0C", 0)	
index_CSE_Ext_0C = get_struc_id("CSE_Ext_0C")

add_struc_member(index_CSE_Ext_0C, "TAG",			0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0C, "size",			0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0C, "FWSKUCaps",		0X8,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0C, "FWSKUCapsRes",	0XC,	0x20000400,	-1,	28)
add_struc_member(index_CSE_Ext_0C, "FWSKUAttrib",	0X28,	0x30100400,	-1,	8)

#------------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_02
add_struc(get_next_struc_idx(index_CSE_Ext_0C), "CSE_Ext_02", 0)
index_CSE_Ext_02 = get_struc_id("CSE_Ext_02")

add_struc_member(index_CSE_Ext_02, "TAG",			0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_02, "Size",			0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_02, "ModuleCount",	0X8,	0x20000400,	-1,	4)

#------------------------------------------------------------------------------------------------------
#CREATE CSE_EXT_02_Mod
add_struc(get_next_struc_idx(index_CSE_Ext_02), "CSE_Ext_02_Mod", 0)
index_CSE_Ext_02_Mod = get_struc_id("CSE_Ext_02_Mod")

add_struc_member(index_CSE_Ext_02_Mod, "UserID",	0,		0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_02_Mod, "Reserved",	0X2,	0x10000400,	-1,	2)

#-------------------------------------------------------------------------------------------------------
#CREATE CSE_EXT_16
add_struc(get_next_struc_idx(index_CSE_Ext_02_Mod), "CSE_Ext_16", 0)
index_CSE_Ext_16 = get_struc_id("CSE_Ext_16")

add_struc_member(index_CSE_Ext_16, "Tag",				0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_16, "Size",				0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_16, "PartitionName",		0X8,	0x5000c400,	 0,	4)
add_struc_member(index_CSE_Ext_16, "PartitionSize",		0XC,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_16, "PartitionVerMin",	0X10,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_16, "PartitionVerMaj",	0X12,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_16, "DataFormatMinor",	0X14,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_16, "DataFormatMajor",	0X16,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_16, "InstanceID",		0X18,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_16, "Flags",				0X1C,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_16, "HASHAlgorithm",		0X20,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_16, "HashSize",			0X21,	0x000400,	-1,	3)
add_struc_member(index_CSE_Ext_16, "Hash",				0X24,	0x20000400,	-1,	32)
add_struc_member(index_CSE_Ext_16, "FlagsPrivate",		0X44,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_16, "Reserved",			0X48,	0x20000400,	-1,	16)

#-------------------------------------------------------------------------------------------------------
#CREATE CSE_EXT_0F_Mod
add_struc(get_next_struc_idx(index_CSE_Ext_16), "CSE_Ext_0F_Mod", 0)
index_CSE_Ext_0F_Mod = get_struc_id("CSE_Ext_0F_Mod")

add_struc_member(index_CSE_Ext_0F_Mod, "Name",			0,		0x5000c400,	 0,	12)
add_struc_member(index_CSE_Ext_0F_Mod, "Type",			0XC,	0x600400,	-1,	1)
add_struc_member(index_CSE_Ext_0F_Mod, "HASHAlgorithm",	0XD,	0x600400,	-1,	1)
add_struc_member(index_CSE_Ext_0F_Mod, "HashSize",		0XE,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_0F_Mod, "MetadataSize",	0X10,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0F_Mod, "MetadataHash",	0X14,	0x20000400,	-1,	32)

#-------------------------------------------------------------------------------------------------------
#CREATE CSE_EXT_0E
add_struc(get_next_struc_idx(index_CSE_Ext_0F_Mod), "CSE_Ext_0E", 0)
index_CSE_Ext_0E = get_struc_id("CSE_Ext_0E")

add_struc_member(index_CSE_Ext_0E, "Tag",		0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0E, "Size",		0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0E, "KeyType",	0X8,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0E, "KeySVN",	0XC,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0E, "OEMID",		0X10,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_0E, "KeyID",		0X12,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0E, "Reserved0",	0X13,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0E, "Reserved1",	0X14,	0x20000400,	-1,	16)
	
#------------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_0E_Mod
add_struc(get_next_struc_idx(index_CSE_Ext_0E), "CSE_Ext_0E_Mod", 0)
index_CSE_Ext_0E_Mod = get_struc_id("CSE_Ext_0E_Mod")

add_struc_member(index_CSE_Ext_0E_Mod, "UsageBitmap",	0,		0x000400,	-1,	16)
add_struc_member(index_CSE_Ext_0E_Mod, "Reserved0",		0X10,	0x20000400,	-1,	16)
add_struc_member(index_CSE_Ext_0E_Mod, "Flags",			0X20,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0E_Mod, "HASHAlgorithm",	0X21,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0E_Mod, "HashSize",		0X22,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_0E_Mod, "Hash",			0X24,	0x20000400,	-1,	32)

#---------------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_0A
add_struc(get_next_struc_idx(index_CSE_Ext_0E_Mod), "CSE_Ext_0A", 0)
index_CSE_Ext_0A = get_struc_id("CSE_Ext_0A")

add_struc_member(index_CSE_Ext_0A, "Tag",			0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0A, "Size",			0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0A, "Compression",	0X8,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0A, "Encryption",	0X9,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0A, "Reserved0",		0XA,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0A, "Reserved1",		0XB,	0x000400,	-1,	1)
add_struc_member(index_CSE_Ext_0A, "SizeUncomp",	0XC,	0x20100400,	-1,	4)
add_struc_member(index_CSE_Ext_0A, "SizeComp",		0X10,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_0A, "DEV_ID",		0X14,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_0A, "VEN_ID",		0X16,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_0A, "Hash",			0X18,	0x20000400,	-1,	32)

#-----------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_05
add_struc(get_next_struc_idx(index_CSE_Ext_0A), "CSE_Ext_05", 0)
index_CSE_Ext_05 = get_struc_id("CSE_Ext_05")

add_struc_member(index_CSE_Ext_05, "Tag",				0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "Size",				0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "Flags",				0X8,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "MainThreadId",		0XC,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "CodeBaseAddress",	0X10,	0x20600400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "CodeSizeUncomp",	0X14,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "CM0HeapSize",		0X18,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "BSS_Size",			0X1C,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "DefualtHeapSize",	0X20,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "MainThreadEntry",	0X24,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "AllowedSysCalls",	0X28,	0x20000400,	-1,	12)
add_struc_member(index_CSE_Ext_05, "UserID",			0X34,	0x10000400,	-1,	2)
add_struc_member(index_CSE_Ext_05, "Reserved0",			0X36,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_05, "Reserved1",			0X3A,	0x10600400,	-1,	2)
add_struc_member(index_CSE_Ext_05, "Reserved2",			0X3C,	0x30000400,	-1,	8)

#---------------------------------------------------------------------------------------------------------------
#CREATE CSE_EXT_18
add_struc(get_next_struc_idx(index_CSE_Ext_05), "CSE_Ext_18", 0)
index_CSE_Ext_18 = get_struc_id("CSE_Ext_18")

add_struc_member(index_CSE_Ext_18, "Tag",		0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_18, "Size",		0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_18, "Reserved",	0X8,	0x20000400,	-1,	4)

#--------------------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_18_Mod
add_struc(get_next_struc_idx(index_CSE_Ext_18), "CSE_Ext_18_Mod", 0)
index_CSE_Ext_18_Mod = get_struc_id("CSE_Ext_18_Mod")

add_struc_member(index_CSE_Ext_18_Mod, "HashType",		0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_18_Mod, "HASHAlgorithm",	0X4,	0x20600400,	-1,	4)
add_struc_member(index_CSE_Ext_18_Mod, "HashSize",		0X8,	0x20600400,	-1,	4)
add_struc_member(index_CSE_Ext_18_Mod, "Hash",			0XC,	0x20000400,	-1,	32)

#-------------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_19
add_struc(get_next_struc_idx(index_CSE_Ext_18_Mod), "CSE_Ext_19", 0)
index_CSE_Ext_19 = get_struc_id("CSE_Ext_19")

add_struc_member(index_CSE_Ext_19, "Tag",		0,		0x20100400,	-1,	4)
add_struc_member(index_CSE_Ext_19, "Size",		0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_19, "Reserved",	0X8,	0x20000400,	-1,	4)

#------------------------------------------------------------------------------------------------------
#CREATE CSE_Ext_19_Mod
add_struc(get_next_struc_idx(index_CSE_Ext_19), "CSE_Ext_19_Mod", 0)
index_CSE_Ext_19_Mod = get_struc_id("CSE_Ext_19_Mod")

add_struc_member(index_CSE_Ext_19_Mod, "HashType",		0,		0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_19_Mod, "HASHAlgorithm",	0X4,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_19_Mod, "HashSize",		0X8,	0x20000400,	-1,	4)
add_struc_member(index_CSE_Ext_19_Mod, "Hash",			0XC,	0x20000400,	-1,	32)

print("----------------------WORK-------------------------------------------")
del_items(0, 0, get_segm_end(0))
create_struct(0x0, -1, get_struc_name(index_ME_Flash_Partiton_Table))

i = 1
ea = get_struc_size(index_ME_Flash_Partiton_Table)
partiotions = {}
while (True):
	if (get_wide_byte(ea) != 0xFF):
		create_struct(ea, -1, get_struc_name(index_ME_FPT_Entry))
		partiotion_name = get_string(ea, 4)
		partiotion_offset = get_wide_dword(ea + 0x8)
		partiotion_size = get_wide_dword(ea + 0xC)
		#print(partiotion_name, "Offset: ", hex(partiotion_offset), "Size: ", hex(partiotion_size))
		
		partiotion = {
			i: {
				"name": partiotion_name,
				"offset": int(hex(partiotion_offset), 16),
				"size": int(hex(partiotion_size), 16)
			}
		}
		partiotions.update(partiotion)
		ea += get_struc_size(index_ME_FPT_Entry)
		i += 1
		continue
	else:
		break

with open('partiotions.json', 'w') as f:
    json.dump(partiotions, f, sort_keys=True, indent=2)

add_hidden_range(ea, partiotions[1]['offset'], "Биты заполнения","", "", 1)
ea = partiotions[1]['offset']

i = 1
while (i <= len(partiotions)):
	if (partiotions[i]['offset'] != 0):																								#проверка (пустой ли раздел)
		ea = partiotions[i]['offset']																								#ea = адрес тукущего раздела в итерации цикла
		if (get_wide_byte(ea) == 0xFF):																								#если раздел целиком состит из FF, то делаем его hide
			add_hidden_range(ea, ea + partiotions[i]['size'], partiotions[i]['name'], "", "", 2)									#делааем hide такго раздела
			ea += partiotions[i]['size']																							#двигаем адрес (текщий адрес сохраняем в переменную)
			if (partiotions[i+1]['size'] == 0):																						#проверяем, пустой ли следующий раздел
				n = i + 1 																											#в цикле ищем раздел
				while (True):																										#который будем не пустым
					if (partiotions[n]['size'] != 0):
						break
					else:
						n += 1
				add_hidden_range(ea, partiotions[n]['offset'], "Биты заполнения", "", "", 1)
			else:
				add_hidden_range(ea, partiotions[i+1]['offset'], "Биты заполнения", "", "", 1)										#делвем битов заполнения
			#print(i, ' ', partiotions[i]['name'], ' - ', hex(ea))
			if (get_wide_byte(ea) == 0xFF):
				ea_edn = partiotions[i + 1]["offset"]
				add_hidden_range(ea, ea_edn, "Биты заполнения", "", "", 1)
		else:																														#если раздел состоит не из FF
			#print(i, ' ', partiotions[i]['name'], ' - ', hex(ea))
			if (get_wide_dword(partiotions[i]['offset']) == 0x44504324):															#проверяем наличие $CPD(тогда раздел с кодом)
				ea = partiotions[i]['offset']
				print("CPD - ", partiotions[i]['name'])
				path = partiotions[i]['name'] + '/'
				os.mkdir(path)																										#создаем папку с соответствующим разделом
				create_struct(partiotions[i]['offset'], -1, get_struc_name(index_ME_CPD_Header))									#размечаем в базе заголовок раздела с кодом
				ea += get_struc_size(index_ME_CPD_Header)
				n = 0
				CPD_Entries = {}																									#создаем словарь с данными об исполняемых модулей
				while (n < get_wide_dword(partiotions[i]['offset'] + 4)):															#цикл: пока количество модулей не будет равно как в заголовке
					create_struct(ea, -1, get_struc_name(index_ME_CPD_Entry))														#размечаем заголовок исполняемого модуля в цикле(0х18 * n)-для цикла
					CPD_Entry = {																									#0x18 - размер заголовка
						n + 1:{																										#созадаем соответствующий словарь
						'name': get_string(partiotions[i]['offset'] + 0x10 + (0x18 * n), 12),										#с данными об исполняемых модулях
						'offset': int(hex(get_wide_dword(partiotions[i]['offset'] + 28 + (0x18 * n) )).replace("20", ""), 16),
						'size': int(hex(get_wide_dword(partiotions[i]['offset'] + 32 + (0x18 * n))), 16)
						}
					}
					CPD_Entries.update(CPD_Entry)
					n += 1
					ea += get_struc_size(index_ME_CPD_Entry)
				create_struct(ea, -1, get_struc_name(index_ME_Manifest_Header))														#разметка заголовка манифеста в разделе с кодом
				ea += get_struc_size(index_ME_Manifest_Header)
				with open(path + partiotions[i]['name'] + ".json", 'w') as f:														#запись в json файл данных об исполняемых модулей раздела
					json.dump(CPD_Entries, f, sort_keys=True, indent=2)
				
				while (ea < partiotions[i]['offset'] + CPD_Entries[1]['offset'] + CPD_Entries[1]['size']):							#после того, как разметили заголовок манифеста, расмечаем др. структуры типа CSE_Ext_...
																																	#манифест не ограничивается заголовком манифеста
					if (get_wide_dword(ea) == 1):																					# если tag = 0x1(для FTRP) то размечаем CSE_Ext_01
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_01))
						n = 0
						ea += get_struc_size(index_CSE_Ext_01) 
						while (n < get_wide_dword(partiotions[i]['offset'] + CPD_Entries[1]['offset'] + 0x284 + 12)):				#после CSE_Ext_01 идет:
							create_strlit(ea, ea + 4)																				#1. Строка
							create_struct(ea + 4, -1, get_struc_name(index_ME_CPD_Entry))											#2. ME_CPD_Entry
							n += 1
							ea += 0x1c

					if (get_wide_dword(ea) == 0):																					#если tag = 0
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_00))														#Размечаем CSE_Ext_00
						ea += get_struc_size(index_CSE_Ext_00)
						ea_if = ea - get_struc_size(index_CSE_Ext_00) + get_wide_dword(ea - get_struc_size(index_CSE_Ext_00) + 4)
						while (ea < ea_if):																							#полсе идут несколь CSE_Ext_00_Mod
							create_struct(ea, -1, get_struc_name(index_CSE_Ext_00_Mod))												#Размечаем и их
							ea += get_struc_size(index_CSE_Ext_00_Mod)

					if (get_wide_dword(ea) == 0xC):																					#если tag = 0xC
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_0C))														#размечаем CSE_Ext_0C
						ea += get_struc_size(index_CSE_Ext_0C)

					if (get_wide_dword(ea) == 2):																					#если tag = 0x2
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_02))														#размечаем  CSE_Ext_02
						ea += get_struc_size(index_CSE_Ext_02)
						n = 1
						ea_if = get_wide_dword(ea - get_struc_size(index_CSE_Ext_02) + 8)
						while (n <= ea_if):																							#после CSE_Ext_02 идут несокльеко CSE_Ext_02_Mod
							create_struct(ea, -1, get_struc_name(index_CSE_Ext_02_Mod))												#размечаем их
							n += 1
							ea += get_struc_size(index_CSE_Ext_02_Mod)

					if (get_wide_byte(ea) == 0xF):																					#если tag = 0xF
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_0F))														#размечаем CSE_Ext_0F
						ea += get_struc_size(index_CSE_Ext_0F)
						if (get_wide_dword(ea) != 0x16):																			#в зависимости от размера, далее может идти 
							create_struct(ea, -1, get_struc_name(index_CSE_Ext_0F_Mod))												#CSE_Ext_0F_Mod
							ea += get_struc_size(index_CSE_Ext_0F_Mod)

					if (get_wide_dword(ea) == 0x16):																				#если tag = 0x16
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_16))														#размечаем CSE_Ext_16
						ea += get_struc_size(index_CSE_Ext_16)

				if (get_wide_byte(ea) == 0xFF):																						#деалем hide битов заполнения 
					add_hidden_range(ea, partiotions[i]['offset'] + CPD_Entries[2]['offset'], "Биты заполнения", "", "", 1)			#после манифеста
					ea = (partiotions[i]['offset'] + CPD_Entries[2]['offset'])

				if (get_wide_dword(ea + 0x1C) == 0x324E4D24):																		#разметка для заголовка манифеста
					create_struct(ea, -1, get_struc_name(index_ME_Manifest_Header))													#для раздела rot.key
					ea += get_struc_size(index_ME_Manifest_Header)

				while (True):
					if (get_wide_dword(ea) == 0xE):																					#размечаем структуры
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_0E))														#в зависимости от тега
						ea += get_struc_size(index_CSE_Ext_0E)
						ea_if = ea - get_struc_size(index_CSE_Ext_0E) +	get_wide_dword(ea - get_struc_size(index_CSE_Ext_0E) + 4)

						while(ea < ea_if):
							create_struct(ea, -1, get_struc_name(index_CSE_Ext_0E_Mod))
							ea += get_struc_size(index_CSE_Ext_0E_Mod)

					if (get_wide_byte(ea) == 0xA):
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_0A))
						ea += get_struc_size(index_CSE_Ext_0A)	

					if (get_wide_byte(ea) == 0x5):
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_05))
						ea += get_struc_size(index_CSE_Ext_05)

					if (get_wide_byte(ea) == 0x18):
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_18))
						ea += get_struc_size(index_CSE_Ext_18)
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_18_Mod))
						ea += get_struc_size(index_CSE_Ext_18_Mod)

					if (get_wide_byte(ea) == 0x19):
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_19))
						ea += get_struc_size(index_CSE_Ext_19)
						create_struct(ea, -1, get_struc_name(index_CSE_Ext_19_Mod))
						ea += get_struc_size(index_CSE_Ext_19_Mod)

					if (get_wide_byte(ea) == 0xFF):																					#делаем hide после метаданных
						ea_edn = ea 																								#битов заполнения
						while (True):
							if (get_wide_byte(ea_edn) == 0xFF):
								ea_edn += 1
							else:
								break
						add_hidden_range(ea, ea_edn, "Биты заполнения", "", "", 1)
						ea = ea_edn
					
					if (ea == partiotions[i]['offset'] + CPD_Entries[2]['offset']):
						break

					if (ea == partiotions[i]['offset'] + CPD_Entries[3]['offset']):
						break

				n = 2
				if (ea == partiotions[i]['offset'] + CPD_Entries[n]['offset']):														#hode исполняемых модулей
					ea_edn = partiotions[i]['offset'] + CPD_Entries[n + 1]['offset']												# разделе, где нет метаданных
					add_hidden_range(ea, ea_edn, CPD_Entries[n]['name'], "", "", 3)
				else:
					add_hidden_range(ea, ea_edn, CPD_Entries[n]['name'], "", "", 3)
						
					if (CPD_Entries[n + 1]['offset'] > CPD_Entries[n]['offset']):
						ea = partiotions[i]['offset'] + CPD_Entries[n + 1]['offset']
						n += 1
					else:
						ea_edn = ea
					#n += 1

				if (CPD_Entries[2]['offset'] > CPD_Entries[3]['offset']):
					ea_start = partiotions[i]['offset'] + CPD_Entries[2]['offset']
					add_hidden_range(ea_start, ea_start + CPD_Entries[2]['size'], CPD_Entries[2]['name'], "", "", 3)
					ea_start += CPD_Entries[2]['size']
					if (i == len(partiotions)):
						add_hidden_range(ea_start, get_segm_end(0), "Биты заполнения", "", "", 1)
					else:
						add_hidden_range(ea_start, partiotions[i + 1]['offset'], "Биты заполнения", "", "", 1)
					n = 3

				while (True):
					if (n < len(CPD_Entries)):
						ea_edn = partiotions[i]['offset'] + CPD_Entries[n + 1]['offset']
						add_hidden_range(ea, ea_edn, CPD_Entries[n]['name'], "", "", 3)
						ea = partiotions[i]['offset'] + CPD_Entries[n + 1]['offset']
						n += 1
					if (n == len(CPD_Entries)):
						if (i == len(partiotions)):
							ea = partiotions[i]['offset'] + CPD_Entries[len(CPD_Entries)]['offset']
							ea_edn = get_segm_end(0)
							add_hidden_range(ea, ea_edn, CPD_Entries[n]['name'], "", "", 3)
							break
						else:
							ea = partiotions[i]['offset'] + CPD_Entries[len(CPD_Entries)]['offset']
							if (partiotions[i+1]['size'] == 0):																								#проверяем, пустой ли следующий раздел
								a = i + 1 																													#в цикле ищем раздел
								while (True):																												#который будем не пустым
									if (partiotions[a]['size'] != 0):
										break
									else:
										a += 1
								ea_edn = partiotions[a]['offset']
								add_hidden_range(ea, ea_edn, CPD_Entries[n]['name'], "", "", 3)
								break
							else:
								ea_edn = partiotions[i + 1]['offset']
								add_hidden_range(ea, ea_edn, CPD_Entries[n]['name'], "", "", 3)
								break

				if (get_wide_byte(ea) == 0xFF):
					if (i < len(partiotions)):
						ea_edn = partiotions[i + 1]['offset']					
						add_hidden_range(ea, ea_edn, "Биты заполнения", "", "", 1)

			else:
				ea = partiotions[i]["offset"]
				add_hidden_range(ea, ea + partiotions[i]["size"], partiotions[i]['name'], "", "", 2)

				ea = partiotions[i]["size"] + partiotions[i]['offset']
				ea_edn = ea
				if (get_wide_byte(ea) == 0xFF):
					while (True):
						if (get_wide_byte(ea_edn) == 0xFF):
							ea_edn += 1
						else:
							break
					add_hidden_range(ea, ea_edn, "Биты заполнения", "", "", 1)

		i += 1
	else:
		i += 1

print("-------------------------ALL-------------------------------------------")