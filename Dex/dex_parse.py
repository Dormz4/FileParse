import binascii
import binhex
import struct
import traceback
import types
import sys
import os
import io
# from dex_repair import repair_dexfile_by_bin_file

debug_mode = True
need_repair_dexfile = 'H:\works\脱壳\com.mobileke.ep\\6401800_dexfile_execute.dex'
# need_repair_dexfile = 'H:\works\classes.dex'
repair_dexfile_bin = "H:\\works\\脱壳\\com.mobileke.ep\\6401800_ins_3228.bin"

enum_access_flag = {
    'ACC_PUBLIC'       : 0x00000001,       # class, field, method, ic
    'ACC_PRIVATE'      : 0x00000002,       # field, method, ic
    'ACC_PROTECTED'    : 0x00000004,       # field, method, ic
    'ACC_STATIC'       : 0x00000008,       # field, method, ic
    'ACC_FINAL'        : 0x00000010,       # class, field, method, ic
    'ACC_SYNCHRONIZED' : 0x00000020,       # method (only allowed on natives)
    'ACC_SUPER'        : 0x00000020,       # class (not used in Dalvik)
    'ACC_VOLATILE'     : 0x00000040,       # field
    'ACC_BRIDGE'       : 0x00000040,       # method (1.5)
    'ACC_TRANSIENT'    : 0x00000080,       # field
    'ACC_VARARGS'      : 0x00000080,       # method (1.5)
    'ACC_NATIVE'       : 0x00000100,       # method
    'ACC_INTERFACE'    : 0x00000200,       # class, ic
    'ACC_ABSTRACT'     : 0x00000400,       # class, method, ic
    'ACC_STRICT'       : 0x00000800,       # method
    'ACC_SYNTHETIC'    : 0x00001000,       # field, method, ic
    'ACC_ANNOTATION'   : 0x00002000,       # class, ic (1.5)
    'ACC_ENUM'         : 0x00004000,       # class, field, ic (1.5)
    'ACC_CONSTRUCTOR'  : 0x00010000,       # method (Dalvik only)
    'ACC_DECLARED_SYNCHRONIZED' :   0x00020000,       # method (Dalvik only)
    'ACC_CLASS_MASK' :  (0x00000001 | 0x00000010 | 0x00000200 | 0x00000400  | 0x00001000 | 0x00002000 | 0x00004000),
    'ACC_INNER_CLASS_MASK' : ((0x00000001 | 0x00000010 | 0x00000200 | 0x00000400  | 0x00001000 | 0x00002000 | 0x00004000) | 0x00000002 | 0x00000004 | 0x00000008),
    'ACC_FIELD_MASK' : (0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010  | 0x00000040 | 0x00000080 | 0x00001000 | 0x00004000),
    'ACC_METHOD_MASK' : (0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00000080 | 0x00000100
         | 0x00000400 | 0x00000800 | 0x00001000 | 0x00010000 | 0x00020000),
}

enum_annotation_constants = {
    'kDexVisibilityBuild'         : 0x00,     #annotation visibility
    'kDexVisibilityRuntime'       : 0x01,
    'kDexVisibilitySystem'        : 0x02,
    'kDexAnnotationByte'          : 0x00,
    'kDexAnnotationShort'         : 0x02,
    'kDexAnnotationChar'          : 0x03,
    'kDexAnnotationInt'           : 0x04,
    'kDexAnnotationLong'          : 0x06,
    'kDexAnnotationFloat'         : 0x10,
    'kDexAnnotationDouble'        : 0x11,
    'kDexAnnotationString'        : 0x17,
    'kDexAnnotationType'          : 0x18,
    'kDexAnnotationField'         : 0x19,
    'kDexAnnotationMethod'        : 0x1a,
    'kDexAnnotationEnum'          : 0x1b,
    'kDexAnnotationArray'         : 0x1c,
    'kDexAnnotationAnnotation'    : 0x1d,
    'kDexAnnotationNull'          : 0x1e,
    'kDexAnnotationBoolean'       : 0x1f,
    'kDexAnnotationValueTypeMask' : 0x1f,     # low 5 bits
    'kDexAnnotationValueArgShift' : 5,
}

enum_item_type_code = {
    'kDexTypeHeaderItem'               : 0x0000,
    'kDexTypeStringIdItem'             : 0x0001,
    'kDexTypeTypeIdItem'               : 0x0002,
    'kDexTypeProtoIdItem'              : 0x0003,
    'kDexTypeFieldIdItem'              : 0x0004,
    'kDexTypeMethodIdItem'             : 0x0005,
    'kDexTypeClassDefItem'             : 0x0006,
    'kDexTypeMapList'                  : 0x1000,
    'kDexTypeTypeList'                 : 0x1001,
    'kDexTypeAnnotationSetRefList'     : 0x1002,
    'kDexTypeAnnotationSetItem'        : 0x1003,
    'kDexTypeClassDataItem'            : 0x2000,
    'kDexTypeCodeItem'                 : 0x2001,
    'kDexTypeStringDataItem'           : 0x2002,
    'kDexTypeDebugInfoItem'            : 0x2003,
    'kDexTypeAnnotationItem'           : 0x2004,
    'kDexTypeEncodedArrayItem'         : 0x2005,
    'kDexTypeAnnotationsDirectoryItem' : 0x2006,
}

enum_auxllary_chuck_code = {
    'kDexChunkClassLookup'           : 0x434c4b50,   #CLKP
    'kDexChunkRegisterMaps'           : 0x524d4150,   #RMAP

    'kDexChunkEnd'                    : 0x41454e44,   #AEND
}

enum_debug_opcode_constant = {
    'DBG_END_SEQUENCE'         : 0x00,
    'DBG_ADVANCE_PC'           : 0x01,
    'DBG_ADVANCE_LINE'         : 0x02,
    'DBG_START_LOCAL'          : 0x03,
    'DBG_START_LOCAL_EXTENDED' : 0x04,
    'DBG_END_LOCAL'            : 0x05,
    'DBG_RESTART_LOCAL'        : 0x06,
    'DBG_SET_PROLOGUE_END'     : 0x07,
    'DBG_SET_EPILOGUE_BEGIN'   : 0x08,
    'DBG_SET_FILE'             : 0x09,
    'DBG_FIRST_SPECIAL'        : 0x0a,
    'DBG_LINE_BASE'            : -4,
    'DBG_LINE_RANGE'           : 15,
}


FMT10T = 0
FMT10X = 1
FMT11N = 2
FMT11X = 3
FMT12X = 4
FMT20T = 5
FMT21C = 6
FMT21H = 7
FMT21S = 8
FMT21T = 9
FMT22B = 10
FMT22C = 11
FMT22S = 12
FMT22T = 13
FMT22X = 14
FMT23X = 15
FMT30T = 16
FMT31C = 17
FMT31I = 18
FMT31T = 19
FMT32X = 20
FMT35C = 21
FMT3RC = 22
FMT51L = 23

'''
reference: 
    https://bathingfox.github.io/2018/11/29/Android%E5%8F%AF%E6%89%A7%E8%A1%8C%E6%96%87%E4%BB%B6%E5%88%86%E6%9E%90/
    https://bbs.pediy.com/thread-199176.htm
'''

'''
    dex_decode parse format:
        dex_code = {index:(type, code, format, number of 16bit-wide word)}
        such as 'fmt10x' means that:
            fmt10x:
                '1': The first number indicates how many 16-bit words the instruction has.
                '0': The second number is the maximum member of registers an instruction can use.
                'x': The third letter is the type code,which represents the type of additional data used by the instruction.
'''

dex_decode = {
    # id:(dalvik-bytecode id, dalvik-bytecode, dalvik-bytecode format, handle function, 16-bit occupied number)
    ## You can view the dalvik-bytecode format on https://source.android.com/devices/tech/dalvik/dalvik-bytecode,
    ## https://source.android.com/devices/tech/dalvik/instruction-formats

    # 好比说 12x格式的，说明指令流占了2个字节(1个word),然后低8位为opcode,高8位划分为两个4位，分别代入值进去位A B
    #

    0: (0x00, 'nop', 'fmt10x', FMT10X, 1),
    1: (0x01, 'move', 'fmt12x', FMT12X, 1),
    2: (0x02, 'move/from16', 'fmt22x', FMT22X, 2),
    3: (0x03, 'move/16', 'fmt32x', FMT32X, 3),
    4: (0x04, 'move-wide', 'fmt12x', FMT12X, 1),
    5: (0x05, 'move-wide/from16', 'fmt22x', FMT22X, 2),
    6: (0x06, 'move-wide/16', 'fmt32x', FMT32X, 3),
    7: (0x07, 'move-object', 'fmt12x', FMT12X, 1),
    8: (0x08, 'move-object/from16', 'fmt22x', FMT22X, 2),
    9: (0x09, 'move-object/16', 'fmt32x', FMT32X, 3),
    10: (0x0a, 'move-result', 'fmt11x', FMT11X, 1),
    11: (0x0b, 'move-result-wide', 'fmt11x', FMT11X, 1),
    12: (0x0c, 'move-result-object', 'fmt11x', FMT11X, 1),
    13: (0x0d, 'move-exception', 'fmt11x', FMT11X, 1),
    14: (0x0e, 'return-void', 'fmt10x', FMT10X, 1),
    15: (0x0f, 'return', 'fmt11x', FMT11X, 1),
    16: (0x10, 'return-wide', 'fmt11x', FMT11X, 1),
    17: (0x11, 'return-object', 'fmt11x', FMT11X, 1),
    18: (0x12, 'const/4', 'fmt11n', FMT11N, 1),
    19: (0x13, 'const/16', 'fmt21s', FMT21S, 2),
    20: (0x14, 'const', 'fmt31i', FMT31I, 3),
    21: (0x15, 'const/high16', 'fmt21h', FMT21H, 2),
    22: (0x16, 'const-wide/16', 'fmt21s', FMT21S, 2),
    23: (0x17, 'const-wide/32', 'fmt31i', FMT31I, 3),
    24: (0x18, 'const-wide', 'fmt51l', FMT51L, 5),
    25: (0x19, 'const-wide/high16', 'fmt21h', FMT21H, 2),
    26: (0x1a, 'const-string', 'fmt21c', FMT21C, 2),
    27: (0x1b, 'const-string/jumbo', 'fmt31c', FMT31C, 3),
    28: (0x1c, 'const-class', 'fmt21c', FMT21C, 2),
    29: (0x1d, 'monitor-enter', 'fmt11x', FMT11X, 1),
    30: (0x1e, 'monitor-exit', 'fmt11x', FMT11X, 1),
    31: (0x1f, 'check-cast', 'fmt21c', FMT21C, 2),
    32: (0x20, 'instance-of', 'fmt22c', FMT22C, 2),
    33: (0x21, 'array-length', 'fmt12x', FMT12X, 1),
    34: (0x22, 'new-instance', 'fmt21c', FMT21C, 2),
    35: (0x23, 'new-array', 'fmt22c', FMT22C, 2),
    36: (0x24, 'filled-new-array', 'fmt35c', FMT35C, 3),
    37: (0x25, 'filled-new-array/range', 'fmt3rc', FMT3RC, 3),
    38: (0x26, 'fill-array-data', 'fmt31t', FMT31T, 3),
    39: (0x27, 'throw', 'fmt11x', FMT11X, 1),
    40: (0x28, 'goto', 'fmt10t', FMT10T, 1),
    41: (0x29, 'goto/16', 'fmt20t', FMT20T, 2),
    42: (0x2a, 'goto/32', 'fmt30t', FMT30T, 3),
    43: (0x2b, 'packed-switch', 'fmt31t', FMT31T, 3),
    44: (0x2c, 'sparse-switch', 'fmt31t', FMT31T, 3),
    45: (0x2d, 'cmpl-float', 'fmt23x', FMT23X, 2),
    46: (0x2e, 'cmpg-float', 'fmt23x', FMT23X, 2),
    47: (0x2f, 'cmpl-double', 'fmt23x', FMT23X, 2),
    48: (0x30, 'cmpg-double', 'fmt23x', FMT23X, 2),
    49: (0x31, 'cmp-long', 'fmt23x', FMT23X, 2),
    50: (0x32, 'if-eq', 'fmt22t', FMT22T, 2),
    51: (0x33, 'if-ne', 'fmt22t', FMT22T, 2),
    52: (0x34, 'if-lt', 'fmt22t', FMT22T, 2),
    53: (0x35, 'if-ge', 'fmt22t', FMT22T, 2),
    54: (0x36, 'if-gt', 'fmt22t', FMT22T, 2),
    55: (0x37, 'if-le', 'fmt22t', FMT22T, 2),
    56: (0x38, 'if-eqz', 'fmt21t', FMT21T, 2),
    57: (0x39, 'if-nez', 'fmt21t', FMT21T, 2),
    58: (0x3a, 'if-ltz', 'fmt21t', FMT21T, 2),
    59: (0x3b, 'if-gez', 'fmt21t', FMT21T, 2),
    60: (0x3c, 'if-gtz', 'fmt21t', FMT21T, 2),
    61: (0x3d, 'if-lez', 'fmt21t', FMT21T, 2),
    62: (0x3e, 'unused', 'fmt10x', FMT10X, 1),
    63: (0x3f, 'unused', 'fmt10x', FMT10X, 1),
    64: (0x40, 'unused', 'fmt10x', FMT10X, 1),
    65: (0x41, 'unused', 'fmt10x', FMT10X, 1),
    66: (0x42, 'unused', 'fmt10x', FMT10X, 1),
    67: (0x43, 'unused', 'fmt10x', FMT10X, 1),
    68: (0x44, 'aget', 'fmt23x', FMT23X, 2),
    69: (0x45, 'aget-wide', 'fmt23x', FMT23X, 2),
    70: (0x46, 'aget-object', 'fmt23x', FMT23X, 2),
    71: (0x47, 'aget-boolean', 'fmt23x', FMT23X, 2),
    72: (0x48, 'aget-byte', 'fmt23x', FMT23X, 2),
    73: (0x49, 'aget-char', 'fmt23x', FMT23X, 2),
    74: (0x4a, 'aget-short', 'fmt23x', FMT23X, 2),
    75: (0x4b, 'aput', 'fmt23x', FMT23X, 2),
    76: (0x4c, 'aput-wide', 'fmt23x', FMT23X, 2),
    77: (0x4d, 'aput-object', 'fmt23x', FMT23X, 2),
    78: (0x4e, 'aput-boolean', 'fmt23x', FMT23X, 2),
    79: (0x4f, 'aput-byte', 'fmt23x', FMT23X, 2),
    80: (0x50, 'aput-shar', 'fmt23x', FMT23X, 2),
    81: (0x51, 'aput-short', 'fmt23x', FMT23X, 2),
    82: (0x52, 'iget', 'fmt22c', FMT22C, 2),
    83: (0x53, 'iget-wide', 'fmt22c', FMT22C, 2),
    84: (0x54, 'iget-object', 'fmt22c', FMT22C, 2),
    85: (0x55, 'iget-boolean', 'fmt22c', FMT22C, 2),
    86: (0x56, 'iget-byte', 'fmt22c', FMT22C, 2),
    87: (0x57, 'iget-char', 'fmt22c', FMT22C, 2),
    88: (0x58, 'iget-short', 'fmt22c', FMT22C, 2),
    89: (0x59, 'iput', 'fmt22c', FMT22C, 2),
    90: (0x5a, 'iput-wide', 'fmt22c', FMT22C, 2),
    91: (0x5b, 'iput-object', 'fmt22c', FMT22C, 2),
    92: (0x5c, 'iput-boolean', 'fmt22c', FMT22C, 2),
    93: (0x5d, 'iput-byte', 'fmt22c', FMT22C, 2),
    94: (0x5e, 'iput-char', 'fmt22c', FMT22C, 2),
    95: (0x5f, 'iput-short', 'fmt22c', FMT22C, 2),
    96: (0x60, 'sget', 'fmt21c', FMT21C, 2),
    97: (0x61, 'sget-wide', 'fmt21c', FMT21C, 2),
    98: (0x62, 'sget-object', 'fmt21c', FMT21C, 2),
    99: (0x63, 'sget-boolean', 'fmt21c', FMT21C, 2),
    100: (0x64, 'sget-byte', 'fmt21c', FMT21C, 2),
    101: (0x65, 'sget-char', 'fmt21c', FMT21C, 2),
    102: (0x66, 'sget-short', 'fmt21c', FMT21C, 2),
    103: (0x67, 'sput', 'fmt21c', FMT21C, 2),
    104: (0x68, 'sput-wide', 'fmt21c', FMT21C, 2),
    105: (0x69, 'sput-object', 'fmt21c', FMT21C, 2),
    106: (0x6a, 'sput-boolean', 'fmt21c', FMT21C, 2),
    107: (0x6b, 'sput-byte', 'fmt21c', FMT21C, 2),
    108: (0x6c, 'sput-char', 'fmt21c', FMT21C, 2),
    109: (0x6d, 'sput-short', 'fmt21c', FMT21C, 2),
    110: (0x6e, 'invoke-virtual', 'fmt35c', FMT35C, 3),
    111: (0x6f, 'invoke-super', 'fmt35c', FMT35C, 3),
    112: (0x70, 'invoke-direct', 'fmt35c', FMT35C, 3),
    113: (0x71, 'invoke-static', 'fmt35c', FMT35C, 3),
    114: (0x72, 'invoke-insterface', 'fmt35c', FMT35C, 3),
    115: (0x73, 'unused', 'fmt10x', FMT10X, 1),
    116: (0x74, 'invoke-virtual/range', 'fmt3rc', FMT3RC, 3),
    117: (0x75, 'invoke-super/range', 'fmt3rc', FMT3RC, 3),
    118: (0x76, 'invoke-direct/range', 'fmt3rc', FMT3RC, 3),
    119: (0x77, 'invoke-static/range', 'fmt3rc', FMT3RC, 3),
    120: (0x78, 'invoke-interface/range', 'fmt3rc', FMT3RC, 3),
    121: (0x79, 'unused', 'fmt10x', FMT10X, 1),
    122: (0x7a, 'unused', 'fmt10x', FMT10X, 1),
    123: (0x7b, 'neg-int', 'fmt12x', FMT12X, 1),
    124: (0x7c, 'not-int', 'fmt12x', FMT12X, 1),
    125: (0x7d, 'neg-long', 'fmt12x', FMT12X, 1),
    126: (0x7e, 'not-long', 'fmt12x', FMT12X, 1),
    127: (0x7f, 'neg-float', 'fmt12x', FMT12X, 1),
    128: (0x80, 'neg-double', 'fmt12x', FMT12X, 1),
    129: (0x81, 'int-to-long', 'fmt12x', FMT12X, 1),
    130: (0x82, 'int-to-float', 'fmt12x', FMT12X, 1),
    131: (0x83, 'int-to-double', 'fmt12x', FMT12X, 1),
    132: (0x84, 'long-to-int', 'fmt12x', FMT12X, 1),
    133: (0x85, 'long-to-float', 'fmt12x', FMT12X, 1),
    134: (0x86, 'long-to-double', 'fmt12x', FMT12X, 1),
    135: (0x87, 'float-to-int', 'fmt12x', FMT12X, 1),
    136: (0x88, 'float-to-long', 'fmt12x', FMT12X, 1),
    137: (0x89, 'float-to-double', 'fmt12x', FMT12X, 1),
    138: (0x8a, 'double-to-int', 'fmt12x', FMT12X, 1),
    139: (0x8b, 'double-to-long', 'fmt12x', FMT12X, 1),
    140: (0x8c, 'double-to-float', 'fmt12x', FMT12X, 1),
    141: (0x8d, 'int-to-byte', 'fmt12x', FMT12X, 1),
    142: (0x8e, 'int-to-char', 'fmt12x', FMT12X, 1),
    143: (0x8f, 'int-to-short', 'fmt12x', FMT12X, 1),
    144: (0x90, 'add-int', 'fmt23x', FMT23X, 2),
    145: (0x91, 'sub-int', 'fmt23x', FMT23X, 2),
    146: (0x92, 'mul-int', 'fmt23x', FMT23X, 2),
    147: (0x93, 'div-int', 'fmt23x', FMT23X, 2),
    148: (0x94, 'rem-int', 'fmt23x', FMT23X, 2),
    149: (0x95, 'and-int', 'fmt23x', FMT23X, 2),
    150: (0x96, 'or-int', 'fmt23x', FMT23X, 2),
    151: (0x97, 'xor-int', 'fmt23x', FMT23X, 2),
    152: (0x98, 'shl-int', 'fmt23x', FMT23X, 2),
    153: (0x99, 'shr-int', 'fmt23x', FMT23X, 2),
    154: (0x9a, 'ushr-int', 'fmt23x', FMT23X, 2),
    155: (0x9b, 'add-long', 'fmt23x', FMT23X, 2),
    156: (0x9c, 'sub-long', 'fmt23x', FMT23X, 2),
    157: (0x9d, 'mul-long', 'fmt23x', FMT23X, 2),
    158: (0x9e, 'div-long', 'fmt23x', FMT23X, 2),
    159: (0x9f, 'rem-long', 'fmt23x', FMT23X, 2),
    160: (0xa0, 'and-long', 'fmt23x', FMT23X, 2),
    161: (0xa1, 'or-long', 'fmt23x', FMT23X, 2),
    162: (0xa2, 'xor-long', 'fmt23x', FMT23X, 2),
    163: (0xa3, 'shl-long', 'fmt23x', FMT23X, 2),
    164: (0xa4, 'shr-long', 'fmt23x', FMT23X, 2),
    165: (0xa5, 'ushr-long', 'fmt23x', FMT23X, 2),
    166: (0xa6, 'add-float', 'fmt23x', FMT23X, 2),
    167: (0xa7, 'sub-float', 'fmt23x', FMT23X, 2),
    168: (0xa8, 'mul-float', 'fmt23x', FMT23X, 2),
    169: (0xa9, 'div-float', 'fmt23x', FMT23X, 2),
    170: (0xaa, 'rem-float', 'fmt23x', FMT23X, 2),
    171: (0xab, 'add-double', 'fmt23x', FMT23X, 2),
    172: (0xac, 'sub-double', 'fmt23x', FMT23X, 2),
    173: (0xad, 'mul-double', 'fmt23x', FMT23X, 2),
    174: (0xae, 'div-double', 'fmt23x', FMT23X, 2),
    175: (0xaf, 'rem-double', 'fmt23x', FMT23X, 2),
    176: (0xb0, 'add-int/2addr', 'fmt12x', FMT12X, 1),
    177: (0xb1, 'sub-int/2addr', 'fmt12x', FMT12X, 1),
    178: (0xb2, 'mul-int/2addr', 'fmt12x', FMT12X, 1),
    179: (0xb3, 'div-int/2addr', 'fmt12x', FMT12X, 1),
    180: (0xb4, 'rem-int/2addr', 'fmt12x', FMT12X, 1),
    181: (0xb5, 'and-int/2addr', 'fmt12x', FMT12X, 1),
    182: (0xb6, 'or-int/2addr', 'fmt12x', FMT12X, 1),
    183: (0xb7, 'xor-int/2addr', 'fmt12x', FMT12X, 1),
    184: (0xb8, 'shl-int/2addr', 'fmt12x', FMT12X, 1),
    185: (0xb9, 'shr-int/2addr', 'fmt12x', FMT12X, 1),
    186: (0xba, 'ushr-int/2addr', 'fmt12x', FMT12X, 1),
    187: (0xbb, 'add-long/2addr', 'fmt12x', FMT12X, 1),
    188: (0xbc, 'sub-long/2addr', 'fmt12x', FMT12X, 1),
    189: (0xbd, 'mul-long/2addr', 'fmt12x', FMT12X, 1),
    190: (0xbe, 'div-long/2addr', 'fmt12x', FMT12X, 1),
    191: (0xbf, 'rem-long/2addr', 'fmt12x', FMT12X, 1),
    192: (0xc0, 'and-long/2addr', 'fmt12x', FMT12X, 1),
    193: (0xc1, 'or-long/2addr', 'fmt12x', FMT12X, 1),
    194: (0xc2, 'xor-long/2addr', 'fmt12x', FMT12X, 1),
    195: (0xc3, 'shl-long/2addr', 'fmt12x', FMT12X, 1),
    196: (0xc4, 'shr-long/2addr', 'fmt12x', FMT12X, 1),
    197: (0xc5, 'ushr-long/2addr', 'fmt12x', FMT12X, 1),
    198: (0xc6, 'add-float/2addr', 'fmt12x', FMT12X, 1),
    199: (0xc7, 'sub-float/2addr', 'fmt12x', FMT12X, 1),
    200: (0xc8, 'mul-float/2addr', 'fmt12x', FMT12X, 1),
    201: (0xc9, 'div-float/2addr', 'fmt12x', FMT12X, 1),
    202: (0xca, 'rem-float/2addr', 'fmt12x', FMT12X, 1),
    203: (0xcb, 'add-double/2addr', 'fmt12x', FMT12X, 1),
    204: (0xcc, 'sub-double/2addr', 'fmt12x', FMT12X, 1),
    205: (0xcd, 'mul-double/2addr', 'fmt12x', FMT12X, 1),
    206: (0xce, 'div-double/2addr', 'fmt12x', FMT12X, 1),
    207: (0xcf, 'rem-double/2addr', 'fmt12x', FMT12X, 1),
    208: (0xd0, 'add-int/lit16', 'fmt22s', FMT22S, 2),
    209: (0xd1, 'rsub-int', 'fmt22s', FMT22S, 2),
    210: (0xd2, 'mul-int/lit16', 'fmt22s', FMT22S, 2),
    211: (0xd3, 'div-int/lit16', 'fmt22s', FMT22S, 2),
    212: (0xd4, 'rem-int/lit16', 'fmt22s', FMT22S, 2),
    213: (0xd5, 'and-int/lit16', 'fmt22s', FMT22S, 2),
    214: (0xd6, 'or-int/lit16', 'fmt22s', FMT22S, 2),
    215: (0xd7, 'xor-int/lit16', 'fmt22s', FMT22S, 2),
    216: (0xd8, 'add-int/lit8', 'fmt22b', FMT22B, 2),
    217: (0xd9, 'rsub-int/lit8', 'fmt22b', FMT22B, 2),
    218: (0xda, 'mul-int/lit8', 'fmt22b', FMT22B, 2),
    219: (0xdb, 'div-int/lit8', 'fmt22b', FMT22B, 2),
    220: (0xdc, 'rem-int/lit8', 'fmt22b', FMT22B, 2),
    221: (0xdd, 'and-int/lit8', 'fmt22b', FMT22B, 2),
    222: (0xde, 'or-int/lit8', 'fmt22b', FMT22B, 2),
    223: (0xdf, 'xor-int/lit8', 'fmt22b', FMT22B, 2),
    224: (0xe0, 'shl-int/lit8', 'fmt22b', FMT22B, 2),
    225: (0xe1, 'shr-int/lit8', 'fmt22b', FMT22B, 2),
    226: (0xe2, 'ushr-int/lit8', 'fmt22b', FMT22B, 2),
    227: (0xe3, 'unused', 'fmt10x', FMT10X, 1),
    228: (0xe4, 'unused', 'fmt10x', FMT10X, 1),
    229: (0xe5, 'unused', 'fmt10x', FMT10X, 1),
    230: (0xe6, 'unused', 'fmt10x', FMT10X, 1),
    231: (0xe7, 'unused', 'fmt10x', FMT10X, 1),
    232: (0xe8, 'unused', 'fmt10x', FMT10X, 1),
    233: (0xe9, 'unused', 'fmt10x', FMT10X, 1),
    234: (0xea, 'unused', 'fmt10x', FMT10X, 1),
    235: (0xeb, 'unused', 'fmt10x', FMT10X, 1),
    236: (0xec, 'unused', 'fmt10x', FMT10X, 1),
    237: (0xed, 'unused', 'fmt10x', FMT10X, 1),
    238: (0xee, 'unused', 'fmt10x', FMT10X, 1),
    239: (0xef, 'unused', 'fmt10x', FMT10X, 1),
    240: (0xf0, 'unused', 'fmt10x', FMT10X, 1),
    241: (0xf1, 'unused', 'fmt10x', FMT10X, 1),
    242: (0xf2, 'unused', 'fmt10x', FMT10X, 1),
    243: (0xf3, 'unused', 'fmt10x', FMT10X, 1),
    244: (0xf4, 'unused', 'fmt10x', FMT10X, 1),
    245: (0xf5, 'unused', 'fmt10x', FMT10X, 1),
    246: (0xf6, 'unused', 'fmt10x', FMT10X, 1),
    247: (0xf7, 'unused', 'fmt10x', FMT10X, 1),
    248: (0xf8, 'unused', 'fmt10x', FMT10X, 1),
    249: (0xf9, 'unused', 'fmt10x', FMT10X, 1),
    250: (0xfa, 'unused', 'fmt10x', FMT10X, 1),
    251: (0xfb, 'unused', 'fmt10x', FMT10X, 1),
    252: (0xfc, 'unused', 'fmt10x', FMT10X, 1),
    253: (0xfd, 'unused', 'fmt10x', FMT10X, 1),
    254: (0xfe, 'unused', 'fmt10x', FMT10X, 1),
    255: (0xff, 'unused', 'fmt10x', FMT10X, 1),
}

class MethodIdItem:
    class_idx=""
    proto_idx=""
    name_idx=""

    def __init__(self,class_idx,proto_idx,name_idx):
        self.class_idx = class_idx
        self.proto_idx = proto_idx
        self.name_idx = name_idx

class ClassDefItem:
    class_idx=""
    access_flags=""
    superclass_idx=""
    interfaces_off=""
    source_file_idx=""
    annotations_off=""
    class_data_off=""
    static_values_off=""

    def __init__(self,class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off):
        self.class_idx=class_idx
        self.access_flags=access_flags
        self.superclass_idx=superclass_idx
        self.interfaces_off=interfaces_off
        self.source_file_idx=source_file_idx
        self.annotations_off=annotations_off
        self.class_data_off=class_data_off
        self.static_values_off=static_values_off


def parse_encoded_annotation(dex_object, content, is_root=False):
    offset = 0
    n, type_idx = get_uleb128(content[offset:5 + offset])
    offset += n
    n, size = get_uleb128(content[offset:5 + offset])
    offset += n
    if is_root:
        print(dex_object.get_type_name_by_id(type_idx), end=' ')
    for i in range(0, size):
        n, name_idx = get_uleb128(content[offset:5 + offset])
        if i == 0 and is_root:
            print(dex_object.get_string_by_id(name_idx), end=' ')
        offset += n
        offset += parse_encoded_value(dex_object, content[offset:], is_root)
    return offset


def parse_encoded_value(dex_object, content, is_root=False):
    offset = 0
    arg_type, = struct.unpack_from("B", content, offset)
    offset += struct.calcsize("B")
    value_arg = arg_type >> 5
    value_type = arg_type & 0x1f
    if value_type in [0x2, 3, 4, 6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        sum = 0
        for q in range(0, value_arg + 1):
            mm = ord(chr(content[offset + q]))
            mm <<= 8 * q
            sum |= mm
        # sum += ord(content[offset+q])
        if value_type == 0x17:
            print("string@%d" % sum, end=' ')
            print(dex_object.get_string_by_id(sum), end=' ')
        elif value_type == 0x18:
            print("type@%d" % sum, end=' ')
            print(dex_object.get_type_name(sum), end=' ')
        elif value_type == 0x19:
            print("field@%d" % sum, end=' ')
            print(dex_object.get_field_name(sum), end=' ')
        elif value_type == 0x1a:
            print("method@%d" % sum, end=' ')
            print(dex_object.get_method_name(sum), end=' ')
        else:
            str = ""
            for q in range(0, value_arg + 1):
                str += "%02x " % (ord(chr(content[offset + q])))
            print(str, end=' ')
        offset += (value_arg + 1)
    elif value_type == 0:
        print("%02x" % ord(chr(content[offset])), end=' ')
        offset += 1

    elif value_type == 0x1e:
        print("NULL", end=' ')
    elif value_type == 0x1f:
        if value_arg == 0:
            print("False", end=' ')
        else:
            print("True", end=' ')
        offset += 0
    elif value_type == 0x1d:
        offset += parse_encoded_annotation(dex_object, content[offset:])
    elif value_type == 0x1c:
        m, asize = get_uleb128(content[offset:5])
        offset += m
        print("[%d]" % asize, end=' ')
        for q in range(0, asize):
            offset += parse_encoded_value(dex_object, content[offset:], False)
    else:
        print("\n***************error parse encode_value**************")
    return offset


def get_encoded_annotation_size(content):
    offset = 0
    n, type_idx = get_uleb128(content[offset:5 + offset])
    offset += n
    n, size = get_uleb128(content[offset:5 + offset])
    offset += n
    for i in range(0, n):
        n, name_idx = get_uleb128(content[offset:5 + offset])
        offset += n
        offset += get_encoded_value_size(content[offset:])
    return offset


def get_encoded_value_size(content):
    offset = 0
    arg_type, = struct.unpack_from("B", content, offset)
    offset += struct.calcsize("B")
    value_arg = arg_type >> 5
    value_type = arg_type & 0x1f
    if value_type in [0x2, 3, 4, 6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        offset += (value_arg + 1)
    elif value_type == 0:
        offset += 1
    elif value_type == 0x1e or value_type == 0x1f:
        offset += 0
    elif value_type == 0x1d:
        offset += get_encoded_annotation_size(content[offset:])
    elif value_type == 0x1c:
        m, asize = get_uleb128(m_file_content[offset:offset + 5])
        offset += m
        for q in range(0, asize):
            offset += get_encoded_value_size(content[offset:])
    else:
        print("***************error parse encode_value**************")
    return offset


def get_static_offset(content, index):
    offset = 0
    m, size = get_uleb128(content[offset:offset + 5])
    if index >= size:
        return -1
    offset += m
    for i in range(0, index):
        offset += get_encoded_value_size(content[offset:])
    return offset


def shorty_decode(name):
    val = {"V": "void",
           "Z": "boolean",
           "B": "byte",
           "S": "short",
           "C": "char",
           "I": "int",
           "J": "long",
           "F": "float",
           "D": "double",
           "L": "L"
           }
    value = ""

    if name[-1] == ';':
        if name[0] == 'L':
            return name[1:-1].replace("/", ".")
        if name[0] == '[':
            if name[1] == 'L':
                return name[2:-1].replace("/", ".") + "[]"
            else:
                return name[1:-1].replace("/", ".") + "[]"
    i = 0
    for ch in name:
        if ch in val:
            if i != 0:
                value += " | "
            value += val[ch]
            i += 1
    if b'[' in name:
        # if name.find(b'[')>0:
        value += "[]"
    return value


def get_uleb128p1(content):
    n, value = get_uleb128(content)
    value -= 1
    return n, value


def get_uleb128(content):
    value = 0
    for i in range(0, 5):
        # print(content[i])
        tmp = ord(chr(content[i])) & 0x7f
        value = tmp << (i * 7) | value
        if (ord(chr(content[i])) & 0x80) != 0x80:
            break
    if i == 4 and (tmp & 0xf0) != 0:
        print("parse a error uleb128 number")
        return -1
    return i + 1, value


def get_leb128(content):
    value = 0

    mask = [0xffffff80, 0xffffc000, 0xffe00000, 0xf0000000, 0]
    bitmask = [0x40, 0x40, 0x40, 0x40, 0x8]
    value = 0
    for i in range(0, 5):
        tmp = ord(chr(content[i])) & 0x7f
        value = tmp << (i * 7) | value
        if (ord(chr(content[i])) & 0x80) != 0x80:
            if bitmask[i] & tmp:
                value |= mask[i]
            break
    if i == 4 and (tmp & 0xf0) != 0:
        print("parse a error uleb128 number")
        return -1
    buffer = struct.pack("I", value)
    value, = struct.unpack("i", buffer)
    return i + 1, value


class DexClass:
    '''
         The 'class_def' item has eights fields:

         struct class_def{
             uint class_idx;
             uint access_flags;
             uint superclass_idx;
             uint interfaces_off;       // index to struct type_item_list
             uint source_file_idx;
             uint annotations_off;      // index to struct annotations_directory_item
             uint class_data_off;       // index to struct class_data_item ★☆★☆★☆  Very Important!!!!!!!
                                        // Master it and you can bypass virtual protection and class method extraction shell.
             uint static_values_off;
         }
         -------------------------------------------------------------------------
            About interface type
        struct type_item_list{
            uint size;
            struct type_item;   // index to type_item
        }
        struct type_item{
            ushort type_idx;
        }
         -------------------------------------------------------------------------

            About annotations.
        struct annotations_directory_item{
            uint class_annotations_off;
            struct annotation_set_item annotations;     // index
            uint filed_size;
            uint method_size;
            uint parameters_size;
        }
        struct annotation_set_item{
            uint size;
            struct annotation_off_item entries;
            struct annotation_off_item entries;
        }
        struct annotation_off_item{
            uint annotation_off;
            struct annotation_item item;
        }
        struct annotation_item{
           enum VISIBILITY viaibility;
           struct encoded_annotation annotation;
        }
        struct encoded_annotation{
            struct uleb128 type_idx;
            struct uleb128 size;
            struct annotation_element elements;
        }
        struct annotation_element{
            struct uleb128 name_idx;
            struct encoded_value value;
        }
    
        struct encoded_value{
            union VALUE{
                enum value_type;
                ubyte vaule_arg;
            }
            struct encoded_annotaion annotation;
        } 
         -------------------------------------------------------------------------

             About class
        struct class_data_item{
            struct uleb128 static_fields_size;
            struct uleb128 instance_fields_size;
            struct uleb128 direct_methods_size;
            struct uleb128 virtual_methods_size;
            struct encoded_method_list virtual_methods;
        }

        struct encoded_method_list{
            struct encoded_method method1;
            struct encoded_method method2;
        }
        
        struct encoded_method{
            struct uleb128 method;
            struct uleb128 access_flags;
            struct uleb128 code_off;
            struct code_item code ;         //This is very important !!!
        }

        ★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆
        struct code_item{
            ushrot register_size;
            ushrot ins_size;
            ushrot outs_size;
            ushrot tries_size;
            uint debug_info_item debug_info;   //index to struct debug_info_item.
            uint insns_size;
            ushrot insns[insns_size];          //The methods opcode!!!
        }
        ★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆

        struct debug_info_item{
            struct uleb128 line_start;
            struct uleb128 parameters_size;
            struct debug_opcode opcode;         //But how to determine the size????
        }

        struct debug_opcode{
            enum DBG_OPCODE opcode;
        }


         -------------------------------------------------------------------------

    '''

    def __init__(self, dex_object, classid,need_detail=True):
        # Now start to parse the 'class_def' item
        if classid >= dex_object.m_dex_header['m_classDefSize']:
            return ""
        offset = dex_object.m_dex_header['m_classDefOffset'] + classid * struct.calcsize("8I")
        self.offset = offset
        format = "I"
        self.class_idx, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        # Such as Public 0x1 Private Protected
        self.access_flags, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.super_class_idx, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.interfaces_off, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.source_file_idx, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.annotations_off, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.class_data_off, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.static_value_off, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)

        self.index = classid
        self.interfaces_size = 0
        if self.interfaces_off != 0:
            self.interfaces_size, = struct.unpack_from("I", dex_object.m_file_content, self.interfaces_off)
        if self.class_data_off != 0:
            offset = self.class_data_off
            count, self.num_static_fields = get_uleb128(dex_object.m_file_content[offset:])
            offset += count
            count, self.num_instance_fields = get_uleb128(dex_object.m_file_content[offset:])
            offset += count
            count, self.num_direct_methods = get_uleb128(dex_object.m_file_content[offset:])
            offset += count
            count, self.num_virtual_methods = get_uleb128(dex_object.m_file_content[offset:])
        else:
            self.num_static_fields = 0
            self.num_instance_fields = 0
            self.num_direct_methods = 0
            self.num_virtual_methods = 0
        a = 1

        self.class_static_fields_list = [];
        self.class_instance_fields_list = [];
        self.class_interfaces_list = [];
        self.class_direct_methods_list = [];
        self.class_virtual_methods_list = [];

        self.class_direct_methods_name_list   = [];
        self.class_virtual_methods_name_list = [];


        # Parse this class for fields,methods
        if need_detail:
            self.parse_dex_class(dex_object)
        else:
            self.parse_dex_class2(dex_object)
        a = 1

    def parse_dex_class(self, dex_object):
        offset = self.interfaces_off + struct.calcsize("I")
        for n in range(0, self.interfaces_size):
            typeid, = struct.unpack_from("H", dex_object.m_file_content, offset)
            offset += struct.calcsize("H")
            self.class_interfaces_list.append(dex_object.get_type_name(typeid).decode())
        offset = self.class_data_off;
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        field_idx = 0

        print("Parsing the class static field...");
        for i in range(0, self.num_static_fields):
            n, field_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            self.class_static_fields_list.append(dex_object.get_field_full_name(field_idx))
            # print("Static field:",dex_object.get_field_full_name(field_idx), end=' ')
            n, modifiers = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            if self.static_value_off:
                staticoffset = get_static_offset(dex_object.m_file_content[self.static_value_off:], i)
                if staticoffset == -1:
                    # print("0;")
                    continue
                parse_encoded_value(dex_object, dex_object.m_file_content[self.static_value_off + staticoffset:])
            # print("")

        print("Parsing the class instance field...");
        field_idx = 0
        for i in range(0, self.num_instance_fields):
            n, field_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            self.class_instance_fields_list.append(dex_object.get_field_full_name(field_idx))
            # print("Instance filed:",dex_object.get_field_full_name(field_idx))
            n, modifiers = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n

        print("Parsing the class direct method...");
        method_idx = 0
        for i in range(0, self.num_direct_methods):
            n, method_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, access_flags = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, code_off = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            method_idx += method_idx_diff
            # print(dex_object.get_method_full_name(method_idx, True))
            # print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
            if code_off != 0:
                # parse the method and instruction...
                method_obj = MethodCode(dex_object, code_off,self.class_idx,self.index)
                method_obj.set_method_attr(True,i);
                method_obj.printf(dex_object,'\t\t');

        print("Parsing the class virtual method...");
        method_idx = 0
        for i in range(0, self.num_virtual_methods):
            n, method_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, access_flags = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, code_off = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            method_idx += method_idx_diff
            print(dex_object.get_method_full_name(method_idx, True))
            # print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
            if code_off != 0:
                MethodCode(dex_object, code_off).printf(dex_object, "\t\t")

    def parse_dex_class2(self, dex_object):
        offset = self.interfaces_off + struct.calcsize("I")
        for n in range(0, self.interfaces_size):
            typeid, = struct.unpack_from("H", dex_object.m_file_content, offset)
            offset += struct.calcsize("H")
            self.class_interfaces_list.append(dex_object.get_type_name(typeid).decode())
        offset = self.class_data_off;
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        field_idx = 0

        for i in range(0, self.num_static_fields):
            n, field_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            self.class_static_fields_list.append(dex_object.get_field_full_name(field_idx))
            # print("Static field:",dex_object.get_field_full_name(field_idx), end=' ')
            n, modifiers = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            if self.static_value_off:
                staticoffset = get_static_offset(dex_object.m_file_content[self.static_value_off:], i)
                if staticoffset == -1:
                    # print("0;")
                    continue
                # parse_encoded_value(dex_object, dex_object.m_file_content[self.static_value_off + staticoffset:])
            # print("")

        field_idx = 0
        for i in range(0, self.num_instance_fields):
            n, field_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            self.class_instance_fields_list.append(dex_object.get_field_full_name(field_idx))
            # print("Instance filed:",dex_object.get_field_full_name(field_idx))
            n, modifiers = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n

        method_idx = 0
        for i in range(0, self.num_direct_methods):
            n, method_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, access_flags = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, code_off = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            method_idx += method_idx_diff
            # print(dex_object.get_method_full_name(method_idx, True))
            # print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
            if code_off != 0:
                # parse the method and instruction...
                method_obj = MethodCode(dex_object, code_off,self.class_idx,self.index)
                method_obj.set_method_attr(True,i);
                # method_obj.printf(dex_object,'\t\t');

        method_idx = 0
        for i in range(0, self.num_virtual_methods):
            n, method_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, access_flags = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            n, code_off = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            method_idx += method_idx_diff
            # print(dex_object.get_method_full_name(method_idx, True))
            # print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
            if code_off != 0:
                # MethodCode(dex_object, code_off).printf(dex_object, "\t\t")
                MethodCode(dex_object, code_off)


    def printf(self, dex_object):
        print("%-20s:%08x:%10d  %s" % (
            "thisClass", self.class_idx, self.class_idx, dex_object.get_type_name(self.class_idx)))
        print("%-20s:%08x:%10d  %s" % (
            "superClass", self.super_class_idx, self.super_class_idx, dex_object.get_type_name(self.super_class_idx)))
        print("%-20s:%08x:%10d" % ("modifiers", self.access_flags, self.access_flags))
        print("%-20s:%08x:%10d" % ("offset", self.offset, self.offset))
        print("%-20s:%08x:%10d" % ("annotationsOff", self.annotations_off, self.annotations_off))
        print("%-20s:%08x:%10d" % ("numStaticFields", self.num_static_fields, self.num_static_fields))
        print("%-20s:%08x:%10d" % ("numInstanceFields", self.num_instance_fields, self.num_instance_fields))
        print("%-20s:%08x:%10d" % ("numDirectMethods", self.num_direct_methods, self.num_direct_methods))
        print("%-20s:%08x:%10d" % ("numVirtualMethods", self.num_virtual_methods, self.num_virtual_methods))
        print("%-20s:%08x:%10d" % ("classDataOff", self.class_data_off, self.class_data_off))
        print("%-20s:%08x:%10d" % ("interfacesOff", self.interfaces_off, self.interfaces_off))
        print("%-20s:%08x:%10d" % ("interfacesSize", self.interfaces_size, self.interfaces_size))
        offset = self.interfaces_off + struct.calcsize("I")
        for n in range(0, self.interfaces_size):
            typeid, = struct.unpack_from("H", dex_object.m_file_content, offset)
            offset += struct.calcsize("H")
            print("\t\t" + dex_object.get_type_name(typeid).decode())

        print("%-20s:%08x:%10d" % ("staticValuesOff", self.static_value_off, self.static_value_off))
        print("%-20s:%08x:%10d  %s" % (
            "sourceFileIdx", self.source_file_idx, self.source_file_idx,
            dex_object.get_string_by_id(self.source_file_idx)))

        # For index to the class_data_item
        ## class_data_item = class_data_off +0x4
        offset = self.class_data_off;
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n



        field_idx = 0
        if self.num_static_fields > 0:
            print("static fields:")
        for i in range(0, self.num_static_fields):
            n, field_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            print("Static field:", dex_object.get_field_full_name(field_idx), end=' ')
            n, modifiers = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            if self.static_value_off:
                staticoffset = get_static_offset(dex_object.m_file_content[self.static_value_off:], i)
                if staticoffset == -1:
                    print("0;")
                    continue
                parse_encoded_value(dex_object, dex_object.m_file_content[self.static_value_off + staticoffset:])
            print("")
        a = 2
        field_idx = 0
        for i in range(0, self.num_instance_fields):
            n, field_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            print("Instance filed:", dex_object.get_field_full_name(field_idx))
            n, modifiers = get_uleb128(dex_object.m_file_content[offset:offset + 5])
            offset += n

        # print("=========numDirectMethods[%d]=numVirtualMethods[%d]=numStaticMethods[0]=========" % (
        #     self.num_direct_methods, self.num_virtual_methods))
        # method_idx = 0
        # for i in range(0, self.num_direct_methods):
        #     n, method_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        #     offset += n
        #     n, access_flags = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        #     offset += n
        #     n, code_off = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        #     offset += n
        #     method_idx += method_idx_diff
        #     print(dex_object.get_method_full_name(method_idx, True))
        #     # print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
        #     if code_off != 0:
        #         # parse the method and instruction...
        #         MethodCode(dex_object, code_off).printf(dex_object, "\t\t")
        # method_idx = 0
        # for i in range(0, self.num_virtual_methods):
        #     n, method_idx_diff = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        #     offset += n
        #     n, access_flags = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        #     offset += n
        #     n, code_off = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        #     offset += n
        #     method_idx += method_idx_diff
        #     print(dex_object.get_method_full_name(method_idx, True))
        #     # print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
        #     if code_off != 0:
        #         MethodCode(dex_object, code_off).printf(dex_object, "\t\t")
        # print("================================================================================")

        if self.annotations_off != 0:
            offset = self.annotations_off
            self.class_annotations_off,self.fields_size,self.annotated_methods_size,self.annotated_parameters_size,=struct.unpack_from("4I",dex_object.m_file_content,offset)
            #print "%-30s:%08x:%09d"%("class_annotations_off",self.class_annotations_off,self.class_annotations_off)
            #print "%-30s:%08x:%09d"%("fields_size",self.fields_size,self.fields_size)
            #print "%-30s:%08x:%09d"%("annotated_methods_size",self.annotated_methods_size,self.annotated_methods_size)
            #print "%-30s:%08x:%09d"%("annotated_parameters_size",self.annotated_parameters_size,self.annotated_parameters_size)
            offset =  self.annotations_off + struct.calcsize("4I")

            if self.fields_size:
                for  i in range(0,self.fields_size):
                    field_idx,annotations_off,=struct.unpack_from("2I",dex_object.m_file_content,offset)
                    offset += struct.calcsize("2I")
                    print(dex_object.get_field_name(field_idx), end=' ')
                    self.parse_annotation_set_item(dex_object,annotations_off)

            if self.annotated_methods_size:
                print("=====annotated_methods_size=====    offset=[%x]===="%offset)
                for  i in range(0,self.annotated_methods_size):
                    method_idx,annotations_off,=struct.unpack_from("2I",dex_object.m_file_content,offset)
                    offset += struct.calcsize("2I")
                    print(dex_object.get_method_name(method_idx), end=' ')
                    self.parse_annotation_set_item(dex_object,annotations_off)
            if self.annotated_parameters_size:
                for  i in range(0,self.annotated_parameters_size):
                    method_idx,annotations_off,=struct.unpack_from("2I",dex_object.m_file_content,offset)
                    offset+=struct.calcsize("2I")
                    print(dex_object.get_method_name(method_idx), end=' ')
                    self.parse_annotation_set_ref_list(dex_object,annotations_off)
            if self.class_annotations_off == 0:
                return
            print("self.class_annotations_off = %x"%self.class_annotations_off)
            self.parse_annotation_set_item(dex_object,self.class_annotations_off)

    def parse_annotation_set_ref_list(self,lex_object,offset,is_root=False):
        size, = struct.unpack_from("I",lex_object.m_file_content,offset)
        offset += struct.calcsize("I")
        for i in range(0,size):
            off,=struct.unpack_from("I",lex_object.m_file_content,offset)
            self.parse_annotation_set_item(lex_object,off,True)
            offset += struct.calcsize("I")


    def parse_annotation_set_item(self,lex_object,offset,is_root=False):
        try:
            size, = struct.unpack_from("I",lex_object.m_file_content,offset)
            offset += struct.calcsize("I")
            for i in range(0,size):
                off,=struct.unpack_from("I",lex_object.m_file_content,offset)
                visibility, = struct.unpack_from("B",lex_object.m_file_content,off)
                if visibility == 0:
                    print("VISIBILITY_BUILD", end=' ')
                elif visibility == 1:
                    print("VISIBILITY_RUNTIME", end=' ')
                elif visibility == 2:
                    print("VISIBILITY_SYSTEM", end=' ')
                else:
                    print("visibility is unknow %02x"%visibility)
                off += struct.calcsize("B")
                parse_encoded_annotation(lex_object,lex_object.m_file_content[off:],True)
                offset += struct.calcsize("I")
                print("")
        except Exception as e:
            print(e)
            pass

class MethodCode:
    # ----------------------------------- Prase dalvik-bytecode api -----------------------------------------
    # legal
    def parse_FMT10X(buffer, dex_object, pc_point, offset):
        # buffer[0] --> X|X|op  Eight bits below the dalvik-bytecode is the opcode
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1])

    # legal
    def parse_FMT10T(buffer, dex_object, pc_point, offset):
        val, = struct.unpack_from("b", buffer, 1)
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "%04x" % (int(val + offset)))

    def parse_FMT11N(buffer, dex_object, pc_point, offset):
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % (ord(chr(buffer[1])) & 0xf),
            "%d" % ((ord(chr(buffer[1])) >> 4) & 0xf))

    #legal
    def parse_FMT11X(buffer, dex_object, pc_point, offset):
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])))

    def parse_FMT12X(buffer, dex_object, pc_point, offset):
        # if len(buffer)==1:
        #    return dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1];
        # else:
        #     return (
        #         dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1],
        #         "v%d" % (ord(chr(buffer[1])) & 0x0f),
        #         "v%d" % ((ord(chr(buffer[1])) >> 4) & 0xf));
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1],
            "v%d" % (ord(chr(buffer[1])) & 0x0f),
            "v%d" % ((ord(chr(buffer[1])) >> 4) & 0xf));

    def parse_FMT20T(buffer, dex_object, pc_point, offset):
        v, = struct.unpack_from("h", buffer, 2)
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "%04x" % (int(v + offset)))

    def parse_FMT21C(buffer, dex_object, pc_point, offset):
        val = ord(chr(buffer[0]))
        if len(buffer)>3:
            v, = struct.unpack_from("H", buffer, 2)
        else:
            v, = struct.unpack_from('B',buffer)
        arg1 = "@%d" % v
        if val == 0x1a:
            arg1 = "\"%s\"" % dex_object.get_string_by_id(v)
        elif val in [0x1c, 0x1f, 0x22]:
            arg1 = "type@%s" % dex_object.get_type_name(v)
        else:
            arg1 = "field@%s  //%s" % (dex_object.get_field_name(v), dex_object.get_field_full_name(v))
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])), arg1)

    def parse_FMT21H(buffer, dex_object, pc_point, offset):
        v, = struct.unpack_from("H", buffer, 2)
        if ord(chr(buffer[1])) == 0x19:
            arg1 = "@%d000000000000" % v
        else:
            arg1 = "@%d0000" % v
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])), arg1)

    def parse_FMT21S(buffer, dex_object, pc_point, offset):
        v, = struct.unpack_from("H", buffer, 2)
        arg1 = "%d" % v
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])), arg1)

    def parse_FMT21T(buffer, dex_object, pc_point, offset):
        v, = struct.unpack_from("h", buffer, 2)
        arg1 = "%04x" % (int(v + offset))
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])), arg1)

    def parse_FMT22B(buffer, dex_object, pc_point, offset):
        cc, bb, = struct.unpack_from("Bb", buffer, 2)
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])),
            "v%d" % bb,
            "%d" % cc)

    def parse_FMT22C(buffer, dex_object, pc_point, offset):
        cccc, = struct.unpack_from("H", buffer, 2)
        if ord(chr(buffer[0])) == 0x20 or ord(chr(buffer[0])) == 0x23:
            prefix = "type@%s" % (dex_object.get_type_name(cccc))
        else:
            prefix = "field@%s  //%s" % (dex_object.get_field_name(cccc), dex_object.get_field_full_name(cccc))

        bb = ord(chr(buffer[1])) >> 4
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % (ord(chr(buffer[1])) & 0xf),
            "v%d" % ((ord(chr(buffer[1])) >> 4) & 0xf), "%s" % prefix)

    def parse_FMT22S(buffer, dex_object, pc_point, offset):
        bb = ord(chr(buffer[1])) >> 4
        cccc, = struct.unpack_from("h", buffer, 2)
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % (ord(chr(buffer[1])) & 0xf),
            "v%d" % ((ord(chr(buffer[1])) >> 4) & 0xf), "%d" % cccc)

    def parse_FMT22T(buffer, dex_object, pc_point, offset):
        bb = ord(chr(buffer[1])) >> 4
        cccc, = struct.unpack_from("h", buffer, 2)

        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % (ord(chr(buffer[1])) & 0xf),
            "v%d" % ((ord(chr(buffer[1])) >> 4) & 0xf), "%04x" % (int(cccc + offset)))

    def parse_FMT22X(buffer, dex_object, pc_point, offset):
        '''
            '2': The first number indicates how many 16-bit words the instruction has.
            '2': The second number is the maximum member of registers an instruction can use.
            'x': The third letter is the type code,which represents the type of additional data used by the instruction.
        '''
        try:
            if len(buffer) < 4:
                v, = struct.unpack_from('B',buffer,2)
                # return ""
            else:
                v, = struct.unpack_from("h", buffer, 2)
            # v, = struct.unpack_from("h", buffer, 2)
        except Exception as e:
            print(e)
        arg1 = "v%d" % v
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])), arg1)

    def parse_FMT23X(buffer, dex_object, pc_point, offset):
        cc, bb, = struct.unpack_from("Bb", buffer, 2)
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])),
            "v%d" % bb,
            "v%d" % cc)

    def parse_FMT30T(buffer, dex_object, pc_point, offset):
        aaaaaaaa, = struct.unpack_from("i", buffer, 2)
        return dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "+%x" % (int(aaaaaaaa + offset))

    def parse_FMT31C(buffer, dex_object, pc_point, offset):
        bbbbbbbb, = struct.unpack_from("I", buffer, 2)
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])),
                "+%d" % bbbbbbbb)

    def parse_FMT31I(buffer, dex_object, pc_point, offset):
        bbbbbbbb, = struct.unpack_from("I", buffer, 2)
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])),
                "%d" % bbbbbbbb)

    def parse_FMT31T(buffer, dex_object, pc_point, offset):
        bbbbbbbb, = struct.unpack_from("i", buffer, 2)
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])),
                "string@%d" % bbbbbbbb)

    def parse_FMT32X(buffer, dex_object, pc_point, offset):
        aaaa, bbbb, = struct.unpack_from("hh", buffer, 2)
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % aaaa, "v%d" % bbbb)

    def parse_FMT35C(buffer, dex_object, pc_point, offset):
        A = ord(chr(buffer[1])) >> 4
        G = ord(chr(buffer[1])) & 0xf
        if len(buffer)>3:
            D = ord(chr(buffer[4])) >> 4
            C = ord(chr(buffer[4])) & 0xf
            F = ord(chr(buffer[5])) >> 4
            E = ord(chr(buffer[5])) & 0xf
            bbbb, = struct.unpack_from("H", buffer, 2)
        else:
            bbbb, = struct.unpack_from('B',buffer,2)
        if ord(chr(buffer[0])) == 0x24:
            prefix = "type@%s" % (dex_object.get_string_by_id(bbbb))
        else:
            prefix = "meth@%s  //%s" % (dex_object.get_method_name(bbbb), dex_object.get_method_full_name(bbbb, True))
            pass
        if A == 5:
            return (
                dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % C, "v%d" % D, "v%d" % E,
                "v%d" % F, "v%d" % G, "%s" % (prefix))
        elif A == 4:
            return (
                dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % C, "v%d" % D, "v%d" % E,
                "v%d" % F, "%s" % (prefix))
        elif A == 3:
            return (
                dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % C, "v%d" % D, "v%d" % E,
                "%s" % (prefix))
        elif A == 2:
            return (
                dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % C, "v%d" % D,
                "%s" % (prefix))
        elif A == 1:
            return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % C, "%s" % (prefix))
        elif A == 0:
            return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "%s" % (prefix))
        else:
            return (dex_decode[ord(chr(buffer[0]))][4], "error .......")
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % C, "v%d" % D, "v%d" % E,
            "v%d" % F,
            "v%d" % G, "%s" % (prefix))

    def parse_FMT3RC(buffer, dex_object, pc_point, offset):
        return (dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1])

    def parse_FMT51L(buffer, dex_object, pc_point, offset):
        if len(buffer) < 10:
            return (1, "")
        bb = struct.unpack_from("q", buffer, 2)
        return (
            dex_decode[ord(chr(buffer[0]))][4], dex_decode[ord(chr(buffer[0]))][1], "v%d" % ord(chr(buffer[1])),
            "%d" % bb)

    func_point = [parse_FMT10T, parse_FMT10X, parse_FMT11N, parse_FMT11X, parse_FMT12X,
                  parse_FMT20T, parse_FMT21C, parse_FMT21H, parse_FMT21S, parse_FMT21T,
                  parse_FMT22B, parse_FMT22C, parse_FMT22S, parse_FMT22T, parse_FMT22X,
                  parse_FMT23X, parse_FMT30T, parse_FMT31C, parse_FMT31I, parse_FMT31T,
                  parse_FMT32X, parse_FMT35C, parse_FMT3RC, parse_FMT51L]
    # ----------------------------------- Prase dalvik-bytecode api end -------------------------------------

    def __init__(self, dex_object, offset,class_idx=None,class_def_item_idx=None):
        self.class_idx = class_idx;
        self.class_def_item_idx = class_def_item_idx;
        format = "H"
        self.registers_size, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.ins_size, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.outs_size, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.tries_size, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        format = "I"
        self.debug_info_off, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.insns_size, = struct.unpack_from(format, dex_object.m_file_content, offset)
        offset += struct.calcsize(format)
        self.insns = offset
        offset += 2 * self.insns_size
        if self.insns_size % 2 == 1:
            offset += 2
        if self.tries_size == 0:
            self.tries = 0
            self.handlers = 0
        else:
            self.tries = offset
            self.handlers = offset + self.tries_size * struct.calcsize("I2H")

    def set_method_attr(self,is_direct,idx):
        self.method_idx = idx;
        self.is_direct_method = is_direct;

    def get_param_list(self, dex_object):
        if self.debug_info_off != 0:
            return self.parse_debug_info_method_parameter_list(dex_object, self.debug_info_off)
        return []

    def parse_debug_info_method_parameter_list(self, dex_object, offset):
        parameter_list = []
        n, current_line = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, parameters_size = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        for i in range(0, parameters_size):
            n, string_idx = get_uleb128p1(dex_object.m_file_content[offset:offset + 5])
            if string_idx != -1:
                parameter_list.append(dex_object.getstringbyid(string_idx))
            offset += n
        return parameter_list

    def parse_instruction(self, buf, offset, dex_object):
        n = len(buf)
        start = 0

        while start < n:
            if n == 1736:
                print("start = %d" % start)
            #Judge opcode ..
            op = ord(chr(buf[int(start)]))
            if op == 0:
                type = ord(chr(buf[start + 1]))
                if type == 1:
                    size, = struct.unpack_from("H", buf, 2 + start)
                    start += (size * 2 + 4) * 2
                    print("1",start)
                    continue
                elif type == 2:
                    size, = struct.unpack_from("H", buf, 2 + start)
                    start += (size * 4 + 2) * 2
                    print("2",start)
                    continue
                elif type == 3:
                    width, = struct.unpack_from("H", buf, 2 + start)
                    size, = struct.unpack_from("I", buf, 4 + start)
                    # width,size,=struct.unpack_from("HI",buffer,2+start)
                    start += (8 + ((size * width + 1) / 2) * 2)
                    print("mode 3",start)
                    continue
            print(start)
            if isinstance(start, float):
                start = int(start)
            val = MethodCode.func_point[dex_decode[op][3]](buf[start:], dex_object, offset + start, start / 2)
            # try:
            #     if isinstance(start,float):
            #         start = int(start)
            #     val = MethodCode.func_point[dex_decode[op][3]](buf[start:],dex_object,offset+start,start/2)
            # except Exception as e:
            #     print(e,traceback.format_exc())
            #     quit(-1)
            str = ""
            m = 0
            for x in buf[start:start + 2 * val[0]]:
                str += "%02x" % ord(chr(x))
                m += 1
                if m % 2 == 0:
                    str += " "

            print("%08x: %-36s |%04x:" % (offset + start, str, int(start / 2)), end=' ')
            m = 0
            for v in val[1:]:
                if m > 1:
                    print(",", end=' ')
                print(v, end=' ')
                m += 1
            print("")
            start += 2 * val[0]
            print(2*val[0]);
            print("after add 2:",start);


    def parse_debug_info(self, dex_object, offset):
        print("===parse_debug_info====offset = %08x" % offset)
        n, current_line = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        n, parameters_size = get_uleb128(dex_object.m_file_content[offset:offset + 5])
        offset += n
        for i in range(0, parameters_size):
            n, string_idx = get_uleb128p1(dex_object.m_file_content[offset:offset + 5])
            if string_idx != -1:
                print(dex_object.getstringbyid(string_idx))
            offset += n
        start = offset
        current_pc = 0
        print("===opcode====offset = %08x  line=%d pc=%d" % (offset, current_line, current_pc))

        totalsize = len(dex_object.m_file_content)
        while offset < totalsize:
            # bytecode = struct.unpack_from("B",dex_object.m_file_content,offset)
            bytecode = ord(chr(dex_object.m_file_content[offset]))
            offset += 1
            print("opcode[%02x]" % bytecode, end=' ')
            if bytecode == 0:
                print("")
                break
            elif bytecode == 1:
                n, val = get_uleb128(dex_object.m_file_content[offset:offset + 5])
                current_pc += val;
                offset += n
                print("line=%d  pc=%x" % (current_line, int(current_pc)))
            elif bytecode == 2:
                n, val = get_leb128(dex_object.m_file_content[offset:offset + 5])

                current_line += val
                offset += n
                print("line=%d  pc=%x   val=%08x(%d)" % (current_line, int(current_pc), val, val))
            elif bytecode == 3:
                n, register_num = get_uleb128(dex_object.m_file_content[offset:offset + 5])
                offset += n
                n, name_idx = get_uleb128p1(dex_object.m_file_content[offset:offset + 5])
                offset += n
                n, type_idx = get_uleb128p1(dex_object.m_file_content[offset:offset + 5])
                offset += n
                print("v%d %s %s  START_LOCAL" % (
                    register_num, dex_object.get_type_name_by_id(type_idx), dex_object.get_string_by_id(name_idx)))
            elif bytecode == 4:
                n, register_num = get_uleb128(dex_object.m_file_content[offset:offset + 5])
                offset += n
                n, name_idx = get_uleb128p1(dex_object.m_file_content[offset:offset + 5])
                offset += n
                n, type_idx = get_uleb128p1(dex_object.m_file_content[offset:offset + 5])
                offset += n
                n, sig_idx = get_uleb128p1(dex_object.m_file_content[offset:offset + 5])
                offset += n
                print("v%d %s %s   START_LOCAL_EXTENDED" % (
                    register_num, dex_object.get_type_name_by_id(type_idx), dex_object.get_string_by_id(name_idx)))
            elif bytecode == 5:
                n, register_num = get_uleb128(dex_object.m_file_content[offset:offset + 5])
                offset += n
                print("v%d  END_LOCAL" % register_num)
            elif bytecode == 6:
                n, register_num = get_uleb128(dex_object.m_file_content[offset:offset + 5])
                offset += n
                print("v%d   register to restart" % register_num)
            elif bytecode == 7:
                print("SET_PROLOGUE_END")
                pass
            elif bytecode == 8:
                print("SET_EPILOGUE_BEGIN")
                pass
            elif bytecode == 9:
                n, name_idx = get_uleb128(dex_object.m_file_content[offset:offset + 5])
                print("%s" % dex_object.get_string_by_id(name_idx))
                offset += n
            else:
                adjusted_opcode = bytecode - 0xa
                current_line += (adjusted_opcode % 15) - 4
                current_pc += (adjusted_opcode / 15)
                # offset += 1
                print("line=%d  pc=%x  adjusted_opcode=%d  pc+ %d  line+%d" % (
                    current_line, int(current_pc), adjusted_opcode, (adjusted_opcode / 15), (adjusted_opcode % 15) - 4))
        print("===parse_debug_info====offset = %08x$" % offset)

    def printf(self, dex_object, prefix=""):

        print("%s%-20s:%08x:%10d" % (prefix, "registers_size", self.registers_size, self.registers_size))
        print("%s%-20s:%08x:%10d" % (prefix, "insns_size", self.insns_size, self.insns_size))
        print("%s%-20s:%08x:%10d" % (prefix, "debug_info_off", self.debug_info_off, self.debug_info_off))
        print("%s%-20s:%08x:%10d" % (prefix, "ins_size", self.ins_size, self.ins_size))
        print("%s%-20s:%08x:%10d" % (prefix, "outs_size", self.outs_size, self.outs_size))
        print("%s%-20s:%08x:%10d" % (prefix, "tries_size", self.tries_size, self.tries_size))
        print("%s%-20s:%08x:%10d" % (prefix, "insns", self.insns, self.insns))
        print("%s%-20s:%08x:%10d" % (prefix, "tries", self.tries, self.tries))
        print("%s%-20s:%08x:%10d" % (prefix, "handlers", self.handlers, self.handlers))

        self.parse_instruction(dex_object.m_file_content[self.insns:self.insns + self.insns_size * 2], self.insns,dex_object)
        # if self.debug_info_off != 0:
        #     self.parse_debug_info(dex_object, self.debug_info_off)


import base64
import re

methodTable = {}

class CodeItem:
    methodname=""
    inssize=0
    insarray=""
    method_idx=0
    def __init__(self,number,methodname, inssize,insarray):
        self.method_idx=number
        self.methodname = methodname
        self.inssize = inssize
        self.insarray=insarray



def repair_dexfile_by_bin_file(dexfile_obj,binfile):
    #先弄个数组
    a =1
    bfd = open(binfile)
    # print(bfd.read())
    # bin_str_arr = bfd.read().split(";")
    bin_str_arr = bfd.read()
    bfd.close()

    insarray=re.findall(r"{name:(.*?),method_idx:(.*?),offset:(.*?),code_item_len:(.*?),ins:(.*?)}",bin_str_arr) #(.*?)最短匹配

    i =1
    for each_ins in insarray:
        '''
            第一步
            1.获取函数名字
            2.获取函数的method_idx
            3.获取函数的偏移
            4.获取code_item_len的长度
            5.获取ins的内容
        '''
        methodname=each_ins[0].replace(" ","")
        method_idx=(int)(each_ins[1])
        offset=(int)(each_ins[2])
        inssize=int(each_ins[3])
        ins=each_ins[4]
        ins = base64.b64decode(ins)
        tempmethod=CodeItem(method_idx,methodname,inssize,ins)
        methodTable[method_idx]=tempmethod #添加method
        ori_ins,ins_size = dexfile_obj.get_ins_and_ins_size_by_method_idx(method_idx,int(offset))
        print("第%d个ori_ins:%s\n size为:%d"%(i,ori_ins,ins_size))
        print("第%d个dump下来的ins:%s\n dump size为:%d"%(i,ins,inssize))
        i+=1

    '''
        第二步
        #1.将被方法抽取的dex 文件加载到内存
        #2.重新计算文件内部各个段之间的值
        #3.进行重新排放，并修改文件头
        
            # 3.1 dex文件内存布局的重新排布
                --》 1.将原来的dex文件加载到内存中
                --》 2.获取每一个class_def_item,得到后将dump出来的code_item字节回填回去。
                --》 
                --》 修正string的 string_id_item offset偏移
                --》 type_id_item 里面只是记录着 type字符串在srting table中的索引，所以不用改
                --》 
                --》 最后修正文件头
                    --》1. 修正checksum
                    --》2. 修正signature
                    --》3. 修正datasize
                
        进行 dex回填的话，先填完ins后，要修改string offset的偏移
    '''

    repair_dex_filepath = need_repair_dexfile.split(".dex")[0]+"_repair.dex"
    # mkdir(repair_dex_filepath)
    repair_dex_file = open(repair_dex_filepath,'wb')

    # 测试 写入文件头
    # repair_dex_file.write(dexfile_obj.m_dex_header['m_magic_struct'])
    repair_dex_file.write(dexfile_obj.m_dex_header['m_magic_struct']['m_magic'])
    repair_dex_file.write(dexfile_obj.m_dex_header['m_magic_struct']['m_version'])
    repair_dex_file.write(dexfile_obj.m_dex_header['m_checksum'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_signature'])
    repair_dex_file.write(dexfile_obj.m_dex_header['m_fileSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_headerSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_endianTag'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_linkSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_linkOff'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_mapOffset'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_stringIdsSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_stringIdsOff'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_typeIdsSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_typeIdsOffset'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_protoIdsSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_protoIdsOffset'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_fieldIdsSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_fieldIdsOffset'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_methodIdsSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_methodIdsOffset'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_classDefSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_classDefOffset'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_dataSize'].to_bytes(4,byteorder="little",signed=False))
    repair_dex_file.write(dexfile_obj.m_dex_header['m_dataOff'].to_bytes(4,byteorder="little",signed=False))

    """
        - 对索引区进行修复
            1.string_id_list 
            2.type_id_list 无需修复
            3.proto_id_list 需要修复parameters_off的偏移
            4.field_id_list 无需修复
            5.method_id_list 无需修复
            6.class_def_item_list 需修复
            7.map_list_type 
    """

    repair_dex_buf = io.BytesIO()
    #进行将原dex中的索引区存放到buf中
    #先将 索引区的数据拼接起来
    repair_dex_buf.write(dexfile_obj.m_file_content[dexfile_obj.m_dex_header['m_stringIdsOff']:
                                                    dexfile_obj.m_dex_header['m_stringIdsOff']+dexfile_obj.m_dex_header['m_stringIdsSize']*4])
    repair_dex_buf.write(dexfile_obj.m_file_content[dexfile_obj.m_dex_header['m_typeIdsOffset']:
                                                    dexfile_obj.m_dex_header['m_typeIdsOffset']+dexfile_obj.m_dex_header['m_typeIdsSize']*4])
    repair_dex_buf.write(dexfile_obj.m_file_content[dexfile_obj.m_dex_header['m_protoIdsOffset']:
                                                    dexfile_obj.m_dex_header['m_protoIdsOffset']+dexfile_obj.m_dex_header['m_protoIdsSize']*0xc])
    repair_dex_buf.write(dexfile_obj.m_file_content[dexfile_obj.m_dex_header['m_fieldIdsOffset']:
                                                    dexfile_obj.m_dex_header['m_fieldIdsOffset']+dexfile_obj.m_dex_header['m_fieldIdsSize']*0x8])
    repair_dex_buf.write(dexfile_obj.m_file_content[dexfile_obj.m_dex_header['m_methodIdsOffset']:
                                                    dexfile_obj.m_dex_header['m_methodIdsOffset']+dexfile_obj.m_dex_header['m_methodIdsSize']*0x8])
    repair_dex_buf.write(dexfile_obj.m_file_content[dexfile_obj.m_dex_header['m_classDefOffset']:
                                                    dexfile_obj.m_dex_header['m_classDefOffset']+dexfile_obj.m_dex_header['m_classDefSize']*0x20])

    """
        data数据区要进行膨胀了
            1.进行对string 数据的获取，可以发现,string数据不会被影响。所以这里的数据直接拼接到内存中就行了
    """
    gogog = 0
    local_file_point = dexfile_obj.m_dex_header['m_stringIdsOff']
    last_start = 0
    if dexfile_obj.m_dex_header['m_stringIdsSize'] > 0:
        for i in range(dexfile_obj.m_dex_header['m_stringIdsSize']):
            offset, = struct.unpack_from("I", dexfile_obj.m_file_content, local_file_point + i * 4)
            if i == 0:
                start = offset
                gogog+=1
            else:
                skip, length = get_uleb128(dexfile_obj.m_file_content[start:start + 5])
                # print("第%d个字符串长度:%d"%(i,length))
                # self.m_string_list.append(self.m_file_content[start + skip:offset - 1])
                # repair_dex_buf.write(dexfile_obj.m_file_content[start + skip:offset - 1])
                # repair_dex_buf.write(dexfile_obj.m_file_content[start + skip:offset])
                repair_dex_buf.write(dexfile_obj.m_file_content[start :offset])
                # gogog+=1
                # if(gogog == 100):
                #     break
                # repair_dex_file.write(repair_dex_buf.getvalue())
            if(i == dexfile_obj.m_dex_header['m_stringIdsSize']-1):
                last_start = offset
            start = offset
            # string_id_item = dexfile_obj.m_file_content[local_file_point:local_file_point+4]
            # # tmp_id,string_size = get_uleb128(dexfile_obj.m_file_content[int(int("0x"+string_id_item.hex(),16).to_bytes(4,byteorder="little",signed=False).hex(),16):
            # #                                                             int(int("0x"+string_id_item.hex(),16).to_bytes(4,byteorder="little",signed=False).hex(),16)+1])
            # local_file_point+=4
            # string_id_item_next = dexfile_obj.m_file_content[local_file_point:local_file_point+4]
            # repair_dex_buf.write(dexfile_obj.m_file_content[int(int("0x"+string_id_item.hex(),16).to_bytes(4,byteorder="little",signed=False).hex(),16)
            #                                                 :int(int("0x"+string_id_item_next.hex(),16).to_bytes(4,byteorder="little",signed=False).hex(),16)])

    """
        data区::string_item_list 的下一段就是 type_item_list的数据,
        string_item_list 4字节对齐
        直接dump原文件的type_item_list段拼接上去就得了。
    """
    # 这里需要获取parameters_off数组的最大值和最小值
    params_off_list = list()
    local_file_point = dexfile_obj.m_dex_header['m_protoIdsOffset']
    for i in range(dexfile_obj.m_dex_header['m_protoIdsSize']):
        # pro
        short_idx,return_type_idx,parameters_off = struct.unpack_from("3I", dexfile_obj.m_file_content, local_file_point + i * 12)
        # parameters_off = proto_id_item[8:12]
        if(parameters_off!=0):
            params_off_list.append(parameters_off)
            # if(parameters_off == 0x23b71a or parameters_off == parameters_off==0x23b71c):
            #     break
    min_parameters_off = min(params_off_list)
    max_parameters_off = max(params_off_list)
    # 进行记录最后的字符串
    repair_dex_buf.write(dexfile_obj.m_file_content[last_start:min_parameters_off])


    repair_dex_buf.write(dexfile_obj.m_file_content[min_parameters_off:max_parameters_off])


    """
        data区::type_item_list 的下一段貌似就是class_def_item的数据了，下面进行验证
    """
    interfaces_off_list = list()
    annotations_off_list = list()
    class_data_off_list = list()
    static_value_off_list = list()
    local_file_point = dexfile_obj.m_dex_header['m_classDefOffset']
    for i in range(dexfile_obj.m_dex_header['m_classDefSize']):
        class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx, \
        annotations_off,class_data_off,static_value_off = struct.unpack_from("8I", dexfile_obj.m_file_content, local_file_point + i * 0x20)
        if(interfaces_off!=0):
            interfaces_off_list.append(interfaces_off)
        if(annotations_off!=0):
            annotations_off_list.append(annotations_off)
        if(class_data_off!=0):
            class_data_off_list.append(class_data_off)
        if(static_value_off!=0):
            static_value_off_list.append(static_value_off)

    aaa =111
    repair_dex_buf2 = io.BytesIO()
    repair_dex_buf2.write(dexfile_obj.m_file_content[0x70:min(class_data_off_list)])
    # min(class_data_off)
    # 遍历每一个 class_data_item,并获取里面的方法数
    class_def_item_list = list()
    for i in range(0, dexfile_obj.m_dex_header['m_classDefSize']):
        local_class_def_item =  DexClass(dexfile_obj, i,False);
        class_def_item_list.append(local_class_def_item)

    aa = 1













    # 将拼接出来的字节流写入到修复的dex中
    # repair_dex_file.write(repair_dex_buf.getvalue())
    repair_dex_file.write(repair_dex_buf2.getvalue())

    tmp_class_data_item_list = list()


    # 下面进行回填指令操作
    for key in methodTable.keys():
        # dexfile_obj.repair_method() m_class_def_item_list
        # 这里注意 class_def_item 的序号 跟class_idx是不对等的哦
        local_method_item = methodTable.get(key)
        class_idx = dexfile_obj.m_method_id_item_list[local_method_item.method_idx].class_idx
        for class_def_item in dexfile_obj.m_class_def_item_list:
            if class_def_item.class_idx == class_idx:
                # 这里开始填充指令回去
                aaa = 1
    repair_dex_buf.close()
    repair_dex_file.close()


class DexFile:
    DEX_MAGIC = "dex\n";      #dex文件
    DEX_OPT_MAGIC = "dey\n";  #opt文件

    def __init__(self, dex_file):
        # Dex file does not distinguish between 32 bits and 64 bits
        self.dex_header_struct = {
            # 魔数
            'magic': 8,
            # 文件校验码 ，使用alder32 算法校验文件除去 maigc ，checksum 外余下的所有文件区域 ，用于检查文件错误 。
            'checksum': 4,
            # 使用 SHA-1 算法 hash 除去 magic ,checksum 和 signature 外余下的所有文件区域 ，用于唯一识别本文件 。
            'signature': 20,
            # Dex 文件的大小 。
            'file_size': 4,
            # header 区域的大小 ，单位 Byte ，一般固定为 0x70 常量 。
            'header_size': 4,
            # 大小端标签 ，标准 .dex 文件格式为 小端 ，此项一般固定为 0x1234 5678 常量 。
            'endian_tag': 4,
            # 链接数据的大小
            'link_size': 4,
            # 链接数据的偏移值
            'link_off': 4,
            # map item 的偏移地址 ，该 item 属于 data 区里的内容 ，值要大于等于 data_off 的大小 。
            'map_off': 4,
            # dex中用到的所有的字符串内容的大小
            'string_ids_size': 4,
            # dex中用到的所有的字符串内容的偏移值
            'string_ids_off': 4,
            # dex中的类型数据结构的大小
            'type_ids_size': 4,
            # dex中的类型数据结构的偏移值
            'type_ids_off': 4,
            # dex中的元数据信息数据结构的大小
            'proto_ids_size': 4,
            # dex中的元数据信息数据结构的偏移值
            'proto_ids_off': 4,
            # dex中的字段信息数据结构的大小
            'field_ids_size': 4,
            # dex中的字段信息数据结构的偏移值
            'field_ids_off': 4,
            # dex中的方法信息数据结构的大小
            'method_ids_size': 4,
            # dex中的方法信息数据结构的偏移值
            'method_ids_off': 4,
            # dex中的类信息数据结构的大小
            'class_defs_size': 4,
            # dex中的类信息数据结构的偏移值
            'class_defs_off': 4,
            # dex中数据区域的结构信息的大小
            'data_size': 4,
            # dex中数据区域的结构信息的偏移值
            'data_off': 4
        }

        # 由于后续各区都需要从header中获取自己的数量和偏移，所以在构造函数中调用它
        self.file_name = dex_file
        self.m_dex_header = dict()
        self.m_string_list = list()
        self.m_class_dict = {}
        self.m_method_name_list = []
        self.m_field_name_list = []
        self.m_type_name_list = []
        self.m_proto_name_list = []
        self.m_class_def_item_list = list()
        self.m_method_id_item_list = list()

        self.parse_dex_header()

    def parse_dex_header(self):
        print("The dex file header has starts to parse...")
        self.m_fd = open(self.file_name, 'rb');
        self.m_file_content = self.m_fd.read();
        self.m_fd.close();
        # Determines whether the file is an 'opt' or 'dex' format
        if self.m_file_content[0:4].decode() == DexFile.DEX_OPT_MAGIC:
            self.init_optheader(self.m_file_content)
            self.init_header(self.m_file_content, 0x40)
        elif self.m_file_content[0:4].decode() == DexFile.DEX_MAGIC:
            self.init_header(self.m_file_content, 0)
        print("Parsing the string table...")
        bOffset = self.m_dex_header['m_stringIdsOff']
        if self.m_dex_header['m_stringIdsSize'] > 0:
            for i in range(0, self.m_dex_header['m_stringIdsSize']):
                offset, = struct.unpack_from("I", self.m_file_content, bOffset + i * 4)
                if i == 0:
                    start = offset
                else:
                    skip, length = get_uleb128(self.m_file_content[start:start + 5])
                    self.m_string_list.append(self.m_file_content[start + skip:offset - 1])
                    # try:
                    #     print("第%d个字符串:%s"%(i,self.m_file_content[start + skip:offset - 1].decode()))
                    # except Exception as e:
                    #     # print("第%d个字符串:%s"%(i,self.m_file_content[start + skip:offset - 1].decode('gbk')))
                    #     print(e)
                    start = offset
            for i in range(start, len(self.m_file_content)):
                if self.m_file_content[i] == chr(0):
                    self.m_string_list.append(self.m_file_content[start + 1:i])
                    break

        print("Parsing all method name...");
        for i in range(0, self.m_dex_header['m_methodIdsSize']):
            self.m_method_name_list.append(self.get_method_name(i));
            self.m_method_id_item_list.append(self.get_method_id_item(i))
            # print (self.get_method_name(i))
        print("Parsing all filed name...");
        for i in range(0, self.m_dex_header['m_fieldIdsSize']):
            self.m_field_name_list.append(self.get_field_name(i));
            # print(self.get_field_name(i))

        print("Parsing all type name...");
        for i in range(0, self.m_dex_header['m_typeIdsSize']):
            self.m_type_name_list.append(self.get_type_name(i));
            # print (self.get_type_name(i))

        # The prototype of java method.
        print("Parsing all prototype name...");
        for i in range(0, self.m_dex_header['m_protoIdsSize']):
            self.m_type_name_list.append(self.get_proto_name(i));
            # print (self.get_proto_name(i))
        print("Parsing all class name...");
        for i in range(0, self.m_dex_header['m_classDefSize']):
            str1 = self.get_class_name(i)
            self.m_class_dict[str1] = i
            self.m_class_def_item_list.append(self.get_class_def_item(i))
        print("Parsing all class details...");
        # parse the class,it too hard..fuck.
        for i in range(0, self.m_dex_header['m_classDefSize']):
            # print('------------------------------ parse class -----------------------------')
            # DexClass(self, i).printf(self);
            # DexClass(self, i);
            # print("------------------------------ parse  end  -----------------------------")
            pass
        print("\n\nFile header parsing complete!!^_^");

    def get_type_name_by_id(self,typeid):
        if typeid >= self.m_dex_header['m_typeIdsSize']:
            return ""
        offset = self.m_dex_header['m_typeIdsOffset'] + typeid * struct.calcsize("I")
        descriptor_idx, = struct.unpack_from("I",self.m_file_content,offset)
        return self.m_string_list[descriptor_idx]

    def get_proto_name(self, protoid):
        if protoid >= self.m_dex_header['m_protoIdsSize']:
            return ""
        offset = self.m_dex_header['m_protoIdsOffset'] + protoid * struct.calcsize("3I")
        shorty_idx, return_type_idx, parameters_off, = struct.unpack_from("3I", self.m_file_content, offset)
        return self.m_string_list[shorty_idx]

    def get_field_name(self, fieldid):
        if fieldid >= self.m_dex_header['m_fieldIdsSize']:
            return ""
        offset = self.m_dex_header['m_fieldIdsOffset'] + fieldid * struct.calcsize("HHI")
        class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.m_file_content, offset)
        return self.m_string_list[name_idx]

    def get_method_name(self, methodid):
        if methodid >= self.m_dex_header['m_methodIdsSize']:
            return ""
        offset = self.m_dex_header['m_methodIdsOffset'] + methodid * struct.calcsize("HHI")
        class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.m_file_content, offset)
        return self.m_string_list[name_idx]

    def get_method_id_item(self,methodid):
        if methodid >= self.m_dex_header['m_methodIdsSize']:
            return ""
        offset = self.m_dex_header['m_methodIdsOffset'] + methodid * struct.calcsize("HHI")
        class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.m_file_content, offset)

        return MethodIdItem(class_idx,proto_idx,name_idx)


    def get_class_name(self, class_def_item_id):
        if class_def_item_id >= self.m_dex_header['m_classDefSize']:
            return ""
        offset = self.m_dex_header['m_classDefOffset'] + class_def_item_id * struct.calcsize("8I");
        class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off, = struct.unpack_from(
            "8I", self.m_file_content, offset)
        return self.get_type_name(class_idx)

    def get_class_def_item(self,class_def_item_id):
        if class_def_item_id >= self.m_dex_header['m_classDefSize']:
            return ""
        offset = self.m_dex_header['m_classDefOffset'] + class_def_item_id * struct.calcsize("8I");
        class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off, = struct.unpack_from(
            "8I", self.m_file_content, offset)
        return ClassDefItem(class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off)


    def get_type_name(self, typeid):
        if typeid >= self.m_dex_header['m_typeIdsSize']:
            return ""
        offset = self.m_dex_header['m_typeIdsOffset'] + typeid * struct.calcsize("I")
        descriptor_idx, = struct.unpack_from("I", self.m_file_content, offset)
        return self.m_string_list[descriptor_idx]

    def init_optheader(self, content):
        offset = 0
        format = "4s"
        self.m_magic, = struct.unpack_from(format, content, offset)
        format = "I"
        offset += struct.calcsize(format)
        self.m_version, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dexOffset, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dexLength, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_depsOffset, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_depsLength, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_optOffset, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_optLength, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_flags, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_checksum, = struct.unpack_from(format, content, offset)

    def init_header(self, content, offset):
        format = "4s"
        self.m_dex_header['m_magic_struct'] = dict()
        self.m_dex_header['m_magic_struct']['m_magic'], = struct.unpack_from(format, content, offset)
        format = "4s"
        offset += struct.calcsize(format)
        self.m_dex_header['m_magic_struct']['m_version'], = struct.unpack_from(format, content, offset);
        format = "I"
        # offset += struct.calcsize(format)
        # self.m_dex_header['m_version'],= struct.unpack_from(format,content,offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_checksum'], = struct.unpack_from(format, content, offset)
        format = "20s"
        offset += 4
        self.m_dex_header['m_signature'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format) - 4
        format = "I"
        offset += struct.calcsize(format)
        self.m_dex_header['m_fileSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_headerSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_endianTag'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_linkSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_linkOff'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_mapOffset'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_stringIdsSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_stringIdsOff'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_typeIdsSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_typeIdsOffset'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_protoIdsSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_protoIdsOffset'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_fieldIdsSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_fieldIdsOffset'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_methodIdsSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_methodIdsOffset'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_classDefSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_classDefOffset'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_dataSize'], = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dex_header['m_dataOff'], = struct.unpack_from(format, content, offset)

    def get_type_name(self, typeid):
        if typeid >= self.m_dex_header['m_typeIdsSize']:
            return ""
        offset = self.m_dex_header['m_typeIdsOffset'] + typeid * struct.calcsize("I")
        descriptor_idx, = struct.unpack_from("I", self.m_file_content, offset)
        return self.m_string_list[descriptor_idx]

    def get_string_by_id(self, stridx):
        if stridx >= self.m_dex_header['m_stringIdsSize']:
            return ""
        return self.m_string_list[stridx]

    def get_field_full_name(self, fieldid):
        if fieldid >= self.m_dex_header['m_fieldIdsSize']:
            return ""
        offset = self.m_dex_header['m_fieldIdsOffset'] + fieldid * struct.calcsize("HHI")
        class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.m_file_content, offset)
        name = self.get_type_name(type_idx)
        name = shorty_decode(name)
        fname = self.get_string_by_id(name_idx)
        return "%s %s" % (name, fname)

    def get_method_full_name(self, methodid, hidden_classname=False):
        if methodid >= self.m_dex_header['m_methodIdsSize']:
            return ""
        offset = self.m_dex_header['m_methodIdsOffset'] + methodid * struct.calcsize("HHI")
        class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.m_file_content, offset)
        classname = self.get_type_name(class_idx)
        classname = shorty_decode(classname)
        funcname = self.get_string_by_id(name_idx)
        if not hidden_classname:
            classname = ""
        return self.get_proto_full_name(proto_idx, classname, funcname)

    def get_proto_full_name(self, protoid, classname, func_name):
        if protoid >= self.m_dex_header['m_protoIdsSize']:
            return ""
        offset = self.m_dex_header['m_protoIdsOffset'] + protoid * struct.calcsize("3I")
        shorty_idx, return_type_idx, parameters_off, = struct.unpack_from("3I", self.m_file_content, offset)
        retname = self.get_type_name(return_type_idx)
        retname = shorty_decode(retname)
        retstr = retname + " "
        if len(classname) == 0:
            retstr += "%s(" % func_name
        else:
            retstr += "%s::%s(" % (classname, func_name)
        if parameters_off != 0:
            offset = parameters_off
            size, = struct.unpack_from("I", self.m_file_content, offset)
            offset += struct.calcsize("I")
            n = 0
            for i in range(0, size):
                type_idx, = struct.unpack_from("H", self.m_file_content, offset)
                offset += struct.calcsize("H")
                arg = self.get_type_name(type_idx)
                arg = shorty_decode(arg)
                if n != 0:
                    retstr += ","
                retstr += arg
                n += 1
        retstr += ")"
        return retstr

    '''
        用于返回方法的code
    '''
    def get_ins_by_method_idx(self,method_idx,offset=None):
        if offset == None:
            print("Now it can't work for not offset,please input offset")
            return
        method_obj = MethodCode(self,offset)
        ori_ins = self.m_file_content[method_obj.insns:method_obj.insns+method_obj.insns_size*2]
        return  ori_ins

    def get_ins_and_ins_size_by_method_idx(self,method_idx,offset=None):
        if offset == None:
            print("Now it can't work for not offset,please input offset")
            return
        method_obj = MethodCode(self,offset)
        ori_ins = self.m_file_content[method_obj.insns:method_obj.insns+method_obj.insns_size*2]

        return  ori_ins,method_obj.insns_size




if __name__ == '__main__':
    # global debug_mode,need_repair_dexfile,repair_dexfile_bin
    dex_file = ""
    command = None
    if sys.argv.__len__() >1:
        command = sys.argv[1]

    # dex_file =  input("Welcome to use the dex parse.Now please input your dex file path:");
    # dex_file = "../classes.dex"
    # dex_file = "../7995032_dexfile.dex"
    # parse_dex_obj = DexFile(dex_file)
    print("please input the dex filepath:")

    # if not debug_mode:
    if  debug_mode:
        parse_dex_obj = DexFile(need_repair_dexfile)
    else:
        while True:
            dex_file = input()
            if not dex_file.endswith(".dex"):
                print("please input the correct dex filepath")
                continue
            parse_dex_obj = DexFile(dex_file)
            if parse_dex_obj !=None:
                break
            else:
                print("parse_dex_obj ")



    # Receives input code..
    receive_input = True
    while receive_input:
        if command == None:
            command = (input('Please input the command(\'q\' to exit):')).lower()
        if command == 'x':
            pass
        elif command == 's' or command == 'string':
            idx = 0
            for i in parse_dex_obj.m_string_list:
                tmp = i
                if isinstance(tmp, bytes):
                    # tmp = str(binascii.b2a_qp(tmp))
                    tmp = binascii.b2a_qp(tmp)
                idx += 1
                print("%d:%s" % (idx, tmp))
        elif command == 'f' or command == 'filed':
            idx = 0
            for i in parse_dex_obj.m_field_name_list:
                tmp = i;
                if isinstance(tmp, bytes):
                    tmp = binascii.b2a_qp(tmp);
                idx += 1;
                print("%d:%s" % (idx, tmp))
        elif command == 'm' or command == 'method':
            idx = 0
            for i in parse_dex_obj.m_method_name_list:
                tmp = i;
                if isinstance(tmp, bytes):
                    tmp = binascii.b2a_qp(tmp);
                idx += 1;
                print("%d:%s" % (idx, tmp))
        elif command == 'p' or command == 'prototype':
            idx = 0
            for i in parse_dex_obj.m_field_name_list:
                tmp = i;
                if isinstance(tmp, bytes):
                    tmp = binascii.b2a_qp(tmp);
                idx += 1;
                print("%d:%s" % (idx, tmp))
        elif command == 'c' or command == 'class':
            print("Start to show class list:\n")
            idx = 0
            for i in parse_dex_obj.m_class_dict.keys():
                tmp = i;
                if isinstance(tmp, bytes):
                    tmp = binascii.b2a_qp(tmp);
                idx += 1;
                print("%d:%s" % (idx, tmp))
            print("\nShow class list is finished!")

        elif command == 'check' or command == 'ch':
            print("Building...please wait ^_^")
            # Only check the dex file header is legal?
        elif command == 'r' or command == 'repair':
            print("This is for fart repair the dex file.\n"
                  "Now please input the *.bin filepath for the dex file which you want to repaire.\n")
            # print("Building...please wait ^_^")
            if debug_mode:
                bin_file = repair_dexfile_bin
            else:
                bin_file = input()
            if not bin_file.endswith(".bin"):
                print("You input the bin file is not vailed")
            else:
                # 这里开始进行修复
                repair_dexfile_by_bin_file(parse_dex_obj,bin_file)
                aaa = 1

        elif command == 'rebuild' or command == 'rb':
            print('This feature is for rebuild the class method extraction dex file.\n');
            invailed_dex_file = input('Please input the invailed dex file path:');
            class_method_item_code_file = input('Please enter the class method opcode file that has been dumped:');
            print("Building...please wait ^_^")
        elif command == 'q':
            receive_input = False;
        elif command == 'h' or command == 'help':
            print("Command list:\n"
                  "'c' or 'class' to show class table\n"
                  "'r' or 'repair' to repair the dex file by input bin file path\n"
                  "'s' or 'string' to show string table\n"
                  "'f' or 'field' to show field table\n"
                  "'m' or 'method' to show method table\n"
                  "'p' or 'prototype' to show prototype table\n"
                  "'check' or 'ch' to check for the dex file correctness\n "
                  "'dex' or 'dh' to show dex file header\n")
        else:
            print("Invailed command! You can input 'h' or 'help' to show menu.");
        if not receive_input:
            break;
        command = None
    print("Bye Bye~")
    quit(0)
