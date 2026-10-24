#!/usr/bin/env python3
"""
Delta IPA Key Bypass Patcher
用法: python3 delta_patch.py <input.ipa> [output.ipa]
"""

import sys, os, shutil, struct, zipfile, tempfile, argparse, plistlib

# ─── ARM64 instruction encoders ───────────────────────────────────────────
def _bl(src, tgt):
    off = (tgt - src) >> 2
    return struct.pack('<I', 0x94000000 | (off & 0x3FFFFFF))

def _b(src, tgt):
    off = (tgt - src) >> 2
    return struct.pack('<I', 0x14000000 | (off & 0x3FFFFFF))

def _cbz(src, tgt, rt):
    off = (tgt - src) >> 2
    return struct.pack('<I', 0xB4000000 | ((off & 0x7FFFF) << 5) | rt)

def _beq(src, tgt):
    off = (tgt - src) >> 2
    return struct.pack('<I', 0x54000000 | ((off & 0x7FFFF) << 5))

def _adrp(pc, tgt, rd):
    page_diff = (tgt >> 12) - (pc >> 12)
    immlo = page_diff & 3
    immhi = (page_diff >> 2) & 0x7FFFF
    return struct.pack('<I', 0x90000000 | (immlo << 29) | (immhi << 5) | rd)

def _add_imm(rd, rn, imm12):
    return struct.pack('<I', 0x91000000 | (imm12 << 10) | (rn << 5) | rd)

def _sub_sp(imm12):
    return struct.pack('<I', 0xD1000000 | (imm12 << 10) | (31 << 5) | 31)

def _add_sp(imm12):
    return struct.pack('<I', 0x91000000 | (imm12 << 10) | (31 << 5) | 31)

def _movz(rd, imm16):
    return struct.pack('<I', 0xD2800000 | (imm16 << 5) | rd)

def _mov_reg(rd, rm):
    return struct.pack('<I', 0xAA000000 | (rm << 16) | (31 << 5) | rd)

def _stp_pre(rt1, rt2, rn, off):
    simm7 = (off // 8) & 0x7F
    return struct.pack('<I', 0xA9800000 | (simm7 << 15) | (rt2 << 10) | (rn << 5) | rt1)

def _stp_off(rt1, rt2, rn, off):
    simm7 = (off // 8) & 0x7F
    return struct.pack('<I', 0xA9000000 | (simm7 << 15) | (rt2 << 10) | (rn << 5) | rt1)

def _ldp_off(rt1, rt2, rn, off):
    simm7 = (off // 8) & 0x7F
    return struct.pack('<I', 0xA9400000 | (simm7 << 15) | (rt2 << 10) | (rn << 5) | rt1)

def _ldp_post(rt1, rt2, rn, off):
    simm7 = (off // 8) & 0x7F
    return struct.pack('<I', 0xA8C00000 | (simm7 << 15) | (rt2 << 10) | (rn << 5) | rt1)

def _cmn_w0_1():
    return struct.pack('<I', 0x3100041F)

def _ret():
    return struct.pack('<I', 0xD65F03C0)

def _add_x0_sp_0():
    return struct.pack('<I', 0x910003E0)  # add x0,sp,#0

DYLIB_PATH = "Payload/Roblox.app/libgloop.dylib"

PATCHES = [
    # Layer 1: Keychain cache bypass
    (0x3bc718, b'\x73\x2a\x01\xb4', "cbz x19  → nop  [無預存key檢查]"),
    (0x3bc71c, b'\x48\x2a\x01\xb4', "cbz x8   → nop  [解密字串空值檢查]"),
    (0x3bc7dc, b'\x54\x24\x01\x35', "cbnz w20 → nop  [SecItemCopyMatching失敗檢查]"),
    (0x3bc7e4, b'\x08\x24\x01\xb4', "cbz x8   → nop  [Keychain結果空值檢查]"),
    # Layer 2: HTTP network validation bypass (polling block @ 0x362da8)
    (0x362dc0, b'\xc1\x00\x00\x54', "b.ne     → nop  [HTTP completed flag檢查]"),
    (0x362dcc, b'\x68\x00\x00\x36', "tbz w8,0 → nop  [HTTP valid flag檢查]"),
    # Layer 5: in-game key check bypass (@ 0x1c2b34)
    (0x1c2b3c, b'\x81\x00\x00\x54', "b.ne     → nop  [in-game key check→無效路徑]"),
    (0x1c2b44, b'\xac\xcd\xff\x97', "BL 0x1b61f4→nop [in-game key檢查函數呼叫]"),
    # Layer 7: key-check side-effect bypass + fn@0x38e274 flag early-return bypass
    (0x38e2dc, b'\x05\x9f\x23\x94', "BL 0xc75ef0→nop [key check #1 side effect bypass]"),
    (0x392d38, b'\x6e\x8c\x23\x94', "BL 0xc75ef0→nop [key check #2 side effect bypass]"),
    (0x397790, b'\xc1\xa9\x04\x54', "B.ne→nop [flag early-return #1 skip]"),
    (0x39779c, b'\x61\xa9\x04\x54', "B.ne→nop [flag early-return #2 skip]"),
]

# Special patches: non-NOP replacements
OVERLAY_PATCH      = (0x3a20ac, b'\xff\x43\x05\xd1', b'\xc0\x03\x5f\xd6')  # show overlay fn → RET
LAYER3_PATCH       = (0x392d54, b'\x68\x51\x02\x37', b'\x8b\x12\x00\x14')   # tbnz → b valid path
INGAME_VALID_PATCH = (0x1c2b48, b'\xa0\x01\x00\x36', b'\x0d\x00\x00\x14')   # tbz → b 0x1c2b7c (always good path)
SHOW_OVERLAY2_PATCH = (0x1b2960, b'\xf4\x4f\xbe\xa9', b'\xc0\x03\x5f\xd6') # fn@0x1b2960 (fail-path show overlay) → RET
# Layer 6: startup overlay bypass — force fn@0x38e274 to always jump to key-processing code,
# skipping the "no cached key" path (0x38eb98) that shows the overlay at startup
LAYER6_PATCH       = (0x38e2f0, b'\xe0\x51\x02\x54', b'\x8f\x12\x00\x14')  # b.eq → b (always → 0x392d2c, bypasses startup overlay)
BLR_NOP_PATCH      = (0x38e29c, b'\x00\x02\x3f\xd6', b'\x1f\x20\x03\xd5')  # BLR x16 → NOP (pre-init call at fn@0x38e274 entry)
# Layer 8: force-skip the 0x39786c–0x39d554 overlay block
# x19 is set to non-zero by ADRP at 0x392d2c so CBZ x19 is never taken → enters overlay block
CBZ_OVERLAY_PATCH  = (0x397868, b'\x73\xe7\x02\xb4', b'\x3b\x17\x00\x14')  # CBZ x19 → B 0x39d554 (always skip overlay block)
# Layer 9: fn@0x33b3a4 (startup overlay init) → returns x0=0 immediately so fn@0x34f488
# takes CBZ x0→0x352a30 (safe null-return early exit), no garbage overlay pointer stored.
# Two-instruction patch: first instruction (SUB SP) → MOV x0,xzr; second (STP) → RET
FN_33B3A4_MOV0_PATCH = (0x33b3a4, b'\xff\x43\x02\xd1', b'\xe0\x03\x1f\xaa')  # SUB SP → MOV x0,#0
FN_33B3A4_RET_PATCH  = (0x33b3a8, b'\xf4\x4f\x07\xa9', b'\xc0\x03\x5f\xd6')  # STP → RET
# Layer 10: overlay update function bypass (called from startup 0x2d07dc; safety guard)
SHOW_OVERLAY4_PATCH = (0x3a4ed4, b'\xff\x83\x02\xd1', b'\xc0\x03\x5f\xd6')  # fn@0x3a4ed4 → RET (overlay update)
# Layer 15: NOP the 3 BL _objc_msgSend calls inside fn@0x3bc648 that present overlay UI.
# Killing fn@0x3bc648 entirely causes crash (function also does init work).
# These 3 calls are the only UI-display side effects; NOP-ing them suppresses the overlay
# while letting the rest of the function's initialization run normally.
LAYER15_PATCHES = [
    (0x3bd9d4, b'\x2d\xe0\x22\x94', "BL _objc_msgSend→nop [fn@3bc648 overlay msgSend #1]"),
    (0x3be2fc, b'\xe3\xdd\x22\x94', "BL _objc_msgSend→nop [fn@3bc648 overlay msgSend #2]"),
    (0x3bec60, b'\x8a\xdb\x22\x94', "BL _objc_msgSend→nop [fn@3bc648 overlay msgSend #3]"),
]
# Layer 15b: NOP remaining active _objc_registerClassPair at 0x3a4ea4
# (allocateClassPair already NOP'd; this prevents any class object from being finalized)
REGISTER_CLASS_NOP2_PATCH = (0x3a4ea4, b'\xfc\x42\x23\x94', b'\x1f\x20\x03\xd5')  # BL registerClassPair → NOP
# Layer 11: NOP calls to stub@0xc75680 (_class_addMethod) — prevents dynamic ObjC method registration
# that would build the overlay class's method table.
LAYER11_PATCHES = [
    (0x341fd8, b'\xaa\xcd\x24\x94', "BL c75680->nop [fn@33ea4c _class_addMethod]"),
    (0x3a4e9c, b'\xf9\x41\x23\x94', "BL c75680->nop [near fn@3a4ed4 _class_addMethod]"),
    (0x2e93e4, b'\xa7\x30\x26\x94', "BL c75680->nop [0x2e93e4 _class_addMethod]"),
    (0x2e9d64, b'\x47\x2e\x26\x94', "BL c75680->nop [0x2e9d64 _class_addMethod]"),
    (0x2ea6f4, b'\xe3\x2b\x26\x94', "BL c75680->nop [0x2ea6f4 _class_addMethod]"),
    (0x2eb06c, b'\x85\x29\x26\x94', "BL c75680->nop [0x2eb06c _class_addMethod]"),
]
# Layer 12: NOP _objc_registerClassPair at 0x2eb078 — prevents the overlay ObjC class from being
# registered in the runtime. Without registration, objc_msgSend cannot dispatch to it.
# Also patch fn@0x33ea4c → RET (class factory, only called from fn@0x2d0770 startup chain).
# And fn@0x2d0770 → RET to kill the entire startup overlay init chain at its root.
REGISTER_CLASS_NOP_PATCH = (0x2eb078, b'\x87\x2a\x26\x94', b'\x1f\x20\x03\xd5')  # BL _objc_registerClassPair → NOP
FN_33EA4C_RET_PATCH      = (0x33ea4c, b'\xff\x43\x03\xd1', b'\xc0\x03\x5f\xd6')  # fn@0x33ea4c (class factory) → RET
FN_2D0770_RET_PATCH      = (0x2d0770, b'\xe9\x23\xb9\x6d', b'\xc0\x03\x5f\xd6')  # fn@0x2d0770 (startup chain) → RET

# Layer 14: Kill fn@0x38e274 (key_val_show) entirely — both callers ignore return value.
# Also kill 4th dispatch_after (HTTP callback tail-call) + both dispatch_async block submitters.
# fn@0x38e274 is a monster function; making it RET immediately is cleaner than patching internals.
LAYER14_PATCHES = [
    (0x38e274, b'\xfc\x6f\xba\xa9', b'\xc0\x03\x5f\xd6'),  # fn@0x38e274 (key_val_show) → RET
    (0x362dfc, b'\x39\x4a\x24\x14', b'\x1f\x20\x03\xd5'),  # B→dispatch_after in HTTP callback (4th)
    (0x3afdd0, b'\x47\x16\x23\x94', b'\x1f\x20\x03\xd5'),  # BL dispatch_async block #1
    (0x3bc5c4, b'\x4a\xe4\x22\x94', b'\x1f\x20\x03\xd5'),  # BL dispatch_async block #2
    (0x38e344, b'\x15\x02\x00\x14', b'\x1f\x20\x03\xd5'),  # B→0x38eb98 (defensive, dead code)
    (0x38e3c8, b'\x65\x3e\x00\x35', b'\x1f\x20\x03\xd5'),  # CBNZ w5→0x38eb94 (defensive)
]

# Layer 13: Kill async dispatch_after overlay triggers + prevent ObjC class allocation
# dispatch_after at 0x3532a0 fires BEFORE BL fn@0x2d0770 at 0x353368 — our RET patch arrives too late;
# 0x353390 is a tail-call B→0xc756e0 in the same function (second dispatch).
# allocateClassPair at 0x2e8a50/0x3a45a8 — class created before addMethod/registerClassPair; was never patched.
LAYER13_PATCHES = [
    (0x3532a0, b'\x10\x89\x24\x94', "BL 0xc756e0→nop [dispatch_after async overlay block #1]"),
    (0x353390, b'\xd4\x88\x24\x14', "B  0xc756e0→nop [dispatch_after tail-call overlay block #2]"),
    (0x2e8a50, b'\x05\x34\x26\x94', "BL 0xc75a64→nop [_objc_allocateClassPair class A]"),
    (0x2c9928, b'\x6e\xaf\x26\x94', "BL 0xc756e0→nop [dispatch_after async overlay block #3]"),
    (0x3a45a8, b'\x2f\x45\x23\x94', "BL 0xc75a64→nop [_objc_allocateClassPair class B]"),
]

# Layer 16: NOP 2 active BL _objc_msgSend calls in callees of fn@0x3bc648 (overlay chain).
# NOTE: fn@3aa68c is called from fn@3afe10 with fn@3bc648's return value as its argument.
# fn@3bc648 (with our patches active) returns a non-nil garbage value → fn@3aa68c's msgSend
# crashes because it receives a non-ObjC pointer. FORCE_DELTA_PATH_PATCH below bypasses
# fn@3aa68c entirely, so these NOP patches are now dead code (fn@3bc648 never finishes init).
LAYER16_PATCHES = [
    (0x3aebf8, b'\xa4\x1b\x23\x94', "BL _objc_msgSend→nop [fn@3ae2dc, callee of fn@3bc648]"),
    (0x3bf54c, b'\x4f\xd9\x22\x94', "BL _objc_msgSend→nop [fn@3bf4c0, tail-call from fn@3bc648]"),
]

# Layer 18: Force fn@0x3afe10 to always take the Delta execution path (0x3afe24).
# fn@0x3afe10 flow: BL fn@3bc648 → CBZ x0, 0x3afe24 → BL fn@3aa68c(overlay_obj) → ...
# With our patches, fn@3bc648 still returns non-nil (its input x0), so CBZ is not taken
# and fn@3aa68c is called with a non-valid ObjC object → crash.
# Fix: change CBZ x0 → unconditional B, permanently skipping fn@3aa68c.
# This also enables Delta features: 0x3afe24 is the "key valid / no overlay" execution path.
FORCE_DELTA_PATH_PATCH = (0x3afe14, b'\x80\x00\x00\xb4', b'\x04\x00\x00\x14')  # cbz x0,0x3afe24 → b 0x3afe24

# Layer 19: Kill fn@0x3bc648 (the overlay controller) at entry point.
# fn@0x3bc648 is called from fn@0x3afe10 and its body DISPLAYS the overlay UI before returning.
# LAYER15's 3 msgSend NOPs were not sufficient — fn@0x3bc648 still shows the overlay.
# Fix: replace its first two instructions with MOV x0,xzr + RET so it returns nil immediately
# without executing any overlay display logic.
# With x0=nil, fn@0x3afe10's cbz x0 branches to 0x3afe24 (Delta execution path, key-valid path).
FN_3BC648_MOV0_PATCH = (0x3bc648, b'\xff\x43\x05\xd1', b'\xe0\x03\x1f\xaa')  # SUB SP → MOV x0,xzr
FN_3BC648_RET_PATCH  = (0x3bc64c, b'\xf8\x5f\x11\xa9', b'\xc0\x03\x5f\xd6')  # STP → RET

# Layer 20 + 21: stderr log + Documents file log
# Cave at 0xe555e8 (96 bytes):
#   stp/stp/stp/stp registers, write(2,msg,18), reload msg, bl log_to_docs, ldp/ldp/ldp/ldp, b 0x3afe24
#   msg "[delta] bypass OK\n" at cave+0x48, zeros to cave+0x60
# Layer 21: log_to_docs subroutine at 0xe55648 (172 bytes):
#   getenv("HOME") → snprintf(path,128,"%s/Documents/delta_log.txt",home) → open/write/close
#   Strings at sub+0x88: "HOME\0\0\0\0", "%s/Documents/delta_log.txt\0"
LOG20_CAVE_ADDR     = 0xe555e8
LOG21_SUBROUTINE_ADDR = 0xe55648   # cave_base + 0x60 (96 bytes into cave)
LOG20_HOOK_ADDR     = 0x3afe14
LOG20_HOOK_EXPECTED = b'\x04\x00\x00\x14'   # B 0x3afe24 (Layer 18 result)
LOG20_HOOK_PATCH    = b'\xf5\x95\x2a\x94'   # BL 0xe555e8

# PLT stubs in libgloop.dylib
_PLT_WRITE    = 0xc75f2c
_PLT_GETENV   = 0xc758c0
_PLT_SNPRINTF = 0xc75d70
_PLT_OPEN     = 0xc75aac
_PLT_CLOSE    = 0xc75698

MSG21 = b'[delta] bypass OK\n'   # 18 bytes

def build_log20_cave(cave_base, log21_addr):
    """Cave at cave_base: write(2,msg,18), call log_to_docs(x1=msg,x2=18), restore, b 0x3afe24.
    Total: 18 instructions (0x48 bytes) + 18-byte msg + 6-byte pad = 96 bytes."""
    msg_addr = cave_base + 0x48
    i = []
    pc = cave_base
    def emit(b): nonlocal pc; i.append(b); pc += 4

    emit(_stp_pre(29, 30, 31, -0x60))            # stp x29,x30,[sp,#-0x60]!
    emit(_stp_off(0, 1, 31, 0x10))               # stp x0,x1,[sp,#0x10]
    emit(_stp_off(2, 3, 31, 0x20))               # stp x2,x3,[sp,#0x20]
    emit(_stp_off(4, 5, 31, 0x30))               # stp x4,x5,[sp,#0x30]
    emit(_movz(0, 2))                             # mov x0,#2 (stderr)
    emit(_adrp(pc, msg_addr, 1))                  # adrp x1, msg_page
    emit(_add_imm(1, 1, msg_addr & 0xFFF))        # add x1,x1,#msg_off
    emit(_movz(2, len(MSG21)))                    # mov x2,#18
    emit(_bl(pc, _PLT_WRITE))                     # bl _write
    emit(_adrp(pc, msg_addr, 1))                  # adrp x1, msg_page  (reload)
    emit(_add_imm(1, 1, msg_addr & 0xFFF))        # add x1,x1,#msg_off
    emit(_movz(2, len(MSG21)))                    # mov x2,#18
    emit(_bl(pc, log21_addr))                     # bl log_to_docs
    emit(_ldp_off(0, 1, 31, 0x10))               # ldp x0,x1,[sp,#0x10]
    emit(_ldp_off(2, 3, 31, 0x20))               # ldp x2,x3,[sp,#0x20]
    emit(_ldp_off(4, 5, 31, 0x30))               # ldp x4,x5,[sp,#0x30]
    emit(_ldp_post(29, 30, 31, 0x60))            # ldp x29,x30,[sp],#0x60
    emit(_b(pc, 0x3afe24))                        # b 0x3afe24

    assert pc == cave_base + 0x48, f"cave instr end at {pc:#x} expected {cave_base+0x48:#x}"
    code = b''.join(i) + MSG21 + b'\x00' * 6     # 72+18+6 = 96 bytes = 0x60
    assert len(code) == 0x60
    return code

def build_log21_subroutine(base):
    """log_to_docs(x1=msg_ptr, x2=msg_len):
    Appends message to $HOME/Documents/delta_log.txt.
    Saves/restores x19-x22, x29, x30. Total: 172 bytes."""
    # String data at base+0x88
    home_addr = base + 0x88
    fmt_addr  = base + 0x90
    log_ret   = base + 0x74   # 29 instructions * 4 = 0x74

    i = []
    pc = base
    def emit(b): nonlocal pc; i.append(b); pc += 4

    emit(_sub_sp(0xb0))                           # sub sp,sp,#0xb0
    emit(_stp_off(19, 20, 31, 0x80))              # stp x19,x20,[sp,#0x80]
    emit(_stp_off(21, 22, 31, 0x90))              # stp x21,x22,[sp,#0x90]
    emit(_stp_off(29, 30, 31, 0xa0))              # stp x29,x30,[sp,#0xa0]
    emit(_mov_reg(19, 1))                         # mov x19,x1  (msg_ptr)
    emit(_mov_reg(20, 2))                         # mov x20,x2  (msg_len)
    emit(_adrp(pc, home_addr, 0))                 # adrp x0, home_page
    emit(_add_imm(0, 0, home_addr & 0xFFF))       # add x0,x0,#home_off
    emit(_bl(pc, _PLT_GETENV))                    # bl _getenv
    emit(_cbz(pc, log_ret, 0))                    # cbz x0, log_ret
    emit(_mov_reg(21, 0))                         # mov x21,x0  (home ptr)
    emit(_add_x0_sp_0())                          # add x0,sp,#0  (pathbuf)
    emit(_movz(1, 128))                           # movz x1,#128
    emit(_adrp(pc, fmt_addr, 2))                  # adrp x2, fmt_page
    emit(_add_imm(2, 2, fmt_addr & 0xFFF))        # add x2,x2,#fmt_off
    emit(_mov_reg(3, 21))                         # mov x3,x21  (home)
    emit(_bl(pc, _PLT_SNPRINTF))                  # bl _snprintf
    emit(_add_x0_sp_0())                          # add x0,sp,#0  (path)
    emit(_movz(1, 0x209))                         # movz x1,#0x209 (O_WRONLY|O_CREAT|O_APPEND)
    emit(_movz(2, 0x1a4))                         # movz x2,#0644
    emit(_bl(pc, _PLT_OPEN))                      # bl _open
    emit(_cmn_w0_1())                             # cmn w0,#1
    emit(_beq(pc, log_ret))                       # b.eq log_ret
    emit(_mov_reg(22, 0))                         # mov x22,x0  (fd)
    emit(_mov_reg(1, 19))                         # mov x1,x19  (msg)
    emit(_mov_reg(2, 20))                         # mov x2,x20  (len)
    emit(_bl(pc, _PLT_WRITE))                     # bl _write  (x0=fd from above)
    emit(_mov_reg(0, 22))                         # mov x0,x22  (fd)
    emit(_bl(pc, _PLT_CLOSE))                     # bl _close
    # log_ret:
    assert pc == log_ret, f"log_ret at {pc:#x} expected {log_ret:#x}"
    emit(_ldp_off(29, 30, 31, 0xa0))              # ldp x29,x30,[sp,#0xa0]
    emit(_ldp_off(21, 22, 31, 0x90))              # ldp x21,x22,[sp,#0x90]
    emit(_ldp_off(19, 20, 31, 0x80))              # ldp x19,x20,[sp,#0x80]
    emit(_add_sp(0xb0))                           # add sp,sp,#0xb0
    emit(_ret())                                  # ret
    # Strings:
    assert pc == base + 0x88, f"strings at {pc:#x} expected {base+0x88:#x}"

    code = b''.join(i)
    code += b'HOME\x00\x00\x00\x00'               # 8 bytes at +0x88
    code += b'%s/Documents/delta_log.txt\x00'     # 27+1=28 bytes at +0x90
    return code                                   # total 0x88+8+28 = 0xAC = 172 bytes

# Layer 17: Runtime log stub injection into code cave at 0xe555e8
# Hooks fn@0x3afe10 entry (original: BL 0x3bc648) to call our stub first.
# Stub: getenv("HOME") → snprintf path → fopen("a") → fprintf → fclose,
# then tail-calls original fn@0x3bc648 so fn@0x3afe10 continues normally.
# Cave is in the zero-filled gap between __TEXT,__eh_frame and __DATA_CONST,__got.
LOG_CAVE_ADDR  = 0xe555e8
LOG_CAVE_BYTES = bytes.fromhex(
    'fd7bbaa9e00701a9e20f02a9e41703a9'  # prologue: stp/stp/stp/stp
    'e61f04a9f35305a9fd030091'          #           stp/stp, mov x29,sp
    '0000009000a01b91'                  # adrp+add x0 → "HOME"
    'ad80f897'                          # bl _getenv
    'c00200b4'                          # cbz x0, skip_all
    'f30300aa'                          # mov x19, x0  (save home ptr)
    'ff0304d1f4030091'                  # sub sp,sp,#256; mov x20,sp
    '80020091'                          # mov x0, x20  (buf)
    '012080d2'                          # movz x1, #256
    '0200009042b41b91'                  # adrp+add x2 → fmt string
    'e30313aa'                          # mov x3, x19  (home)
    'cf81f897'                          # bl _snprintf
    '80020091'                          # mov x0, x20  (path)
    '0100009021201c91'                  # adrp+add x1 → "a"
    '6980f897'                          # bl _fopen
    'e00000b4'                          # cbz x0, skip_write
    'f30300aa'                          # mov x19, x0  (fp)
    '0100009021281c91'                  # adrp+add x1 → msg
    '6780f897'                          # bl _fprintf
    'e00313aa'                          # mov x0, x19
    '4a80f897'                          # bl _fclose
    'ff030491'                          # skip_write: add sp,sp,#256
    'e00741a9e20f42a9e41743a9e61f44a9'  # skip_all: ldp x0-x7
    'f35345a9fd7bc6a8'                  # ldp x19,x20; ldp x29,x30,[sp],#96
    'f29bd517'                          # b fn@0x3bc648  (tail-call original)
    # 100 NUL bytes padding: brings data section to offset 0x100 from cave start
    + '00' * 100
    # Data strings
    + b'HOME\x00'.hex()
    + b'%s/Documents/delta_log.txt\x00'.hex()
    + b'a\x00'.hex()
    + b'[delta] fn@3afe10 triggered\n\x00'.hex()
)
# Original first instruction at fn@0x3afe10: BL 0x3bc648
LOG_HOOK_ADDR     = 0x3afe10
LOG_HOOK_EXPECTED = b'\x0e\x32\x00\x94'   # BL 0x3bc648
LOG_HOOK_PATCH    = b'\xf6\x95\x2a\x94'   # BL 0xe555e8 (our stub)

NOP = b'\x1f\x20\x03\xd5'

TAG      = b'By LYSTORE'          # 10 bytes
TAG_PAD  = TAG + b'\x00' * 6      # 16 bytes, fills LC_UUID field
UUID_OFF = 0x850                  # LC_UUID uuid field offset in libgloop.dylib

PLIST_PATH   = "Payload/Roblox.app/Info.plist"
DISPLAY_NAME = "Delta | By LYSTORE"

def stamp_dylib(dylib_data: bytearray):
    """Hide 'By LYSTORE' in the dylib's LC_UUID field (non-functional bytes)."""
    dylib_data[UUID_OFF:UUID_OFF + 16] = TAG_PAD
    print(f"  [隱藏] LC_UUID @ 0x{UUID_OFF:x} ← '{TAG.decode()}'")

def stamp_plist(plist_data: bytes) -> bytes:
    """Set CFBundleDisplayName to 'Delta | By LYSTORE' (visible under app icon)."""
    pl = plistlib.loads(plist_data)
    pl['CFBundleDisplayName']              = DISPLAY_NAME
    pl['CFBundleName']                     = DISPLAY_NAME
    pl['UIFileSharingEnabled']             = True   # 讓「檔案」app 看到 Documents 資料夾
    pl['LSSupportsOpeningDocumentsInPlace'] = True
    return plistlib.dumps(pl, fmt=plistlib.FMT_BINARY)

def patch_dylib(dylib_data: bytearray) -> bytearray:
    patched = 0
    for off, expected, desc in PATCHES:
        found = bytes(dylib_data[off:off+4])
        if found == NOP:
            print(f"  [已patch] 0x{off:x}: {desc}")
            patched += 1
            continue
        if found != expected:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")
            continue
        dylib_data[off:off+4] = NOP
        print(f"  [✓] 0x{off:x}: {expected.hex()} → {NOP.hex()}  {desc}")
        patched += 1

    # Overlay prevention: patch show-overlay fn to RET immediately
    off, expected, replacement = OVERLAY_PATCH
    found = bytes(dylib_data[off:off+4])
    if found == replacement:
        print(f"  [已patch] 0x{off:x}: overlay RET")
        patched += 1
    elif found == expected:
        dylib_data[off:off+4] = replacement
        print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [show overlay fn → RET]")
        patched += 1
    else:
        print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 3: unconditional branch to valid path (special non-NOP patch)
    off, expected, replacement = LAYER3_PATCH
    found = bytes(dylib_data[off:off+4])
    if found == replacement:
        print(f"  [已patch] 0x{off:x}: layer3 branch")
        patched += 1
    elif found == expected:
        dylib_data[off:off+4] = replacement
        print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [tbnz → b (valid路徑)]")
        patched += 1
    else:
        print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 5: in-game valid check — TBZ → unconditional B to good path (0x1c2b7c)
    off, expected, replacement = INGAME_VALID_PATCH
    found = bytes(dylib_data[off:off+4])
    if found == replacement:
        print(f"  [已patch] 0x{off:x}: in-game valid branch")
        patched += 1
    elif found == expected:
        dylib_data[off:off+4] = replacement
        print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [tbz → b (good path永遠)]")
        patched += 1
    else:
        print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    for label, (off, expected, replacement) in [
        ("fn@0x1b2960 (fail-path show overlay) → RET", SHOW_OVERLAY2_PATCH),
        ("fn@0x38e274 B.eq→B (啟動overlay路徑繞過)", LAYER6_PATCH),
        ("fn@0x38e274 BLR x16→NOP (pre-init overlay call)", BLR_NOP_PATCH),
        ("0x397868 CBZ x19→B 0x39d554 (強制跳過overlay block)", CBZ_OVERLAY_PATCH),
        ("fn@0x33b3a4 SUB SP→MOV x0,0 (啟動overlay init強制null返回)", FN_33B3A4_MOV0_PATCH),
        ("fn@0x33b3a4 STP→RET (啟動overlay init立即返回)", FN_33B3A4_RET_PATCH),
        ("fn@0x3a4ed4 → RET (overlay更新函數繞過)", SHOW_OVERLAY4_PATCH),
        ("0x2eb078 _objc_registerClassPair→NOP (阻止overlay ObjC class註冊)", REGISTER_CLASS_NOP_PATCH),
        ("0x3a4ea4 _objc_registerClassPair→NOP (剩餘active registerClassPair)", REGISTER_CLASS_NOP2_PATCH),
        ("fn@0x33ea4c → RET (class factory徹底阻斷)", FN_33EA4C_RET_PATCH),
        ("fn@0x2d0770 → RET (啟動overlay init chain根部阻斷)", FN_2D0770_RET_PATCH),
    ]:
        found = bytes(dylib_data[off:off+4])
        if found == replacement:
            print(f"  [已patch] 0x{off:x}: {label}")
            patched += 1
        elif found == expected:
            dylib_data[off:off+4] = replacement
            print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [{label}]")
            patched += 1
        else:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 13: NOP async dispatch_after triggers + allocateClassPair (async overlay root cause)
    for off, expected, desc in LAYER13_PATCHES:
        found = bytes(dylib_data[off:off+4])
        if found == NOP:
            print(f"  [已patch] 0x{off:x}: {desc}")
            patched += 1
        elif found == expected:
            dylib_data[off:off+4] = NOP
            print(f"  [✓] 0x{off:x}: {expected.hex()} → {NOP.hex()}  {desc}")
            patched += 1
        else:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 14: Kill fn@0x38e274 entirely + 4th dispatch_after + both dispatch_async submitters
    for off, expected, replacement in LAYER14_PATCHES:
        found = bytes(dylib_data[off:off+4])
        if found == replacement:
            print(f"  [已patch] 0x{off:x}: layer14")
            patched += 1
        elif found == expected:
            dylib_data[off:off+4] = replacement
            print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [layer14]")
            patched += 1
        else:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 15: NOP 3 BL _objc_msgSend inside fn@0x3bc648 (overlay UI calls only)
    for off, expected, desc in LAYER15_PATCHES:
        found = bytes(dylib_data[off:off+4])
        if found == NOP:
            print(f"  [已patch] 0x{off:x}: {desc}")
            patched += 1
        elif found == expected:
            dylib_data[off:off+4] = NOP
            print(f"  [✓] 0x{off:x}: {expected.hex()} → {NOP.hex()}  {desc}")
            patched += 1
        else:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 16: NOP 3 active msgSend calls in callees of fn@0x3bc648/fn@0x3afe10
    for off, expected, desc in LAYER16_PATCHES:
        found = bytes(dylib_data[off:off+4])
        if found == NOP:
            print(f"  [已patch] 0x{off:x}: {desc}")
            patched += 1
        elif found == expected:
            dylib_data[off:off+4] = NOP
            print(f"  [✓] 0x{off:x}: {expected.hex()} → {NOP.hex()}  {desc}")
            patched += 1
        else:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 11: NOP all 6 callers of stub@0xc75680 (overlay display PLT stub)
    for off, expected, desc in LAYER11_PATCHES:
        found = bytes(dylib_data[off:off+4])
        if found == NOP:
            print(f"  [已patch] 0x{off:x}: {desc}")
            patched += 1
        elif found == expected:
            dylib_data[off:off+4] = NOP
            print(f"  [✓] 0x{off:x}: {expected.hex()} → {NOP.hex()}  {desc}")
            patched += 1
        else:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 18: Force Delta execution path — CBZ x0 → unconditional B (bypasses fn@3aa68c crash)
    off, expected, replacement = FORCE_DELTA_PATH_PATCH
    found = bytes(dylib_data[off:off+4])
    if found == replacement:
        print(f"  [已patch] 0x{off:x}: force-Delta-path")
        patched += 1
    elif found == expected:
        dylib_data[off:off+4] = replacement
        print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [fn@0x3afe10 CBZ→B (強制走Delta執行路徑)]")
        patched += 1
    else:
        print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 19: Kill fn@0x3bc648 (overlay controller) at entry — returns nil immediately
    for label, (off, expected, replacement) in [
        ("fn@0x3bc648 SUB SP→MOV x0,xzr (overlay controller強制nil返回)", FN_3BC648_MOV0_PATCH),
        ("fn@0x3bc648 STP→RET (overlay controller立即返回)", FN_3BC648_RET_PATCH),
    ]:
        found = bytes(dylib_data[off:off+4])
        if found == replacement:
            print(f"  [已patch] 0x{off:x}: {label}")
            patched += 1
        elif found == expected:
            dylib_data[off:off+4] = replacement
            print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [{label}]")
            patched += 1
        else:
            print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    # Layer 20+21: stderr + Documents file logger
    # Build cave and subroutine bytes now (PC-relative encodings depend on base addresses)
    cave_bytes = build_log20_cave(LOG20_CAVE_ADDR, LOG21_SUBROUTINE_ADDR)
    sub_bytes  = build_log21_subroutine(LOG21_SUBROUTINE_ADDR)

    # Layer 21: write log_to_docs subroutine at 0xe55648
    off21 = LOG21_SUBROUTINE_ADDR
    sub_found = bytes(dylib_data[off21:off21+len(sub_bytes)])
    if sub_found == sub_bytes:
        print(f"  [已patch] 0x{off21:x}: log21 subroutine")
        patched += 1
    elif all(b == 0 for b in sub_found):
        dylib_data[off21:off21+len(sub_bytes)] = sub_bytes
        print(f"  [✓] 0x{off21:x}: log21 subroutine 寫入 ({len(sub_bytes)} bytes)")
        patched += 1
    else:
        print(f"  [跳過] 0x{off21:x}: subroutine cave 不是零 — IPA 版本不符")

    # Layer 20: write cave at 0xe555e8 (stderr + call log_to_docs)
    off20 = LOG20_CAVE_ADDR
    cave_found = bytes(dylib_data[off20:off20+len(cave_bytes)])
    if cave_found == cave_bytes:
        print(f"  [已patch] 0x{off20:x}: log20 cave")
        patched += 1
    elif all(b == 0 for b in cave_found):
        dylib_data[off20:off20+len(cave_bytes)] = cave_bytes
        print(f"  [✓] 0x{off20:x}: log20 cave 寫入 ({len(cave_bytes)} bytes)")
        patched += 1
    else:
        print(f"  [跳過] 0x{off20:x}: cave 不是零 — IPA 版本不符")

    # Hook: replace B 0x3afe24 at 0x3afe14 with BL cave (共用)
    off, expected, replacement = LOG20_HOOK_ADDR, LOG20_HOOK_EXPECTED, LOG20_HOOK_PATCH
    found = bytes(dylib_data[off:off+4])
    if found == replacement:
        print(f"  [已patch] 0x{off:x}: log20 hook")
        patched += 1
    elif found == expected:
        dylib_data[off:off+4] = replacement
        print(f"  [✓] 0x{off:x}: {expected.hex()} → {replacement.hex()}  [log20/21 hook B→BL cave]")
        patched += 1
    else:
        print(f"  [跳過] 0x{off:x}: 預期 {expected.hex()} 但找到 {found.hex()} — IPA 版本不符")

    return dylib_data, patched

def process_ipa(input_path: str, output_path: str):
    if not os.path.exists(input_path):
        print(f"錯誤: 找不到 {input_path}")
        sys.exit(1)

    print(f"輸入: {input_path}")
    print(f"輸出: {output_path}\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        print("解壓 IPA...")
        with zipfile.ZipFile(input_path, 'r') as z:
            z.extractall(tmpdir)

        dylib_full = os.path.join(tmpdir, DYLIB_PATH)
        if not os.path.exists(dylib_full):
            print(f"錯誤: 找不到 {DYLIB_PATH}")
            print("請確認 IPA 是 Delta executor (包含 libgloop.dylib)")
            sys.exit(1)

        print(f"修補 {DYLIB_PATH}...")
        with open(dylib_full, 'rb') as f:
            data = bytearray(f.read())

        data, count = patch_dylib(data)

        if count == 0:
            print("\n沒有成功 patch 任何位置，IPA 版本可能不符。")
            sys.exit(1)

        stamp_dylib(data)

        with open(dylib_full, 'wb') as f:
            f.write(data)

        plist_full = os.path.join(tmpdir, PLIST_PATH)
        if os.path.exists(plist_full):
            with open(plist_full, 'rb') as f:
                new_plist = stamp_plist(f.read())
            with open(plist_full, 'wb') as f:
                f.write(new_plist)
            print(f"  [顯眼] CFBundleDisplayName ← '{DISPLAY_NAME}'")

        total = len(PATCHES) + len(LAYER11_PATCHES) + len(LAYER13_PATCHES) + len(LAYER14_PATCHES) + len(LAYER15_PATCHES) + len(LAYER16_PATCHES) + 20
        print(f"\n重新打包 IPA ({count}/{total} patch 套用)...")
        payload_dir = os.path.join(tmpdir, "Payload")
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for root, dirs, files in os.walk(payload_dir):
                for file in files:
                    full = os.path.join(root, file)
                    arc = os.path.relpath(full, tmpdir)
                    zout.write(full, arc)

    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"\n完成! → {output_path}  ({size_mb:.1f} MB)")
    print("\n安裝方式: AltStore / Sideloadly / TrollStore 重新簽名後安裝")

def main():
    p = argparse.ArgumentParser(description="Delta IPA Key Bypass Patcher")
    p.add_argument("input", help="原始 IPA 路徑")
    p.add_argument("output", nargs="?", help="輸出 IPA 路徑 (預設: input_nokey.ipa)")
    args = p.parse_args()

    out = args.output
    if not out:
        base = os.path.splitext(args.input)[0]
        out = base + "_nokey.ipa"

    process_ipa(args.input, out)

if __name__ == "__main__":
    main()
