#!/usr/bin/env python3
"""
Delta IPA Key Bypass Patcher
用法: python3 delta_patch.py <input.ipa> [output.ipa]
"""

import sys, os, shutil, struct, zipfile, tempfile, argparse, plistlib

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
    pl['CFBundleDisplayName'] = DISPLAY_NAME
    pl['CFBundleName']        = DISPLAY_NAME
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

        total = len(PATCHES) + len(LAYER11_PATCHES) + len(LAYER13_PATCHES) + len(LAYER14_PATCHES) + 13  # +OVERLAY +LAYER3 +INGAME_VALID +SHOW_OVERLAY2 +LAYER6 +BLR_NOP +CBZ_OVERLAY +FN33B3A4_MOV0 +FN33B3A4_RET +SHOW_OVERLAY4 +REGISTER_CLASS_NOP +FN33EA4C_RET +FN2D0770_RET
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
