#!/usr/bin/env python3
"""
Delta IPA Key Bypass Patcher
用法: python3 delta_patch.py <input.ipa> [output.ipa]
"""

import sys, os, shutil, struct, zipfile, tempfile, argparse

DYLIB_PATH = "Payload/Roblox.app/libgloop.dylib"

PATCHES = [
    # (fileoff, expected_bytes, description)
    (0x3bc718, b'\x73\x2a\x01\xb4', "cbz x19 → nop  [無預存key檢查]"),
    (0x3bc71c, b'\x48\x2a\x01\xb4', "cbz x8  → nop  [解密字串空值檢查]"),
    (0x3bc7dc, b'\x54\x24\x01\x35', "cbnz w20→ nop  [SecItemCopyMatching失敗檢查]"),
    (0x3bc7e4, b'\x08\x24\x01\xb4', "cbz x8  → nop  [Keychain結果空值檢查]"),
]

NOP = b'\x1f\x20\x03\xd5'

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

        with open(dylib_full, 'wb') as f:
            f.write(data)

        print(f"\n重新打包 IPA ({count}/4 patch 套用)...")
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
