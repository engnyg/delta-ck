# Delta IPA Key Bypass Patcher

移除 Delta executor IPA 的 key 驗證，無需輸入 key 即可使用。

## 需求

- Python 3（不需要安裝任何額外套件）
- Delta executor IPA 檔案（`Delta-2.741.1062202.ipa`）

## 使用方法

```bash
python3 delta_patch.py <input.ipa>
```

**範例：**

```bash
python3 delta_patch.py Delta-2.741.1062202.ipa
# 輸出: Delta-2.741.1062202_nokey.ipa
```

也可以自訂輸出檔名：

```bash
python3 delta_patch.py Delta-2.741.1062202.ipa Delta_patched.ipa
```

## 安裝 IPA

patch 後的 IPA 需要重新簽名才能安裝，選一種方式：

| 工具 | 適用情況 |
|------|----------|
| [AltStore](https://altstore.io) | 一般 iPhone，免越獄 |
| [Sideloadly](https://sideloadly.io) | 一般 iPhone，免越獄 |
| TrollStore | iOS 14–16.6.1 特定版本 |

## 原理

patcher 在 `libgloop.dylib` 的 key 驗證函數（`fn@0x3bc658`）中套用 4 個 NOP 指令，繞過所有 Keychain key 檢查：

| 位置 | 原指令 | 說明 |
|------|--------|------|
| `0x3bc718` | `cbz x19` | 無預存 key 檢查 |
| `0x3bc71c` | `cbz x8` | 解密字串空值檢查 |
| `0x3bc7dc` | `cbnz w20` | SecItemCopyMatching 失敗檢查 |
| `0x3bc7e4` | `cbz x8` | Keychain 結果空值檢查 |
