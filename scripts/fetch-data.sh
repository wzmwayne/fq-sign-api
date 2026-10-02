#!/usr/bin/env bash
# 从【你自己合法持有的番茄小说 APK】中提取服务所需的原生库到 ./data/
# 用法: ./scripts/fetch-data.sh /path/to/你的番茄小说.apk
set -euo pipefail

APK="${1:-}"
if [ -z "$APK" ] || [ ! -f "$APK" ]; then
  echo "用法: $0 <你的番茄小说.apk>" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${FQ_DATA_DIR:-$ROOT/data}"
mkdir -p "$OUT"

echo "==> 提取到 $OUT"
for lib in libmetasec_ml.so libc++_shared.so; do
  if unzip -o -j "$APK" "lib/arm64-v8a/$lib" -d "$OUT" >/dev/null 2>&1; then
    echo "  ✓ $lib"
  else
    echo "  ✗ 未在 APK 中找到 lib/arm64-v8a/$lib" >&2
    echo "     注意：必须是【与代码匹配的版本】，否则签名入口偏移不同、无法工作" >&2
  fi
done

# 纯签名服务不需要真 APK，放个占位即可
[ -s "$OUT/base.apk" ] || printf 'placeholder' > "$OUT/base.apk"
echo "  ✓ base.apk（占位）"

# ms_16777218.bin 是上游 unidbg 项目随资源附带的数据文件，不在 APK 内
echo
echo "==> 完成："
ls -la "$OUT"
echo
echo "提示：ms_16777218.bin 属于第三方 unidbg 项目的附带资源，不在 APK 内，按需自行获取。"
