#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动更新越狱源索引脚本（配合 GitHub Actions 使用）
- 扫描 debs/ 下所有 deb，解析 control，生成 Packages 条目
- 严格规范：Packages 用 CRLF、条目间 \r\n\r\n 分隔
- 旧版本共存：只追加新条目，不删任何已存在条目
- 只改目标条目：已存在的条目原样保留，不重建其他条目
- 中文/非 ASCII 文件名自动重命名为 {Package}_{Version}_{Arch}.deb
- 删除同步：debs/ 下被删除的 deb，自动从索引移除对应条目
- 更新 Packages.bz2 / Packages.xz / Release（保留原 Label 等头部）
- 无任何变更时不产生 commit（避免 Actions 无限循环）
"""
import os
import sys
import re
import gzip
import bz2
import lzma
import hashlib
import shutil

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else '.')
DEBS_DIR = os.path.join(ROOT, 'debs')
PACKAGES_PATH = os.path.join(ROOT, 'Packages')
RELEASE_PATH = os.path.join(ROOT, 'Release')


def parse_control_with_dpkg(path):
    """优先用系统 dpkg-deb 解析 control（最可靠）"""
    import subprocess
    try:
        out = subprocess.run(
            ['dpkg-deb', '-f', path],
            capture_output=True, timeout=20, check=True,
        )
        ctl = out.stdout.decode('utf-8', 'replace')
        fields = {}
        for line in ctl.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                fields[k.strip()] = v.strip()
        return fields or None
    except Exception as e:
        print('dpkg-deb 失败:', e)
        return None


def parse_ar_deb(path):
    """解析 deb（ar 归档），返回 control 文本 dict"""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return None
    if not data.startswith(b'!<arch>\n'):
        return None
    off = 8
    members = {}
    while off + 60 <= len(data):
        header = data[off:off + 60]
        name = header[0:16].decode('ascii', 'replace').strip()
        size = int(header[48:58].decode('ascii').strip())
        payload = data[off + 60:off + 60 + size]
        members[name] = payload
        off += 60 + size
        if size % 2 == 1:
            off += 1
    ct = members.get('control.tar.gz') or members.get('control.tar.xz')
    if not ct:
        return None
    import io
    import tarfile
    try:
        if ct[:2] == b'\x1f\x8b':
            buf = io.BytesIO(ct)
            cf = gzip.GzipFile(fileobj=buf).read()
            tf = tarfile.open(fileobj=io.BytesIO(cf))
        elif ct[:5] == b'\xfd7zXZ':
            buf = io.BytesIO(ct)
            cf = lzma.LZMADecompressor().decompress(buf.read())
            tf = tarfile.open(fileobj=io.BytesIO(cf))
        else:
            tf = tarfile.open(fileobj=io.BytesIO(ct))
        names = [m for m in tf.getnames() if m.endswith('/control')]
        if not names:
            return None
        ctl = tf.extractfile(names[0]).read().decode('utf-8', 'replace')
        fields = {}
        for line in ctl.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                fields[k.strip()] = v.strip()
        return fields
    except Exception as e:
        print('ar 解析失败 %s: %s' % (os.path.basename(path), e))
        return None


def normalize_section(sec, name, pkg):
    """新插件 Section 归一化到三大类：微信插件 / 系统美化 / 实用工具（禁止新分类）"""
    sec = (sec or '').strip()
    name = (name or '').strip()
    pkg = (pkg or '').strip()
    if sec in ('微信插件', '系统美化', '实用工具'):
        return sec
    text = (sec + ' ' + name + ' ' + pkg).lower()
    if any(k in text for k in (
            '微信', 'wechat', 'weixin', 'wcglass', 'wcliquidglass',
            'liquidui', 'wechatx', 'wkk.wechatx')):
        return '微信插件'
    if any(k in text for k in (
            '美化', '液态', '灵动', '控制中心', '玻璃', 'glass', '主题',
            'dock', '水印', '圆角', '套壳', '开关', '壁纸', '背景', '弹窗')):
        return '系统美化'
    return '实用工具'


def ascii_safe_name(package, version, arch):
    """生成安全文件名：Package_Version_Arch.deb（去非法字符）"""
    def safe(s):
        return re.sub(r'[^A-Za-z0-9._+~-]', '.', s)
    return '%s_%s_%s.deb' % (safe(package), safe(version), safe(arch))


def read_packages():
    """读现有 Packages，返回（条目列表, 是否 CRLF）"""
    if not os.path.exists(PACKAGES_PATH):
        return [], '\r\n'
    with open(PACKAGES_PATH, 'rb') as f:
        data = f.read()
    eol = '\r\n' if b'\r\n' in data else '\n'
    text = data.decode('utf-8', 'replace').replace('\r\n', '\n').replace('\r', '\n')
    entries = []
    for block in text.split('\n\n'):
        block = block.strip()
        if block:
            entries.append(block)
    return entries, eol


def write_packages(entries):
    """写 Packages：全部 CRLF、条目间 \r\n\r\n"""
    if not entries:
        return
    normalized = []
    for e in entries:
        e = e.replace('\r\n', '\n').replace('\r', '\n')
        normalized.append('\r\n'.join(e.split('\n')))
    content = '\r\n\r\n'.join(normalized) + '\r\n'
    with open(PACKAGES_PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(content)


def build_entry(control, filename, size, md5, sha1, sha256):
    """按标准顺序构造条目，只取 control 中存在的字段"""
    order = [
        'Package', 'Name', 'Version', 'Architecture', 'Section',
        'Author', 'Maintainer', 'Depends', 'Icon', 'SileoDepiction',
        'Description',
    ]
    lines = []
    for k in order:
        if k in control and control[k]:
            v = control[k]
            lines.append('%s: %s' % (k, v))
    lines.append('Filename: %s' % filename)
    lines.append('Size: %d' % size)
    lines.append('MD5sum: %s' % md5)
    lines.append('SHA1: %s' % sha1)
    lines.append('SHA256: %s' % sha256)
    return '\n'.join(lines)


def update_release(entries):
    """更新 Release：保留 MD5Sum 之前的头部，重建三个哈希块"""
    if not os.path.exists(RELEASE_PATH):
        return False
    with open(RELEASE_PATH, 'rb') as f:
        rel = f.read().decode('utf-8', 'replace')
    lines = rel.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    head = []
    for l in lines:
        if l.startswith('MD5Sum'):
            break
        head.append(l)
    while head and head[-1] == '':
        head.pop()
    normalized = []
    for e in entries:
        e = e.replace('\r\n', '\n').replace('\r', '\n')
        normalized.append('\r\n'.join(e.split('\n')))
    pkg_bytes = ('\r\n\r\n'.join(normalized) + '\r\n').encode('utf-8')
    pkg_bz2 = bz2.compress(pkg_bytes, 9)
    pkg_xz = lzma.compress(pkg_bytes, preset=9)
    new_lines = head + ['']
    for mode, algo in (('MD5Sum', 'md5'), ('SHA1', 'sha1'), ('SHA256', 'sha256')):
        new_lines.append('%s:' % mode)
        for fn, fp in (('Packages', pkg_bytes), ('Packages.bz2', pkg_bz2), ('Packages.xz', pkg_xz)):
            h = getattr(hashlib, algo)(fp).hexdigest()
            new_lines.append(' %s %d %s' % (h, len(fp), fn))
        new_lines.append('')
    with open(RELEASE_PATH, 'w', encoding='utf-8', newline='') as f:
        f.write('\r\n'.join(new_lines))
    with open(os.path.join(ROOT, 'Packages.bz2'), 'wb') as f:
        f.write(pkg_bz2)
    with open(os.path.join(ROOT, 'Packages.xz'), 'wb') as f:
        f.write(pkg_xz)
    return True


def main():
    if not os.path.isdir(DEBS_DIR):
        print('debs/ 目录不存在')
        return
    entries, eol = read_packages()
    existing_keys = set()
    for e in entries:
        m = re.search(r'^Filename: (.+)$', e, re.M)
        if m:
            existing_keys.add(os.path.basename(m.group(1)))
        m2 = re.search(r'^Package: (.+)$', e, re.M)
        m3 = re.search(r'^Version: (.+)$', e, re.M)
        if m2 and m3:
            existing_keys.add('%s_%s' % (m2.group(1).strip(), m3.group(1).strip()))

    changed = False

    # ---- 删除同步：索引中指向 debs/ 的文件已不存在 → 移除对应条目 ----
    present = set()
    for fname in os.listdir(DEBS_DIR):
        if fname.endswith('.deb'):
            present.add(fname)

    if present:
        total_debs = 0
        missing = []
        for e in entries:
            mf = re.search(r'^Filename: (.+)$', e, re.M)
            if mf:
                fn = mf.group(1).strip()
                base = os.path.basename(fn)
                if '/debs/' in ('/' + fn.replace('\\', '/')):
                    total_debs += 1
                    if base.endswith('.deb') and base not in present:
                        missing.append((e, base))
        # 安全护栏：待删除条目超过总条目一半 → 疑似 checkout 异常/误删，中止
        if total_debs and len(missing) > total_debs * 0.5:
            print('ABORT 删除数量异常 (%d/%d)，疑似环境问题，跳过删除' % (len(missing), total_debs))
        else:
            removed_keys = set()
            for e, base in missing:
                mp = re.search(r'^Package: (.+)$', e, re.M)
                mv = re.search(r'^Version: (.+)$', e, re.M)
                print('REMOVE %s %s (%s)' % (
                    mp.group(1).strip() if mp else '?',
                    mv.group(1).strip() if mv else '?',
                    base,
                ))
                removed_keys.add(base)
                changed = True
            entries = [e for e in entries if not (
                re.search(r'^Filename: (.+)$', e, re.M) and
                os.path.basename(re.search(r'^Filename: (.+)$', e, re.M).group(1).strip()) in removed_keys
            )]

    for fname in sorted(os.listdir(DEBS_DIR)):
        if not fname.endswith('.deb'):
            continue
        fpath = os.path.join(DEBS_DIR, fname)
        control = parse_control_with_dpkg(fpath) or parse_ar_deb(fpath)
        if not control:
            print('SKIP 无法解析 control:', fname)
            continue
        package = control.get('Package', '')
        version = control.get('Version', '')
        arch = control.get('Architecture', 'iphoneos-arm64')
        # 新插件 Section 归一化：只归入三大类，不新增分类
        if 'Section' in control:
            control['Section'] = normalize_section(
                control.get('Section'), control.get('Name'), package)
        with open(fpath, 'rb') as f:
            data = f.read()
        size = len(data)
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        key = fname
        key2 = '%s_%s' % (package, version)
        if key in existing_keys or key2 in existing_keys:
            # 已存在条目：绝不重命名、不追加
            continue

        # 仅新增 deb：中文/非 ASCII 文件名 → 自动改英文
        safe_new = ascii_safe_name(package, version, arch)
        if not fname.isascii():
            newpath = os.path.join(DEBS_DIR, safe_new)
            if not os.path.exists(newpath):
                os.rename(fpath, newpath)
                print('RENAME %s -> %s' % (fname, safe_new))
                fname = safe_new
                fpath = newpath
                changed = True
            else:
                print('WARN 目标已存在，保留原名:', fname)

        entry = build_entry(control, 'debs/%s' % fname, size, md5, sha1, sha256)
        entries.append(entry)
        existing_keys.add(key)
        existing_keys.add(key2)
        print('ADD %s %s' % (package, version))
        changed = True

    if not changed:
        print('NO_CHANGES')
        return

    write_packages(entries)
    update_release(entries)
    print('DONE entries=%d' % len(entries))


if __name__ == '__main__':
    main()
