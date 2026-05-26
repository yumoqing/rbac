"""
RBAC 工具函数 — 权限查询与文件扫描。

提供两个功能：
1. 查询指定路径拥有权限的所有角色
2. 扫描 wwwroot 下符号链接目录中未授权的文件

.dspy 文件应调用此模块的函数（通过 request._run_ns），自身不做 import。
每个函数返回 (title, message, is_error) 三元组，.dspy 据此返回 UiMessage 或 UiError。
"""
import os
from collections import defaultdict


async def query_path_roles(sor, path):
    """
    查询指定路径拥有权限的角色列表。

    Returns:
        (title, message, is_error)
    """
    if not path:
        return ('错误', '请输入路径', True)
    if not path.startswith('/'):
        path = '/' + path

    perm_recs = await sor.sqlExe(
        "SELECT id, path FROM permission WHERE path=${path}$",
        {'path': path}
    )
    if not perm_recs:
        like_path = path.rstrip('/') + '/%'
        like_recs = await sor.sqlExe(
            "SELECT path FROM permission WHERE path LIKE ${lp}$",
            {'lp': like_path}
        )
        msg = f"路径 '{path}' 未在 permission 表中注册。"
        if like_recs:
            sub = '<br>'.join([f'  {r.path}' for r in like_recs[:10]])
            if len(like_recs) > 10:
                sub += f'<br>... 共 {len(like_recs)} 条'
            msg += f'<br><br>模糊匹配到 {len(like_recs)} 个子路径：<br>{sub}'
        return ('未找到', msg, True)

    perm = perm_recs[0]
    permid = perm.id

    rp_recs = await sor.sqlExe(
        "SELECT roleid FROM rolepermission WHERE permid=${permid}$",
        {'permid': permid}
    )
    if not rp_recs:
        msg = f"路径: <b>{path}</b> (perm_id: {permid})<br><br>无任何角色拥有此路径权限。"
        return ('查询结果', msg, False)

    role_ids = [r.roleid for r in rp_recs]
    special = [rid for rid in role_ids if rid in ('any', 'anonymous', 'logined')]
    normal = [rid for rid in role_ids if rid not in ('any', 'anonymous', 'logined')]

    rows = []
    for sp in special:
        rows.append(f"<tr><td>{sp}</td><td>*</td><td>{sp}</td></tr>")

    if normal:
        placeholders = ','.join([f'${i}$' for i in range(len(normal))])
        ns = {f'_{i}': rid for i, rid in enumerate(normal)}
        role_recs = await sor.sqlExe(
            f"SELECT id, orgtypeid, name FROM role WHERE id IN ({placeholders})",
            ns
        )
        for r in role_recs:
            rows.append(
                f"<tr><td>{r.id}</td>"
                f"<td>{getattr(r, 'orgtypeid', '*')}</td>"
                f"<td>{getattr(r, 'name', r.id)}</td></tr>"
            )

    table = (
        "<table style='border-collapse:collapse;width:100%;'>"
        "<tr style='background:#334155;color:#fff;'>"
        "<th style='padding:6px 12px;text-align:left;border:1px solid #475569;'>角色ID</th>"
        "<th style='padding:6px 12px;text-align:left;border:1px solid #475569;'>orgtypeid</th>"
        "<th style='padding:6px 12px;text-align:left;border:1px solid #475569;'>名称</th>"
        "</tr>"
        + ''.join(rows) +
        "</table>"
    )

    html = (
        f"<p>路径: <b>{path}</b> (perm_id: {permid})</p>"
        f"<p>共 {len(rp_recs)} 个角色有权限：</p>"
        f"{table}"
    )
    return ('查询结果', html, False)


def find_symlink_dirs(root):
    """找出指定目录下直接子目录中是符号链接的目录。"""
    symlinks = []
    for entry in sorted(os.listdir(root)):
        full = os.path.join(root, entry)
        if os.path.islink(full) and os.path.isdir(full):
            target = os.readlink(full)
            symlinks.append((entry, full, target))
    return symlinks


def walk_symlink_dirs(root, symlinks):
    """
    遍历所有符号链接目录下的文件。
    Returns: list of (relative_path, absolute_path)
    """
    real_root = os.path.realpath(root)
    visited_real = set()
    files = []
    for name, link_path, target in symlinks:
        for r, dirs, filenames in os.walk(link_path, followlinks=True):
            real_r = os.path.realpath(r)
            if real_r in visited_real:
                dirs.clear()
                continue
            visited_real.add(real_r)
            dirs[:] = [d for d in dirs if os.path.realpath(os.path.join(r, d)) != real_root]
            for fname in sorted(filenames):
                abs_path = os.path.join(r, fname)
                rel = '/' + os.path.relpath(abs_path, root)
                files.append((rel, abs_path))
    return files


def resolve_wwwroot(wwwroot_param, file_path):
    """自动定位 wwwroot 目录。"""
    if wwwroot_param:
        wwwroot_param = os.path.abspath(wwwroot_param)
        if os.path.isdir(wwwroot_param):
            return wwwroot_param, None
        return None, f"wwwroot 目录不存在: {wwwroot_param}"

    sage_root = os.environ.get('SAGE_ROOT')
    if sage_root:
        wr = os.path.join(sage_root, 'wwwroot')
        if os.path.isdir(wr):
            return wr, None
        return None, f"SAGE_ROOT 指向的 wwwroot 不存在: {wr}"

    if '/wwwroot/' in file_path:
        idx = file_path.index('/wwwroot/')
        wr = file_path[:idx + len('/wwwroot')]
        if os.path.isdir(wr):
            return wr, None

    candidate = file_path
    for _ in range(5):
        candidate = os.path.dirname(candidate)
        if not candidate or candidate == '/':
            break
        wr = os.path.join(candidate, 'wwwroot')
        if os.path.isdir(wr):
            return wr, None

    return None, '无法自动定位 wwwroot 目录，请传入 wwwroot 参数或设置 SAGE_ROOT 环境变量。'


async def scan_unauth_files(sor, wwwroot_param, file_path):
    """
    扫描 wwwroot 下符号链接目录中未授权的文件。

    Returns:
        (title, message, is_error)
    """
    wwwroot, err = resolve_wwwroot(wwwroot_param, file_path)
    if err:
        return ('错误', err, True)

    symlinks = find_symlink_dirs(wwwroot)
    if not symlinks:
        return ('扫描结果', f"在 {wwwroot} 中未发现任何符号链接目录。", False)

    all_files = walk_symlink_dirs(wwwroot, symlinks)
    symlink_info = '<br>'.join([
        f"  {name}/ &rarr; {target}" for name, _, target in symlinks
    ])

    perm_recs = await sor.sqlExe("SELECT id, path FROM permission", {})
    path_to_permid = {r.path: r.id for r in perm_recs}

    rp_recs = await sor.sqlExe("SELECT DISTINCT permid FROM rolepermission", {})
    perms_with_roles = {r.permid for r in rp_recs}

    unauth = []
    authed = 0
    for rel_path, abs_path in all_files:
        permid = path_to_permid.get(rel_path)
        if permid is None:
            unauth.append((rel_path, '路径未注册'))
        elif permid not in perms_with_roles:
            unauth.append((rel_path, '有记录但无角色'))
        else:
            authed += 1

    by_module = defaultdict(list)
    for rel_path, reason in unauth:
        parts = rel_path.strip('/').split('/')
        module = parts[0] if parts else 'root'
        by_module[module].append((rel_path, reason))

    html = (
        f"<p><b>wwwroot:</b> {wwwroot}</p>"
        f"<p><b>符号链接目录 ({len(symlinks)}):</b><br>{symlink_info}</p>"
        f"<p>总文件数: {len(all_files)} | 已授权: {authed} | 未授权: {len(unauth)}</p>"
    )

    if not unauth:
        html += "<p style='color:#22C55E;font-weight:bold;'>所有文件均有权限覆盖，无需处理。</p>"
    else:
        html += f"<p style='color:#EF4444;font-weight:bold;'>未授权文件 ({len(unauth)} 个):</p>"
        for module in sorted(by_module.keys()):
            items = by_module[module]
            html += f"<h4 style='color:#FBBF24;'>{module}/ ({len(items)} 个文件)</h4>"
            html += "<ul style='font-family:monospace;font-size:12px;'>"
            for rel_path, reason in items[:50]:
                color = '#EF4444' if reason == '路径未注册' else '#F97316'
                html += f"<li style='color:{color};'>[{reason}] {rel_path}</li>"
            if len(items) > 50:
                html += f"<li>... 还有 {len(items) - 50} 个文件</li>"
            html += "</ul>"

    return ('扫描结果', html, False)
