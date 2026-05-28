#!/usr/bin/env python3
"""
rbac 模块 RBAC 权限管理脚本

使用方法:
    cd ~/repos/sage
    ./py3/bin/python ~/rbac/scripts/load_path.py

每次代码变更如有新 path 出现，需同步更新此脚本。
"""

import subprocess
import os
import sys

def find_sage_root():
    candidates = [
        os.path.expanduser("~/repos/sage"),
        os.path.expanduser("~/sage"),
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    ]
    for c in candidates:
        if os.path.isdir(os.path.join(c, "py3")) and os.path.isdir(os.path.join(c, "wwwroot")):
            return c
    return None

SAGE_ROOT = find_sage_root()
if not SAGE_ROOT:
    print("ERROR: Cannot find Sage root directory")
    sys.exit(1)

PYTHON = os.path.join(SAGE_ROOT, "py3", "bin", "python")
SET_PERM_SCRIPT = os.path.join(SAGE_ROOT, "set_role_perm.py")

MOD = "rbac"

# ============================================================
# 权限路径定义 — 每次新增页面或API时同步更新
# ============================================================

# any — 无需登录（菜单、登录页等）
PATHS_ANY = [
    f"/rbac/admin_menu.ui",
    f"/rbac/gen_sms_code.dspy",
    f"/rbac/phone_login.dspy",
    f"/rbac/qr_scan.ui",
    f"/rbac/user/code_login.dspy",
    f"/rbac/user/login.ui",
    f"/rbac/user/logout.dspy",
    f"/rbac/user/register.dspy",
    f"/rbac/user/register.ui",
    f"/rbac/user/reset_password/index.ui",
    f"/rbac/user/reset_password/reset_password.dspy",
    f"/rbac/user/up_login.dspy",
    f"/rbac/usermenu.ui",
    f"/rbac/userpassword_login.dspy",
    f"/rbac/userpassword_login.ui",]

# logined — 需要认证的页面和 API
PATHS_LOGINED = [
    f"/rbac",
    f"/rbac/add_adminuser.dspy",
    f"/rbac/add_adminuser.ui",
    f"/rbac/add_provider.dspy",
    f"/rbac/add_provider.ui",
    f"/rbac/add_reseller.dspy",
    f"/rbac/add_superuser.dspy",
    f"/rbac/find_unauth_files.dspy",
    f"/rbac/get_all_roles.dspy",
    f"/rbac/get_normal_roles.dspy",
    f"/rbac/get_provider.dspy",
    f"/rbac/get_reseller.dspy",
    f"/rbac/index.ui",
    f"/rbac/list_path_roles.dspy",
    f"/rbac/list_path_roles.ui",
    f"/rbac/organization",
    f"/rbac/orgtypes",
    f"/rbac/permission",
    f"/rbac/provider",
    f"/rbac/refresh_userperm.dspy",
    f"/rbac/reseller",
    f"/rbac/role",
    f"/rbac/rolepermission",
    f"/rbac/stat_active_users.ui",
    f"/rbac/stat_total_orgs.ui",
    f"/rbac/stat_total_users.ui",
    f"/rbac/user",
    f"/rbac/user/myrole.ui",
    f"/rbac/user/user.ui",
    f"/rbac/user/user_panel.ui",
    f"/rbac/user/userapikey",
    f"/rbac/user/userapikey/add_userapikey.dspy",
    f"/rbac/user/userapikey/delete_userapikey.dspy",
    f"/rbac/user/userapikey/get_userapikey.dspy",
    f"/rbac/user/userapikey/index.ui",
    f"/rbac/user/userapikey/update_userapikey.dspy",
    f"/rbac/user/userinfo.ui",
    f"/rbac/user/wechat_login.ui",
    f"/rbac/userapp",
    f"/rbac/userdepartment",
    f"/rbac/userrole",
    f"/rbac/users",
    f"/rbac/usersync",
    f"/rbac/usersync/index.dspy",]

# ============================================================
# 执行注册
# ============================================================

def run_set_perm(role, path):
    cmd = [PYTHON, SET_PERM_SCRIPT, role, path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

def register_role_paths(role, paths):
    count = 0
    for p in paths:
        if run_set_perm(role, p):
            count += 1
    print(f"  {role}: {count}/{len(paths)} paths registered")
    return count

def main():
    print(f"Sage root: {SAGE_ROOT}")
    total = 0
    total += register_role_paths("any", PATHS_ANY)
    total += register_role_paths("logined", PATHS_LOGINED)
    print(f"\nDone. Total {total} permission entries registered.")
    print("NOTE: Restart Sage after permission changes to reload RBAC cache.")

if __name__ == "__main__":
    main()
