#!/usr/bin/env python3
"""rbac 模块 RBAC 权限注册。"""

import subprocess

MOD = "rbac"

# any — 无需登录（登录页、注册、验证码、公共资源等）
PATHS_ANY = [
    f"/{MOD}/admin_menu.ui",
    f"/{MOD}/gen_sms_code.dspy",
    f"/{MOD}/login.css",
    f"/{MOD}/phone_login.dspy",
    f"/{MOD}/qr_scan.ui",
    f"/{MOD}/user/code_login.dspy",
    f"/{MOD}/user/login.ui",
    f"/{MOD}/user/logout.dspy",
    f"/{MOD}/user/register.dspy",
    f"/{MOD}/user/register.ui",
    f"/{MOD}/user/sms_register.dspy",
    f"/{MOD}/user/reset_password/index.ui",
    f"/{MOD}/user/reset_password/reset_password.dspy",
    f"/{MOD}/user/up_login.dspy",
    f"/{MOD}/usermenu.ui",
    f"/{MOD}/userpassword_login.dspy",
    f"/{MOD}/userpassword_login.ui",
    # 公共资源
    "/favicon.ico",
    "/i18n_getmsgs",
]

# logined — 需要认证的页面和 API
PATHS_LOGINED = [
    f"/{MOD}",
    f"/{MOD}/add_adminuser.dspy",
    f"/{MOD}/add_adminuser.ui",
    f"/{MOD}/add_provider.dspy",
    f"/{MOD}/add_provider.ui",
    f"/{MOD}/add_reseller.dspy",
    f"/{MOD}/add_superuser.dspy",
    f"/{MOD}/find_unauth_files.dspy",
    f"/{MOD}/get_all_roles.dspy",
    f"/{MOD}/get_normal_roles.dspy",
    f"/{MOD}/get_provider.dspy",
    f"/{MOD}/get_reseller.dspy",
    f"/{MOD}/index.ui",
    f"/{MOD}/list_path_roles.dspy",
    f"/{MOD}/list_path_roles.ui",
    f"/{MOD}/organization",
    f"/{MOD}/orgtypes",
    f"/{MOD}/permission",
    f"/{MOD}/provider",
    f"/{MOD}/refresh_userperm.dspy",
    f"/{MOD}/reseller",
    f"/{MOD}/role",
    f"/{MOD}/rolepermission",
    f"/{MOD}/stat_active_users.ui",
    f"/{MOD}/stat_total_orgs.ui",
    f"/{MOD}/stat_total_users.ui",
    f"/{MOD}/user",
    f"/{MOD}/user/myrole.ui",
    f"/{MOD}/user/user.ui",
    f"/{MOD}/user/user_panel.ui",
    f"/{MOD}/user/userapikey",
    f"/{MOD}/user/userapikey/add_userapikey.dspy",
    f"/{MOD}/user/userapikey/delete_userapikey.dspy",
    f"/{MOD}/user/userapikey/get_userapikey.dspy",
    f"/{MOD}/user/userapikey/index.ui",
    f"/{MOD}/user/userapikey/update_userapikey.dspy",
    f"/{MOD}/user/userinfo.ui",
    f"/{MOD}/user/edit_profile.dspy",
    f"/{MOD}/user/save_profile.dspy",
    f"/{MOD}/user/wechat_login.ui",
    f"/{MOD}/userapp",
    f"/{MOD}/userdepartment",
    f"/{MOD}/userrole",
    f"/{MOD}/users",
    f"/{MOD}/usersync",
    f"/{MOD}/usersync/index.dspy",
    f"/{MOD}/api/add_user.dspy",
    f"/{MOD}/api/update_user.dspy",
]


def register_paths():
    for path in PATHS_ANY:
        subprocess.run(["py3/bin/python", "set_role_perm.py", "any", path])
        print(f"  any: {path}")

    for path in PATHS_LOGINED:
        subprocess.run(["py3/bin/python", "set_role_perm.py", "logined", path])
        print(f"  logined: {path}")


if __name__ == "__main__":
    print(f"=== {MOD} RBAC registration ===")
    register_paths()
    print("Done.")
