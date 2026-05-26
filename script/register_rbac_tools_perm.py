#!/usr/bin/env python
"""
注册 RBAC 工具的权限到数据库。
运行在 Sage Python 虚拟环境中。

用法:
    ./py3/bin/python ../rbac/script/register_rbac_tools_perm.py

或在 Sage 根目录执行:
    cd ~/repos/sage && ./py3/bin/python ../rbac/script/register_rbac_tools_perm.py
"""
import os
import sys
import asyncio

# 确保 Sage 路径在 sys.path 中
sage_root = os.environ.get('SAGE_ROOT')
if sage_root and sage_root not in sys.path:
    sys.path.insert(0, sage_root)

from sqlor.dbpools import DBPools
from appPublic.jsonConfig import getConfig
from appPublic.uniqueID import getID

# 需要注册的权限列表: (path, role)
permissions = [
    ('/rbac/list_path_roles.ui', 'owner.superuser'),
    ('/rbac/list_path_roles.dspy', 'owner.superuser'),
    ('/rbac/find_unauth_files.dspy', 'owner.superuser'),
    ('/rbac/admin_menu.ui', 'owner.superuser'),
]


async def main():
    config = getConfig('.')
    db = DBPools(config.databases)
    registered = 0

    async with db.sqlorContext('sage') as sor:
        # 查找 superuser 角色 ID
        role_recs = await sor.sqlExe(
            "SELECT id FROM role WHERE orgtypeid='owner' AND name='superuser'", {}
        )
        if not role_recs:
            print("错误: 未找到 owner.superuser 角色")
            sys.exit(1)
        superuser_id = role_recs[0].id
        print(f"superuser role_id: {superuser_id}")

        for path, role in permissions:
            # 检查 permission 是否已存在
            existing_perm = await sor.sqlExe(
                "SELECT id FROM permission WHERE path=${path}$", {'path': path}
            )
            if existing_perm:
                perm_id = existing_perm[0].id
                print(f"  permission 已存在: {path} (id={perm_id})")
            else:
                perm_id = getID()
                await sor.C('permission', {'id': perm_id, 'path': path})
                print(f"  + permission: {path}")

            # 检查 rolepermission 是否已存在
            existing_rp = await sor.sqlExe(
                "SELECT id FROM rolepermission WHERE roleid=${roleid}$ AND permid=${permid}$",
                {'roleid': superuser_id, 'permid': perm_id}
            )
            if existing_rp:
                print(f"    rolepermission 已存在")
            else:
                await sor.C('rolepermission', {
                    'id': getID(),
                    'roleid': superuser_id,
                    'permid': perm_id
                })
                registered += 1
                print(f"    + rolepermission: superuser -> {path}")

    print(f"\n共注册 {registered} 条新权限。")
    if registered > 0:
        print("请重启 Sage 以刷新权限缓存。")
    else:
        print("所有权限已存在，无需操作。")


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
