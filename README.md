# rbac — 角色权限模块

产线平台/Sage 系应用的基础模块，提供**用户、机构、角色、权限（RBAC）**的完整管理体系，以及登录认证（密码/短信/扫码/Bearer API key 等多种认证方式注册点）、权限校验拦截、审计日志和双层权限缓存。所有宿主应用的鉴权都收敛到本模块的 `objcheckperm`（挂到 `AuthAPI.checkUserPermission`）。

## 模块定位

- 数据模型层：用户/机构/角色/权限四套表（见下）。
- 认证层：`check_perm.py` 实现密码登录（含 3 次失败锁定 5 分钟）、`getAuthenticationUserid` 按 `Authorization` 头前缀分发到已注册的认证方法（内置 `Basic `，其他模块可通过 `register_auth_method` 注册，如 dapi 注册 `Bearer `/`Deerer `）。
- 授权层：`userperm.py` 的 `UserPermissions`（单例）负责"用户→角色→路径权限"的判定，含 LRU+Redis 双层缓存。
- 事件层：`init.py` 通过 DBPools 绑定 role/userrole/permission/rolepermission 四表的 C/U/D after 事件，变更即失效缓存。

## 表清单（models/*.json）

| 表 | 标题 | 关键字段 | 说明 |
|---|---|---|---|
| `users` | 用户 | id, username, password, email, orgid, nick_name, mobile, login_fail_count, last_login_fail, last_login | 密码 RC4（appPublic.rc4）加密存储 |
| `organization` | 机构 | id, orgname, orgabbr, alias_name, contactor, contactor_phone, province_id, city_id | 支持层级（parentid） |
| `orgtypes` | 机构拥有角色 | id, orgid, orgtypeid | orgtypeid 取自 appbase 的 `appcodes_kv`（parentid='org_type'） |
| `role` | 角色 | id, orgtypeid(默认'0'), name | 角色全名 = `{orgtypeid}.{name}` |
| `userrole` | 用户角色 | id, userid, roleid | 用户↔角色多对多 |
| `permission` | 权限 | id, name, parentid, path, icon, permtype, need_audit | path 即受保护的 URL 路径 |
| `rolepermission` | 角色权限表 | id, roleid, permid | 角色↔权限多对多 |
| `audit_log` | 审计日志 | id, permid, userid, params_kw, exe_date, exe_timestamp, remote_ip | need_audit 权限调用时由 `audit_log.write_audit_log` 落表 |

`models/` 为 sqlor DDL 源，`json/` 为 bricks CRUD 页面定义（另含 reseller.json、provider.json 等展示用定义）。

## 角色模型

- 判定键为 `{orgtypeid}.{name}`，加载用户角色时自动派生通配角色：`{orgtypeid}.*`、`*.{name}`；每个登录用户固定拥有 `any`、`logined` 两个隐式角色，未登录请求按 `anonymous`/`any` 处理。
- 常用内置角色（由部署脚本/SQL 种子创建）：
  - `owner.superuser` — 平台超级管理员（rbac 管理页面、`register_rbac_tools_perm.py` 注册的工具权限都挂在此角色）。
  - `owner.admin` — 平台管理员。
  - `owner.audit` — 审计只读角色（配合 audit_log 模块，审计独立性）。
  - `downapp.logined` — dapi 模块在 API key 认证成功后自动创建并授予（见 `ensure_downappuser_role_and_assign`）。
- 路径匹配（`check_roles_path`）：精确匹配、`**`/`%` 前缀通配、`/main/xxx` → `/xxx` 归一化。
- 超管创建参考 `pipeline-app/scripts/create_superuser.py`（orgtypeid=owner, roles=[superuser, admin]）。

## 缓存机制（重点）

`UserPermissions` 使用**双层缓存**：

- **L1 进程内**：`ur_caches`（用户→角色，LRU maxsize=10000，TTL **300s**）；`rp_caches`（角色→路径集合，全量，TTL **600s**，双检锁+原子换入防止加载期间 403）。
- **L2 Redis 共享**：经 `appPublic.share_cache`（`cache_set/cache_get/cache_invalidate`）写入，key 为 `rbac:role_perms`、`rbac:user_roles:{userid}`，TTL 与 L1 相同（600s/300s），供多 worker 进程复用。
- 开关：`config.json` 的 `module_cache.rbac=false` 可整体禁用缓存（调试用）。
- 失效途径：
  1. role/userrole/permission/rolepermission 表 C/U/D 事件（`register_rbac_event_listeners`，userrole 变更精确失效单个用户，其余全量失效 rp_caches）；
  2. `hot_reload` 事件（`on_hot_reload` 清空两层）；
  3. 手动调用 `ServerEnv().invalidate_user_perm_cache(userid)` / `invalidate_all_perm_caches()` / `invalidate_role_perm_cache()`，或访问 `/rbac/refresh_userperm.dspy`。

> **部署纪律：直接改数据库里的角色/权限数据（绕过事件绑定）后，缓存不会自动失效。必须 `redis-cli FLUSHDB` 清掉 L2 共享缓存并重启应用进程清掉各 worker 的 L1 缓存，否则最长 600 秒内旧权限继续生效（可能放行或误拦）。**

## 对外 API / dspy 端点（wwwroot/）

- 登录认证：`userpassword_login.dspy`、`phone_login.dspy`、`gen_sms_code.dspy`、`user/up_login.dspy`、`user/code_login.dspy`、`user/logout.dspy`、`user/register.dspy`、`user/sms_register.dspy`、`user/reset_password/reset_password.dspy`
- 用户资料：`user/edit_profile.dspy`、`user/save_profile.dspy`
- 管理端：`add_adminuser.dspy`、`add_provider.dspy`、`get_provider.dspy`、`add_reseller.dspy`、`get_reseller.dspy`
- 角色权限查询：`get_all_roles.dspy`、`get_normal_roles.dspy`、`list_path_roles.dspy`、`find_unauth_files.dspy`（扫描 wwwroot 中未注册权限的文件）、`api/get_search_roleid.dspy`
- 用户 CRUD：`api/add_user.dspy`、`api/update_user.dspy`
- 管理员对他人的敏感操作（仅 `* admin` 角色，见 load_path.py 的 PATHS_ADMIN）：`api/admin_reset_password.dspy`（重置他人密码，禁止对自己操作，自己改密走自助入口）、`api/clear_login_fail.dspy`（清除连续登录失败次数）、`admin_reset_password.ui`（PopupWindow 表单，隐藏字段 userid 由 `params_kw.get('id')` 服务端注入）
- 缓存刷新：`refresh_userperm.dspy`
- 用户同步：`usersync/index.dspy`（把 rbac 用户同步到 dapi 并生成 API key，接口文档见 `docs/userasync-api.md`）
- UI：`admin_menu.ui`、`list_path_roles.ui`、`user/login.ui`、`user/user_panel.ui`、`stat_*.ui`（用户/机构统计卡片）等

权限注册分三档：`any`（免登录，见 `scripts/load_path.py` 的 PATHS_ANY）、`logined`（登录即可）、具体角色（如 `owner.superuser`，见 `script/register_rbac_tools_perm.py`；全局管理员档 `* admin` 见 PATHS_ADMIN）。`set_role_perm.py`（pipeline-app 根目录）按 `[orgtypeid.]name` 查 role 表取真实 roleid，特殊角色 any/anonymous/logined 用字面 id。

## load 注册函数

入口 `rbac/init.py` 的 **`load_rbac()`**，向 `ServerEnv()` 单例挂载：

```
env.userpermissions            # UserPermissions 单例
env.create_org / create_user / register_user / register_auth_method
env.check_user_password / get_user_roles / get_org_users / sor_get_org_users
env.set_role_perm / set_role_perms / sor_add_user_roles
env.get_platform_providers / get_owner_orgid
env.invalidate_user_perm_cache / invalidate_all_perm_caches / invalidate_role_perm_cache
AuthAPI.checkUserPermission = objcheckperm   # ahserver 鉴权拦截点
```

并绑定 hot_reload 事件与四张权限表的 DB 事件监听。

辅助模块：`rbac_tools.py`（query_path_roles/scan_unauth_files）、`audit_log.py`（write_audit_log）、`orgs.py`（get_platform_providers）、`user_stats.py`、`set_role_perms.py`、`version.py`。

## 宿主集成

宿主应用在启动入口（如 `sage/app/sage.py`、`pipeline-app/app/pipeline_app.py`、`cpcc/app/cpcc.py`、`filemgr/app/fileMGR.py`）中：

```python
from rbac.init import load_rbac
...
load_appbase()   # 先加载 appbase（rbac 注册开关读 params 表）
load_rbac()
load_dapi()      # 依赖 rbac 的 register_auth_method，必须在其后
```

依赖：ahserver（AuthAPI/ServerEnv）、sqlor（DBPools/get_sor_context）、appPublic（rc4/share_cache/jsonConfig 等）、appbase（params 表的 `register_open` 控制注册开关）。

数据库名解析：`ServerEnv().get_module_dbname('rbac')`，宿主需在 config.json 中配置模块→库映射（或默认同库）。

## 部署注意

1. **加载顺序**：appbase → rbac → dapi/业务模块；rbac 必须最先完成 `AuthAPI.checkUserPermission` 挂载，否则所有请求无鉴权。
2. **权限注册**：部署新页面/dspy 后运行 `scripts/load_path.py`（any/logined 分档）或 `set_role_perm.py` 注册路径权限，否则会被默认拦截；可用 `find_unauth_files.dspy` 扫描遗漏。
3. **改权限数据后必须 FLUSHDB + 重启**（见上文缓存机制），这是双层缓存（进程内 LRU + Redis，rp TTL 600s）下的硬性运维动作。
4. `script/init.py` 内含示例数据库口令，仅供本地初始化参考，生产以宿主 config.json 为准；密码字段一律 RC4（`appPublic.rc4.password`）加密。
5. 登录防爆破：3 次失败锁定 5 分钟（`LOGIN_LOCKOUT_DURATION`），审计写 `audit_log` 表；`need_audit='1'` 的权限调用也会落审计。
6. usersync 接口把用户下发给 dapi（下位系统 API key 体系），文档见 `docs/userasync-api.md`。
