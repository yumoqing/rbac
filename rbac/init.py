from ahserver.auth_api import AuthAPI
from ahserver.serverenv import ServerEnv
from .orgs import (
	get_platform_providers
)
from .userperm import UserPermissions
from rbac.check_perm import (
	objcheckperm, 
	get_org_users,
	sor_get_org_users,
	checkUserPassword, 
	register_user, 
	register_auth_method, 
	create_org, 
	create_user
)
from rbac.set_role_perms import (
	sor_add_user_roles,
	set_role_perm, 
	set_role_perms
)
from sqlor.dbpools import DBPools


def _get_rbac_dbname():
	env = ServerEnv()
	return env.get_module_dbname('rbac')


async def on_rbac_role_event(data):
	"""role 表变更后，全量失效 rp_caches"""
	up = UserPermissions()
	up.invalidate_rp_cache()


async def on_rbac_userrole_event(data):
	"""userrole 表变更后，精确失效对应用户的 ur_caches"""
	ns = data.get('ns', {})
	userid = ns.get('userid')
	up = UserPermissions()
	if userid:
		up.invalidate_user_cache(userid)
	else:
		up.invalidate_all_user_caches()


async def on_rbac_permission_event(data):
	"""permission 表变更后，全量失效 rp_caches"""
	up = UserPermissions()
	up.invalidate_rp_cache()


async def on_rbac_rolepermission_event(data):
	"""rolepermission 表变更后，全量失效 rp_caches"""
	up = UserPermissions()
	up.invalidate_rp_cache()


def register_rbac_event_listeners():
	db = DBPools()
	dbname = _get_rbac_dbname()

	# role 表
	db.bind(f'{dbname}:role:c:after', on_rbac_role_event)
	db.bind(f'{dbname}:role:u:after', on_rbac_role_event)
	db.bind(f'{dbname}:role:d:after', on_rbac_role_event)

	# userrole 表
	db.bind(f'{dbname}:userrole:c:after', on_rbac_userrole_event)
	db.bind(f'{dbname}:userrole:u:after', on_rbac_userrole_event)
	db.bind(f'{dbname}:userrole:d:after', on_rbac_userrole_event)

	# permission 表
	db.bind(f'{dbname}:permission:c:after', on_rbac_permission_event)
	db.bind(f'{dbname}:permission:u:after', on_rbac_permission_event)
	db.bind(f'{dbname}:permission:d:after', on_rbac_permission_event)

	# rolepermission 表
	db.bind(f'{dbname}:rolepermission:c:after', on_rbac_rolepermission_event)
	db.bind(f'{dbname}:rolepermission:u:after', on_rbac_rolepermission_event)
	db.bind(f'{dbname}:rolepermission:d:after', on_rbac_rolepermission_event)

async def get_owner_orgid(*args, **kw):
	return '0'

async def sor_get_owner_orgid(sor, orgid):
	return '0'

def load_rbac():
	AuthAPI.checkUserPermission = objcheckperm
	env = ServerEnv()
	env.userpermissions = UserPermissions()
	env.create_org = create_org
	env.get_platform_providers = get_platform_providers
	env.create_user = create_user
	env.get_user_roles = env.userpermissions.get_user_roles
	env.check_user_password = checkUserPassword
	env.register_user = register_user
	env.set_role_perm = set_role_perm
	env.set_role_perms = set_role_perms
	env.register_auth_method = register_auth_method
	env.get_org_users = get_org_users
	env.sor_get_org_users = sor_get_org_users
	env.get_owner_orgid = get_owner_orgid
	env.sor_add_user_roles = sor_add_user_roles
	# Cache invalidation methods for use after role/permission changes
	env.invalidate_user_perm_cache = env.userpermissions.invalidate_user_cache
	env.invalidate_all_perm_caches = env.userpermissions.invalidate_all_user_caches
	env.invalidate_role_perm_cache = env.userpermissions.invalidate_rp_cache
	# Bind hot_reload event — instance method, WeakMethod safe (stored on env)
	if hasattr(env, 'event_dispatcher'):
		env.event_dispatcher.bind('hot_reload', env.userpermissions.on_hot_reload)
	register_rbac_event_listeners()
