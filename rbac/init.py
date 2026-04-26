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
