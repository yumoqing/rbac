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
from rbac.set_role_perms import set_role_perm, set_role_perms
from rbac.userperm import UserPermisions

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
	env.get_user_roles = userpermsissions.get_user_roles
	env.check_user_password = checkUserPassword
	env.register_user = register_user
	env.set_role_perm = set_role_perm
	env.set_role_perms = set_role_perms
	env.register_auth_method = register_auth_method
	env.get_org_users = get_org_users
	env.sor_get_org_users = sor_get_org_users
	env.get_owner_orgid = get_owner_orgid

