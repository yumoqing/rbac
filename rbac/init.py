from ahserver.auth_api import AuthAPI
from ahserver.serverenv import ServerEnv
from rbac.check_perm import objcheckperm, get_user_roles, checkUserPassword, register_user, register_auth_method, create_org, create_user
from rbac.set_role_perms import set_role_perm, set_role_perms

def load_rbac():
	AuthAPI.checkUserPermission = objcheckperm
	env = ServerEnv()
	env.create_org = create_org
	env.create_user = create_user
	env.get_user_roles = get_user_roles
	env.check_user_password = checkUserPassword
	env.register_user = register_user
	env.set_role_perm = set_role_perm
	env.set_role_perms = set_role_perms
	env.register_auth_method = register_auth_method


