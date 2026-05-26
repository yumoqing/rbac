from ahserver.auth_api import AuthAPI
from ahserver.serverenv import ServerEnv
from sqlor.dbpools import DBPools
from .orgs import (
	get_platform_providers
)
from .userperm import UserPermissions
from .user_stats import get_user_stats
from .rbac_tools import (
	query_path_roles,
	scan_unauth_files
)
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
from appPublic.log import debug
from ahserver.cache_sync import get_cache_sync

async def get_owner_orgid(*args, **kw):
	return '0'

async def sor_get_owner_orgid(sor, orgid):
	return '0'

def _bind_rbac_events(dbpools, dbname, up):
	"""Bind database events to RBAC cache invalidation handlers.
	
	Events are dispatched by sqlor after C/U/D operations.
	Format: {dbname}:{tablename}:{c|u|d}:after
	"""
	bindings = [
		# users table: invalidate specific user cache on C/U/D
		(f'{dbname}.users:c:after',     up.on_user_create),
		(f'{dbname}.users:u:after',     up.on_user_update),
		(f'{dbname}.users:d:after',     up.on_user_delete),
		# rolepermission table: invalidate role-permission cache on any change
		(f'{dbname}.rolepermission:c:after', up.on_rolepermission_change),
		(f'{dbname}.rolepermission:u:after', up.on_rolepermission_change),
		(f'{dbname}.rolepermission:d:after', up.on_rolepermission_change),
		# permission table: invalidate role-permission cache on update
		(f'{dbname}.permission:u:after',     up.on_permission_change),
		# role table: invalidate ALL caches (affects all users)
		(f'{dbname}.role:c:after',      up.on_role_change),
		(f'{dbname}.role:u:after',      up.on_role_change),
		(f'{dbname}.role:d:after',      up.on_role_change),
		# userrole table: invalidate specific user cache based on userid
		(f'{dbname}.userrole:c:after',  up.on_userrole_change),
		(f'{dbname}.userrole:u:after',  up.on_userrole_change),
		(f'{dbname}.userrole:d:after',  up.on_userrole_change),
	]
	for event_name, handler in bindings:
		dbpools.bind(event_name, handler)
		debug(f'RBAC event bound: {event_name}')


async def start_cache_sync():
	"""Start cache_sync and register RBAC reload callbacks."""
	env = ServerEnv()
	cache_sync = get_cache_sync()
	
	# Get Redis URL from session config
	try:
		redis_url = env.conf.website.session_redis.url
	except AttributeError:
		redis_url = "redis://127.0.0.1:6379"
	
	await cache_sync.start(redis_url)
	debug(f'RBAC cache_sync started with Redis URL: {redis_url}')
	
	# Register callbacks for cache invalidation messages from other processes
	up = env.userpermissions
	cache_sync.register('rbac:rp', up.invalidate_rp_cache)
	cache_sync.register('rbac:ur:all', up.invalidate_all_user_caches)
	# Note: rbac:ur:{userid} callbacks are handled by the invalidate_user_cache method itself


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
	env.get_user_stats = get_user_stats
	env.query_path_roles = query_path_roles
	env.scan_unauth_files = scan_unauth_files
	# Cache invalidation methods for use after role/permission changes
	env.invalidate_user_perm_cache = env.userpermissions.invalidate_user_cache
	env.invalidate_all_perm_caches = env.userpermissions.invalidate_all_user_caches
	env.invalidate_role_perm_cache = env.userpermissions.invalidate_rp_cache

	# Bind database events for automatic cache invalidation
	dbpools = DBPools()
	dbname = env.get_module_dbname('rbac')
	if dbname:
		_bind_rbac_events(dbpools, dbname, env.userpermissions)
		debug(f'RBAC event listeners bound for database: {dbname}')
	else:
		debug('RBAC event listeners skipped: no database configured for rbac module')
