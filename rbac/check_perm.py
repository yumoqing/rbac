import time

from traceback import format_exc
from aiohttp import BasicAuth
from sqlor.dbpools import DBPools, get_sor_context
from appPublic.registerfunction import RegisterFunction
from appPublic.rc4 import password, unpassword
from appPublic.jsonConfig import getConfig
from appPublic.log import debug, exception
from appPublic.dictObject import DictObject
from appPublic.timeUtils import curDateString
from appPublic.uniqueID import getID
from ahserver.auth_api import AuthAPI, user_login
from ahserver.globalEnv import password_encode
from ahserver.serverenv import ServerEnv, get_serverenv, set_serverenv
from .userperm import UserPermissions

async def get_org_users(orgid):
	env = ServerEnv()
	async with get_sor_context(env, 'rbac') as sor:
		return await sor_get_org_users(sor, orgid)
	return []

async def sor_get_org_users(sor, orgid):
	sql = "select * from users where orgid=${orgid}$"
	recs = await sor.sqlExe(sql, {'orgid': orgid})
	if len(recs):
		return recs
	return []

async def create_org(sor, ns, orgtypes=[]):
	await sor.C('organization', ns)
	if orgtypes == []:
		orgtypes = ['customer']
	if 'customer' not in orgtypes:
		orgtypes.append('customer')
	for ot in orgtypes:
		otns = {
			'id':getID(),
			'orgid':ns.id,
			'orgtypeid':ot
		}
		await sor.C('orgtypes', otns)
	
async def create_user(sor, ns, roles=[]):
	"""
	role format:
		{
			orgtypeid: rr,
			roles: ['ee', 'bb']
		}
	"""
	await sor.C('users', ns)
	if roles == []:
		roles = [
			{
				'orgtypeid': 'customer',
				'roles': [ 'customer']
			}
		]
	for rt in roles:
		sql = "select * from role where orgtypeid = ${otid}$ and name in ${roles}$"
		recs = await sor.sqlExe(sql, {
			'otid': rt['orgtypeid'],
			'roles': rt['roles']
			})
		for r in recs:
			await sor.C('userrole', {
					'id':getID(),
					'userid':ns.id,
					'roleid':r.id
			})

async def register_user(sor, ns):
	if ns.password != ns.cfm_password:
		debug('password not match')
		return False
	ns.password = password_encode(ns.password)
	recs = await sor.R('users', {'username': ns.username})
	if recs:
		return {
			"status": "error",
			"data": {
				"message": f"username({ns.username}) exists",
				"user": recs[0]
			}
		}
	id = getID()
	ns.id = id
	ns.orgid = id
	ns1 = DictObject(id=id, orgname=ns.username)
	await create_org(sor, ns1)
	await create_user(sor, ns)
	return {
		"status": "ok",
		"data": {
			"user": ns
		}
	}

def get_dbname():
	f = get_serverenv('get_module_dbname')
	if f is None:
		return None
	return f('rbac')

async def checkUserPassword(request, username, password):
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		sql = "select * from users where username=${username}$ and password=${password}$"
		recs = await sor.sqlExe(sql, {'username':username, 'password':password})
		if len(recs) < 1:
			return False
		await user_login(request, recs[0].id, 
							username=recs[0].username, 
							userorgid=recs[0].orgid)
		return True
	return False

async def basic_auth(sor, request):
	auth = request.headers.get('Authorization')
	auther = BasicAuth('x')
	m = auther.decode(auth)
	username = m.login
	password = password_encode(m.password)
	sql = "select * from users where username=${username}$ and password=${password}$"
	recs = await sor.sqlExe(sql, {'username':username,'password':password})
	if len(recs) < 1:
		return None
	await user_login(request, recs[0].id, 
							username=recs[0].username, 
							userorgid=recs[0].orgid)
	return recs[0].id
	
async def getAuthenticationUserid(sor, request):
	auth = request.headers.get('Authorization')
	if auth is None:
		return None
	for h,f in registered_auth_methods.items():
		if auth.startswith(h):
			return await f(sor, request)
	debug(f'{auth=}, {registered_auth_methods=} no match')
	return None
	
async def objcheckperm(obj, request, userid, path):
	debug(f'check permission: {userid=}, {path=}')
	sql = """select distinct a.*, c.userid from
(select id, path from permission where path=${path}$) a
right join
	rolepermission b on a.id = b.permid
right join userrole c on b.roleid = c.roleid
where c.userid = ${userid}$
"""

	dbname = get_dbname()
	db = DBPools()
	async with db.sqlorContext(dbname) as sor:
		if userid is None:
			userid = await getAuthenticationUserid(sor, request)
	uperm = UserPermissions()
	ret = await uperm.is_user_has_path_perm(userid, path)
	roles = await uperm.get_user_roles(userid)
	rp_keys = [k for k in uperm.self.rp_caches.keys()]
	debug(f'{userid=}, {path=} permission is {ret},userroles={roles}, {rp_keys}')
	return ret
	"""

		perms = await sor.R('permission', {'path':path})
		if len(perms) == 0:
			debug(f'{path=} not found in permission, can access')
			return True
		if userid is None:
			debug(f'{userid=} is None, can not access {path=}')
			return False

		recs = await sor.sqlExe(sql, {'path':path, 'userid':userid})
		for r in recs:
			id = r['id']
			if id is not None:
				debug(f'{userid=} can access {path=}')
				return True
		debug(f'{userid=} has not permission to call {path=}')
		return False
	e = db.e_except
	debug(f'objcheckperm() error happened {userid}, {path}, {e}\n{format_exc()}')
	return False
	"""

registered_auth_methods = {
	"Basic ": basic_auth
}

def register_auth_method(heading, func):
	registered_auth_methods[heading] = func

