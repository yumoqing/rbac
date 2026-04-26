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
	# Set registration timestamp
	ns.created_at = curDateString('%Y-%m-%d %H:%M:%S')
	ns.login_fail_count = 0
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
	"""Authenticate user with password, supporting login lockout mechanism.
	
	After 3 consecutive failed login attempts, the user is locked out for 5 minutes.
	On successful login, last_login is updated and fail count is reset.
	"""
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		# Get user record including login status fields
		sql = "select * from users where username=${username}$"
		recs = await sor.sqlExe(sql, {'username': username})
		if len(recs) < 1:
			return False
		
		user = recs[0]
		
		# Check login lockout: 3 consecutive failures within 5 minutes
		fail_count = getattr(user, 'login_fail_count', 0) or 0
		last_fail = getattr(user, 'last_login_fail', None)
		
		if fail_count >= 3 and last_fail:
			# Calculate time elapsed since last failed attempt
			now_ts = time.time()
			fail_ts = _parse_timestamp(last_fail)
			elapsed = now_ts - fail_ts
			if elapsed < 300:  # 5 minutes = 300 seconds
				remaining = int(300 - elapsed)
				debug(f'User {username} locked out, {remaining}s remaining')
				return False
			else:
				# Lockout period expired, reset fail count
				await sor.U('users', {'id': user.id}, {
					'login_fail_count': 0,
					'last_login_fail': None
				})
		
		# Check password
		sql = "select * from users where username=${username}$ and password=${password}$"
		recs = await sor.sqlExe(sql, {'username': username, 'password': password})
		if len(recs) < 1:
			# Password wrong - increment fail count
			new_fail_count = fail_count + 1
			await sor.U('users', {'id': user.id}, {
				'login_fail_count': new_fail_count,
				'last_login_fail': curDateString('%Y-%m-%d %H:%M:%S')
			})
			debug(f'Login failed for {username}, fail_count={new_fail_count}')
			return False
		
		# Login successful - reset fail count, update last_login
		await sor.U('users', {'id': user.id}, {
			'login_fail_count': 0,
			'last_login_fail': None,
			'last_login': curDateString('%Y-%m-%d %H:%M:%S')
		})
		await user_login(request, user.id, 
							username=user.username, 
							userorgid=user.orgid)
		return True
	return False

def _parse_timestamp(ts):
	"""Parse a timestamp string to unix timestamp."""
	from datetime import datetime
	if ts is None:
		return 0
	if isinstance(ts, (int, float)):
		return ts
	try:
		dt = datetime.strptime(str(ts), '%Y-%m-%d %H:%M:%S')
		return dt.timestamp()
	except (ValueError, TypeError):
		return 0

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
	# Update last_login on successful basic auth
	await sor.U('users', {'id': recs[0].id}, {
		'last_login': curDateString('%Y-%m-%d %H:%M:%S'),
		'login_fail_count': 0,
		'last_login_fail': None
	})
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
	if not ret:
		roles = await uperm.get_user_roles(userid)
		rp_keys = [k for k in uperm.rp_caches.keys()]
		debug(f'{userid=}, {path=} permission check failed,userroles={roles}')
	return ret

registered_auth_methods = {
	"Basic ": basic_auth
}

def register_auth_method(heading, func):
	registered_auth_methods[heading] = func

