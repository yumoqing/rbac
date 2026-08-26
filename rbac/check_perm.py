import time

from traceback import format_exc
from datetime import datetime, timedelta
from aiohttp import BasicAuth
from sqlor.dbpools import DBPools, get_sor_context
from appPublic.registerfunction import RegisterFunction
from appPublic.rc4 import password, unpassword
from appPublic.jsonConfig import getConfig
from appPublic.log import debug, exception
from appPublic.dictObject import DictObject
from appPublic.timeUtils import timestampstr
from appPublic.uniqueID import getID
from ahserver.auth_api import AuthAPI, user_login
from ahserver.globalEnv import password_encode
from ahserver.serverenv import ServerEnv, get_serverenv, set_serverenv
from .userperm import UserPermissions


# DB-agnostic time constants
LOGIN_LOCKOUT_DURATION = 300  # 5 minutes in seconds


def _now_ts():
	"""Current time as standard SQL timestamp string."""
	return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _is_locked(fail_count, last_fail, lockout_seconds=LOGIN_LOCKOUT_DURATION):
	"""Check if user is locked out. Pure Python, DB-agnostic."""
	if fail_count < 3 or last_fail is None:
		return False
	try:
		if isinstance(last_fail, str):
			stored = datetime.strptime(last_fail, '%Y-%m-%d %H:%M:%S')
		elif isinstance(last_fail, datetime):
			stored = last_fail
		else:
			return False
		return (datetime.now() - stored).total_seconds() < lockout_seconds
	except (ValueError, TypeError):
		return False

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
	if not ns.get('orgname'):
		ns.orgname = ns.id  # fallback: use id as orgname
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
	# 注册开关检查：appbase params 表 register_open（1=开放，0=关闭），superuser 可在参数管理界面改
	try:
		pro = await sor.R('params', {'params_name': 'register_open'})
		if pro and str(pro[0].params_value).strip() == '0':
			return {
				"status": "error",
				"data": {
					"message": "注册暂未开放，请联系管理员",
					"user": None
				}
			}
	except Exception as e:
		debug(f'register_user: register_open check skipped: {e}')

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
	ns.created_at = timestampstr()
	ns.login_fail_count = 0
	ns1 = DictObject(id=id, orgname=ns.username)
	if ns.get('parentid'):
		ns1.parentid = ns.parentid
	await create_org(sor, ns1)
	roles = [
		{
			'orgtypeid': 'customer',
			'roles': ['customer', 'admin']
		}
	]
	await create_user(sor, ns, roles)
	# 自动开客户账户（accounting 模块）。旁路，不阻断注册主流程：
	# 模块未加载/开户失败都只记日志，注册本身成功。
	try:
		env = ServerEnv()
		open_fn = getattr(env, 'openCustomerAccounts', None)
		get_dbname_fn = get_serverenv('get_module_dbname')
		if open_fn is not None and get_dbname_fn is not None:
			acc_dbname = get_dbname_fn('accounting')
			async with DBPools().sqlorContext(acc_dbname) as acc_sor:
				await open_fn(acc_sor, '0', ns.orgid)
				await acc_sor.sqlExe("COMMIT", {})
			debug(f'register_user: customer accounts opened for org({ns.orgid})')
	except Exception as e:
		debug(f'register_user: auto open customer accounts skipped: {e}')
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

def _req_ip(request):
	"""安全取客户端 IP（审计用），request 可能是 aiohttp Request 或 dict-like。"""
	try:
		return request.get('client_ip', '') if hasattr(request, 'get') else ''
	except Exception:
		return ''


async def _audit_login(sor, request, user_id, username, action, result='ok'):
	"""登录审计：检查系统是否安装审计模块(app_audit)，有则写入登录审计日志。

	审计是旁路，模块缺失或写入失败都不阻断登录主流程。
	"""
	try:
		from app_audit import audit_log
	except ImportError:
		return  # 未安装审计模块，跳过
	try:
		await audit_log(sor, user_id, username, action, result=result,
						client_ip=_req_ip(request))
	except Exception as e:
		debug(f'audit_login({action}) failed: {e}')


async def checkUserPassword(request, username, password):
	"""Authenticate user with password, supporting login lockout mechanism.
	
	High-concurrency safe:
	- Atomic UPDATE for fail_count increment (standard SQL, all databases)
	- Lockout check done in Python layer (no DB-specific functions)
	- Password verified with single atomic query
	"""
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		# Get user record with lockout fields
		sql = "select * from users where username=${username}$"
		recs = await sor.sqlExe(sql, {'username': username})
		if len(recs) < 1:
			debug(f'User {username} not found')
			await _audit_login(sor, request, None, username, 'login_fail', 'fail')
			return False
		
		user = recs[0]
		# Check user status (disabled)
		user_status = getattr(user, 'user_status', '0') or '0'
		if user_status != '0':
			debug(f'User {username} is disabled (status={user_status})')
			await _audit_login(sor, request, user.id, username, 'login_fail', 'fail')
			return False
		fail_count = getattr(user, 'login_fail_count', 0) or 0
		last_fail = getattr(user, 'last_login_fail', None)
		
		# Lockout check in Python (DB-agnostic)
		if _is_locked(fail_count, last_fail):
			debug(f'User {username} locked out')
			await _audit_login(sor, request, user.id, username, 'login_fail', 'fail')
			return False
		
		# Verify password with standard SQL
		sql = "select * from users where username=${username}$ and password=${password}$"
		recs = await sor.sqlExe(sql, {'username': username, 'password': password})
		if len(recs) < 1:
			# 5分钟窗口：超过5分钟前的失败次数默认为0（原子 SQL，DB 无关）
			now_str = _now_ts()
			stale_before = (datetime.now() - timedelta(seconds=LOGIN_LOCKOUT_DURATION)).strftime('%Y-%m-%d %H:%M:%S')
			await sor.sqlExe("""
				UPDATE users 
				SET login_fail_count = CASE WHEN last_login_fail IS NULL OR last_login_fail < ${stale}$ THEN 1 ELSE login_fail_count + 1 END,
				    last_login_fail = ${now}$
				WHERE id = ${id}$
			""", {'id': user.id, 'now': now_str, 'stale': stale_before})
			debug(f'Login failed for {username}, fail_count incremented')
			await _audit_login(sor, request, user.id, username, 'login_fail', 'fail')
			return False
		
		# Login successful -- atomic reset
		now_str = _now_ts()
		await sor.sqlExe("""
			UPDATE users 
			SET login_fail_count = 0,
			    last_login_fail = NULL,
			    last_login = ${now}$
			WHERE id = ${id}$
		""", {'id': user.id, 'now': now_str})
		await user_login(request, user.id, 
							username=user.username, 
							userorgid=user.orgid)
		await _audit_login(sor, request, user.id, user.username, 'login', 'ok')
		return True
	return False

async def basic_auth(sor, request):
	auth = request.headers.get('Authorization')
	auther = BasicAuth('x')
	m = auther.decode(auth)
	username = m.login
	password = password_encode(m.password)
	# Standard SQL -- no DB-specific functions
	sql = "select * from users where username=${username}$ and password=${password}$"
	recs = await sor.sqlExe(sql, {'username':username,'password':password})
	if len(recs) < 1:
		await _audit_login(sor, request, None, username, 'login_fail', 'fail')
		return None
	# Check lockout in Python layer (DB-agnostic)
	user = recs[0]
	# Check user status (disabled)
	user_status = getattr(user, 'user_status', '0') or '0'
	if user_status != '0':
		debug(f'User {username} is disabled (status={user_status}) via basic auth')
		await _audit_login(sor, request, user.id, username, 'login_fail', 'fail')
		return None
	fail_count = getattr(user, 'login_fail_count', 0) or 0
	last_fail = getattr(user, 'last_login_fail', None)
	if _is_locked(fail_count, last_fail):
		debug(f'User {username} locked out via basic auth')
		await _audit_login(sor, request, user.id, username, 'login_fail', 'fail')
		return None
	# Update last_login on successful basic auth (standard SQL)
	now_str = _now_ts()
	await sor.sqlExe("""
		UPDATE users 
		SET login_fail_count = 0, last_login_fail = NULL,
		    last_login = ${now}$
		WHERE id = ${id}$
	""", {'id': recs[0].id, 'now': now_str})
	await user_login(request, recs[0].id, 
						username=recs[0].username, 
						userorgid=recs[0].orgid)
	await _audit_login(sor, request, recs[0].id, recs[0].username, 'login', 'ok')
	return recs[0].id
	
async def getAuthenticationUserid(sor, request):
	# 先检查 x-api-key header (Anthropic 标准认证)
	x_api_key = request.headers.get('x-api-key')
	if x_api_key:
		x_api_key_handler = get_serverenv('x_api_key_auth')
		if x_api_key_handler:
			return await x_api_key_handler(sor, request)
	
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

