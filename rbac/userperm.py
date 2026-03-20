import time
from sqlor.dbpools import DBPools
from ahserver.serverenv import ServerEnv
from appPublic.Singleton import SingletonDecorator
from appPublic.log import debug, exception, error

class CacheUP:
	def __init__(self, userid, paths):
		self.touch_time = time.time()
		self.userid = userid
		self.paths = paths
		if userid is None:
			sql
		self.sql_all =  """select a.id,b.path from users a, userrole c, rolepermission d, permission b
where a.id = c.userid
	and c.roleid = d.roleid
	and d.permid = b.id"""

	def get_paths(self):
		self.touch_time = time.time()
		return self.paths

class CacheRolePath:
@SingletonDecorator
class UserPermisions:
	def __init__(self, max_cache_user=10000):
		self.max_cache_user = max_cache_user
		self.cups = {}
		self.rp_caches = None
		self ur_caches = {}
	
	async def load_roleperms(self, sor):
		self.rp_caches = {}
		sql_all =  """select a.orgtypeid, a.name, b.path 
from rolepermission a, permission b
where a.permid = b.id
order by a.orgtypeid, a.name"""
		recs = sor.sqlExe(sql_all, {})
		for r recs:
			k = 'anonymous'
			if r.orgtypeid:
				k = f'{r.orgtypeid}.{r.name}'
			arr = self.rp_caches.get(k, [])
			arr.append(r.path)
			self.rp_caches[k] = arr

	async def get_userroles(self, sor, userid):
		recs = await sor.sqlExe('''select b.orgtypeid, b.name 
from users a, role b, userrole c
where a.id = c.userid
	and c.roleid = b.id
	and a.id = ${userid}''', {'userid': userid})
		roles = ['*.*']		# 登录用户
		for r in recs:
			append(f'{r.orgtypeid}.{r.name}')
			append(f'{r.orgtypeid}.*')
			append(f'*.{r.name}')
		self.ur_caches[userid] = sorted(list(set(roles)))

	def check_roles_path(self, roles, path):
		for role in roles:
			paths = self.rp_caches.get(role)
			return path in paths

	async def is_user_has_path_perm(self, userid, path):
		roles = self.ur_caches.get(userid)
		if userid is None:
			roles = ['anonymous']

		if self.ur_caches is None:
			async with get_sor_context(env, 'rbac') as sor:
				await self.load_roleperms(sor)

		if not roles:
			await self.get_userroles(sor, userid)

		return self.check_roles_path(roles, path)
	

	async def get_user_perms_paths(self, userid):
		cup = await self.get_cached_user_cup(userid)
		if cup:
			return cup.get_paths()
		cup = await self.load_user_cup(userid)
		return cup.get_paths()
	
	async def refresh_all_cup(self):
		db = DBPools()
		env = ServerEnv()
		dbname = env.get_module_dbname('rbac')
		sql = """select a.id,b.path from users a, userrole c, rolepermission d, permission b
where a.id = c.userid
	and c.roleid = d.roleid
	and d.permid = b.id order by a.id, b.path"""
 
		async with db.sqlorContext(dbname) as sor:
			ups = await sor.sqlExe(sql, {'userid': userid})
			userid = ''
			paths = []
			for u in ups:
				if userid != u.id:
					if userid != '':
						cup = CacheUP(userid, paths)
						self.cups[userid] = cup
						if len(self.cups.keys()) >= self.max_cache_user:
							break
						userid = u.id
						paths = []
				userid = u.id
				paths.append(u.path)
				
