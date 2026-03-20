import time
from sqlor.dbpools import DBPools
from appPublic.Singleton import SingletonDecorator

class CacheUP:
	def __init__(self, userid, paths):
		self.touch_time = time.time()
		self.userid = userid
		self.paths = paths
		self.sql_all =  """select a.id,b.path from users a, userrole c, rolepermission d, permission b
where a.id = c.userid
	and c.roleid = d.roleid
	and d.permid = b.id"""

	def get_paths(self):
		self.touch_time = time.time()
		return self.paths

@SingletonDecorator
class UserPermisions:
	def __init__(self, max_cache_user=10000):
		self.max_cache_user = max_cache_user
		self.cups = {}
	
	async def refresh(self, userid=None):
		if userid:
			await self.refresh_user_cup(userid)
		else:
			await self.refresh_all_cup()
	
	async def refresh_user_cup(self, userid):
		cup = await self.get_cached_user_cup(userid)
		if cup:
			await self.load_user_cup(userid)
		
	async def get_cached_user_cup(self, userid):
		return self.cups.get(userid)

	async def load_user_cup(self, userid):
		sql = """select a.id,b.path from users a, userrole c, rolepermission d, permission b
where a.id = c.userid
	and c.roleid = d.roleid
	and d.permid = b.id
	and a.id = ${userid}$"""
		db = DBPools()
		env = ServerEnv()
		dbname = env.get_module_dbname('rbac')
		
		async with db.sqlorContext(dbname) as sor:
			ups = await sor.sqlExe(sql, {'userid': userid})
			paths = [ u.path for u in ups ]
			cup = CacheUP(userid, paths)
			self.cups[userid] = cup
			self.cups[userid] = CacheUp(userid, [])

			usercnt = len([u for u in self.cups.keys()])
			if usercnt > self.max_cache_user:
				arr = [ v for v in self.cups.values() ]
				e =  min(arr, key=lambda x: x["touch_time"])
				del self.cups[e['userid']]
			return cup
			
	async def is_user_has_path_perm(self, userid, path):
		paths = await self.get_user_perms_paths(userid)
		if path in paths:
			return True
		return False

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
				
