import time
from sqlor.dbpools import DBPools
from ahserver.serverenv import ServerEnv
from appPublic.Singleton import SingletonDecorator
from appPublic.log import debug, exception, error

@SingletonDecorator
class UserPermisions:
	def __init__(self, max_cache_user=10000):
		self.max_cache_user = max_cache_user
		self.cups = {}
		self.rp_caches = None
		self.ur_caches = {}
	
	async def load_roleperms(self, sor):
		self.rp_caches = {}
		sql_all =  """select a.orgtypeid, a.name, b.path 
from rolepermission a, permission b
where a.permid = b.id
order by a.orgtypeid, a.name"""
		recs = sor.sqlExe(sql_all, {})
		for r in recs:
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
		roles = None
		if self.ur_caches is None:
			async with get_sor_context(env, 'rbac') as sor:
				await self.load_roleperms(sor)
				if userid:
					roles = self.ur_caches.get(userid)
					if not roles:
						await self.get_userroles(sor, userid)
					roles = self.ur_caches.get(userid)

		if userid is None:
			roles = ['anonymous']

		return self.check_roles_path(roles, path)
	

