import time
from sqlor.dbpools import DBPools, get_sor_context
from ahserver.serverenv import ServerEnv
from appPublic.Singleton import SingletonDecorator
from appPublic.log import debug, exception, error

@SingletonDecorator
class UserPermissions:
	def __init__(self, max_cache_user=10000):
		self.max_cache_user = max_cache_user
		self.cups = {}
		self.rp_caches = None
		self.ur_caches = {}
	
	async def get_user_roles(self, userid):
		if userid is None:
			return ['anonymous', 'any']
		roles = self.ur_caches.get(userid)
		if roles:
			return roles
		async with get_sor_context(ServerEnv(), 'rbac') as sor:
			await self.get_userroles(sor, userid)
			return self.ur_caches.get(userid)
		return None

	async def load_roleperms(self, sor):
		self.rp_caches = {}
		sql_all =  """select c.orgtypeid, c.name, b.path 
from rolepermission a, permission b, role c
where a.permid = b.id
	and c.id = a.roleid
order by c.orgtypeid, c.name"""
		recs = await sor.sqlExe(sql_all, {})
		for r in recs:
			k = 'anonymous'
			if k == 'any.any':
				k = 'any'
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
	and a.id = ${userid}$''', {'userid': userid})
		roles = ['any', '*.*']		# 登录用户
		for r in recs:
			if r.name == 'any':
				roles.append('any')
			else:
				roles.append(f'{r.orgtypeid}.{r.name}')
				roles.append(f'{r.orgtypeid}.*')
				roles.append(f'*.{r.name}')
		self.ur_caches[userid] = sorted(list(set(roles)))

	def check_roles_path(self, roles, path):
		for role in roles:
			paths = self.rp_caches.get(role)
			if not paths:
				return False
			return path in paths

	async def is_user_has_path_perm(self, userid, path):
		roles = self.ur_caches.get(userid)
		if userid is None:
			roles = ['any', 'anonymous']

		if self.rp_caches is None or not roles:
			env = ServerEnv()
			async with get_sor_context(env, 'rbac') as sor:
				if not self.rp_caches:
					await self.load_roleperms(sor)
				if not roles:
					await self.get_userroles(sor, userid)
					roles = self.ur_caches.get(userid)

		return self.check_roles_path(roles, path)
	

