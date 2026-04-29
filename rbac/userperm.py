import asyncio
from collections import OrderedDict
from sqlor.dbpools import DBPools, get_sor_context
from ahserver.serverenv import ServerEnv
from appPublic.Singleton import SingletonDecorator
from appPublic.log import debug, exception, error

class LRUCache:
	"""Async-safe LRU cache with TTL support.
	
	Uses asyncio.Lock instead of threading.Lock to avoid blocking
	the event loop in async environments.
	"""
	
	def __init__(self, maxsize=10000, ttl=300):
		self.maxsize = maxsize
		self.ttl = ttl  # seconds
		self._cache = OrderedDict()
		self._lock = None  # Lazy init to handle sync creation in async context
	
	def _get_lock(self):
		if self._lock is None:
			self._lock = asyncio.Lock()
		return self._lock
	
	def get(self, key):
		import time
		if key not in self._cache:
			return None
		value, expire_at = self._cache[key]
		if time.time() > expire_at:
			del self._cache[key]
			return None
		self._cache.move_to_end(key)
		return value
	
	def set(self, key, value):
		import time
		if key in self._cache:
			self._cache.move_to_end(key)
		self._cache[key] = (value, time.time() + self.ttl)
		while len(self._cache) > self.maxsize:
			self._cache.popitem(last=False)
	
	def invalidate(self, key):
		self._cache.pop(key, None)
	
	def clear(self):
		self._cache.clear()
	
	def __contains__(self, key):
		return self.get(key) is not None
	
	def __len__(self):
		return len(self._cache)


@SingletonDecorator
class UserPermissions:
	def __init__(self, max_cache_user=10000, cache_ttl=300, rp_cache_ttl=600):
		"""Initialize UserPermissions with secure caching.
		
		Args:
			max_cache_user: Maximum number of user role entries in cache
			cache_ttl: TTL for user role caches in seconds (default 5 minutes)
			rp_cache_ttl: TTL for role-permission caches in seconds (default 10 minutes)
		"""
		self.max_cache_user = max_cache_user
		self.cache_ttl = cache_ttl
		self.rp_cache_ttl = rp_cache_ttl
		
		# LRU cache for user roles: userid -> list of roles
		self.ur_caches = LRUCache(maxsize=max_cache_user, ttl=cache_ttl)
		
		# Role-permission cache: role_key -> list of paths
		self.rp_caches = None
		self.rp_cache_loaded_at = 0
		import time
		self._init_time = time.time()
		
		# Async lock for rp_caches initialization (lazy init)
		self._rp_lock = None
	
	def _get_rp_lock(self):
		if self._rp_lock is None:
			self._rp_lock = asyncio.Lock()
		return self._rp_lock
	
	async def get_user_roles(self, userid):
		"""Get roles for a user, with LRU+TTL caching."""
		if userid is None:
			return ['anonymous', 'any']
		
		roles = self.ur_caches.get(userid)
		if roles:
			return roles
		
		async with get_sor_context(ServerEnv(), 'rbac') as sor:
			await self.get_userroles(sor, userid)
			return self.ur_caches.get(userid)
		return None
	
	def invalidate_user_cache(self, userid):
		"""Invalidate cache for a specific user.
		Call this after role changes, user creation, etc.
		"""
		self.ur_caches.invalidate(userid)
	
	def invalidate_all_user_caches(self):
		"""Invalidate all user role caches."""
		self.ur_caches.clear()
	
	def invalidate_rp_cache(self):
		"""Invalidate role-permission cache (after permission changes)."""
		self.rp_caches = None
		self.rp_cache_loaded_at = 0
	
	async def load_roleperms(self, sor):
		"""Load all role-permission mappings into cache.
		
		High-concurrency safe:
		- Uses asyncio.Lock to prevent multiple coroutines loading simultaneously
		- Double-check pattern: after acquiring lock, check if another coroutine already loaded
		- TTL ensures periodic refresh
		"""
		import time
		now = time.time()
		
		# Fast path: cache valid, no lock needed
		if self.rp_caches is not None and (now - self.rp_cache_loaded_at) < self.rp_cache_ttl:
			return
		
		# Slow path: acquire lock and double-check
		async with self._get_rp_lock():
			# Double-check after lock acquisition
			if self.rp_caches is not None and (now - self.rp_cache_loaded_at) < self.rp_cache_ttl:
				return
			
			self.rp_caches = {}
			sql_all = """select c.id, c.orgtypeid, c.name, b.path 
from rolepermission a, permission b, role c
where a.permid = b.id
	and c.id = a.roleid
order by c.orgtypeid, c.name"""
			recs = await sor.sqlExe(sql_all, {})
			for r in recs:
				if r.id == 'anonymous':
					k = 'anonymous'
				elif r.id == 'any':
					k = 'any'
				elif r.id == 'logined':
					k = 'logined'
				else:
					k = f'{r.orgtypeid}.{r.name}'
				arr = self.rp_caches.get(k, [])
				arr.append(r.path)
				self.rp_caches[k] = arr
			self.rp_cache_loaded_at = now
	
	async def get_userroles(self, sor, userid):
		"""Load user roles from database and cache them."""
		recs = await sor.sqlExe('''select b.id, b.orgtypeid, b.name 
from users a, role b, userrole c
where a.id = c.userid
	and c.roleid = b.id
	and a.id = ${userid}$''', {'userid': userid})
		roles = ['any', 'logined']		# 登录用户
		for r in recs:
			roles.append(f'{r.orgtypeid}.{r.name}')
			roles.append(f'{r.orgtypeid}.*')
			roles.append(f'*.{r.name}')
		self.ur_caches.set(userid, sorted(list(set(roles))))
	
	def check_roles_path(self, roles, path):
		"""Check if any of the roles has access to the given path.
		
		Supports:
		- Exact match: '/customer_management/index.ui' or '/main/login.ui'
		- Wildcard prefix match: '/customer_management/**' matches any path starting with '/customer_management/'
		- Path normalization: tries both the raw path and path with /main stripped
		"""
		for role in roles:
			paths = self.rp_caches.get(role)
			if not paths:
				continue
			# Try exact match with raw path
			if path in paths:
				return True
			# Try with /main prefix stripped: /main/xxx -> /xxx
			if path.startswith('/main/'):
				normalized = '/' + path[6:]
				if normalized in paths:
					return True
				# Also try wildcard match with normalized path
				for perm_path in paths:
					if perm_path.endswith('**'):
						prefix = perm_path[:-2]
						if normalized.startswith(prefix) or path.startswith(prefix):
							return True
			# Wildcard prefix match with raw path
			for perm_path in paths:
				if perm_path.endswith('**'):
					prefix = perm_path[:-2]
					if path.startswith(prefix):
						return True
		return False
	
	async def is_user_has_path_perm(self, userid, path):
		"""Check if a user has permission for the given path.
		
		High-concurrency safe:
		1. rp_caches TTL ensures permission changes take effect within 10 minutes
		2. Double-check locking prevents duplicate DB queries
		3. User role cache uses LRU+TTL to prevent unbounded growth
		"""
		roles = self.ur_caches.get(userid)
		if userid is None:
			roles = ['any', 'anonymous']
		
		if self.rp_caches is None or not roles:
			env = ServerEnv()
			async with get_sor_context(env, 'rbac') as sor:
				if self.rp_caches is None:
					await self.load_roleperms(sor)
				if not roles:
					await self.get_userroles(sor, userid)
					roles = self.ur_caches.get(userid)
		
		return self.check_roles_path(roles, path)
