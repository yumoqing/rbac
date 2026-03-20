from sqlor.dbpools import get_sor_context
from ahserver.serverenv import ServerEnv

async def get_platform_providers():
	env = ServerEnv()
	async with get_sor_context(env, 'rbac') as sor:
		sql = "select a.id, a.orgname from organization a, orgtypes b where a.id= b.orgid and b.orgtypeid = 'provider' order by a.orgname"
		return await sor.sqlExe(sql, {})
	return []
