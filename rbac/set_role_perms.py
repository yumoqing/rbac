import sys
import os
import asyncio
from sqlor.dbpools import DBPools
from appPublic.jsonConfig import getConfig
from appPublic.uniqueID import getID
from appPublic.dictObject import DictObject
from appPublic.asynciorun import run
from ahserver.serverenv import ServerEnv

async def sor_get_user_roles(sor, username):
	env = ServerEnv()
	sql = """select a.id,a.username, c.orgtypeid, c.name from users a, userrole b, role c where a.id = b.userid and b.roleid = c.id and a.username=${username}$"""
	recs = sor.sqlExe(sql, {'username': username})
	return recs

async def safe_add_user_role(sor, userid, orgtypeid, name):
	sql = """select b.* 
from users a, userrole b, role c
where a.id = b.userid
	and c.id = b.roleid
	and a.id = ${userid}$
	and c.orgtypeid = ${orgtypeid}$
	and c.name = ${name}$"""
	recs = await sor.sqlExe(sql, {
		'userid': userid,
		'orgtypeid': orgypeid,
		'name': name
	})
	if recs:
		return recs[0]
	ns = DictObject()
	ns.id = getID()
	roles = await sor.R('role', {
		'orgtypeid': orgypeid,
        'name': name
    })
	if not roles:
		return None
	ns.roleid = roles[0].id
	ns.userid = userid
	await sor.C('userrole', ns.copy())
	return ns

async def sor_add_user_roles(sor, userid, roles):
	"""
	roles is a list of role, each role has follow format
	orgtypeid1.*
	*.rolename1
	tttt.yyyyyy
	"""
	sql = """select
a.id, a.username, c.orgtypeid, c.name
from users a, orgtypes b, role c
where a.orgid = b.orgid
	and b.orgtypeid = c.orgtypeid
	and c.orgtypeid != '*'
	and c.name != '*'
	and a.id = ${userid}$"""
	recs = await sor.sqlExe(sql, {'userid': userid})
	for role in roles:
		otid, rname = role.split('.')
		ns = DictObject()
		if otid != '*':
			ns.otid = otid
		if rname != '*':
			ns.rname = rname
		for r in recs:
			if ns.otid and ns.otid != r.orgtypeid:
				continue
			if ns.rname and ns.rname != r.name:
				continue
			await safe_add_user_role(sor, userid, r.orgtypeid, r.name)

async def set_role_perm(dbname, module, orgtype, role, tblname):
	db = DBPools()
	async with db.sqlorContext(dbname) as sor:
		if '/' in dbname:
			path = [f'/{module}/{dbname}']
		else:
			paths = [
				f'/{module}/{tblname}',
				f'/{module}/{tblname}/index.ui',
				f'/{module}/{tblname}/get_{tblname}.dspy',
				f'/{module}/{tblname}/add_{tblname}.dspy',
				f'/{module}/{tblname}/delete_{tblname}.dspy',
				f'/{module}/{tblname}/update_{tblname}.dspy'
			]
		for pat in paths:
			recs = await sor.R('permission', {'path': pat})
			if len(recs) == 0:
				permid = getID()
				await sor.C('permission', {'id':permid, 'path':pat})
			else:
				permid = recs[0].id
			recs = await sor.R('role', {'orgtypeid':orgtype, 'name':role})
			if len(recs) == 0:
				roleid = getID()
				await sor.C('role', {
					'id':roleid,
					'name':role,
					'orgtypeid':orgtype
				})
			else:
				roleid = recs[0].id
			await sor.C('rolepermission', {
				'id':getID(),
				'roleid':roleid,
				'permid':permid
			})
		print(f'{orgtype=}, {role=}, {tblname=} permission configured')
						
async def set_role_perms(dbname, module, orgtype, role, items):
	for tblname in items:
		await set_role_perm(dbname, module, orgtype, role, tblname)

if __name__ == '__main__':
	async def main():
		if len(sys.argv) < 6:
			print(f'{sys.argv[0]} dbname module orgtype role tblname ...\n')
			sys.exit(1)
		dbname = sys.argv[1]
		module = sys.argv[2]
		orgtype = sys.argv[3]
		role = sys.argv[4]
		await set_role_perms(dbname, module, orgtype, role, sys.argv[5:])
		
	def run(coro):
		p = '.' 
		config = getConfig(p, {'woridir':p})
		DBPools(config.databases)
		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		loop.run_until_complete(coro())

	run(main)

