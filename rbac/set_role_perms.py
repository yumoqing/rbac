import sys
import os
import asyncio
from sqlor.dbpools import DBPools
from appPublic.jsonConfig import getConfig
from appPublic.uniqueID import getID
from appPublic.asynciorun import run

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

