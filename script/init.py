import os
import sys
import argparse

from traceback import format_exc
import asyncio
from appPublic.uniqueID import getID
from appPublic.timeUtils import days_between, strdate_add
from appPublic.jsonConfig import getConfig
from random import randint, random
from appPublic.folderUtils import listFile
from appPublic.registerfunction import RegisterFunction

from sqlor.dbpools import DBPools
from rbac.check_perm import mypassword
databases = {
		"sage":{
			"driver":"aiomysql",
			"async_mode":True,
			"coding":"utf8",
			"maxconn":100,
			"dbname":"sage",
			"kwargs":{
				"user":"test",
				"db":"sage",
				"password":"QUZVcXg5V1p1STMybG5Ia6mX9D0v7+g=",
				"host":"localhost"
			}
		}
}

async def insert_perm(path):
	db = DBPools()
	async with db.sqlorContext('sage') as sor:
		ns = {
			'id':getID(),
			'path':path
		}
		await sor.C('permission', ns)

av_folders = [
	'/index.ui',
	'/user.ui',
	'/menu.ui',
	'/get_code.dspy',
	'/top.ui',
	'/center',
	'/bottom.ui',
	'/app_panel.ui',
	'/bricks',
	'/imgs',
	'/login.ui',
	'/gen_code.dspy',
	'/code_login.dspy',
	'/up_login.dspy',
	'/wechat_login.ui',
	'/public',
	'/debug/index.dspy',
	'/rbac/userpassword_login.ui',
	'/rbac/userpassword_login.dspy',
	'/tmp'
]


orgtypes = ['owner', 'reseller']
type_roles = {
	'owner':['superuser', 'customer'],
	'reseller':['admin','operator', 'sale', 'maintainer', 'accountant'],
	'customer':['admin', 'customer']
}

rbac_tables = [
	"organization", "orgtypes", "role", "users", "userrole", "rolepermission", "permission", 
	"userapp", "userdepartment" ]
	
role_perms = {
	'superuser': [
		'/get_code.dspy',
		'/rbac/add_adminuser.ui',
		'/rbac/add_adminuser.dspy',
		'/rbac/role/index.ui',
		'/rbac/role/get_role.dspy',
		'/rbac/role/update_role.dspy',
		'/rbac/role/delete_role.dspy',
		'/rbac/role/add_role.dspy',
		'/rbac/permission/add_permission.dspy',
		'/rbac/permission/delete_permission.dspy',
		'/rbac/permission/update_permission.dspy',
		'/rbac/permission/get_permission.dspy',
		'/rbac/permission/index.ui',
		'/rbac/rolepermission/add_rolepermission.dspy',
		'/rbac/rolepermission/delete_rolepermission.dspy',
		'/rbac/rolepermission/update_rolepermission.dspy',
		'/rbac/rolepermission/get_rolepermission.dspy',
		'/rbac/rolepermission/index.ui'
	],
	'admin':[
		'/rbac/users/add_users.dspy',
		'/rbac/users/delete_users.dspy',
		'/rbac/users/update_users.dspy',
		'/rbac/users/get_users.dspy',
		'/rbac/users/index.ui',
		'/rbac/userrole/add_userrole.dspy',
		'/rbac/userrole/delete_userrole.dspy',
		'/rbac/userrole/update_userrole.dspy',
		'/rbac/userrole/get_userrole.dspy',
		'/rbac/userrole/index.ui'
	]
}

async def init_perms():
	db = DBPools()
	async with db.sqlorContext('sage') as sor:
		for rn, pths in role_perms.items():
			roles = await sor.sqlExe('select * from role where name=${rn}$', {'rn':rn})
			if len(roles) == 0:
				print(f'{rn=} not exists')
				continue
			for p in pths:
				print(f'{rn=} set {p=}')
				perms = await sor.sqlExe('select * from permission where path=${p}$', {'p':p})
				if len(perms):
					await sor.C('rolepermission', {'id':getID(), 
								'roleid':roles[0].id,
								'permid':perms[0].id})
				else:
					print(f'{p} is not exists')
	
async def init_rbac(passwd):
	db = DBPools()
	async with db.sqlorContext('sage') as sor:
		recs = await sor.R('organization', {'id':'0'})
		if len(recs) > 0:
			return
		await sor.C('organization',{'id':'0'})
		await sor.C('orgtypes', {'id':getID(), 'orgid':'0', 'orgtypeid':'owner'})
		await sor.C('orgtypes', {'id':getID(), 'orgid':'0', 'orgtypeid':'reseller'})
		roleid = ''
		for orgtype, roles in type_roles.items():
			for r in roles:
				id = getID()
				await sor.C('role', {'id':id,'orgtypeid':orgtype,'name':r})
				if orgtype == 'owner' and r == 'superuser':
					roleid = id
		ns = {
			'id':getID(),
			'username':'superuser',
			'orgid':'0',
			'password':passwd
		}
		await sor.C('users', ns)
		ns1 = {
			'id':getID(),
			'userid':ns['id'],
			'roleid':roleid
		}
		await sor.C('userrole', ns1)

async def add_permissions(workdir):
	root = os.path.join(workdir, 'wwwroot')
	for f in listFile(root, rescursive=True):
		cnt = len(root)
		pth = f[cnt:]
		print(f'{f=},{root=},{pth=}, {cnt=}')
		act = True
		for f in av_folders:
			if pth.startswith(f):
				act = False
				break
		if act:
			await insert_perm(pth)

async def main(workdir, passwd):
	await add_permissions(workdir)
	await init_rbac(passwd)
	await init_perms()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog='RBAC init')
	parser.add_argument('-w', '--workdir')
	parser.add_argument('password')
	args = parser.parse_args()
	if args.password is None:
		parser.usage()
		sys.exit(1)
	print(f'{args=}')
	config = getConfig(args.workdir, {'workdir':args.workdir})
	supassword = mypassword(args.password)
	DBPools(config.databases)
	asyncio.get_event_loop().run_until_complete(main(args.workdir, supassword))

