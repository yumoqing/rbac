#!/usr/bin/bash

python -m rbac.set_role_perms sage rbac owner superuser role permission rolepermission user user    role organizationorgtypes
python -m rbac.set_role_perms sage rbac owner admin user userrole
python -m rbac.set_role_perms sage rbac customer admin user userrole
python -m rbac.set_role_perms sage rbac reseller admin user userrole

