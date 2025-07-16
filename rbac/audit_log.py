from sqlor.dbpools import DBPools
from appPublic.dictObject import DictObject
from appPublic.uniqueID import getID
import json

def write_audit_log(sor, request):
	id = getID()
	params_kw = get_params_kw(request)
	
