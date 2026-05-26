from sqlor.dbpools import get_sor_context
from appPublic.timeUtils import curDateString, timestampstr
from datetime import datetime, timedelta
from appPublic.log import debug, exception

async def get_user_stats(request):
    """Get user statistics for the platform"""
    env = request._run_ns
    today = curDateString()
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    month_start = datetime.now().strftime('%Y-%m-01')
    
    stats = {
        'total_users': 0,
        'active_users_today': 0,
        'new_users_this_month': 0,
        'total_orgs': 0
    }
    
    async with get_sor_context(env, 'rbac') as sor:
        # Total users
        sql_users = """
            SELECT COUNT(*) as cnt FROM users
        """
        recs = await sor.sqlExe(sql_users, {})
        if recs:
            stats['total_users'] = int(recs[0].cnt or 0)
        
        # Active users today (users with llmusage records today)
        sql_active = """
            SELECT COUNT(DISTINCT userid) as cnt FROM llmusage
            WHERE use_date >= ${today}$
                AND use_date < ${tomorrow}$
        """
        recs = await sor.sqlExe(sql_active, {
            'today': today,
            'tomorrow': tomorrow
        })
        if recs:
            stats['active_users_today'] = int(recs[0].cnt or 0)
        
        # New users this month
        sql_new = """
            SELECT COUNT(*) as cnt FROM users
            WHERE created_date >= ${month_start}$
        """
        recs = await sor.sqlExe(sql_new, {'month_start': month_start})
        if recs:
            stats['new_users_this_month'] = int(recs[0].cnt or 0)
        
        # Total organizations
        sql_orgs = """
            SELECT COUNT(*) as cnt FROM organization
        """
        recs = await sor.sqlExe(sql_orgs, {})
        if recs:
            stats['total_orgs'] = int(recs[0].cnt or 0)
    
    return stats
