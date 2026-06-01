created = datetime.strptime(role["CreateDate"], "%Y-%m-%d")
today = datetime.now()
role_age_days = (today - created).days

if role_age_days > 90 and len(used) == 0:
    ghost = True
else:
    ghost = False
