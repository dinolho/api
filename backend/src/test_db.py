import database, sys
database.set_current_db('postgresql://finances:password@localhost:5432/finances_user', 'postgres')
database.init_db()
print("Success")
