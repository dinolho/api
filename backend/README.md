python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 database.py
sqlite3 user/finance.db 'PRAGMA journal_mode=WAL;'
python3 app.py


update transactions set amount = 0 where type like '%transfer%' and amount > 0;
