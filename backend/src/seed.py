from database import get_db_connection, init_db
import datetime

def seed_data():
    conn = get_db_connection()
    
    # Create Accounts
    accounts = [
        ('Nubank', 'bank', 250050, 'Nubank'),
        ('XP Investimentos', 'wallet', 1500000, 'XP'),
        ('Binance BTC', 'crypto', 450000, 'Binance'),
        ('Inter Wallet', 'bank', 120000, 'Inter')
    ]
    
    for name, type, bal, inst in accounts:
        conn.execute('INSERT INTO accounts (name, type, balance, institution) VALUES (?, ?, ?, ?)', (name, type, bal, inst))
    
    conn.commit()
    
    # Get account IDs
    acc_rows = conn.execute('SELECT id, name FROM accounts').fetchall()
    nubank_id = [r['id'] for r in acc_rows if r['name'] == 'Nubank'][0]
    
    # Create Transactions
    today = datetime.date.today()
    transactions = [
        (nubank_id, (today - datetime.timedelta(days=1)).isoformat(), 'Supermercado', 'Alimentação', 25000, 'expense'),
        (nubank_id, (today - datetime.timedelta(days=2)).isoformat(), 'Posto Shell', 'Transporte', 18000, 'expense'),
        (nubank_id, (today - datetime.timedelta(days=3)).isoformat(), 'Salário Mensal', 'Salário', 500000, 'income'),
        (nubank_id, (today - datetime.timedelta(days=5)).isoformat(), 'Netflix', 'Assinaturas', 5590, 'expense'),
        (nubank_id, (today - datetime.timedelta(days=10)).isoformat(), 'Restaurante Japones', 'Alimentação', 15000, 'expense')
    ]
    
    for acc_id, date, desc, cat, amt, type in transactions:
        conn.execute('INSERT INTO transactions (account_id, date, description, category, amount, type, is_manual) VALUES (?, ?, ?, ?, ?, ?, 1)',
                     (acc_id, date, desc, cat, amt, type))
    
    conn.commit()
    conn.close()
    print("Sample data seeded.")

if __name__ == '__main__':
    init_db()
    seed_data()
