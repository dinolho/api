"""init_db

Revision ID: 6bf245557571
Revises: 
Create Date: 2026-03-30 14:07:06.617792

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text

# revision identifiers, used by Alembic.
revision: str = '6bf245557571'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def get_now_expr(dialect_name: str) -> text:
    if dialect_name == 'postgresql':
        return text("TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')")
    return text("datetime('now')")

def upgrade() -> None:
    dialect = op.get_context().dialect.name
    now_expr = get_now_expr(dialect)

    # Accounts
    op.create_table(
        'accounts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('balance', sa.Integer(), server_default='0'),
        sa.Column('total_transfers', sa.Integer(), server_default='0'),
        sa.Column('total_balance', sa.Integer(), server_default='0'),
        sa.Column('currency', sa.String(), server_default='BRL'),
        sa.Column('institution', sa.String(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.PrimaryKeyConstraint('id')
    )

    # Entities
    op.create_table(
        'entities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('type', sa.String(), server_default='company'),
        sa.Column('document', sa.String(), nullable=True),
        sa.Column('bank', sa.String(), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('flags', sa.Integer(), server_default='0'),
        sa.Column('original_entity_id', sa.Integer(), nullable=True),
        sa.Column('display_name', sa.String(), nullable=True),
        sa.Column('exclude_from_reports', sa.Integer(), server_default='0'),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.ForeignKeyConstraint(['original_entity_id'], ['entities.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_entity_name', 'entities', ['name'])
    op.create_index('idx_entity_parent', 'entities', ['original_entity_id'])
    op.create_index('idx_entity_flags', 'entities', ['flags'])

    # Transactions
    op.create_table(
        'transactions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=True),
        sa.Column('date', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=True),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('is_manual', sa.Boolean(), server_default='0'),
        sa.Column('external_uid', sa.String(), nullable=True),
        sa.Column('raw_external_uid', sa.String(), nullable=True),
        sa.Column('entity_id', sa.Integer(), nullable=True),
        sa.Column('destination_account_id', sa.Integer(), nullable=True),
        sa.Column('raw_entity_id', sa.Integer(), nullable=True),
        sa.Column('conciliation_status', sa.Integer(), server_default='0'),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('flags', sa.Integer(), server_default='0'),
        sa.Column('recurring_id', sa.Integer(), nullable=True),
        sa.Column('raw_description', sa.String(), nullable=True),
        sa.Column('raw_amount', sa.Integer(), server_default='0'),
        sa.Column('liquidation_date', sa.String(), nullable=True),
        sa.Column('metadata', sa.String(), nullable=True),
        sa.Column('transaction_ref_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ),
        sa.ForeignKeyConstraint(['destination_account_id'], ['accounts.id'], ),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_txn_date', 'transactions', ['date'])
    op.create_index('idx_txn_account', 'transactions', ['account_id'])
    op.create_index('idx_txn_entity', 'transactions', ['entity_id'])
    op.create_index('idx_txn_raw_entity', 'transactions', ['raw_entity_id'])
    op.create_index('idx_txn_uid', 'transactions', ['external_uid'])
    op.create_index('idx_txn_conciliation', 'transactions', ['conciliation_status'])
    op.create_index('idx_txn_type_date', 'transactions', ['type', 'date'])
    op.create_index('idx_txn_category', 'transactions', ['category'])
    op.create_index('idx_txn_flags', 'transactions', ['flags'])
    op.create_index('idx_txn_recurring', 'transactions', ['recurring_id'])

    # Investments
    op.create_table(
        'investments',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('purchase_price', sa.Integer(), nullable=True),
        sa.Column('current_price', sa.Integer(), nullable=True),
        sa.Column('date', sa.String(), nullable=False),
        sa.Column('ticker', sa.String(), nullable=True),
        sa.Column('quantity', sa.Float(), server_default='0'),
        sa.Column('indexer', sa.String(), nullable=True),
        sa.Column('rate', sa.Float(), server_default='0'),
        sa.Column('maturity_date', sa.String(), nullable=True),
        sa.Column('application_date', sa.String(), nullable=True),
        sa.Column('redemption_term', sa.String(), nullable=True),
        sa.Column('gross_value', sa.Integer(), server_default='0'),
        sa.Column('net_value', sa.Integer(), server_default='0'),
        sa.Column('tax', sa.Integer(), server_default='0'),
        sa.Column('quota_value', sa.Integer(), server_default='0'),
        sa.Column('quota_date', sa.String(), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('institution', sa.String(), nullable=True),
        sa.Column('applied', sa.Integer(), server_default='0'),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Redacted Texts
    op.create_table(
        'redacted_texts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('text', sa.String(), nullable=False),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('text')
    )

    # System Config
    system_config_table = op.create_table(
        'system_config',
        sa.Column('key', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=True),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.PrimaryKeyConstraint('key')
    )
    op.bulk_insert(system_config_table, [
        {'key': 'redaction_enabled', 'value': '0'},
        {'key': 'invoice_day', 'value': '15'},
        {'key': 'db_version', 'value': '1.0.0'},
        {'key': 'credit_invoice_category', 'value': 'Fatura Cartão'},
        {'key': 'cents_migrated', 'value': '1'},
    ])

    # Categories
    categories_table = op.create_table(
        'categories',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('color', sa.String(), server_default='#6366f1'),
        sa.Column('icon', sa.String(), server_default='tag'),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    _default_categories = [
        ("Alimentação",  "#f59e0b"), ("Transporte",   "#06b6d4"),
        ("Moradia",      "#8b5cf6"), ("Saúde",        "#22c55e"),
        ("Educação",     "#3b82f6"), ("Lazer",        "#ec4899"),
        ("Assinaturas",  "#6366f1"), ("Salário",      "#10b981"),
        ("Investimento", "#0ea5e9"), ("Consórcios",   "#f97316"),
        ("Boleto",       "#ef4444"), ("Outros",       "#a1a1aa"),
        ("Crédito em Conta", "#22c55e"), ("Débito em Conta", "#ef4444"),
        ("Estorno", "#0b1913"), ("Fatura Cartão", "#2135f1"),
        ("Pix Enviado", "#02dba6"), ("Pix Recebido", "#d911b4"),
        ("Saque", "#7f67ec"),
    ]
    op.bulk_insert(categories_table, [
        {'name': n, 'color': c} for n, c in _default_categories
    ])

    # Tags
    op.create_table(
        'tags',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    op.create_table(
        'transaction_tags',
        sa.Column('transaction_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['tag_id'], ['tags.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['transaction_id'], ['transactions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('transaction_id', 'tag_id')
    )
    op.create_index('idx_txn_tags', 'transaction_tags', ['tag_id'])

    op.create_table(
        'entity_tags',
        sa.Column('entity_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tag_id'], ['tags.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('entity_id', 'tag_id')
    )
    op.create_index('idx_entity_tags', 'entity_tags', ['tag_id'])

    # Recurring Expenses
    op.create_table(
        'recurring_expenses',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=True),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(), server_default='expense'),
        sa.Column('frequency', sa.String(), server_default='monthly', nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=True),
        sa.Column('entity_id', sa.Integer(), nullable=True),
        sa.Column('next_date', sa.String(), nullable=True),
        sa.Column('active', sa.Integer(), server_default='1'),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Patrimony Items
    op.create_table(
        'patrimony_items',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('type', sa.String(), server_default='asset', nullable=False),
        sa.Column('category', sa.String(), nullable=True),
        sa.Column('value', sa.Integer(), server_default='0', nullable=False),
        sa.Column('acquisition_date', sa.String(), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.PrimaryKeyConstraint('id')
    )

    # Pre-transactions
    op.create_table(
        'pre_transactions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('date', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=True),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(), server_default='expense'),
        sa.Column('account_id', sa.Integer(), nullable=True),
        sa.Column('entity_id', sa.Integer(), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('status', sa.String(), server_default='pending'),
        sa.Column('recurring_id', sa.Integer(), nullable=True),
        sa.Column('transaction_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ),
        sa.ForeignKeyConstraint(['recurring_id'], ['recurring_expenses.id'], ),
        sa.ForeignKeyConstraint(['transaction_id'], ['transactions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Daily Reconciliation
    op.create_table(
        'daily_reconciliation',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=False),
        sa.Column('date', sa.String(), nullable=False),
        sa.Column('external_balance', sa.Integer(), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=now_expr),
        sa.Column('updated_at', sa.String(), server_default=now_expr),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('account_id', 'date')
    )

    # Create Triggers explicitly if SQLite for now.
    all_tables = [
        "accounts", "entities", "transactions", "investments", 
        "categories", "tags", "recurring_expenses", 
        "patrimony_items", "pre_transactions", "daily_reconciliation"
    ]
    
    if dialect == 'sqlite':
        for table in all_tables:
            op.execute(f"""
                CREATE TRIGGER trg_{table}_updated_at
                AFTER UPDATE ON {table}
                FOR EACH ROW
                BEGIN
                    UPDATE {table} SET updated_at = datetime('now') WHERE id = OLD.id;
                END;
            """)
            op.execute(f"""
                CREATE TRIGGER trg_{table}_created_at
                AFTER INSERT ON {table}
                FOR EACH ROW
                WHEN NEW.created_at = '' OR NEW.created_at IS NULL
                BEGIN
                    UPDATE {table} SET 
                        created_at = datetime('now'),
                        updated_at = datetime('now')
                    WHERE id = NEW.id;
                END;
            """)
        
        op.execute("""
            CREATE TRIGGER trg_txn_total_transfers_insert
            AFTER INSERT ON transactions
            FOR EACH ROW
            WHEN NEW.type IN ('transfer_in', 'transfer_out')
            BEGIN
                UPDATE accounts 
                SET total_transfers = total_transfers + NEW.raw_amount
                WHERE id = NEW.account_id;
            END;
        """)

        op.execute("""
            CREATE TRIGGER trg_txn_total_transfers_delete
            AFTER DELETE ON transactions
            FOR EACH ROW
            WHEN OLD.type IN ('transfer_in', 'transfer_out')
            BEGIN
                UPDATE accounts 
                SET total_transfers = total_transfers - OLD.raw_amount
                WHERE id = OLD.account_id;
            END;
        """)

        op.execute("""
            CREATE TRIGGER trg_txn_total_transfers_update
            AFTER UPDATE ON transactions
            FOR EACH ROW
            BEGIN
                UPDATE accounts 
                SET total_transfers = total_transfers - OLD.raw_amount
                WHERE id = OLD.account_id AND OLD.type IN ('transfer_in', 'transfer_out');
                
                UPDATE accounts 
                SET total_transfers = total_transfers + NEW.raw_amount
                WHERE id = NEW.account_id AND NEW.type IN ('transfer_in', 'transfer_out');
            END;
        """)

        op.execute("""
            CREATE TRIGGER trg_accounts_sync_total_balance
            AFTER UPDATE OF balance, total_transfers ON accounts
            FOR EACH ROW
            BEGIN
                UPDATE accounts SET total_balance = NEW.balance + NEW.total_transfers WHERE id = NEW.id;
            END;
        """)

    elif dialect == 'postgresql':
        op.execute("""
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS');
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """)
        
        op.execute("""
            CREATE OR REPLACE FUNCTION set_created_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                IF NEW.created_at = '' OR NEW.created_at IS NULL THEN
                    NEW.created_at = TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS');
                    NEW.updated_at = TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS');
                END IF;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """)

        for table in all_tables:
            op.execute(f"""
                CREATE TRIGGER trg_{table}_updated_at
                BEFORE UPDATE ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
            """)
            op.execute(f"""
                CREATE TRIGGER trg_{table}_created_at
                BEFORE INSERT ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION set_created_at_column();
            """)

        op.execute("""
            CREATE OR REPLACE FUNCTION update_total_transfers_insert()
            RETURNS TRIGGER AS $$
            BEGIN
                IF NEW.type IN ('transfer_in', 'transfer_out') THEN
                    UPDATE accounts
                    SET total_transfers = total_transfers + NEW.raw_amount
                    WHERE id = NEW.account_id;
                END IF;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """)
        op.execute("""
            CREATE TRIGGER trg_txn_total_transfers_insert
            AFTER INSERT ON transactions
            FOR EACH ROW
            EXECUTE FUNCTION update_total_transfers_insert();
        """)

        op.execute("""
            CREATE OR REPLACE FUNCTION update_total_transfers_delete()
            RETURNS TRIGGER AS $$
            BEGIN
                IF OLD.type IN ('transfer_in', 'transfer_out') THEN
                    UPDATE accounts
                    SET total_transfers = total_transfers - OLD.raw_amount
                    WHERE id = OLD.account_id;
                END IF;
                RETURN OLD;
            END;
            $$ language 'plpgsql';
        """)
        op.execute("""
            CREATE TRIGGER trg_txn_total_transfers_delete
            AFTER DELETE ON transactions
            FOR EACH ROW
            EXECUTE FUNCTION update_total_transfers_delete();
        """)

        op.execute("""
            CREATE OR REPLACE FUNCTION update_total_transfers_update()
            RETURNS TRIGGER AS $$
            BEGIN
                IF OLD.type IN ('transfer_in', 'transfer_out') THEN
                    UPDATE accounts
                    SET total_transfers = total_transfers - OLD.raw_amount
                    WHERE id = OLD.account_id;
                END IF;
                IF NEW.type IN ('transfer_in', 'transfer_out') THEN
                    UPDATE accounts
                    SET total_transfers = total_transfers + NEW.raw_amount
                    WHERE id = NEW.account_id;
                END IF;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """)
        op.execute("""
            CREATE TRIGGER trg_txn_total_transfers_update
            AFTER UPDATE ON transactions
            FOR EACH ROW
            EXECUTE FUNCTION update_total_transfers_update();
        """)

        op.execute("""
            CREATE OR REPLACE FUNCTION accounts_sync_total_balance()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.total_balance = NEW.balance + NEW.total_transfers;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """)
        op.execute("""
            CREATE TRIGGER trg_accounts_sync_total_balance
            BEFORE UPDATE OF balance, total_transfers ON accounts
            FOR EACH ROW
            EXECUTE FUNCTION accounts_sync_total_balance();
        """)

def downgrade() -> None:
    pass
