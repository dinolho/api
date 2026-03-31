"""init_audit

Revision ID: 517d73c90807
Revises: 
Create Date: 2026-03-30 19:56:22.535213

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '517d73c90807'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


from sqlalchemy.sql import text

def upgrade() -> None:
    dialect = op.get_context().dialect.name

    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('occurred_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('table_name', sa.String(), nullable=True),
        sa.Column('record_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('user_email', sa.String(), nullable=True),
        sa.Column('user_name', sa.String(), nullable=True),
        sa.Column('ip', sa.String(), nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('old_data', sa.String(), nullable=True),
        sa.Column('new_data', sa.String(), nullable=True),
        sa.Column('extra', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table(
        'change_history',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('occurred_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('table_name', sa.String(), nullable=False),
        sa.Column('record_id', sa.Integer(), nullable=False),
        sa.Column('field', sa.String(), nullable=False),
        sa.Column('old_value', sa.String(), nullable=True),
        sa.Column('new_value', sa.String(), nullable=True),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('user_email', sa.String(), nullable=True),
        sa.Column('user_name', sa.String(), nullable=True),
        sa.Column('audit_log_id', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index('idx_al_action', 'audit_log', ['action'])
    op.create_index('idx_al_table', 'audit_log', ['table_name'])
    op.create_index('idx_al_user', 'audit_log', ['user_id'])
    op.create_index('idx_al_date', 'audit_log', ['occurred_at'])
    op.create_index('idx_ch_table_id', 'change_history', ['table_name', 'record_id'])
    op.create_index('idx_ch_date', 'change_history', ['occurred_at'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('change_history')
    op.drop_table('audit_log')
