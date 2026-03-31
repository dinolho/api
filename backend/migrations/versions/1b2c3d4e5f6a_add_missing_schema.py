"""add_missing_schema

Revision ID: 1b2c3d4e5f6a
Revises: 6bf245557571
Create Date: 2026-03-31 00:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1b2c3d4e5f6a'
down_revision = '6bf245557571'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add columns to patrimony_items
    op.add_column('patrimony_items', sa.Column('purchase_price', sa.Integer(), server_default='0', nullable=True))
    op.add_column('patrimony_items', sa.Column('depreciation_rate', sa.Float(), server_default='0.0', nullable=True))

    # Add automation_rules
    op.create_table(
        'automation_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('match_text', sa.String(), nullable=False),
        sa.Column('match_type', sa.String(), server_default='contains', nullable=False),
        sa.Column('priority', sa.Integer(), server_default='100', nullable=False),
        sa.Column('active', sa.Integer(), server_default='1', nullable=False),
        sa.Column('trigger_mode', sa.String(), server_default='all', nullable=False),
        sa.Column('apply_category', sa.String(), nullable=True),
        sa.Column('apply_tags', sa.String(), nullable=True),
        sa.Column('apply_entity_id', sa.Integer(), nullable=True),
        sa.Column('apply_flags', sa.Integer(), server_default='0', nullable=True),
        sa.Column('apply_type', sa.String(), nullable=True),
        sa.Column('apply_notes', sa.String(), nullable=True),
        sa.Column('apply_account_ids', sa.String(), nullable=True),
        sa.Column('apply_source_account_id', sa.Integer(), nullable=True),
        sa.Column('apply_destination_account_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.PrimaryKeyConstraint('id')
    )

    # Add automation_logs
    op.create_table(
        'automation_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('transaction_id', sa.Integer(), nullable=False),
        sa.Column('rule_id', sa.Integer(), nullable=False),
        sa.Column('applied_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['transaction_id'], ['transactions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['rule_id'], ['automation_rules.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade() -> None:
    op.drop_table('automation_logs')
    op.drop_table('automation_rules')
    op.drop_column('patrimony_items', 'depreciation_rate')
    op.drop_column('patrimony_items', 'purchase_price')
