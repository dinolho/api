"""init_market

Revision ID: 1a2b3c4d
Revises: 
Create Date: 2026-03-30 23:40:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a2b3c4d'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('market_snapshots',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('queried_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('indicator', sa.String(), nullable=False),
        sa.Column('value', sa.Float(), nullable=True),
        sa.Column('changed', sa.Integer(), server_default=sa.text('0'), nullable=True),
        sa.Column('prev_value', sa.Float(), nullable=True),
        sa.Column('metadata', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_ms_indicator', 'market_snapshots', ['indicator'], unique=False)
    op.create_index('idx_ms_queried', 'market_snapshots', ['queried_at'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_ms_queried', table_name='market_snapshots')
    op.drop_index('idx_ms_indicator', table_name='market_snapshots')
    op.drop_table('market_snapshots')
