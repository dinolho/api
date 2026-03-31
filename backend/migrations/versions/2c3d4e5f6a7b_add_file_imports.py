"""add_file_imports

Revision ID: 2c3d4e5f6a7b
Revises: 1b2c3d4e5f6a
Create Date: 2026-03-31 00:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2c3d4e5f6a7b'
down_revision = '1b2c3d4e5f6a'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add file_imports
    op.create_table(
        'file_imports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('filename', sa.String(), nullable=False),
        sa.Column('md5', sa.String(), nullable=False),
        sa.Column('bank', sa.String(), nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=True),
        sa.Column('imported', sa.Integer(), server_default='0', nullable=True),
        sa.Column('duplicates', sa.Integer(), server_default='0', nullable=True),
        sa.Column('invalid', sa.Integer(), server_default='0', nullable=True),
        sa.Column('processed_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('md5')
    )

def downgrade() -> None:
    op.drop_table('file_imports')
