"""init_auth

Revision ID: c4f58401d754
Revises: 
Create Date: 2026-03-30 19:56:22.396544

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4f58401d754'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


from sqlalchemy.sql import text

def upgrade() -> None:
    dialect = op.get_context().dialect.name

    op.create_table(
        'users',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('name', sa.String(), server_default='', nullable=False),
        sa.Column('totp_secret', sa.String(), nullable=True),
        sa.Column('totp_enabled', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email', name='uq_users_email')
    )

    op.create_table(
        'organizations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('slug', sa.String(), nullable=False),
        sa.Column('require_2fa', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug', name='uq_organizations_slug')
    )

    op.create_table(
        'org_members',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('role', sa.String(), server_default='member', nullable=False),
        sa.Column('invited_by', sa.String(), nullable=True),
        sa.Column('joined_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['invited_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_id', 'user_id', name='uq_org_members_org_user')
    )

    op.create_table(
        'org_databases',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=True),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('db_path', sa.String(), nullable=True),
        sa.Column('db_name', sa.String(), server_default='', nullable=False),
        sa.Column('type', sa.String(), server_default='api', nullable=False),
        sa.Column('base_url', sa.String(), nullable=True),
        sa.Column('filename', sa.String(), nullable=True),
        sa.Column('access_mode', sa.String(), server_default='all_members', nullable=False),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('engine', sa.String(), server_default='sqlite', nullable=True),
        sa.Column('dsn', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_id', 'db_path', name='uq_org_databases_org_path')
    )

    op.create_table(
        'db_member_access',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_database_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('can_read', sa.Integer(), server_default='1', nullable=False),
        sa.Column('can_write', sa.Integer(), server_default='1', nullable=False),
        sa.Column('granted_by', sa.String(), nullable=True),
        sa.Column('granted_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['granted_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['org_database_id'], ['org_databases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_database_id', 'user_id', name='uq_db_member_access_db_user')
    )

    op.create_table(
        'central_config',
        sa.Column('key', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=True),
        sa.Column('updated_at', sa.String(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.PrimaryKeyConstraint('key')
    )

def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('central_config')
    op.drop_table('db_member_access')
    op.drop_table('org_databases')
    op.drop_table('org_members')
    op.drop_table('organizations')
    op.drop_table('users')
