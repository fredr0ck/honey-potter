from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'initial_migration'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('users',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('username', sa.String(), nullable=False),
    sa.Column('email', sa.String(), nullable=True),
    sa.Column('hashed_password', sa.String(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('is_superuser', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    op.create_table('honeypot_services',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('type', sa.String(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('address', sa.String(), nullable=True),
    sa.Column('status', sa.Enum('STOPPED', 'RUNNING', 'ERROR', name='honeypotstatus'), nullable=True),
    sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=True),
    sa.Column('docker_container_id', sa.String(), nullable=True),
    sa.Column('notification_levels', postgresql.JSON(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )

    op.create_table('notification_settings',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('telegram_enabled', sa.Boolean(), nullable=True),
    sa.Column('telegram_bot_token', sa.String(), nullable=True),
    sa.Column('telegram_chat_id', sa.String(), nullable=True),
    sa.Column('email_enabled', sa.Boolean(), nullable=True),
    sa.Column('email_address', sa.String(), nullable=True),
    sa.Column('level_1_enabled', sa.Boolean(), nullable=True),
    sa.Column('level_2_enabled', sa.Boolean(), nullable=True),
    sa.Column('level_3_enabled', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id')
    )

    op.create_table('credentials',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('service_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column('service_type', sa.String(), nullable=False),
    sa.Column('username', sa.String(), nullable=False),
    sa.Column('password', sa.String(), nullable=False),
    sa.Column('generated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('meta_data', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['service_id'], ['honeypot_services.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_credentials_username'), 'credentials', ['username'], unique=True)

    op.create_table('incidents',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('honeypot_id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('source_ip', sa.String(), nullable=False),
    sa.Column('threat_level', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('NEW', 'INVESTIGATING', 'RESOLVED', 'IGNORED', name='incidentstatus'), nullable=True),
    sa.Column('event_count', sa.Integer(), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypot_services.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incidents_source_ip'), 'incidents', ['source_ip'], unique=False)

    op.create_table('events',
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('honeypot_id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('incident_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column('event_type', sa.String(), nullable=False),
    sa.Column('level', sa.Integer(), nullable=False),
    sa.Column('source_ip', sa.String(), nullable=False),
    sa.Column('honeytoken_id', postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypot_services.id'], ),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
    sa.ForeignKeyConstraint(['honeytoken_id'], ['credentials.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_events_source_ip'), 'events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_events_timestamp'), 'events', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_events_timestamp'), table_name='events')
    op.drop_index(op.f('ix_events_source_ip'), table_name='events')
    op.drop_table('events')
    op.drop_index(op.f('ix_incidents_source_ip'), table_name='incidents')
    op.drop_table('incidents')
    op.drop_index(op.f('ix_credentials_username'), table_name='credentials')
    op.drop_table('credentials')
    op.drop_table('notification_settings')
    op.drop_table('honeypot_services')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.execute('DROP TYPE IF EXISTS incidentstatus')
    op.execute('DROP TYPE IF EXISTS honeypotstatus')

