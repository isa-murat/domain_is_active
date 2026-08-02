"""seed_initial_whitelist_domains

Revision ID: e85f9214b2d1
Revises: c96acda6c566
Create Date: 2026-08-02 19:15:00.000000

"""
from typing import Sequence, Union
import datetime
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e85f9214b2d1'
down_revision: Union[str, Sequence[str], None] = 'c96acda6c566'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INITIAL_WHITELIST_DOMAINS = [
    # Finans / Bankacılık / Kripto
    "garanti.com.tr",
    "garantibbva.com.tr",
    "garanti.com",
    "isbank.com.tr",
    "isbank.com",
    "akbank.com",
    "yapikredi.com.tr",
    "ziraatbank.com.tr",
    "ziraat.com.tr",
    "halkbank.com.tr",
    "vakifbank.com.tr",
    "vakifbank.com",
    "qnbfinansbank.com",
    "finansbank.com",
    "denizbank.com",
    "teb.com.tr",
    "ing.com.tr",
    "kuveytturk.com.tr",
    "albaraka.com.tr",
    "sekerbank.com.tr",
    "fibabanka.com.tr",
    "odeabank.com.tr",
    "enpara.com",
    "papara.com",
    "payfix.com.tr",
    "troyodeme.com",
    "binance.com",
    "btcturk.com",
    "paribu.com",
    # 11 Kurum & Kamu & Borsa
    "turkiye.gov.tr",
    "egov.tr",
    "edevlet.gov.tr",
    "gib.gov.tr",
    "sgk.gov.tr",
    "mhrs.gov.tr",
    "togg.com.tr",
    "togg.com",
    "borsaistanbul.com",
    "borsaistanbul.com.tr",
    "bist.com.tr",
    "takasbank.com.tr",
    "otokoc.com.tr",
    "otokocotomotiv.com.tr",
    "azercell.com",
    "bidv.com.vn",
    "bidv.com",
    "thebodyshop.com.tr",
    "thebodyshop.com",
    "a101.com.tr",
    "a101.com",
    # Telekom & Kargo
    "turkcell.com.tr",
    "vodafone.com.tr",
    "turktelekom.com.tr",
    "ptt.gov.tr",
    "pttkargo.com.tr",
    # E-Ticaret
    "sahibinden.com",
    "trendyol.com",
    "hepsiburada.com",
    "n11.com",
    "getir.com",
    "ciceksepeti.com",
    # Global Popüler Servisler
    "google.com",
    "youtube.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "twitter.com",
    "x.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "gitlab.com",
    "cloudflare.com",
    "openai.com",
    "anthropic.com",
    "steampowered.com",
    "netflix.com",
    "spotify.com",
    "outlook.com",
    "live.com",
    "office.com",
    "gmail.com",
]


def upgrade() -> None:
    """Alembic data migration - seeds whitelist_domains table."""
    whitelist_table = sa.sql.table(
        'whitelist_domains',
        sa.sql.column('domain', sa.String),
        sa.sql.column('source', sa.String),
        sa.sql.column('added_at', sa.DateTime),
    )

    now = datetime.datetime.utcnow()
    records = [
        {"domain": d.strip().lower(), "source": "Alembic Initial Seed", "added_at": now}
        for d in INITIAL_WHITELIST_DOMAINS
    ]

    # Insert initial whitelist records into DB table, skipping existing ones
    connection = op.get_bind()
    for record in records:
        connection.execute(
            sa.text(
                "INSERT OR IGNORE INTO whitelist_domains (domain, source, added_at) VALUES (:domain, :source, :added_at)"
            ),
            record,
        )


def downgrade() -> None:
    """Removes initial seed records from whitelist_domains table."""
    op.execute("DELETE FROM whitelist_domains WHERE source = 'Alembic Initial Seed'")
