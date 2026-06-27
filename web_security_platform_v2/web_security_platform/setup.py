#!/usr/bin/env python3
"""
WebGuard Pro — Setup Script
Creates the database and a demo admin user
"""
import asyncio
import sys
import os
import secrets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


async def setup():
    print("🛡️  WebGuard Pro Setup")
    print("=" * 40)

    # Init DB
    from core.database import init_db, AsyncSessionLocal
    from models import User, UserRole
    from core.security import hash_password
    from sqlalchemy import select

    print("📦 Creating database tables...")
    await init_db()
    print("✅ Database ready")

    # Create admin user
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        existing = result.scalar_one_or_none()

        if existing:
            print("ℹ️  Admin user already exists")
        else:
            # Use provided ADMIN_PASSWORD or generate a secure one
            admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
            admin = User(
                username="admin",
                email="admin@webguard.local",
                hashed_password=hash_password(admin_password),
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True,
            )
            db.add(admin)
            await db.commit()
            print("✅ Admin user created")
            print("   Username: admin")
            print(f"   Password: {admin_password}")
            print("   ⚠️  Change password after first login!")

    print("\n🚀 Setup complete! Run: uvicorn main:app --reload")
    print("   Open: http://localhost:8000")


if __name__ == "__main__":
    asyncio.run(setup())
