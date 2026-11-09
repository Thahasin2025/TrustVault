
from backend.database import Base, engine
from backend import models

# Create all tables defined in models.py
Base.metadata.create_all(bind=engine)

print("TrustVault database tables created successfully!")
