import os
from sqlalchemy import create_engine, text

# جلب رابط الداتابيز من متغيرات البيئة
DATABASE_URL = os.getenv("MYSQL_URL") or os.getenv("DATABASE_URL")

if DATABASE_URL:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        columns = ["github_id", "linkedin_id", "gitlab_id", "facebook_id"]
        for col in columns:
            try:
                connection.execute(text(f"ALTER TABLE users ADD COLUMN {col} VARCHAR(255);"))
                print(f"Added column: {col}")
            except Exception as e:
                print(f"Column {col} might already exist or error: {e}")
        
        connection.commit()
    print("Database update script executed successfully!")
else:
    print("Error: DATABASE_URL not found!")
