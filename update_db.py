import os
from sqlalchemy import create_engine, text

# جلب رابط الداتابيز من متغيرات البيئة في Railway أو وضعه مباشرة
DATABASE_URL = os.getenv("MYSQL_URL") or os.getenv("DATABASE_URL")

if DATABASE_URL:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        # تنفيذ إضافة الأعمدة لو مش موجودة
        try:
            connection.execute(text("ALTER TABLE users ADD COLUMN github_id VARCHAR(255);"))
            print("Added github_id")
        except Exception as e:
            print("github_id might already exist:", e)

        try:
            connection.execute(text("ALTER TABLE users ADD COLUMN linkedin_id VARCHAR(255);"))
            print("Added linkedin_id")
        except Exception as e:
            print("linkedin_id might already exist:", e)

        try:
            connection.execute(text("ALTER TABLE users ADD COLUMN gitlab_id VARCHAR(255);"))
            print("Added gitlab_id")
        except Exception as e:
            print("gitlab_id might already exist:", e)

        try:
            connection.execute(text("ALTER TABLE users ADD COLUMN facebook_id VARCHAR(255);"))
            print("Added facebook_id")
        except Exception as e:
            print("facebook_id might already exist:", e)
        
        connection.commit()
    print("Database update script executed successfully!")
