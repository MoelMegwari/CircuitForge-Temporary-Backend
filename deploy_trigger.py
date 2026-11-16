import os
import requests

def trigger_vercel_deploy():
    # استدعاء الرابط من متغيرات البيئة في Railway
    deploy_url = os.getenv("VERCEL_DEPLOY_HOOK_URL")
    
    if not deploy_url:
        print("خطأ: رابط Vercel Deploy Hook غير موجود في متغيرات البيئة.")
        return False

    try:
        # إرسال طلب POST لتشغيل التحديث على Vercel
        response = requests.post(deploy_url, timeout=30)
        
        # التحقق من نجاح العملية
        if response.status_code == 200:
            print("تم إرسال طلب التحديث إلى Vercel بنجاح!")
            return True
        else:
            print(f"فشل التحديث. الرمز: {response.status_code}, الرد: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"حدث خطأ أثناء الاتصال بمنصة Vercel: {e}")
        return False

# --- مثال على الاستخدام داخل المهمة ---
if __name__ == "__main__":
    print("جاري تنفيذ المهمة على Railway (تحديث قواعد البيانات / بناء الملفات)...")
    # [هنا ضع كود المهمة الخاص بك...]
    
    # بعد نجاح المهمة، قم بتحديث Vercel تلقائياً
    trigger_vercel_deploy()
