# CircuitForge AI — Temporary Backend (MVP)

هذه نسخة اختبار مؤقتة من Backend باستخدام FastAPI. تعمل على Render Free بدون إعداد Google Cloud Billing.

## ما الذي تفعله؟
- تعرض حالة الخدمة عبر `/health`.
- تعرض قدرات API عبر `/api/v1/status`.
- تستقبل ملفات `.kicad_pcb` حتى 20 MB.
- تنشئ رقم مهمة مؤقتًا وتتيح الاستعلام عنها.

## ما الذي لا تفعله؟
هذه النسخة **لا تحتوي على KiCad CLI أو FreeRouting**، ولا تنتج Gerber أو Drill أو DRC. لا تستخدم مخرجاتها للتصنيع.
الملفات وسجلات المهام مؤقتة، وقد تُحذف عند إعادة التشغيل أو النوم أو إعادة النشر. لا ترفع تصميمًا سريًا أو حساسًا.

## النشر من المتصفح
1. أنشئ حسابًا على https://render.com/
2. أنشئ مستودع GitHub جديدًا (يفضل Private) من المتصفح.
3. ارفع محتويات هذه الحزمة إلى المستودع، وليس ملف ZIP نفسه.
4. في Render اختر **New → Blueprint** ثم اربط مستودع GitHub.
5. راجع `render.yaml` وتأكد أن الخطة `free`، ثم أنشئ الخدمة.
6. انتظر نجاح Deploy. سيظهر لك رابط شبيه بـ:
   `https://circuitforge-temporary-api.onrender.com`
7. افتح:
   - `/health`
   - `/docs`
   - `/api/v1/status`

قد يطلب Render ربط حساب GitHub. لا تختَر خطة مدفوعة. الخطة المجانية قد تنام بعد 15 دقيقة من عدم النشاط، ويستغرق إيقاظها بعض الوقت. كما أن نظام الملفات مؤقت.

## اختبار رفع ملف
من صفحة `/docs`:
1. افتح `POST /api/v1/boards/upload`.
2. اضغط **Try it out**.
3. اختر ملف `.kicad_pcb` تجريبيًا غير سري.
4. نفّذ الطلب واحفظ `job_id`.
5. افتح `GET /api/v1/jobs/{job_id}` والصق رقم المهمة.

أو باستخدام curl:
```bash
curl -X POST "https://YOUR-SERVICE.onrender.com/api/v1/boards/upload" \
  -F "file=@board.kicad_pcb"
```

## ربط واجهة CircuitForge
```javascript
const API_BASE = "https://YOUR-SERVICE.onrender.com";

const health = await fetch(`${API_BASE}/health`).then(r => r.json());
console.log(health);

const form = new FormData();
form.append("file", pcbFile);

const response = await fetch(`${API_BASE}/api/v1/boards/upload`, {
  method: "POST",
  body: form
});
const result = await response.json();
console.log(result);
```
استبدل `YOUR-SERVICE` باسم الخدمة الحقيقي. لا تضع أسرارًا أو مفاتيح خاصة داخل HTML.

## ملاحظات قبل الإنتاج
- اضبط `FRONTEND_ORIGINS` على نطاق الواجهة الفعلي بدل `*`.
- أضف مصادقة وحدود طلبات وفحصًا للملفات.
- استخدم تخزينًا دائمًا خاصًا للملفات.
- شغّل KiCad وFreeRouting في Worker منفصل يدعم المهام الطويلة.
- لا تعلن أن ملفات التصنيع جاهزة إلا بعد تشغيل المحرك والتحقق من تطابق Gerber وDrill.
