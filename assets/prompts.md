# The original "pre-launch security kit" prompts

Kept for reference: the 27-step prompt as spoken in the source video (Persian), an English rendering, and the short version posted under the video. The skill implements all of them (plus extra checks, tests and load testing), so you normally just say "run the security kit on this project".

## 1. Video prompt (Persian, 27 steps)
> هی Claude! نمی‌خوام هکرها راهی پیدا کنن توی اپی که با وایب‌کد ساختم. پس لطفاً:
> ۱. احراز هویت رو درست و حسابی راه بنداز.
> ۲. کلیدهای API رو مخفی کن.
> ۳. دیتابیس رو امن کن.
> ۴. HTTPS رو اجباری کن.
> ۵. پسوردها رو هش کن.
> ۶. فرم‌ها رو سمت سرور اعتبارسنجی کن.
> ۷. جلوی XSS رو بگیر.
> ۸. فعالیت‌های مشکوک رو لاگ کن و زیر نظر داشته باش.
> ۹. مسیرهای ادمین رو قفل کن.
> ۱۰. از کوئری‌های پارامتردار استفاده کن.
> ۱۱. متغیرهای محیطی رو چک کن.
> ۱۲. برای لاگین ریت‌لیمیت بذار.
> ۱۳. تنظیمات CORS رو محدود کن.
> ۱۴. هدرهای امنیتی رو به پروژه اضافه کن.
> ۱۵. کوکی‌های سشن رو امن کن.
> ۱۶. محافظت CSRF رو اضافه کن.
> ۱۷. لینک‌های ریست پسورد رو زمان‌دار کن.
> ۱۸. نوع و حجم فایل‌های آپلودی رو محدود کن.
> ۱۹. قیمت‌ها و پرداخت‌ها رو (سمت سرور) دوباره چک کن.
> ۲۰. حالت دیباگ رو روی نسخه‌ی اصلی خاموش کن.
> ۲۱. پکیج‌های آسیب‌پذیر رو آپدیت کن.
> ۲۲. پکیج‌های بدون استفاده رو پاک کن.
> ۲۳. دنبال فایل‌های لورفته بگرد.
> ۲۴. تاریخچه‌ی گیت رو دنبال رمزهای لورفته اسکن کن.
> ۲۵. کلیدهای لورفته رو باطل کن و عوضشون کن.
> ۲۶. در نهایت یه بررسی امنیتی کامل انجام بده.
> ۲۷. همه‌ی این محافظت‌ها رو تست کن و یه گزارش از مشکلات و راه‌حل‌ها بهم بده.

## 2. English rendering
> Claude, I don't want hackers getting into the app I vibe-coded. So please: set up authentication properly · hide the API keys · secure the database · enforce HTTPS · hash passwords · validate forms on the server · prevent XSS · log and monitor suspicious activity · lock the admin routes · use parameterized queries · check environment variables · rate-limit login · restrict CORS · add security headers · secure session cookies · add CSRF protection · make password-reset links expire · restrict upload type and size · re-check prices and payments on the server · turn debug off in production · update vulnerable packages · remove unused packages · look for leaked files · scan git history for leaked secrets · revoke and replace leaked keys · do a full security review · test every protection and give me a report of problems and fixes.

## 3. Short version (posted under the video)
> Act as my security engineer. Audit this whole project and fix: auth, exposed API keys, database access, password hashing, server-side validation, XSS / SQL injection / CSRF, admin routes, rate limiting, security headers, CORS, cookies, file uploads, debug mode, vulnerable packages and leaked secrets in git. Then test it all and give me a short report: what you fixed + what's still risky.

## 4. Handy one-liners for this skill
- «کیت امنیتی رو روی این پروژه اجرا کن، همه رو درست کن، تست کن و گزارش کوتاه بده.»
- «فقط بررسی کن و گزارش بده، هنوز به کد دست نزن.»
- «کلید Stripe لو رفته — چی‌کار کنم؟»
- «تست فشار بگیر ببین با ۵۰۰ کاربر همزمان دووم میاره یا نه.»
- "Run the security kit on ./my-app — fix everything you safely can, test it, short report."
- "Audit only, no code changes: give me a prioritized report."
- "Load test staging with a spike to 500 users; I own the server."
