import streamlit as st
from link_analyzer import LinkAnalyzer
from virustotal_scanner import VirusTotalScanner
from google_safe_browsing import GoogleSafeBrowsingChecker
from database import create_table, insert_scan, get_recent_scans

# إعدادات API
VT_API_KEY = "c67d5b67b9d3edf040641feba166562fbd0f5dbcf380e270529bc1581d5504a9"
GOOGLE_API_KEY = "AIzaSyACp4Vofk_--pCNxsRREFY7eQEtBh8Ij8Y"

# إعدادات واجهة المستخدم
create_table()

# تعريف كلمة المرور للوحة الإدارة
ADMIN_PASSWORD = "admin123"

# إعدادات Streamlit يجب أن تكون أول شيء في الكود
st.set_page_config(page_title="PhishHawk AI", layout="centered", initial_sidebar_state="collapsed")

# إضافة الخطوط العربية الجيدة
st.markdown("""
    <style>
        /* تحميل الخط العربي */
        @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@700&display=swap');

        /* تنسيق التبويبات */
        .stTabs>div>div>button {
            font-size: 22px;
            font-weight: bold;
            color: white;
            background-color: #1f222e;
            border-radius: 10px;
            padding: 20px;
            width: 250px;
            margin: 10px auto;
            display: block;
            text-align: center;
            transition: all 0.3s ease;
            font-family: 'Cairo', sans-serif;
        }

        /* تأثير التبويبات عند التمرير */
        .stTabs>div>div>button:hover {
            background-color: #00CED1;
            color: black;
        }

        /* تنسيق النص داخل التبويبات */
        .stTab {
            font-size: 18px;
            color: white;
            text-align: center;
            font-family: 'Cairo', sans-serif;
        }

        /* تنسيق الصفحة بشكل عام */
        .main {
            background-color: #0f1117;
            color: white;
            font-family: 'Cairo', sans-serif;
        }

        /* تحسين شكل الرأس */
        .header {
            background-color: #1f222e;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #00CED1;
            font-size: 30px;
            font-weight: bold;
        }
        .header p {
            color: #ccc;
            font-weight: bold;
        }
    </style>
""", unsafe_allow_html=True)


def run_app():
    # بناء واجهة التطبيق
    tab1, tab2 = st.tabs(["🔍 فحص الروابط", "🛡️ لوحة الإدارة"])

    with tab1:
        st.markdown("""
            <div class="header">
                <h1>🦅 PhishHawk AI</h1>
                <p>نظام ذكي لتحليل وكشف الروابط المشبوهة باستخدام الذكاء الاصطناعي</p>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("### 📥 أدخل الرابط المشبوه:")
        link = st.text_input("", placeholder="https://example.com")

        if st.button("🔍 فحص الرابط الآن"):
            if link:
                with st.spinner("🔄 جاري فحص الرابط..."):
                    try:
                        # فحص باستخدام VirusTotal
                        vt_scanner = VirusTotalScanner(VT_API_KEY)
                        vt_result = vt_scanner.scan_url(link)

                        # فحص باستخدام Google Safe Browsing
                        google_checker = GoogleSafeBrowsingChecker(GOOGLE_API_KEY)
                        google_result = google_checker.check(link)


                        # تحليل الرابط باستخدام النتائج السابقة
                        analyzer = LinkAnalyzer(link, virustotal_result=vt_result, google_safe=google_result)
                        result = analyzer.analyze()
                        details = analyzer.get_details()

                        # عرض النتائج
                        st.markdown("### 🧪 نتائج الفحص:")
                        col1, col2 = st.columns(2)

                        with col1:
                            st.write(f"🌐 **النطاق:** `{details['domain']}`")
                            st.write(f"📁 **المسار:** `{details['path']}`")
                            st.write(f"🔎 **الاستعلام:** `{details['query']}`")

                        with col2:
                            if vt_result:
                                st.write(
                                    f"🧠 VirusTotal: خبيث: `{vt_result.get('malicious', 0)}` | مشبوه: `{vt_result.get('suspicious', 0)}`")
                            if google_result is not None:
                                if google_result:
                                    st.write(f"🔵 Google Safe Browsing: آمن")
                                else:
                                    st.write(f"🔴 Google Safe Browsing: غير آمن")
                            else:
                                st.warning("❌ فشل الاتصال بـ Google Safe Browsing.")

                        # حفظ النتيجة في قاعدة البيانات
                        insert_scan(link, details['domain'], details['path'], details['query'], result)

                        # عرض الحالة النهائية
                        if "Safe" in result:
                            st.success(result)
                        elif "Suspicious" in result:
                            st.warning(result)
                        else:
                            st.error(result)
                    except Exception as e:
                        st.error(f"❌ حدث خطأ أثناء الفحص: {e}")
            else:
                st.warning("⚠️ يرجى إدخال رابط أولاً.")

    with tab2:
        st.markdown("""
            <div class="header">
                <h2 style="color:#FFD700;">🛡️ لوحة الإدارة</h2>
                <p style="color:#aaa;">هنا يمكنك متابعة أحدث الروابط المفحوصة</p>
            </div>
        """, unsafe_allow_html=True)

        password = st.text_input("🔐 أدخل كلمة المرور", type="password")

        if password == ADMIN_PASSWORD:
            recent_links = get_recent_scans()
            if recent_links:
                st.markdown("### 📋 أحدث الفحوصات:")
                for url, status in recent_links:
                    status_color = "green" if "Safe" in status else "orange" if "Suspicious" in status else "red"
                    st.markdown(f"""
                        <div style="background-color:#2a2d3a; padding:10px; margin:5px 0; border-radius:6px;">
                            <span style="color:#87CEFA;">🔗 {url}</span><br>
                            <span style="color:{status_color}; font-weight:bold;">📌 {status}</span>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("🚫 لا توجد سجلات حالياً.")
        else:
            if password:
                st.warning("❌ كلمة المرور غير صحيحة!")


if __name__ == "__main__":
    run_app()
