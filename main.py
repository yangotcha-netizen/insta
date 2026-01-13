import requests
import json
import time
import random
import string
import threading
import queue
import re
import secrets
import uuid
import base64
import hashlib
import gc
from datetime import datetime, timezone

# التلجرام
TELEGRAM_TOKEN = "8459989963:AAF8yaQ4aw7rkyUzw2WsWQEB51vaG2Nk2c4"
TELEGRAM_CHAT_ID = "7367658915"

# الألوان للأخطاء فقط
class Colors:
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    RESET = '\033[0m'

# ============ Telegram Manager ============
class TelegramManager:
    """مدير التلجرام"""
    
    @staticmethod
    def send_message(text):
        """إرسال رسالة للتلجرام"""
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': text,
                'parse_mode': 'HTML'
            }
            requests.post(url, data=data, timeout=5)
            return True
        except:
            return False
    
    @staticmethod
    def send_start_message():
        """إرسال رسالة بدء التشغيل"""
        start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"""
🚀 <b>Instagram Username Checker Started</b>
📅 <b>Time:</b> {start_time}
🔍 <b>Mode:</b> Silent Mode - Errors Only
🛡️ <b>WARP:</b> Same device until 429
📧 <b>Email:</b> Same email until 429
🔄 <b>Rotation:</b> Only on 429 error
        """
        return TelegramManager.send_message(message)

# ============ WARP Manager ============
class WARPMANAGER:
    """مدير WARP - يحفظ الجهاز حتى خطأ 429"""
    
    def __init__(self):
        self.base_url = "https://api.cloudflareclient.com"
        self.api_version = "v0a2510"
        self.current_device = None
        self.device_counter = 0
    
    def create_first_device(self):
        """إنشاء أول جهاز WARP"""
        return self._create_warp_device()
    
    def rotate_device(self):
        """إنشاء جهاز جديد فقط عند 429"""
        print(f"{Colors.RED}🔄 Rotating WARP device due to 429{Colors.RESET}")
        self.current_device = None
        return self._create_warp_device()
    
    def _create_warp_device(self):
        """إنشاء جهاز WARP"""
        try:
            install_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=22))
            
            headers = {
                'CF-Client-Version': 'a-6.11-2510',
                'User-Agent': 'okhttp/4.11.0',
                'Content-Type': 'application/json',
            }
            
            payload = {
                "install_id": install_id,
                "fcm_token": f"{install_id}:APA91b{secrets.token_hex(67)}",
                "type": "Android",
                "locale": "en_US",
                "key": base64.b64encode(secrets.token_bytes(32)).decode(),
                "tos": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "model": f"Pixel {random.randint(1, 8)}",
                "serial_number": secrets.token_hex(8).upper(),
            }
            
            url = f"{self.base_url}/{self.api_version}/reg"
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                self.device_counter += 1
                
                device_info = {
                    'device_id': data.get('id'),
                    'install_id': install_id,
                    'token': data.get('token'),
                    'created_at': time.time(),
                    'device_number': self.device_counter
                }
                
                self.current_device = device_info
                return device_info
                
        except Exception as e:
            print(f"{Colors.RED}❌ WARP Error: {str(e)} {Colors.RESET}")
        
        return None
    
    def get_current_device(self):
        """الحصول على الجهاز الحالي أو إنشاء أول جهاز"""
        if not self.current_device:
            return self.create_first_device()
        return self.current_device

# ============ Email Manager ============
class EmailManager:
    """مدير البريد - يحفظ نفس البريد حتى 429"""
    
    def __init__(self):
        self.current_email = None
        self.email_counter = 0
        self.domains = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'icloud.com', 'protonmail.com', 'yandex.com', 'mail.com',
            'aol.com', 'zoho.com'
        ]
    
    def create_first_email(self):
        """إنشاء أول بريد"""
        return self._generate_email()
    
    def rotate_email(self):
        """إنشاء بريد جديد فقط عند 429"""
        print(f"{Colors.RED}🔄 Rotating email due to 429{Colors.RESET}")
        self.current_email = None
        return self._generate_email()
    
    def _generate_email(self):
        """توليد بريد"""
        self.email_counter += 1
        
        prefixes = [
            ''.join(random.choices(string.ascii_lowercase, k=10)),
            ''.join(random.choices(string.ascii_lowercase, k=8)) + str(random.randint(100, 999)),
            'user' + str(random.randint(10000, 99999)),
            'account' + str(random.randint(1000, 9999)),
        ]
        
        prefix = random.choice(prefixes)
        domain = random.choice(self.domains)
        email = f"{prefix}@{domain}"
        
        self.current_email = email
        return email
    
    def get_current_email(self):
        """الحصول على البريد الحالي أو إنشاء أول بريد"""
        if not self.current_email:
            return self.create_first_email()
        return self.current_email

# ============ Instagram Session ============
class InstagramSession:
    """جلسة Instagram واحدة - تحافظ على كل شيء حتى 429"""
    
    def __init__(self):
        self.session = None
        self.csrf_token = None
        self.checks_count = 0
        self.last_check = time.time()
    
    def initialize(self, warp_device, email):
        """تهيئة الجلسة"""
        self.session = requests.Session()
        
        # Headers الأساسية
        self.session.headers.update({
            'User-Agent': 'Instagram 269.0.0.18.75 Android (26/8.0.0; 480dpi; 1080x1920; OnePlus; 6T Dev; qcom; en_US; 314665256)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'X-IG-App-ID': '936619743392459',
            'X-IG-WWW-Claim': '0',
            'Origin': 'https://www.instagram.com',
            'Referer': 'https://www.instagram.com/',
            'Connection': 'keep-alive',
        })
        
        # إضافة WARP headers
        if warp_device:
            self.session.headers.update({
                'CF-Device-ID': warp_device['device_id'],
                'Authorization': f'Bearer {warp_device["token"]}',
                'CF-Client-Version': 'a-6.11-2510',
            })
        
        # جلب CSRF token
        self.csrf_token = self._get_csrf_token()
        
        return self.csrf_token is not None
    
    def _get_csrf_token(self):
        """جلب CSRF token"""
        try:
            response = self.session.get(
                'https://www.instagram.com/accounts/emailsignup/',
                timeout=10
            )
            
            patterns = [
                r'"csrf_token":"([^"]+)"',
                r'csrf_token["\']\s*:\s*["\']([^"\']+)["\']',
                r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, response.text)
                if match:
                    token = match.group(1)
                    self.session.headers['X-CSRFToken'] = token
                    self.session.cookies['csrftoken'] = token
                    return token
            
            # توليد عشوائي إذا فشل
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            self.session.headers['X-CSRFToken'] = token
            return token
            
        except Exception as e:
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            self.session.headers['X-CSRFToken'] = token
            return token
    
    def check_username(self, username, email):
        """فحص يوزر"""
        try:
            self.checks_count += 1
            self.last_check = time.time()
            
            first_name = random.choice(['Ali', 'Omar', 'Adam', 'Ahmed', 'Mohammed'])
            last_name = random.choice(['Al', 'Ben', 'Ibn', 'Abd'])
            
            data = {
                'email': email,
                'username': username,
                'first_name': f"{first_name} {last_name}",
                'opt_into_one_tap': 'false',
                'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:TestPass{random.randint(1000, 9999)}',
                'client_id': str(uuid.uuid4())[:22],
                'seamless_login_enabled': '1',
                'tos_version': random.choice(['row', 'eu', 'us']),
                'force_sign_up_code': '',
                'day': str(random.randint(1, 28)),
                'month': str(random.randint(1, 12)),
                'year': str(random.randint(1985, 2000)),
            }
            
            headers = {
                'X-CSRFToken': self.csrf_token,
                'X-Instagram-AJAX': '1',
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': 'https://www.instagram.com/accounts/emailsignup/',
            }
            
            response = self.session.post(
                'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/',
                data=data,
                headers=headers,
                timeout=15
            )
            
            return response
            
        except Exception as e:
            print(f"{Colors.RED}❌ Request Error: {str(e)} @{username}{Colors.RESET}")
            return None
    
    def cleanup(self):
        """تنظيف الجلسة"""
        if self.session:
            try:
                self.session.close()
            except:
                pass
        self.session = None
        self.csrf_token = None

# ============ Main Checker ============
class InstagramUsernameChecker:
    """الفحاص الرئيسي - نفس الجهاز ونفس البريد حتى 429"""
    
    def __init__(self):
        # الإحصائيات
        self.stats = {
            'total_checks': 0,
            'available_found': 0,
            'errors': 0,
            'rate_limits': 0,
            'warp_devices_used': 0,
            'emails_used': 0,
            'checks_per_session': 0,
        }
        
        # المانجرز
        self.warp_manager = WARPMANAGER()
        self.email_manager = EmailManager()
        self.telegram_manager = TelegramManager()
        self.current_session = None
        
        # متغيرات التحكم
        self.running = True
        self.last_available_sent = 0
        
    def generate_4char_username(self):
        """توليد يوزر رباعي"""
        patterns = [
            lambda: ''.join(random.choices(string.ascii_lowercase, k=4)),
            lambda: ''.join(random.choices(string.ascii_lowercase, k=3)) + random.choice(string.digits),
            lambda: ''.join(random.choices(string.ascii_lowercase, k=2)) + ''.join(random.choices(string.digits, k=2)),
            lambda: random.choice(string.ascii_lowercase) + ''.join(random.choices(string.digits, k=3)),
        ]
        
        username = random.choice(patterns)()
        
        if username.isdigit():
            return self.generate_4char_username()
        
        banned = ['insta', 'gram', 'admin', 'test', 'user', 'null']
        for word in banned:
            if word in username.lower():
                return self.generate_4char_username()
        
        return username
    
    def setup_session(self):
        """إعداد الجلسة الأولى أو بعد 429"""
        # الحصول على الجهاز الحالي (أو إنشاء أول جهاز)
        warp_device = self.warp_manager.get_current_device()
        if not warp_device:
            return False
        
        # الحصول على البريد الحالي (أو إنشاء أول بريد)
        email = self.email_manager.get_current_email()
        
        # إنشاء جلسة جديدة
        self.current_session = InstagramSession()
        
        # تهيئة الجلسة
        if not self.current_session.initialize(warp_device, email):
            return False
        
        # تحديث الإحصائيات
        self.stats['warp_devices_used'] = self.warp_manager.device_counter
        self.stats['emails_used'] = self.email_manager.email_counter
        self.stats['checks_per_session'] = 0
        
        return True
    
    def check_single_username(self, username):
        """فحص يوزر واحد"""
        # إذا لم توجد جلسة، ننشئ واحدة
        if not self.current_session:
            if not self.setup_session():
                print(f"{Colors.RED}❌ Failed to setup session{Colors.RESET}")
                self.stats['errors'] += 1
                return False
        
        # تحديث الإحصائيات
        self.stats['total_checks'] += 1
        self.stats['checks_per_session'] += 1
        
        try:
            # الحصول على البريد الحالي
            current_email = self.email_manager.get_current_email()
            
            # إرسال طلب الفحص
            response = self.current_session.check_username(username, current_email)
            
            if response:
                status_code = response.status_code
                
                if status_code == 200:
                    try:
                        json_data = response.json()
                        response_json_str = json.dumps(json_data).lower()
                        
                        # الحالة: يوزر متاح!
                        if 'dryrun_passed' in response_json_str or 'force_sign_up_code' in response_json_str:
                            self.stats['available_found'] += 1
                            
                            # إرسال للتلجرام
                            current_time = time.time()
                            if current_time - self.last_available_sent > 60:
                                warp_device = self.warp_manager.get_current_device()
                                telegram_msg = f"""
🎯 <b>Available Username Found!</b>

👤 <b>Username:</b> @{username}
📧 <b>Email Used:</b> {current_email}
🆔 <b>WARP Device:</b> #{warp_device['device_number']} ({warp_device['device_id'][:15]}...)
📊 <b>Checks this session:</b> {self.stats['checks_per_session']}
🕒 <b>Time:</b> {datetime.now().strftime('%H:%M:%S')}
                                """
                                self.telegram_manager.send_message(telegram_msg)
                                self.last_available_sent = current_time
                            
                            return True
                            
                    except json.JSONDecodeError:
                        pass
                        
                elif status_code == 429:
                    print(f"{Colors.RED}⚠ Rate Limit (429) @{username}{Colors.RESET}")
                    print(f"{Colors.RED}   Session did {self.stats['checks_per_session']} checks before 429{Colors.RESET}")
                    self.stats['rate_limits'] += 1
                    
                    # 🔄 🔄 🔄 هنا فقط نغير كل شيء عند 429 🔄 🔄 🔄
                    
                    # 1. تنظيف الجلسة الحالية
                    self.current_session.cleanup()
                    self.current_session = None
                    
                    # 2. إنشاء جهاز WARP جديد
                    new_warp = self.warp_manager.rotate_device()
                    
                    # 3. إنشاء بريد جديد
                    new_email = self.email_manager.rotate_email()
                    
                    # 4. إنشاء جلسة جديدة
                    if self.setup_session():
                        print(f"{Colors.RED}   New session created with new WARP and email{Colors.RESET}")
                    
                    return False
                    
                elif status_code == 403 or status_code == 400:
                    print(f"{Colors.RED}⚡ Blocked ({status_code}) @{username}{Colors.RESET}")
                    self.stats['errors'] += 1
                    return False
                    
                else:
                    print(f"{Colors.RED}❌ HTTP {status_code} @{username}{Colors.RESET}")
                    self.stats['errors'] += 1
                    return False
            else:
                print(f"{Colors.RED}❌ No Response @{username}{Colors.RESET}")
                self.stats['errors'] += 1
                return False
                
        except Exception as e:
            print(f"{Colors.RED}❌ Error @{username}: {str(e)[:50]}{Colors.RESET}")
            self.stats['errors'] += 1
            return False
    
    def cleanup_memory(self):
        """تنظيف الذاكرة"""
        gc.collect()
    
    def start_continuous_checking(self):
        """بدء الفحص المستمر"""
        print(f"{Colors.GREEN}🚀 Starting Instagram Username Checker{Colors.RESET}")
        print(f"{Colors.GREEN}📱 Mode: Same WARP + Same Email until 429{Colors.RESET}")
        print(f"{Colors.GREEN}🔄 Rotation: Only on 429 error{Colors.RESET}")
        
        # إرسال رسالة بدء للتلجرام
        if self.telegram_manager.send_start_message():
            print(f"{Colors.GREEN}✅ Start message sent to Telegram{Colors.RESET}")
        
        # إعداد الجلسة الأولى
        if not self.setup_session():
            print(f"{Colors.RED}❌ Failed to setup initial session{Colors.RESET}")
            return
        
        check_counter = 0
        
        try:
            while self.running:
                # توليد يوزر جديد
                username = self.generate_4char_username()
                
                # فحص اليوزر
                self.check_single_username(username)
                
                # زيادة العداد
                check_counter += 1
                
                # تأخير عشوائي بين الفحوصات
                delay = random.uniform(1.5, 3)  # تأخير أقل لأننا نستخدم نفس الجلسة
                time.sleep(delay)
                
                # تنظيف الذاكرة كل 20 فحص
                if check_counter % 20 == 0:
                    self.cleanup_memory()
                
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}🛑 Stopping checker...{Colors.RESET}")
            self.running = False
    
    def print_final_stats(self):
        """طباعة الإحصائيات النهائية"""
        if self.stats['total_checks'] > 0:
            print(f"\n{Colors.GREEN}📊 FINAL STATISTICS:{Colors.RESET}")
            print(f"{Colors.GREEN}   Total Checks: {self.stats['total_checks']}{Colors.RESET}")
            print(f"{Colors.GREEN}   Available Found: {self.stats['available_found']}{Colors.RESET}")
            print(f"{Colors.GREEN}   Errors: {self.stats['errors']}{Colors.RESET}")
            print(f"{Colors.GREEN}   Rate Limits (429): {self.stats['rate_limits']}{Colors.RESET}")
            print(f"{Colors.GREEN}   WARP Devices Used: {self.stats['warp_devices_used']}{Colors.RESET}")
            print(f"{Colors.GREEN}   Emails Used: {self.stats['emails_used']}{Colors.RESET}")

def main():
    """الدالة الرئيسية"""
    # إنشاء checker
    checker = InstagramUsernameChecker()
    
    # بدء الفحص المستمر
    checker.start_continuous_checking()
    
    # طباعة الإحصائيات النهائية
    checker.print_final_stats()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}👋 Stopped by user{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error: {e}{Colors.RESET}")
