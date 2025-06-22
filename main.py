import os
import json
from datetime import datetime,date
from tkinter import messagebox
import ttkbootstrap as ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class EncryptionHandler:
    """处理AES加密解密的类"""
    BLOCK_SIZE = 16  # AES块大小
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.current_key = self.key_manager.get_current_key()
        
    def encrypt(self, data: str) -> bytes:
        """加密数据"""
        cipher = AES.new(self.current_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), self.BLOCK_SIZE))
        return cipher.iv + ct_bytes
        
    def decrypt(self, encrypted_data: bytes) -> str:
        """解密数据"""
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = AES.new(self.current_key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), self.BLOCK_SIZE)
        return pt.decode()

class KeyManager:
    """管理加密密钥的类"""
    KEY_FILE = "user_data/system.key"
    
    def __init__(self):
        self.check_key_rotation()
        
    def get_current_key(self) -> bytes:
        """获取当前密钥"""
        if os.path.exists(self.KEY_FILE):
            with open(self.KEY_FILE, "rb") as f:
                return f.read()
        return self.generate_new_key()
        
    def generate_new_key(self) -> bytes:
        """生成新密钥"""
        key = get_random_bytes(32)  # AES-256需要32字节密钥
        os.makedirs(os.path.dirname(self.KEY_FILE), exist_ok=True)
        with open(self.KEY_FILE, "wb") as f:
            f.write(key)
        return key
        
    def check_key_rotation(self):
        """检查是否需要轮换密钥"""
        LAST_KEY_DATE_FILE = "user_data/last_key_date"
        
        # 获取当前日期
        now = datetime.now()
        
        rotation_dates = [
            date(now.year, 1, 1),
            date(now.year, 7, 1)
        ]

        # 检查是否需要生成新密钥的条件
        need_new_key = False
        
        if not os.path.exists(self.KEY_FILE):
            # 如果密钥文件不存在，直接生成新密钥
            need_new_key = True
        else:
            # 读取上次密钥生成时间
            if os.path.exists(LAST_KEY_DATE_FILE):
                with open(LAST_KEY_DATE_FILE, "r") as f:
                    last_date_str = f.read().strip()
                    last_date = datetime.strptime(last_date_str, "%Y-%m-%d")
                    
                    # 检查是否跨过了1月1日或7月1日
                    for rotation_date in rotation_dates:
                        if last_date.date() < rotation_date <= date.today():
                            need_new_key = True
            else:
                # 如果没有记录文件，生成新密钥
                need_new_key = True
                
        if need_new_key:
            # 备份旧密钥
            old_key = None
            if os.path.exists(self.KEY_FILE):
                with open(self.KEY_FILE, "rb") as f:
                    old_key = f.read()
            
            # 生成新密钥
            self.generate_new_key()
            
            # 重新加密所有用户数据
            if old_key:
                self.re_encrypt_user_data(old_key)
            
            # 记录日期
            with open(LAST_KEY_DATE_FILE, "w") as f:
                f.write(now.strftime("%Y-%m-%d"))
    
    def re_encrypt_user_data(self, old_key: bytes):
        """用新密钥重新加密所有用户数据"""
        import glob
        import shutil
        from os import remove
        
        # 获取所有用户数据文件
        user_files = glob.glob("user_data/*.userdata")
        
        for user_file in user_files:
            try:
                # 创建备份文件
                backup_file = user_file + ".old"
                shutil.copyfile(user_file, backup_file)
                
                # 读取加密数据
                with open(user_file, "r") as f:
                    data = json.load(f)
                
                # 验证数据格式
                if "username" not in data or "password" not in data:
                    print(f"无效的用户数据格式: {user_file}")
                    continue
                    
                try:
                    # 用旧密钥解密
                    old_handler = EncryptionHandler()
                    old_handler.current_key = old_key
                    
                    username = bytes.fromhex(data["username"])
                    password = bytes.fromhex(data["password"])
                    
                    # 尝试解密数据
                    try:
                        decrypted_username = old_handler.decrypt(username)
                        decrypted_password = old_handler.decrypt(password)
                    except ValueError as e:
                        print(f"解密失败，可能使用了错误的密钥: {user_file}")
                        continue
                        
                    # 用新密钥重新加密
                    new_handler = EncryptionHandler()
                    data["username"] = new_handler.encrypt(decrypted_username).hex()
                    data["password"] = new_handler.encrypt(decrypted_password).hex()
                    
                    # 保存回文件
                    with open(user_file, "w") as f:
                        json.dump(data, f)     
                    
                    remove(backup_file)
     
                except Exception as e:
                    # 恢复备份文件
                    shutil.copyfile(backup_file, user_file)
                    print(f"重新加密失败，已恢复备份: {user_file}, 错误: {e}")

            except Exception as e:
                print(f"处理用户数据文件失败: {user_file}, 错误: {e}")

class LoginApp(ttk.Window):
    """主登录应用"""
    
    def __init__(self):
        super().__init__(themename="cosmo")
        self.title("安全登录系统")
        self.geometry("400x300")
        
        self.encryption = EncryptionHandler()
        
        self.create_widgets()
        
    def create_widgets(self):
        """创建界面组件"""
        # 用户名标签和输入框
        ttk.Label(self, text="用户名:").pack(pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.pack(pady=5)
        
        # 密码标签和输入框
        ttk.Label(self, text="密码:").pack(pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.pack(pady=5)
        
        # 登录按钮 - 使用绿色
        login_btn = ttk.Button(
            self, 
            text="登录", 
            command=self.handle_login,
            bootstyle="success"
        )
        login_btn.pack(pady=10)
        
        # 注册按钮 - 使用蓝色
        register_btn = ttk.Button(
            self, 
            text="注册", 
            command=self.show_register_dialog,
            bootstyle="info"
        )
        register_btn.pack(pady=10)
        
        # 忘记密码按钮 - 使用红色
        reset_password_btn = ttk.Button(
            self, 
            text="忘记密码", 
            command=self.show_reset_password_dialog,
            bootstyle="danger"
        )
        reset_password_btn.pack(pady=10)

    def handle_login(self):
        """处理登录逻辑"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("错误", "用户名和密码不能为空")
            return
            
        user_data = UserDataManager()
        if user_data.verify_user(username, password):
            messagebox.showinfo("成功", "登录成功!")
        else:
            messagebox.showerror("失败", "用户名或密码错误")
            
    def show_register_dialog(self):
        """显示注册对话框"""
        self.withdraw()  # 隐藏主窗口
        dialog = ttk.Toplevel(self)
        dialog.title("注册新用户")
        dialog.geometry("400x400")
        
        def on_dialog_close():
            """对话框关闭时的回调"""
            self.deiconify()  # 恢复显示主窗口
            dialog.destroy()
            
        dialog.protocol("WM_DELETE_WINDOW", on_dialog_close)
        
        ttk.Label(dialog, text="用户名:").pack(pady=5)
        username_entry = ttk.Entry(dialog)
        username_entry.pack(pady=5)
        
        ttk.Label(dialog, text="密码:").pack(pady=5)
        password_entry = ttk.Entry(dialog, show="*")
        password_entry.pack(pady=5)
        
        ttk.Label(dialog, text="确认密码:").pack(pady=5)
        confirm_entry = ttk.Entry(dialog, show="*")
        confirm_entry.pack(pady=5)
        
        def handle_register():
            username = username_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not username or not password:
                messagebox.showerror("错误", "用户名和密码不能为空", parent=dialog)
                return
                
            if password != confirm:
                messagebox.showerror("错误", "两次输入的密码不一致", parent=dialog)
                return
                
            user_data = UserDataManager()
            if os.path.exists(user_data.get_user_file(username)):
                messagebox.showerror("错误", "用户名已存在", parent=dialog)
                return
                
            user_data.save_user(username, password)
            messagebox.showinfo("成功", "注册成功!", parent=dialog)
            self.deiconify()  # 恢复显示主窗口
            dialog.destroy()
            
        # 注册对话框中的注册按钮 - 使用蓝色
        ttk.Button(
            dialog, 
            text="注册", 
            command=handle_register,
            bootstyle="info"
        ).pack(pady=10)

        ttk.Button(
            dialog, 
            text="返回登录", 
            command=on_dialog_close,
            bootstyle="secondary"
        ).pack(pady=10)

    def show_reset_password_dialog(self):
        """显示重置密码对话框"""
        self.withdraw()  # 隐藏主窗口
        dialog = ttk.Toplevel(self)
        dialog.title("重置密码")
        dialog.geometry("400x400")
        
        def on_dialog_close():
            """对话框关闭时的回调"""
            self.deiconify()  # 恢复显示主窗口
            dialog.destroy()
            
        dialog.protocol("WM_DELETE_WINDOW", on_dialog_close)
        
        ttk.Label(dialog, text="用户名:").pack(pady=5)
        username_entry = ttk.Entry(dialog)
        username_entry.pack(pady=5)
        
        ttk.Label(dialog, text="新密码:").pack(pady=5)
        password_entry = ttk.Entry(dialog, show="*")
        password_entry.pack(pady=5)
        
        ttk.Label(dialog, text="确认密码:").pack(pady=5)
        confirm_entry = ttk.Entry(dialog, show="*")
        confirm_entry.pack(pady=5)
        
        def handle_reset_password():
            username = username_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not username or not password:
                messagebox.showerror("错误", "用户名和密码不能为空", parent=dialog)
                return
                
            if password != confirm:
                messagebox.showerror("错误", "两次输入的密码不一致", parent=dialog)
                return
                
            user_data = UserDataManager()
            if not os.path.exists(user_data.get_user_file(username)):
                messagebox.showerror("错误", "用户名不存在", parent=dialog)
                return
                
            user_data.save_user(username, password)
            messagebox.showinfo("成功", "密码重置成功!", parent=dialog)
            self.deiconify()  # 恢复显示主窗口
            dialog.destroy()
            
        # 注册对话框中的注册按钮 - 使用蓝色
        ttk.Button(
            dialog, 
            text="重置密码", 
            command=handle_reset_password,
            bootstyle="info"
        ).pack(pady=10)

        ttk.Button(
            dialog, 
            text="返回登录", 
            command=on_dialog_close,
            bootstyle="secondary"
        ).pack(pady=10)

class UserDataManager:
    """管理用户数据的类"""
    
    def __init__(self):
        self.encryption = EncryptionHandler()
        os.makedirs("user_data", exist_ok=True)
        
    def get_user_file(self, username: str) -> str:
        """获取用户数据文件路径"""
        import base64
        username_bytes = username.encode('utf-8')
        username_hash = base64.b64encode(username_bytes).decode('utf-8')
        return f"user_data/{username_hash}.userdata"
        
    def save_user(self, username: str, password: str):
        """保存用户数据"""
        user_file = self.get_user_file(username)
        data = {
            "username": self.encryption.encrypt(username).hex(),
            "password": self.encryption.encrypt(password).hex()
        }
        with open(user_file, "w") as f:
            json.dump(data, f)
            
    def verify_user(self, username: str, password: str) -> bool:
        """验证用户"""
        user_file = self.get_user_file(username)
        if not os.path.exists(user_file):
            return False
            
        try:
            with open(user_file, "r") as f:
                data = json.load(f)
                
            stored_username = bytes.fromhex(data["username"])
            stored_password = bytes.fromhex(data["password"])
            
            decrypted_username = self.encryption.decrypt(stored_username)
            decrypted_password = self.encryption.decrypt(stored_password)
            
            return decrypted_username == username and decrypted_password == password
        except:
            return False

if __name__ == "__main__":
    app = LoginApp()
    app.mainloop()
