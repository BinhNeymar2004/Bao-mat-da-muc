import requests
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, ttk, font
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import random
import string
import os
import io
import datetime
import threading
import time
from PIL import Image, ImageTk, ImageDraw, ImageFilter

TELEGRAM_BOT_TOKEN = '8077218739:AAEXUP4rOH09jHWkpxqgiSPQuIE6n0Vv8ag'
CHAT_ID = '5818107830'

# Tạo khóa RSA
def generate_rsa_keys():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Hàm hash dữ liệu bằng SHA-256
def hash_data(data):
    sha256 = SHA256.new()
    sha256.update(data)
    return sha256.hexdigest()

# Mã hóa với AES
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

# Giải mã với AES
def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Mã hóa với DES
def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    return cipher.iv + ct_bytes

# Giải mã với DES
def des_decrypt(encrypted_data, key):
    iv = encrypted_data[:DES.block_size]
    ct = encrypted_data[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size)

# Tạo OTP
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

# Gửi OTP qua Telegram
def send_otp_via_telegram(otp, purpose=""):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    message = f"Your OTP for {purpose} is: {otp}"
    data = {"chat_id": CHAT_ID, "text": message}
    response = requests.post(url, data=data)
    return response.status_code == 200

# Hàm kiểm tra nếu file là hình ảnh
def is_image_file(file_path):
    image_extensions = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff']
    ext = os.path.splitext(file_path)[1].lower()
    return ext in image_extensions

# Tạo hình thumbnail tròn cho hình ảnh
def create_circular_thumbnail(image_data, size=(150, 150)):
    try:
        img = Image.open(io.BytesIO(image_data))
        img = img.convert("RGBA")
        
        # Tạo hình vuông
        img.thumbnail(size, Image.Resampling.LANCZOS)
        
        # Tạo mặt nạ hình tròn
        mask = Image.new('L', size, 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0) + size, fill=255)
        
        # Tạo hình tròn
        result = Image.new('RGBA', size, (0, 0, 0, 0))
        result.paste(img, (0, 0), mask)
        
        # Thêm viền
        border = Image.new('RGBA', size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(border)
        draw.ellipse((0, 0) + size, outline="#4a90e2", width=3)
        result.paste(border, (0, 0), border)
        
        return ImageTk.PhotoImage(result)
    except Exception as e:
        print(f"Không thể tạo thumbnail: {str(e)}")
        return None

# Tạo hiệu ứng nút hover
class HoverButton(tk.Button):
    def __init__(self, master, active_bg="#4a90e2", active_fg="white", **kw):
        self.active_bg = active_bg
        self.active_fg = active_fg
        self.default_bg = kw.get('background', 'SystemButtonFace')
        self.default_fg = kw.get('foreground', 'SystemButtonText')
        
        super().__init__(master, **kw)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
    
    def on_enter(self, e):
        self['background'] = self.active_bg
        self['foreground'] = self.active_fg
    
    def on_leave(self, e):
        self['background'] = self.default_bg
        self['foreground'] = self.default_fg

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Bảo mật đa mức")
        self.master.geometry("1100x800")
        self.master.minsize(900, 700)
        
        # Định nghĩa bảng màu mới - màu sắc hiện đại
        self.colors = {
            "primary": "#4a90e2",  # Xanh dương chính
            "secondary": "#5c6bc0",  # Xanh tím nhạt
            "success": "#66bb6a",  # Xanh lá
            "warning": "#ffa726",  # Cam
            "danger": "#ef5350",  # Đỏ
            "light": "#f5f7fa",  # Xám nhạt
            "dark": "#263238",  # Xám đậm
            "text": "#37474f",  # Màu chữ
            "border": "#e0e0e0",  # Viền
            "highlight": "#bbdefb",  # Xanh dương nhạt dùng làm highlight
            "card_bg": "#ffffff"  # Nền card
        }
        
        # Thiết lập màu nền chính
        self.master.configure(background=self.colors["light"])
        
        # Thiết lập fonts - sử dụng font Roboto hoặc tương tự nếu có
        self.fonts = {
            "title": font.Font(family="Segoe UI", size=16, weight="bold"),
            "header": font.Font(family="Segoe UI", size=13, weight="bold"),
            "subheader": font.Font(family="Segoe UI", size=11, weight="bold"),
            "normal": font.Font(family="Segoe UI", size=10),
            "small": font.Font(family="Segoe UI", size=9),
            "button": font.Font(family="Segoe UI", size=10, weight="bold")
        }

        # Khởi tạo các khóa và biến
        self.private_key, self.public_key = generate_rsa_keys()
        self.encrypted_data = None
        self.encrypted_key = None
        self.original_hash = None
        self.encryption_otp = None
        self.decryption_otp = None
        self.des_key = None
        self.aes_key = None
        self.selected_file_path = None
        self.is_image = False
        self.image_thumbnail = None
        
        # Tạo style cho ttk widgets
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Định nghĩa các style cho ttk
        self.style.configure("TFrame", background=self.colors["light"])
        self.style.configure("Card.TFrame", background=self.colors["card_bg"], relief="solid", borderwidth=1)
        
        self.style.configure("Header.TLabel", 
                          background=self.colors["primary"], 
                          foreground="white", 
                          font=self.fonts["header"], 
                          padding=10)
        
        self.style.configure("TLabel", 
                          background=self.colors["light"], 
                          foreground=self.colors["text"], 
                          font=self.fonts["normal"])
        
        self.style.configure("Card.TLabel", 
                          background=self.colors["card_bg"], 
                          foreground=self.colors["text"], 
                          font=self.fonts["normal"])
        
        self.style.configure("Title.TLabel", 
                          background=self.colors["light"], 
                          foreground=self.colors["dark"], 
                          font=self.fonts["title"],
                          padding=5)
        
        self.style.configure("TButton", 
                          font=self.fonts["button"], 
                          background=self.colors["primary"],
                          foreground="white")
        
        self.style.map("TButton", 
                    background=[('active', self.colors["secondary"])],
                    foreground=[('active', "white")])
        
        self.style.configure("Primary.TButton", 
                          background=self.colors["primary"], 
                          foreground="white")
        
        self.style.map("Primary.TButton",
                    background=[('active', self.colors["secondary"])],
                    foreground=[('active', "white")])
        
        self.style.configure("Success.TButton", 
                          background=self.colors["success"], 
                          foreground="white")
        
        self.style.map("Success.TButton",
                    background=[('active', "#43a047")],  # Màu success đậm hơn
                    foreground=[('active', "white")])
                          
        self.style.configure("Warning.TButton", 
                          background=self.colors["warning"], 
                          foreground="white")
        
        self.style.map("Warning.TButton",
                    background=[('active', "#fb8c00")],  # Màu warning đậm hơn
                    foreground=[('active', "white")])
        
        self.style.configure("Danger.TButton", 
                          background=self.colors["danger"], 
                          foreground="white")
        
        self.style.map("Danger.TButton",
                    background=[('active', "#e53935")],  # Màu danger đậm hơn
                    foreground=[('active', "white")])
        
        self.style.configure("TEntry", 
                          padding=5,
                          fieldbackground="white",
                          background="white",
                          foreground=self.colors["text"],
                          insertcolor=self.colors["primary"],
                          bordercolor=self.colors["border"])
        
        self.style.map("TEntry",
                    fieldbackground=[('focus', "white")],
                    bordercolor=[('focus', self.colors["primary"])])
        
        self.style.configure("TCheckbutton", 
                          background=self.colors["light"], 
                          foreground=self.colors["text"], 
                          font=self.fonts["normal"])
        
        self.style.map("TCheckbutton",
                    background=[('active', self.colors["light"])],
                    foreground=[('active', self.colors["primary"])])
        
        self.style.configure("Card.TCheckbutton", 
                          background=self.colors["card_bg"], 
                          foreground=self.colors["text"], 
                          font=self.fonts["normal"])
        
        self.style.map("Card.TCheckbutton",
                    background=[('active', self.colors["card_bg"])],
                    foreground=[('active', self.colors["primary"])])
        
        self.style.configure("TLabelframe", 
                          background=self.colors["card_bg"], 
                          foreground=self.colors["text"],
                          bordercolor=self.colors["border"])
        
        self.style.configure("TLabelframe.Label", 
                          background=self.colors["card_bg"], 
                          foreground=self.colors["primary"],
                          font=self.fonts["subheader"])
        
        self.style.configure("TProgressbar", 
                          background=self.colors["primary"],
                          troughcolor=self.colors["light"],
                          bordercolor=self.colors["border"])
        
        self.style.configure("TNotebook", 
                          background=self.colors["light"], 
                          tabmargins=[2, 5, 2, 0])
        
        self.style.configure("TNotebook.Tab", 
                          background=self.colors["card_bg"],
                          foreground=self.colors["text"],
                          font=self.fonts["normal"],
                          padding=[10, 4],
                          bordercolor=self.colors["border"])
        
        self.style.map("TNotebook.Tab",
                    background=[('selected', self.colors["primary"])],
                    foreground=[('selected', "white")],
                    padding=[('selected', [10, 6, 10, 4])])
        
        # Tạo Canvas chính và thanh cuộn
        self.main_canvas = tk.Canvas(self.master, background=self.colors["light"], highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.master, orient="vertical", command=self.main_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.main_canvas)
        
        # Thiết lập cấu hình cuộn
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.main_canvas.configure(
                scrollregion=self.main_canvas.bbox("all")
            )
        )
        
        # Tạo cửa sổ trong canvas
        self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.main_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Sắp xếp canvas và thanh cuộn
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Thêm sự kiện cuộn bằng chuột
        self.main_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Container chính - trong scrollable_frame
        self.main_container = ttk.Frame(self.scrollable_frame, style="TFrame")
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Tiêu đề ứng dụng với logo/biểu tượng
        self.header_frame = ttk.Frame(self.main_container)
        self.header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Tạo logo biểu tượng khóa
        logo_frame = ttk.Frame(self.header_frame)
        logo_frame.pack(fill=tk.X, ipady=15, ipadx=10)
        
        # Tạo wave animated effect
        self.wave_canvas = tk.Canvas(logo_frame, background=self.colors["primary"], highlightthickness=0, height=80)
        self.wave_canvas.pack(fill=tk.X)
        
        self.draw_waves()  # Vẽ sóng ban đầu
        
        # Tạo tiêu đề ứng dụng
        self.app_title = ttk.Label(self.wave_canvas, text="BẢO MẬT ĐA MỨC", font=self.fonts["title"], 
                                 background=self.colors["primary"], foreground="white")
        self.app_title.place(relx=0.5, rely=0.5, anchor="center")
        
        # Tạo frame chứa nội dung chính (cả hai cột)
        self.content_frame = ttk.Frame(self.main_container)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Tạo Notebook để tổ chức các tab
        self.notebook = ttk.Notebook(self.content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab Mã hóa và Giải mã
        self.encryption_tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.encryption_tab, text="Mã hóa & Giải mã")
        
        # Tab Thông tin Thuật toán
        self.algorithm_info_tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.algorithm_info_tab, text="Thông tin Thuật toán")
        
        # Tab Nhật ký & Thống kê
        self.log_tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.log_tab, text="Nhật ký & Thống kê")
        
        # Tạo nội dung cho tab mã hóa và giải mã
        self.setup_encryption_tab()
        
        # Tạo nội dung cho tab thông tin thuật toán
        self.setup_algorithm_info_tab()
        
        # Tạo nội dung cho tab nhật ký
        self.setup_log_tab()
        
        # Thanh trạng thái - được đặt cố định ở dưới cùng của scrollable frame
        self.status_frame = ttk.Frame(self.main_container)
        self.status_frame.pack(fill=tk.X, pady=(20, 0), side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Sẵn sàng")
        self.status_bar = ttk.Label(self.status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X)
        
        self.progress = ttk.Progressbar(self.status_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(5, 0))
        
        self.decrypted_file_path = None
        
        # Hiệu ứng loading
        self.loading_frame = ttk.Frame(self.master, style="TFrame")
        self.loading_var = tk.StringVar(value="Đang xử lý...")
        self.loading_label = ttk.Label(self.loading_frame, textvariable=self.loading_var, 
                                    font=self.fonts["header"], background=self.colors["light"])
        self.loading_progress = ttk.Progressbar(self.loading_frame, mode="indeterminate")
        
        # Thêm sau khi tất cả widgets đã được tạo
        self.create_tooltip()
        
        # Cập nhật vùng cuộn sau khi tất cả widget đã được tạo
        self.scrollable_frame.update_idletasks()
        self.main_canvas.config(scrollregion=self.main_canvas.bbox("all"))
        
        # Bắt đầu animation 
        self.start_wave_animation()
        
        # Thêm log mặc định
        self.add_log("Ứng dụng đã khởi động")

    def draw_waves(self):
        # Xóa wave canvas
        self.wave_canvas.delete("all")
        
        # Tạo hiệu ứng sóng
        self.wave_canvas.create_rectangle(0, 0, self.wave_canvas.winfo_width(), self.wave_canvas.winfo_height(),
                                      fill=self.colors["primary"], outline="")
        
        # Lấy kích thước canvas
        width = self.wave_canvas.winfo_width()
        height = self.wave_canvas.winfo_height()
        
        # Vẽ các sóng với độ trong suốt
        for i in range(3):
            offset = (time.time() * (i+1)) % 3.14159
            points = []
            for x in range(0, width+20, 20):
                y = height - 10 - (5 * (i+1)) + (7 * (i+1)) * math.sin(x/100 + offset)
                points.extend([x, y])
            
            # Thêm các điểm để đóng đường cong
            points.extend([width, height, 0, height])
            
            # Tạo màu sóng với độ trong suốt dựa trên chỉ số
            wave_color = self.hex_to_rgb(self.colors["secondary"])
            alpha = 0.2 + (0.2 * i)
            fill_color = f"#{wave_color[0]:02x}{wave_color[1]:02x}{wave_color[2]:02x}"
            
            # Vẽ sóng
            self.wave_canvas.create_polygon(points, fill=fill_color, outline="", smooth=True)

    def hex_to_rgb(self, hex_color):
        """Chuyển đổi màu HEX sang RGB"""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def start_wave_animation(self):
        """Bắt đầu hoạt ảnh sóng"""
        self.draw_waves()
        self.master.after(50, self.start_wave_animation)

    def setup_encryption_tab(self):
        """Thiết lập nội dung cho tab mã hóa và giải mã"""
        # Chia tab thành hai cột 
        encryption_content = ttk.Frame(self.encryption_tab)
        encryption_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ========== CỘT TRÁI ==========
        self.left_frame = ttk.Frame(encryption_content, padding=10)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Frame chọn thuật toán
        self.algorithm_frame = ttk.LabelFrame(self.left_frame, text="Thuật toán mã hóa", padding=10)
        self.algorithm_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.algorithm_vars = {}
        self.algorithms = ["AES", "DES", "RSA", "SHA"]
        
        # Tạo layout 2x2 cho các checkbox thuật toán với icon
        algo_container = ttk.Frame(self.algorithm_frame)
        algo_container.pack(fill=tk.X)
        
        row, col = 0, 0
        for alg in self.algorithms:
            self.algorithm_vars[alg] = tk.BooleanVar()
            
            # Container cho mỗi checkbox để thêm icon và mô tả
            algo_item = ttk.Frame(algo_container, style="Card.TFrame", padding=5)
            algo_item.grid(row=row, column=col, sticky=tk.W, padx=5, pady=5)
            
            # Checkbox
            chk = ttk.Checkbutton(algo_item, text=alg, variable=self.algorithm_vars[alg], 
                                style="Card.TCheckbutton", command=self.update_algorithm_comparison)
            chk.pack(anchor=tk.W)
            
            # Mô tả thuật toán
            if alg == "AES":
                desc = "Mã hóa đối xứng tiêu chuẩn"
            elif alg == "DES":
                desc = "Mã hóa khối truyền thống"
            elif alg == "RSA":
                desc = "Mã hóa khóa công khai"
            else:
                desc = "Bảo vệ tính toàn vẹn dữ liệu"
                
            desc_label = ttk.Label(algo_item, text=desc, style="Card.TLabel", font=self.fonts["small"])
            desc_label.pack(anchor=tk.W, padx=(15, 0))
            
            col += 1
            if col > 1:
                col = 0
                row += 1
                
        # Frame xem trước hình ảnh
        self.image_preview_frame = ttk.LabelFrame(self.left_frame, text="Xem trước hình ảnh", padding=10)
        self.image_preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        self.image_container = ttk.Frame(self.image_preview_frame, height=170, width=170)
        self.image_container.pack(pady=5, expand=True)
        self.image_container.pack_propagate(False)
        
        # Thêm đường viền cho khung hình ảnh
        self.image_border = ttk.Frame(self.image_container, style="Card.TFrame")
        self.image_border.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.image_preview_label = ttk.Label(self.image_border, text="Không có hình ảnh", style="Card.TLabel")
        self.image_preview_label.pack(expand=True)
        
        # Frame OTP mã hóa và giải mã riêng biệt
        self.otp_frame = ttk.LabelFrame(self.left_frame, text="Xác thực OTP", padding=10)
        self.otp_frame.pack(fill=tk.X, pady=(0, 0))

        # Frame cho OTP mã hóa
        self.encrypt_otp_frame = ttk.Frame(self.otp_frame)
        self.encrypt_otp_frame.pack(fill=tk.X, pady=5)
        
        encrypt_otp_label = ttk.Label(self.encrypt_otp_frame, text="OTP Mã hóa:", style="Card.TLabel")
        encrypt_otp_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.encryption_otp_var = tk.StringVar()
        self.encryption_otp_entry = ttk.Entry(self.encrypt_otp_frame, textvariable=self.encryption_otp_var, 
                                           font=self.fonts["normal"], width=15)
        self.encryption_otp_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        self.encrypt_otp_button = ttk.Button(self.encrypt_otp_frame, text="Tạo OTP", 
                                          command=self.generate_encryption_otp, style="Primary.TButton",
                                          width=10)
        self.encrypt_otp_button.pack(side=tk.RIGHT)

        # Frame cho OTP giải mã
        self.decrypt_otp_frame = ttk.Frame(self.otp_frame)
        self.decrypt_otp_frame.pack(fill=tk.X, pady=5)
        
        decrypt_otp_label = ttk.Label(self.decrypt_otp_frame, text="OTP Giải mã:", style="Card.TLabel")
        decrypt_otp_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.decryption_otp_var = tk.StringVar()
        self.decryption_otp_entry = ttk.Entry(self.decrypt_otp_frame, textvariable=self.decryption_otp_var, 
                                           font=self.fonts["normal"], width=15)
        self.decryption_otp_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        self.decrypt_otp_button = ttk.Button(self.decrypt_otp_frame, text="Tạo OTP", 
                                          command=self.generate_decryption_otp, style="Primary.TButton",
                                          width=10)
        self.decrypt_otp_button.pack(side=tk.RIGHT)
        
        # ========== CỘT PHẢI ==========
        self.right_frame = ttk.Frame(encryption_content, padding=10)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # Frame thông tin tệp
        self.file_frame = ttk.LabelFrame(self.right_frame, text="Thông tin tệp", padding=10)
        self.file_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.select_file_btn = ttk.Button(self.file_frame, text="Chọn tệp", command=self.select_file,
                                       style="Primary.TButton")
        self.select_file_btn.pack(fill=tk.X, pady=5, ipady=5)
        
        # Thêm frame thông tin tệp với shadow effect
        file_info_border = ttk.Frame(self.file_frame, style="Card.TFrame")
        file_info_border.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        self.file_info_frame = ttk.Frame(file_info_border, style="Card.TFrame")
        self.file_info_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        self.file_path_var = tk.StringVar(value="Chưa chọn tệp")
        self.file_path_label = ttk.Label(self.file_info_frame, textvariable=self.file_path_var, 
                                      style="Card.TLabel", wraplength=350)
        self.file_path_label.pack(fill=tk.X, pady=2)
        
        self.file_status_var = tk.StringVar(value="Trạng thái: Chưa sẵn sàng")
        self.file_status = ttk.Label(self.file_info_frame, textvariable=self.file_status_var, 
                                   style="Card.TLabel")
        self.file_status.pack(fill=tk.X, pady=2)
        
        # Frame hash SHA với Card style
        self.hash_frame = ttk.LabelFrame(self.right_frame, text="Thông tin hash SHA", padding=10)
        self.hash_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Thêm frame hash với shadow effect
        hash_info_border = ttk.Frame(self.hash_frame, style="Card.TFrame")
        hash_info_border.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        self.hash_info_frame = ttk.Frame(hash_info_border, style="Card.TFrame")
        self.hash_info_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        self.original_hash_var = tk.StringVar(value="Hash gốc: Chưa có")
        self.original_hash_label = ttk.Label(self.hash_info_frame, textvariable=self.original_hash_var, 
                                         style="Card.TLabel", wraplength=350)
        self.original_hash_label.pack(fill=tk.X, pady=2)
        
        self.decrypted_hash_var = tk.StringVar(value="Hash sau giải mã: Chưa có")
        self.decrypted_hash_label = ttk.Label(self.hash_info_frame, textvariable=self.decrypted_hash_var, 
                                           style="Card.TLabel", wraplength=350)
        self.decrypted_hash_label.pack(fill=tk.X, pady=2)
        
        self.hash_match_var = tk.StringVar(value="Trạng thái: Chưa so sánh")
        self.hash_match_label = ttk.Label(self.hash_info_frame, textvariable=self.hash_match_var, 
                                       style="Card.TLabel")
        self.hash_match_label.pack(fill=tk.X, pady=2)
        
        # Frame hành động - Di chuyển lên đầu cột phải để luôn hiển thị
        self.action_frame = ttk.LabelFrame(self.right_frame, text="Hành động", padding=10)
        self.action_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.button_frame = ttk.Frame(self.action_frame)
        self.button_frame.pack(fill=tk.X, expand=True)
        
        # Nút mã hóa với hiệu ứng
        self.encrypt_button = ttk.Button(self.button_frame, text="Mã hóa tệp", 
                                    command=self.encrypt_file, style="Primary.TButton")
        self.encrypt_button.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5, padx=(0, 5), ipady=8)
        
        # Nút giải mã với hiệu ứng
        self.decrypt_button = ttk.Button(self.button_frame, text="Giải mã tệp", 
                                    command=self.decrypt_file, style="Success.TButton")
        self.decrypt_button.pack(side=tk.RIGHT, fill=tk.X, expand=True, pady=5, padx=(5, 0), ipady=8)
        
        # Nút xem hình ảnh
        self.view_image_button = ttk.Button(self.action_frame, text="Xem hình ảnh đã giải mã", 
                                        command=self.view_decrypted_image, state=tk.DISABLED,
                                        style="Warning.TButton")
        self.view_image_button.pack(fill=tk.X, pady=(5, 0), ipady=8)
        
    def setup_algorithm_info_tab(self):
        """Thiết lập tab thông tin thuật toán"""
        # Frame chính
        algo_info_main = ttk.Frame(self.algorithm_info_tab)
        algo_info_main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Tiêu đề
        algo_title = ttk.Label(algo_info_main, text="Thông tin và So sánh các Thuật toán Mã hóa", 
                              style="Title.TLabel")
        algo_title.pack(fill=tk.X, pady=(0, 15))
        
        # Tạo frame để hiển thị thông tin thuật toán
        algo_content = ttk.Frame(algo_info_main)
        algo_content.pack(fill=tk.BOTH, expand=True)
        
        # Tạo bảng so sánh
        self.comparison_frame = ttk.LabelFrame(algo_content, text="So sánh mã hóa & giải mã", padding=10)
        self.comparison_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Thêm thanh cuộn cho vùng văn bản so sánh với style mới
        comparison_container = ttk.Frame(self.comparison_frame, style="Card.TFrame")
        comparison_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.comparison_scroll = ttk.Scrollbar(comparison_container)
        self.comparison_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.comparison_text = tk.Text(comparison_container, font=self.fonts["normal"], wrap=tk.WORD, 
                                     height=12, bg=self.colors["card_bg"], 
                                     fg=self.colors["text"],
                                     bd=0, highlightthickness=0,
                                     yscrollcommand=self.comparison_scroll.set)
        self.comparison_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.comparison_scroll.config(command=self.comparison_text.yview)
        
        self.update_algorithm_comparison()  # Khởi tạo với nội dung mặc định
        
        # Thêm bảng so sánh thuật toán
        self.algorithm_table_frame = ttk.LabelFrame(algo_content, text="Bảng Đặc điểm Thuật toán", padding=10)
        self.algorithm_table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Tạo bảng so sánh thuật toán
        table_container = ttk.Frame(self.algorithm_table_frame, style="Card.TFrame")
        table_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tạo header cho bảng
        header_frame = ttk.Frame(table_container, style="Card.TFrame")
        header_frame.pack(fill=tk.X)
        
        headers = ["Thuật toán", "Loại", "Kích thước khóa", "Tốc độ", "Độ bảo mật", "Ứng dụng"]
        widths = [100, 80, 120, 80, 100, 150]
        
        for i, header in enumerate(headers):
            header_label = ttk.Label(header_frame, text=header, font=self.fonts["subheader"], 
                                   style="Card.TLabel", anchor=tk.CENTER,
                                   background=self.colors["primary"], foreground="white")
            header_label.grid(row=0, column=i, padx=1, pady=1, sticky=tk.NSEW, ipadx=5, ipady=5)
            header_frame.grid_columnconfigure(i, weight=1, minsize=widths[i])
        
        # Dữ liệu thuật toán
        algorithm_data = [
            ["AES", "Đối xứng", "128, 192, 256 bit", "Nhanh", "Rất cao", "Mã hóa file, web, ứng dụng"],
            ["DES", "Đối xứng", "56 bit", "Trung bình", "Thấp (lỗi thời)", "Legacy systems"],
            ["RSA", "Bất đối xứng", "1024-4096 bit", "Chậm", "Cao", "Mã hóa khóa, chữ ký số"],
            ["SHA", "Hàm băm", "224-512 bit", "Nhanh", "Cao", "Kiểm tra toàn vẹn dữ liệu"]
        ]
        
        # Tạo các hàng dữ liệu
        for row_idx, algo_row in enumerate(algorithm_data):
            row_frame = ttk.Frame(table_container, style="Card.TFrame")
            row_frame.pack(fill=tk.X)
            
            # Màu nền hàng chẵn/lẻ
            bg_color = self.colors["light"] if row_idx % 2 else self.colors["card_bg"]
            
            for col_idx, cell_data in enumerate(algo_row):
                cell_label = ttk.Label(row_frame, text=cell_data, style="Card.TLabel", 
                                     background=bg_color, anchor=tk.CENTER,
                                     wraplength=widths[col_idx]-10)
                cell_label.grid(row=0, column=col_idx, padx=1, pady=1, sticky=tk.NSEW, ipadx=5, ipady=5)
                row_frame.grid_columnconfigure(col_idx, weight=1, minsize=widths[col_idx])
    
    def setup_log_tab(self):
        """Thiết lập tab nhật ký"""
        log_main = ttk.Frame(self.log_tab)
        log_main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Tiêu đề
        log_title = ttk.Label(log_main, text="Nhật ký Hoạt động và Thống kê", 
                             style="Title.TLabel")
        log_title.pack(fill=tk.X, pady=(0, 15))
        
        # Tạo frame nhật ký
        self.log_frame = ttk.LabelFrame(log_main, text="Nhật ký hoạt động", padding=10)
        self.log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Thêm thanh cuộn cho vùng văn bản log
        log_container = ttk.Frame(self.log_frame, style="Card.TFrame")
        log_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_scroll = ttk.Scrollbar(log_container)
        self.log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
 
        self.log_text = tk.Text(log_container, font=self.fonts["normal"], wrap=tk.WORD, 
                               height=15, bg=self.colors["card_bg"], 
                               fg=self.colors["text"],
                               bd=0, highlightthickness=0,
                               yscrollcommand=self.log_scroll.set)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_scroll.config(command=self.log_text.yview)
        self.log_text.config(state=tk.DISABLED)
        
        # Tạo frame thống kê
        self.stats_frame = ttk.LabelFrame(log_main, text="Thống kê hoạt động", padding=10)
        self.stats_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Container cho thống kê
        stats_container = ttk.Frame(self.stats_frame, style="Card.TFrame")
        stats_container.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        # Tạo 3 card thống kê theo hàng ngang
        self.files_processed = tk.IntVar(value=0)
        self.encryptions = tk.IntVar(value=0)
        self.decryptions = tk.IntVar(value=0)
        
        # Frame chứa các card
        stats_cards = ttk.Frame(stats_container, style="Card.TFrame")
        stats_cards.pack(fill=tk.X, expand=True, padx=10, pady=10)
        
        # Card thống kê 1
        stats_card1 = ttk.Frame(stats_cards, style="Card.TFrame")
        stats_card1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        card1_title = ttk.Label(stats_card1, text="Tệp đã xử lý", 
                             style="Card.TLabel", font=self.fonts["subheader"],
                             foreground=self.colors["primary"])
        card1_title.pack(pady=5)
        
        card1_value = ttk.Label(stats_card1, textvariable=self.files_processed, 
                              style="Card.TLabel", font=self.fonts["title"])
        card1_value.pack(pady=5)
        
        # Card thống kê 2
        stats_card2 = ttk.Frame(stats_cards, style="Card.TFrame")
        stats_card2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        card2_title = ttk.Label(stats_card2, text="Mã hóa thành công", 
                             style="Card.TLabel", font=self.fonts["subheader"],
                             foreground=self.colors["success"])
        card2_title.pack(pady=5)
        
        card2_value = ttk.Label(stats_card2, textvariable=self.encryptions, 
                              style="Card.TLabel", font=self.fonts["title"])
        card2_value.pack(pady=5)
        
        # Card thống kê 3
        stats_card3 = ttk.Frame(stats_cards, style="Card.TFrame")
        stats_card3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        card3_title = ttk.Label(stats_card3, text="Giải mã thành công", 
                             style="Card.TLabel", font=self.fonts["subheader"],
                             foreground=self.colors["warning"])
        card3_title.pack(pady=5)
        
        card3_value = ttk.Label(stats_card3, textvariable=self.decryptions, 
                              style="Card.TLabel", font=self.fonts["title"])
        card3_value.pack(pady=5)

    def create_tooltip(self):
        """Tạo tooltip cho các thành phần UI"""
        self.tooltips = []
        
        # Tooltip cho OTP mã hóa
        self.tooltips.append(ToolTip(self.encrypt_otp_button, 
                                    "Tạo và gửi mã OTP dùng cho xác thực khi mã hóa tệp. OTP sẽ được gửi qua Telegram."))
        
        # Tooltip cho OTP giải mã
        self.tooltips.append(ToolTip(self.decrypt_otp_button, 
                                    "Tạo và gửi mã OTP dùng cho xác thực khi giải mã tệp. OTP sẽ được gửi qua Telegram."))
        
        # Tooltip cho nút mã hóa
        self.tooltips.append(ToolTip(self.encrypt_button, 
                                    "Mã hóa tệp đã chọn bằng thuật toán được chọn. Cần xác thực OTP mã hóa."))
        
        # Tooltip cho nút giải mã
        self.tooltips.append(ToolTip(self.decrypt_button, 
                                    "Giải mã tệp đã chọn. Cần xác thực OTP giải mã."))

    def _on_mousewheel(self, event):
        """Xử lý sự kiện cuộn chuột"""
        self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def add_log(self, message):
        """Thêm thông báo vào nhật ký hoạt động"""
        import datetime
        
        # Lấy thời gian hiện tại
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Cấu hình trạng thái của text widget để có thể chỉnh sửa
        self.log_text.config(state=tk.NORMAL)
        
        # Chèn dòng log với thời gian
        self.log_text.insert(tk.END, f"[{current_time}] {message}\n")
        
        # Cuộn xuống dòng mới nhất
        self.log_text.see(tk.END)
        
        # Khóa lại text widget để không thể chỉnh sửa
        self.log_text.config(state=tk.DISABLED)

    def update_algorithm_comparison(self):
        """Cập nhật nội dung so sánh mã hóa và giải mã dựa trên thuật toán được chọn"""
        self.comparison_text.config(state=tk.NORMAL)
        self.comparison_text.delete(1.0, tk.END)
        selected_algorithms = self.get_selected_algorithms()
        
        if not selected_algorithms:
            self.comparison_text.insert(tk.END, "Chưa chọn thuật toán nào.\nVui lòng chọn ít nhất một thuật toán để xem sự khác biệt.")
            self.comparison_text.config(state=tk.DISABLED)
            return

        # Tạo header với định dạng đẹp
        self.comparison_text.insert(tk.END, "SO SÁNH CÁC THUẬT TOÁN MÃ HÓA\n", "header")
        self.comparison_text.insert(tk.END, "="*50 + "\n\n")
        
        # Định dạng text widget
        self.comparison_text.tag_configure("header", font=self.fonts["subheader"], foreground=self.colors["primary"])
        self.comparison_text.tag_configure("subheader", font=self.fonts["subheader"], foreground=self.colors["secondary"])
        self.comparison_text.tag_configure("important", font=self.fonts["normal"], foreground=self.colors["danger"])
        self.comparison_text.tag_configure("highlight", background=self.colors["highlight"])

        for alg in selected_algorithms:
            if alg == "AES":
                self.comparison_text.insert(tk.END, "AES (Advanced Encryption Standard):\n", "subheader")
                self.comparison_text.insert(tk.END, "- Mã hóa: ", "important")
                self.comparison_text.insert(tk.END, "Sử dụng khóa đối xứng 16 byte, chế độ CBC với IV ngẫu nhiên, padding dữ liệu.\n")
                self.comparison_text.insert(tk.END, "- Giải mã: ", "important")
                self.comparison_text.insert(tk.END, "Dùng cùng khóa và IV để giải mã, loại bỏ padding.\n")
                self.comparison_text.insert(tk.END, "- Ưu điểm: ", "highlight")
                self.comparison_text.insert(tk.END, "Tốc độ nhanh, bảo mật cao, tiêu chuẩn quốc tế.\n\n")
            elif alg == "DES":
                self.comparison_text.insert(tk.END, "DES (Data Encryption Standard):\n", "subheader")
                self.comparison_text.insert(tk.END, "- Mã hóa: ", "important")
                self.comparison_text.insert(tk.END, "Sử dụng khóa đối xứng 8 byte, chế độ CBC với IV ngẫu nhiên, padding dữ liệu.\n")
                self.comparison_text.insert(tk.END, "- Giải mã: ", "important")
                self.comparison_text.insert(tk.END, "Dùng cùng khóa và IV để giải mã, loại bỏ padding.\n")
                self.comparison_text.insert(tk.END, "- Lưu ý: ", "highlight")
                self.comparison_text.insert(tk.END, "Thuật toán đã lỗi thời và không còn được khuyến khích sử dụng cho mục đích bảo mật cao.\n\n")
            elif alg == "RSA":
                self.comparison_text.insert(tk.END, "RSA (Rivest-Shamir-Adleman):\n", "subheader")
                self.comparison_text.insert(tk.END, "- Mã hóa: ", "important")
                self.comparison_text.insert(tk.END, "Sử dụng khóa công khai 4096-bit để mã hóa khóa đối xứng (AES/DES).\n")
                self.comparison_text.insert(tk.END, "- Giải mã: ", "important")
                self.comparison_text.insert(tk.END, "Dùng khóa riêng để giải mã khóa đối xứng.\n")
                self.comparison_text.insert(tk.END, "- Ưu điểm: ", "highlight")
                self.comparison_text.insert(tk.END, "Bảo mật cao, phù hợp cho trao đổi khóa và mã hóa dữ liệu nhỏ.\n\n")
            elif alg == "SHA":
                self.comparison_text.insert(tk.END, "SHA (Secure Hash Algorithm):\n", "subheader")
                self.comparison_text.insert(tk.END, "- Mã hóa: ", "important")
                self.comparison_text.insert(tk.END, "Tạo hàm băm SHA-256 từ dữ liệu gốc để kiểm tra tính toàn vẹn.\n")
                self.comparison_text.insert(tk.END, "- Giải mã: ", "important")
                self.comparison_text.insert(tk.END, "Không giải mã, chỉ so sánh hash để xác minh dữ liệu.\n")
                self.comparison_text.insert(tk.END, "- Ứng dụng: ", "highlight")
                self.comparison_text.insert(tk.END, "Xác minh tính toàn vẹn dữ liệu, lưu trữ mật khẩu, chữ ký số.\n\n")
        
        self.comparison_text.config(state=tk.DISABLED)
        
    def select_file(self):
        file_path = filedialog.askopenfilename(title="Chọn tệp để mã hóa/giải mã")
        if not file_path:
            return
            
        self.selected_file_path = file_path
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        
        # Hiển thị thông tin tệp
        self.file_path_var.set(f"Tệp: {filename}")
        
        # Cập nhật số tệp đã xử lý
        self.files_processed.set(self.files_processed.get() + 1)
        
        # Tạo hiệu ứng highlight cho thông tin tệp
        self.style.configure("Highlight.TFrame", background=self.colors["highlight"])
        self.master.after(100, lambda: self.file_info_frame.configure(style="Highlight.TFrame"))
        self.master.after(500, lambda: self.file_info_frame.configure(style="Card.TFrame"))

        
        # Kiểm tra nếu là tệp đã mã hóa
        if filename.endswith('.enc'):
            self.file_status_var.set(f"Trạng thái: Tệp đã mã hóa | Kích thước: {filesize/1024:.1f} KB")
            self.is_image = False  # Chưa biết tệp mã hóa là gì
            self.clear_image_preview()
            self.add_log(f"Đã chọn tệp mã hóa: {filename}")
        else:
            self.file_status_var.set(f"Trạng thái: Tệp chưa mã hóa | Kích thước: {filesize/1024:.1f} KB")
            
            # Kiểm tra nếu là hình ảnh
            self.is_image = is_image_file(file_path)
            
            if self.is_image:
                self.file_status_var.set(f"Trạng thái: Hình ảnh chưa mã hóa | Kích thước: {filesize/1024:.1f} KB")
                self.update_image_preview(file_path)
                self.add_log(f"Đã chọn hình ảnh: {filename}")
            else:
                self.clear_image_preview()
                self.add_log(f"Đã chọn tệp thông thường: {filename}")
            
        self.status_var.set(f"Đã chọn: {filename}")
        
        # Vô hiệu hóa nút xem hình ảnh
        self.view_image_button.config(state=tk.DISABLED)

    def clear_image_preview(self):
        self.image_preview_label.config(text="Không có hình ảnh", image='')
        self.image_thumbnail = None

    def update_image_preview(self, image_path):
        try:
            # Đọc hình ảnh và tạo thumbnail với kích thước nhỏ hơn
            with open(image_path, 'rb') as f:
                image_data = f.read()
                
            # Giảm kích thước thumbnail xuống còn nhỏ hơn và tạo hình tròn
            self.image_thumbnail = create_circular_thumbnail(image_data, size=(150, 150))
            
            if self.image_thumbnail:
                self.image_preview_label.config(image=self.image_thumbnail, text='')
                self.add_log("Đã tạo xem trước hình ảnh")
            else:
                self.image_preview_label.config(text="Không thể hiển thị hình ảnh", image='')
                self.add_log("Không thể tạo xem trước hình ảnh")
                
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể hiển thị hình ảnh: {str(e)}")
            self.add_log(f"Lỗi hiển thị hình ảnh: {str(e)}")
            self.clear_image_preview()

    def view_decrypted_image(self):
        if not self.decrypted_file_path or not os.path.exists(self.decrypted_file_path):
            messagebox.showerror("Lỗi", "Không tìm thấy hình ảnh đã giải mã")
            self.add_log("Lỗi: Không tìm thấy hình ảnh đã giải mã")
            return
            
        try:
            # Mở hình ảnh bằng PIL và hiển thị
            img = Image.open(self.decrypted_file_path)
            img.show()
            self.add_log(f"Đã mở hình ảnh: {os.path.basename(self.decrypted_file_path)}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể mở hình ảnh: {str(e)}")
            self.add_log(f"Lỗi mở hình ảnh: {str(e)}")

    def show_loading(self, message="Đang xử lý..."):
        """Hiển thị hiệu ứng loading"""
        self.loading_var.set(message)
        self.loading_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.loading_label.pack(pady=10)
        self.loading_progress.pack(fill=tk.X, padx=20, pady=10)
        self.loading_progress.start(10)
        self.master.update()

    def hide_loading(self):
        """Ẩn hiệu ứng loading"""
        self.loading_progress.stop()
        self.loading_frame.place_forget()
        self.master.update()

    def generate_encryption_otp(self):
        """Tạo và gửi OTP cho quá trình mã hóa"""
        self.status_var.set("Đang tạo OTP mã hóa...")
        self.master.update()
        
        # Hiệu ứng loading
        self.show_loading("Đang tạo và gửi OTP mã hóa...")
        
        # Tạo OTP trong thread riêng
        def generate_otp_thread():
            self.encryption_otp = generate_otp()
            self.add_log("Đã tạo OTP mới cho mã hóa")
            
            # Gửi OTP qua Telegram
            success = send_otp_via_telegram(self.encryption_otp, "mã hóa")
            
            # Cập nhật UI trong main thread
            self.master.after(0, lambda: self.finish_otp_generation(success, "mã hóa"))
        
        # Chạy trong thread riêng
        threading.Thread(target=generate_otp_thread, daemon=True).start()

    def generate_decryption_otp(self):
        """Tạo và gửi OTP cho quá trình giải mã"""
        self.status_var.set("Đang tạo OTP giải mã...")
        self.master.update()
        
        # Hiệu ứng loading
        self.show_loading("Đang tạo và gửi OTP giải mã...")
        
        # Tạo OTP trong thread riêng
        def generate_otp_thread():
            self.decryption_otp = generate_otp()
            self.add_log("Đã tạo OTP mới cho giải mã")
            
            # Gửi OTP qua Telegram
            success = send_otp_via_telegram(self.decryption_otp, "giải mã")
            
            # Cập nhật UI trong main thread
            self.master.after(0, lambda: self.finish_otp_generation(success, "giải mã"))
        
        # Chạy trong thread riêng
        threading.Thread(target=generate_otp_thread, daemon=True).start()

    def finish_otp_generation(self, success, purpose):
        """Hoàn thành quá trình tạo OTP và cập nhật UI"""
        # Ẩn hiệu ứng loading
        self.hide_loading()
        
        if success:
            if purpose == "mã hóa":
                messagebox.showinfo("Thành công", "Mã OTP mã hóa đã được gửi tới Telegram của bạn.")
                self.status_var.set("OTP mã hóa đã được gửi")
                self.add_log("Đã gửi OTP mã hóa thành công qua Telegram")
                
                # Hiệu ứng highlight cho trường nhập OTP
                self.encryption_otp_entry.focus_set()
                self.master.after(100, lambda: self.encrypt_otp_frame.configure(style="Highlight.TFrame"))
                self.master.after(500, lambda: self.encrypt_otp_frame.configure(style="Card.TFrame"))
            else:
                messagebox.showinfo("Thành công", "Mã OTP giải mã đã được gửi tới Telegram của bạn.")
                self.status_var.set("OTP giải mã đã được gửi")
                self.add_log("Đã gửi OTP giải mã thành công qua Telegram")
                
                # Hiệu ứng highlight cho trường nhập OTP
                self.decryption_otp_entry.focus_set()
                self.master.after(100, lambda: self.decrypt_otp_frame.configure(background=self.colors["highlight"]))
                self.master.after(500, lambda: self.decrypt_otp_frame.configure(style="TFrame"))
        else:
            messagebox.showerror("Lỗi", "Không thể gửi OTP qua Telegram. Vui lòng kiểm tra kết nối mạng.")
            self.status_var.set(f"Lỗi gửi OTP {purpose}")
            self.add_log(f"Lỗi: Không gửi được OTP {purpose} qua Telegram")

        self.progress['value'] = 0
        self.master.update_idletasks()

    def reset_progress(self):
        """Reset thanh tiến trình về 0"""
        self.progress['value'] = 0
        self.master.update_idletasks()

    def get_selected_algorithms(self):
        """Lấy danh sách các thuật toán đã chọn"""
        selected = []
        for alg, var in self.algorithm_vars.items():
            if var.get():
                selected.append(alg)
        return selected

    def encrypt_file(self):
        """Hàm mã hóa tệp tin được chọn"""
        if not self.selected_file_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn tệp để mã hóa")
            return
            
        # Kiểm tra xem tệp đã được mã hóa chưa
        if self.selected_file_path.endswith('.enc'):
            messagebox.showerror("Lỗi", "Tệp đã được mã hóa. Vui lòng chọn tệp khác.")
            return
            
        # Kiểm tra đã chọn thuật toán chưa
        selected_algorithms = self.get_selected_algorithms()
        if not selected_algorithms or ("AES" not in selected_algorithms and "DES" not in selected_algorithms):
            messagebox.showerror("Lỗi", "Vui lòng chọn ít nhất một thuật toán mã hóa (AES hoặc DES)")
            return
            
        # Kiểm tra OTP mã hóa
        if not self.encryption_otp:
            messagebox.showerror("Lỗi", "Vui lòng tạo OTP mã hóa trước")
            
            # Highlight nút tạo OTP
            self.master.after(100, lambda: self.encrypt_otp_button.configure(background=self.colors["danger"]))
            self.master.after(1000, lambda: self.encrypt_otp_button.configure(style="Primary.TButton"))
            return
            
        entered_otp = self.encryption_otp_var.get()
        if not entered_otp:
            messagebox.showerror("Lỗi", "Vui lòng nhập mã OTP mã hóa")
            
            # Highlight trường nhập OTP
            self.encryption_otp_entry.focus_set()
            self.master.after(100, lambda: self.encrypt_otp_frame.configure(background=self.colors["highlight"]))
            self.master.after(500, lambda: self.encrypt_otp_frame.configure(style="TFrame"))
            return
            
        if entered_otp != self.encryption_otp:
            messagebox.showerror("Lỗi", "Mã OTP mã hóa không đúng. Vui lòng kiểm tra lại.")
            self.add_log("Lỗi: OTP mã hóa không đúng")
            
            # Highlight trường nhập OTP với màu lỗi
            self.encryption_otp_entry.focus_set()
            self.encryption_otp_entry.select_range(0, tk.END)
            self.master.after(100, lambda: self.encrypt_otp_frame.configure(background=self.colors["danger"]))
            self.master.after(500, lambda: self.encrypt_otp_frame.configure(style="TFrame"))
            return
        
        # Hiệu ứng loading
        self.show_loading("Đang mã hóa tệp tin...")
        
        # Thực hiện mã hóa trong thread riêng
        def encrypt_thread():
            try:
                # Đọc dữ liệu tệp gốc
                with open(self.selected_file_path, 'rb') as f:
                    original_data = f.read()
                    
                # Tính hash để kiểm tra tính toàn vẹn sau này
                self.master.after(0, lambda: self.update_status("Đang tính hash...", 20))
                self.original_hash = hash_data(original_data)
                
                # Chọn thuật toán mã hóa đối xứng và tạo khóa
                use_aes = "AES" in selected_algorithms
                
                self.master.after(0, lambda: self.update_status("Đang mã hóa dữ liệu...", 40))
                
                if use_aes:
                    # Sử dụng AES
                    self.aes_key = get_random_bytes(16)  # AES-128
                    encrypted_data = aes_encrypt(original_data, self.aes_key)
                    encryption_key = self.aes_key
                    algorithm_name = "AES"
                else:
                    # Sử dụng DES
                    self.des_key = get_random_bytes(8)  # DES key
                    encrypted_data = des_encrypt(original_data, self.des_key)
                    encryption_key = self.des_key
                    algorithm_name = "DES"
                    
                # Sử dụng RSA để mã hóa khóa đối xứng nếu được chọn
                if "RSA" in selected_algorithms:
                    self.master.after(0, lambda: self.update_status("Đang mã hóa khóa bằng RSA...", 60))
                    
                    rsa_key = RSA.import_key(self.public_key)
                    cipher_rsa = PKCS1_OAEP.new(rsa_key)
                    self.encrypted_key = cipher_rsa.encrypt(encryption_key)
                else:
                    # Lưu khóa dưới dạng không mã hóa (chỉ cho mục đích demo)
                    self.encrypted_key = encryption_key
                    
                # Lưu dữ liệu mã hóa vào tệp
                self.master.after(0, lambda: self.update_status("Đang lưu tệp mã hóa...", 80))
                
                output_file = self.selected_file_path + ".enc"
                
                with open(output_file, 'wb') as f:
                    # Format tệp: [algorithm_name_length(1 byte)][algorithm_name]
                    #             [key_length(4 bytes)][encrypted_key]
                    #             [hash_length(4 bytes)][original_hash]
                    #             [encrypted_data]
                    
                    # Lưu tên thuật toán
                    f.write(len(algorithm_name).to_bytes(1, byteorder='big'))
                    f.write(algorithm_name.encode())
                    
                    # Lưu khóa mã hóa
                    f.write(len(self.encrypted_key).to_bytes(4, byteorder='big'))
                    f.write(self.encrypted_key)
                    
                    # Lưu hash gốc
                    hash_bytes = self.original_hash.encode()
                    f.write(len(hash_bytes).to_bytes(4, byteorder='big'))
                    f.write(hash_bytes)
                    
                    # Lưu dữ liệu mã hóa
                    f.write(encrypted_data)
                
                # Cập nhật UI từ main thread
                self.master.after(0, lambda: self.finish_encryption(True, output_file, algorithm_name, selected_algorithms))
            
            except Exception as e:
                self.master.after(0, lambda: self.finish_encryption(False, None, None, None, str(e)))
        
        # Chạy mã hóa trong thread riêng
        threading.Thread(target=encrypt_thread, daemon=True).start()

    def update_status(self, message, progress_value):
        """Cập nhật trạng thái và thanh tiến trình"""
        self.status_var.set(message)
        self.progress['value'] = progress_value
        self.master.update_idletasks()

    def finish_encryption(self, success, output_file=None, algorithm_name=None, selected_algorithms=None, error_message=None):
        """Hoàn thành quá trình mã hóa và cập nhật UI"""
        # Ẩn hiệu ứng loading
        self.hide_loading()
        
        if success:
            # Cập nhật thống kê
            self.encryptions.set(self.encryptions.get() + 1)
            
            # Cập nhật hiển thị hash
            self.original_hash_var.set(f"Hash gốc: {self.original_hash}")
            
            # Hiệu ứng highlight cho hash
            self.master.after(100, lambda: self.hash_info_frame.configure(background=self.colors["highlight"]))
            self.master.after(500, lambda: self.hash_info_frame.configure(style="Card.TFrame"))
            
            messagebox.showinfo("Thành công", f"Mã hóa thành công với xác thực OTP.\nTệp đã được lưu tại: {output_file}")
            self.add_log(f"Mã hóa thành công với OTP. Thuật toán: {algorithm_name}")
            
            # Cập nhật trạng thái
            self.status_var.set(f"Mã hóa thành công: {os.path.basename(output_file)}")
            
            # Cho người dùng biết các thuật toán đã sử dụng
            alg_message = f"Thuật toán sử dụng: {', '.join(selected_algorithms)}"
            self.add_log(alg_message)
            
            # Reset OTP sau khi mã hóa thành công
            self.encryption_otp = None
            self.encryption_otp_var.set("")
            
        else:
            messagebox.showerror("Lỗi", f"Mã hóa thất bại: {error_message}")
            self.add_log(f"Lỗi mã hóa: {error_message}")
            self.status_var.set("Mã hóa thất bại")
        
        self.progress['value'] = 0

    def decrypt_file(self):
        """Hàm giải mã tệp tin đã chọn"""
        if not self.selected_file_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn tệp để giải mã")
            return
            
        # Kiểm tra xem tệp đã được mã hóa chưa
        if not self.selected_file_path.endswith('.enc'):
            messagebox.showerror("Lỗi", "Tệp chưa được mã hóa. Vui lòng chọn tệp .enc để giải mã.")
            return
            
        # Kiểm tra OTP giải mã
        if not self.decryption_otp:
            messagebox.showerror("Lỗi", "Vui lòng tạo OTP giải mã trước")
            
            # Highlight nút tạo OTP
            self.master.after(100, lambda: self.decrypt_otp_button.configure(background=self.colors["danger"]))
            self.master.after(1000, lambda: self.decrypt_otp_button.configure(style="Primary.TButton"))
            return
            
        entered_otp = self.decryption_otp_var.get()
        if not entered_otp:
            messagebox.showerror("Lỗi", "Vui lòng nhập mã OTP giải mã")
            
            # Highlight trường nhập OTP
            self.decryption_otp_entry.focus_set()
            self.master.after(100, lambda: self.decrypt_otp_frame.configure(background=self.colors["highlight"]))
            self.master.after(500, lambda: self.decrypt_otp_frame.configure(style="TFrame"))
            return
            
        if entered_otp != self.decryption_otp:
            messagebox.showerror("Lỗi", "Mã OTP giải mã không đúng. Vui lòng kiểm tra lại.")
            self.add_log("Lỗi: OTP giải mã không đúng")
            
            # Highlight trường nhập OTP với màu lỗi
            self.decryption_otp_entry.focus_set()
            self.decryption_otp_entry.select_range(0, tk.END)
            self.master.after(100, lambda: self.decrypt_otp_frame.configure(background=self.colors["danger"]))
            self.master.after(500, lambda: self.decrypt_otp_frame.configure(style="TFrame"))
            return
        
        # Hiệu ứng loading
        self.show_loading("Đang giải mã tệp tin...")
        
        # Thực hiện giải mã trong thread riêng
        def decrypt_thread():
            try:
                # Đọc dữ liệu tệp mã hóa
                with open(self.selected_file_path, 'rb') as f:
                    # Đọc tên thuật toán
                    alg_name_length = int.from_bytes(f.read(1), byteorder='big')
                    algorithm_name = f.read(alg_name_length).decode()
                    
                    # Đọc khóa mã hóa
                    key_length = int.from_bytes(f.read(4), byteorder='big')
                    encrypted_key = f.read(key_length)
                    
                    # Đọc hash gốc
                    hash_length = int.from_bytes(f.read(4), byteorder='big')
                    original_hash = f.read(hash_length).decode()
                    
                    # Đọc dữ liệu mã hóa
                    encrypted_data = f.read()
                
                self.master.after(0, lambda: self.update_status("Đang giải mã khóa...", 30))
                
                # Kiểm tra độ dài khóa để xác định xem khóa đã bị mã hóa bằng RSA chưa
                if key_length > 16:  # Khóa đã bị mã hóa bằng RSA
                    rsa_key = RSA.import_key(self.private_key)
                    cipher_rsa = PKCS1_OAEP.new(rsa_key)
                    decryption_key = cipher_rsa.decrypt(encrypted_key)
                else:
                    # Khóa không bị mã hóa
                    decryption_key = encrypted_key
                
                self.master.after(0, lambda: self.update_status("Đang giải mã dữ liệu...", 50))
                
                # Sử dụng thuật toán tương ứng để giải mã
                if algorithm_name == "AES":
                    decrypted_data = aes_decrypt(encrypted_data, decryption_key)
                elif algorithm_name == "DES":
                    decrypted_data = des_decrypt(encrypted_data, decryption_key)
                else:
                    raise ValueError(f"Thuật toán không được hỗ trợ: {algorithm_name}")
                
                # Tính hash và kiểm tra tính toàn vẹn
                self.master.after(0, lambda: self.update_status("Đang kiểm tra tính toàn vẹn...", 70))
                
                decrypted_hash = hash_data(decrypted_data)
                
                # Lưu dữ liệu giải mã vào tệp
                self.master.after(0, lambda: self.update_status("Đang lưu tệp giải mã...", 90))
                
                # Xác định tên tệp gốc
                original_filename = os.path.basename(self.selected_file_path[:-4])  # Loại bỏ .enc
                output_dir = os.path.dirname(self.selected_file_path)
                
                # Tạo tên mới để tránh ghi đè
                base_name, ext = os.path.splitext(original_filename)
                output_file = os.path.join(output_dir, f"{base_name}_decrypted{ext}")
                
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                
                # Cập nhật UI từ main thread
                self.master.after(0, lambda: self.finish_decryption(True, output_file, algorithm_name, 
                                                                  original_hash, decrypted_hash))
            
            except Exception as e:
                self.master.after(0, lambda: self.finish_decryption(False, None, None, None, None, str(e)))
        
        # Chạy giải mã trong thread riêng
        threading.Thread(target=decrypt_thread, daemon=True).start()

    def finish_decryption(self, success, output_file=None, algorithm_name=None, 
                         original_hash=None, decrypted_hash=None, error_message=None):
        """Hoàn thành quá trình giải mã và cập nhật UI"""
        # Ẩn hiệu ứng loading
        self.hide_loading()
        
        if success:
            # Cập nhật thống kê
            self.decryptions.set(self.decryptions.get() + 1)
            
            # Cập nhật hiển thị hash
            self.original_hash_var.set(f"Hash gốc: {original_hash}")
            self.decrypted_hash_var.set(f"Hash sau giải mã: {decrypted_hash}")
            
            # Kiểm tra hash match
            hash_match = original_hash == decrypted_hash
            
            if hash_match:
                self.hash_match_var.set("Trạng thái: Hash khớp - Dữ liệu toàn vẹn")
                self.add_log("Kiểm tra hash thành công - Dữ liệu toàn vẹn")
                
                # Hiệu ứng highlight cho hash thành công
                self.master.after(100, lambda: self.hash_info_frame.configure(background=self.colors["success"]))
                self.master.after(800, lambda: self.hash_info_frame.configure(style="Card.TFrame"))
            else:
                self.hash_match_var.set("Trạng thái: Hash không khớp - Dữ liệu đã bị thay đổi!")
                self.add_log("Cảnh báo: Hash không khớp - Dữ liệu có thể đã bị sửa đổi")
                
                # Hiệu ứng highlight cho hash thất bại
                self.master.after(100, lambda: self.hash_info_frame.configure(background=self.colors["danger"]))
                self.master.after(800, lambda: self.hash_info_frame.configure(style="Card.TFrame"))
                
                messagebox.showwarning("Cảnh báo", "Hash không khớp. Dữ liệu có thể đã bị thay đổi!")
            
            messagebox.showinfo("Thành công", f"Giải mã thành công với xác thực OTP.\nTệp đã được lưu tại: {output_file}")
            self.add_log(f"Giải mã thành công với OTP. Thuật toán: {algorithm_name}")
                
            # Cập nhật đường dẫn tệp giải mã
            self.decrypted_file_path = output_file
            
            # Kích hoạt nút xem hình ảnh nếu là tệp hình ảnh
            if is_image_file(output_file):
                self.view_image_button.config(state=tk.NORMAL)
                self.is_image = True
                self.update_image_preview(output_file)
                self.add_log("Hình ảnh đã được giải mã thành công")
                
                # Highlight nút xem hình ảnh
                self.master.after(100, lambda: self.view_image_button.configure(background=self.colors["warning"]))
                self.master.after(800, lambda: self.view_image_button.configure(style="Warning.TButton"))
            else:
                self.view_image_button.config(state=tk.DISABLED)
                self.is_image = False
                self.clear_image_preview()
                
            # Cập nhật trạng thái
            self.status_var.set(f"Giải mã thành công: {os.path.basename(output_file)}")
            
            # Reset OTP sau khi giải mã thành công
            self.decryption_otp = None
            self.decryption_otp_var.set("")
            
        else:
            messagebox.showerror("Lỗi", f"Giải mã thất bại: {error_message}")
            self.add_log(f"Lỗi giải mã: {error_message}")
            self.status_var.set("Giải mã thất bại")
        
        self.progress['value'] = 0

# Lớp Tooltip để tạo gợi ý cho các phần tử UI
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)
        
    def on_enter(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        # Tạo cửa sổ tooltip
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        # Tạo khung có viền
        frame = ttk.Frame(self.tooltip, relief="solid", borderwidth=1)
        frame.pack(fill="both", expand=True)
        
        # Tạo nhãn bên trong khung
        label = ttk.Label(frame, text=self.text, background="#ffffcc", wraplength=250, 
                        font=("Segoe UI", 9), justify="left", padding=(5, 3))
        label.pack(fill="both", expand=True)
        
    def on_leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

# Định nghĩa module math giả (thay thế cho import math)
class math:
    @staticmethod
    def sin(x):
        import math as real_math
        return real_math.sin(x)

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
    
