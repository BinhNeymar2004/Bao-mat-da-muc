import requests
import tkinter as tk
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
from PIL import Image, ImageTk

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
def send_otp_via_telegram(otp):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": f"Your OTP is: {otp}"}
    response = requests.post(url, data=data)
    return response.status_code == 200

# Hàm kiểm tra nếu file là hình ảnh
def is_image_file(file_path):
    image_extensions = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff']
    ext = os.path.splitext(file_path)[1].lower()
    return ext in image_extensions

# Hàm tạo thumbnail từ dữ liệu hình ảnh
def create_thumbnail(image_data, max_size=(150, 150)):
    try:
        img = Image.open(io.BytesIO(image_data))
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception as e:
        print(f"Không thể tạo thumbnail: {str(e)}")
        return None

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Bảo mật đa mức")
        self.master.geometry("1000x750")
        self.master.minsize(800, 600)
        self.master.configure(bg="#f5f5f5")

        # Thiết lập fonts
        self.title_font = font.Font(family="Segoe UI", size=14, weight="bold")
        self.header_font = font.Font(family="Segoe UI", size=12, weight="bold")
        self.normal_font = font.Font(family="Segoe UI", size=10)
        self.button_font = font.Font(family="Segoe UI", size=10, weight="bold")

        # Khởi tạo các khóa và biến
        self.private_key, self.public_key = generate_rsa_keys()
        self.encrypted_data = None
        self.encrypted_key = None
        self.original_hash = None
        self.otp = None
        self.des_key = None
        self.aes_key = None
        self.selected_file_path = None
        self.is_image = False
        self.image_thumbnail = None
        
        # Tạo style cho ttk widgets
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Định nghĩa các màu chính
        self.primary_color = "#4a4e69"
        self.secondary_color = "#9a8c98"
        self.accent_color = "#c9ada7"
        self.success_color = "#4caf50"
        self.warning_color = "#ff9800"
        self.danger_color = "#f44336"
        self.light_color = "#f5f5f5"
        self.dark_color = "#22223b"
        
        # Định nghĩa các style cho ttk
        self.style.configure("TFrame", background=self.light_color)
        self.style.configure("Header.TLabel", background=self.primary_color, foreground="white", font=self.header_font, padding=5)
        self.style.configure("TLabel", background=self.light_color, font=self.normal_font)
        self.style.configure("TButton", font=self.button_font)
        self.style.configure("Success.TButton", background=self.success_color)
        self.style.configure("Primary.TButton", background=self.primary_color)
        self.style.configure("Warning.TButton", background=self.warning_color)
        self.style.configure("Danger.TButton", background=self.danger_color)
        
        # Tạo Canvas chính và thanh cuộn
        self.main_canvas = tk.Canvas(self.master, bg=self.light_color, highlightthickness=0)
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
        
        # Tiêu đề ứng dụng
        self.header_frame = ttk.Frame(self.main_container)
        self.header_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.app_title = ttk.Label(self.header_frame, text="BẢO MẬT ĐA MỨC", font=self.title_font, background=self.primary_color, foreground="white")
        self.app_title.pack(fill=tk.X, ipady=10)
        
        # Tạo frame chứa nội dung chính (cả hai cột)
        self.content_frame = ttk.Frame(self.main_container)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # ========== CỘT TRÁI ==========
        self.left_frame = ttk.Frame(self.content_frame, padding=10)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Frame chọn thuật toán
        self.algorithm_frame = ttk.LabelFrame(self.left_frame, text="Thuật toán mã hóa", padding=10)
        self.algorithm_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.algorithm_vars = {}
        self.algorithms = ["AES", "DES", "RSA", "SHA"]
        
        # Tạo layout 2x2 cho các checkbox thuật toán
        algo_container = ttk.Frame(self.algorithm_frame)
        algo_container.pack(fill=tk.X)
        
        row, col = 0, 0
        for alg in self.algorithms:
            self.algorithm_vars[alg] = tk.BooleanVar()
            chk = ttk.Checkbutton(algo_container, text=alg, variable=self.algorithm_vars[alg], 
                                command=self.update_algorithm_comparison)
            chk.grid(row=row, column=col, sticky=tk.W, padx=10, pady=2)
            col += 1
            if col > 1:
                col = 0
                row += 1
                
        # Frame so sánh thuật toán
        self.comparison_frame = ttk.LabelFrame(self.left_frame, text="So sánh mã hóa & giải mã", padding=10)
        self.comparison_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Thêm thanh cuộn cho vùng văn bản so sánh
        self.comparison_scroll = ttk.Scrollbar(self.comparison_frame)
        self.comparison_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.comparison_text = tk.Text(self.comparison_frame, font=self.normal_font, wrap=tk.WORD, 
                                      height=8, bg="#ffffff", 
                                      yscrollcommand=self.comparison_scroll.set)
        self.comparison_text.pack(fill=tk.BOTH, expand=True)
        self.comparison_scroll.config(command=self.comparison_text.yview)
        
        self.update_algorithm_comparison()  # Khởi tạo với nội dung mặc định
        
        # Frame xem trước hình ảnh
        self.image_preview_frame = ttk.LabelFrame(self.left_frame, text="Xem trước hình ảnh", padding=10)
        self.image_preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        self.image_container = ttk.Frame(self.image_preview_frame, height=150, width=150)
        self.image_container.pack(pady=5, expand=True)
        self.image_container.pack_propagate(False)
        
        self.image_preview_label = ttk.Label(self.image_container, text="Không có hình ảnh")
        self.image_preview_label.pack(expand=True)
        
        # Frame OTP - Đặt trong cột trái để hiển thị rõ ràng
        self.otp_frame = ttk.LabelFrame(self.left_frame, text="Xác thực OTP", padding=10)
        self.otp_frame.pack(fill=tk.X, pady=(0, 0))

        self.otp_button = ttk.Button(self.otp_frame, text="Tạo và gửi OTP qua Telegram", 
                                   command=self.generate_otp_and_send_telegram)
        self.otp_button.pack(fill=tk.X, pady=5)

        self.otp_var = tk.StringVar()
        self.otp_entry_label = ttk.Label(self.otp_frame, text="Nhập mã OTP:")
        self.otp_entry_label.pack(anchor=tk.W, pady=(5,0))

        self.otp_entry = ttk.Entry(self.otp_frame, textvariable=self.otp_var, font=self.normal_font)
        self.otp_entry.pack(fill=tk.X, pady=5)
        
        # ========== CỘT PHẢI ==========
        self.right_frame = ttk.Frame(self.content_frame, padding=10)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # Frame thông tin tệp
        self.file_frame = ttk.LabelFrame(self.right_frame, text="Thông tin tệp", padding=10)
        self.file_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.select_file_btn = ttk.Button(self.file_frame, text="Chọn tệp", command=self.select_file)
        self.select_file_btn.pack(fill=tk.X, pady=5)
        
        # Sử dụng canvas có thể cuộn cho thông tin tệp
        self.file_info_canvas = tk.Canvas(self.file_frame, height=80, bg=self.light_color, 
                                        highlightthickness=0)
        self.file_info_canvas.pack(fill=tk.X, expand=True, pady=5)
        
        self.file_info_frame = ttk.Frame(self.file_info_canvas)
        self.file_info_frame.pack(fill=tk.X, expand=True)
        
        self.file_path_var = tk.StringVar(value="Chưa chọn tệp")
        self.file_path_label = ttk.Label(self.file_info_frame, textvariable=self.file_path_var, 
                                       wraplength=350)
        self.file_path_label.pack(fill=tk.X, pady=2)
        
        self.file_status_var = tk.StringVar(value="Trạng thái: Chưa sẵn sàng")
        self.file_status = ttk.Label(self.file_info_frame, textvariable=self.file_status_var)
        self.file_status.pack(fill=tk.X, pady=2)
        
        # Frame hash SHA với Canvas có thể cuộn
        self.hash_frame = ttk.LabelFrame(self.right_frame, text="Thông tin hash SHA", padding=10)
        self.hash_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.hash_canvas = tk.Canvas(self.hash_frame, height=100, bg=self.light_color, 
                                   highlightthickness=0)
        self.hash_canvas.pack(fill=tk.X, expand=True)
        
        self.hash_info_frame = ttk.Frame(self.hash_canvas)
        self.hash_info_frame.pack(fill=tk.X, expand=True)
        
        self.original_hash_var = tk.StringVar(value="Hash gốc: Chưa có")
        self.original_hash_label = ttk.Label(self.hash_info_frame, textvariable=self.original_hash_var, 
                                         wraplength=350)
        self.original_hash_label.pack(fill=tk.X, pady=2)
        
        self.decrypted_hash_var = tk.StringVar(value="Hash sau giải mã: Chưa có")
        self.decrypted_hash_label = ttk.Label(self.hash_info_frame, textvariable=self.decrypted_hash_var, 
                                           wraplength=350)
        self.decrypted_hash_label.pack(fill=tk.X, pady=2)
        
        self.hash_match_var = tk.StringVar(value="Trạng thái: Chưa so sánh")
        self.hash_match_label = ttk.Label(self.hash_info_frame, textvariable=self.hash_match_var)
        self.hash_match_label.pack(fill=tk.X, pady=2)
        
        # Frame hành động - Di chuyển lên đầu cột phải để luôn hiển thị
        self.action_frame = ttk.LabelFrame(self.right_frame, text="Hành động", padding=10)
        self.action_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.button_frame = ttk.Frame(self.action_frame)
        self.button_frame.pack(fill=tk.X, expand=True)
        
        self.encrypt_button = ttk.Button(self.button_frame, text="Mã hóa tệp", 
                                     command=self.encrypt_file, style="Primary.TButton")
        self.encrypt_button.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5, padx=(0, 5), ipady=5)
        
        self.decrypt_button = ttk.Button(self.button_frame, text="Giải mã tệp", 
                                     command=self.decrypt_file, style="Success.TButton")
        self.decrypt_button.pack(side=tk.RIGHT, fill=tk.X, expand=True, pady=5, padx=(5, 0), ipady=5)
        
        self.view_image_button = ttk.Button(self.action_frame, text="Xem hình ảnh đã giải mã", 
                                     command=self.view_decrypted_image, state=tk.DISABLED)
        self.view_image_button.pack(fill=tk.X, pady=(5, 0), ipady=5)
        
        # Frame nhật ký hoạt động - thêm mới
        self.log_frame = ttk.LabelFrame(self.right_frame, text="Nhật ký hoạt động", padding=10)
        self.log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_scroll = ttk.Scrollbar(self.log_frame)
        self.log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
 
        self.log_text = tk.Text(self.log_frame, font=self.normal_font, wrap=tk.WORD, 
                               height=10, bg="#ffffff", 
                               yscrollcommand=self.log_scroll.set)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_scroll.config(command=self.log_text.yview)
        self.log_text.config(state=tk.DISABLED)
        
        # Thêm log mặc định
        self.add_log("Ứng dụng đã khởi động")
        
        # Thanh trạng thái - được đặt cố định ở dưới cùng của scrollable frame
        self.status_frame = ttk.Frame(self.main_container)
        self.status_frame.pack(fill=tk.X, pady=(20, 0), side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Sẵn sàng")
        self.status_bar = ttk.Label(self.status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X)
        
        self.progress = ttk.Progressbar(self.status_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(5, 0))
        
        self.decrypted_file_path = None
        
        # Cập nhật vùng cuộn sau khi tất cả widget đã được tạo
        self.scrollable_frame.update_idletasks()
        self.main_canvas.config(scrollregion=self.main_canvas.bbox("all"))

    def _on_mousewheel(self, event):
        """Xử lý sự kiện cuộn chuột"""
        self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def add_log(self, message):
        """Thêm thông báo vào nhật ký hoạt động"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[LOG] {message}\n")
        self.log_text.see(tk.END)  # Cuộn xuống dòng mới nhất
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

        for alg in selected_algorithms:
            if alg == "AES":
                self.comparison_text.insert(tk.END, "AES (Advanced Encryption Standard):\n")
                self.comparison_text.insert(tk.END, "- Mã hóa: Sử dụng khóa đối xứng 16 byte, chế độ CBC với IV ngẫu nhiên, padding dữ liệu.\n")
                self.comparison_text.insert(tk.END, "- Giải mã: Dùng cùng khóa và IV để giải mã, loại bỏ padding.\n\n")
            elif alg == "DES":
                self.comparison_text.insert(tk.END, "DES (Data Encryption Standard):\n")
                self.comparison_text.insert(tk.END, "- Mã hóa: Sử dụng khóa đối xứng 8 byte, chế độ CBC với IV ngẫu nhiên, padding dữ liệu.\n")
                self.comparison_text.insert(tk.END, "- Giải mã: Dùng cùng khóa và IV để giải mã, loại bỏ padding.\n\n")
            elif alg == "RSA":
                self.comparison_text.insert(tk.END, "RSA (Rivest-Shamir-Adleman):\n")
                self.comparison_text.insert(tk.END, "- Mã hóa: Sử dụng khóa công khai 4096-bit để mã hóa khóa đối xứng (AES/DES).\n")
                self.comparison_text.insert(tk.END, "- Giải mã: Dùng khóa riêng để giải mã khóa đối xứng.\n\n")
            elif alg == "SHA":
                self.comparison_text.insert(tk.END, "SHA (Secure Hash Algorithm):\n")
                self.comparison_text.insert(tk.END, "- Mã hóa: Tạo hàm băm SHA-256 từ dữ liệu gốc để kiểm tra tính toàn vẹn.\n")
                self.comparison_text.insert(tk.END, "- Giải mã: Không giải mã, chỉ so sánh hash để xác minh dữ liệu.\n\n")
        
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
                
            # Giảm kích thước thumbnail xuống còn nhỏ hơn
            self.image_thumbnail = create_thumbnail(image_data, max_size=(140, 140))
            
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

    def add_log(self, message):
        """Thêm thông báo vào nhật ký hoạt động với thời gian"""
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
    def generate_otp_and_send_telegram(self):
        self.status_var.set("Đang tạo OTP...")
        self.master.update()
        
        self.otp = generate_otp()
        self.add_log("Đã tạo OTP mới")
        
        self.status_var.set("Đang gửi OTP qua Telegram...")
        self.master.update()
        
        self.progress['value'] = 50
        self.master.update_idletasks()
        
        # Gửi OTP qua Telegram
        if send_otp_via_telegram(self.otp):
            messagebox.showinfo("Thành công", "Mã OTP đã được gửi tới Telegram của bạn.")
            self.status_var.set("OTP đã được gửi")
            self.add_log("Đã gửi OTP thành công qua Telegram")
        else:
            messagebox.showerror("Lỗi", "Không thể gửi OTP qua Telegram. Vui lòng kiểm tra kết nối mạng.")
            self.status_var.set("Lỗi gửi OTP")
            self.add_log("Lỗi: Không gửi được OTP qua Telegram")

        self.progress['value'] = 100
        self.master.update_idletasks()
        
        # Reset thanh tiến trình sau vài giây
        self.master.after(1000, self.reset_progress)

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
            
        try:
            self.status_var.set("Đang đọc tệp...")
            self.progress['value'] = 10
            self.master.update_idletasks()
            
            # Đọc dữ liệu tệp gốc
            with open(self.selected_file_path, 'rb') as f:
                original_data = f.read()
                
            # Tính hash để kiểm tra tính toàn vẹn sau này
            self.status_var.set("Đang tính hash...")
            self.progress['value'] = 20
            self.master.update_idletasks()
            
            self.original_hash = hash_data(original_data)
            self.original_hash_var.set(f"Hash gốc: {self.original_hash}")
            
            # Chọn thuật toán mã hóa đối xứng và tạo khóa
            use_aes = "AES" in selected_algorithms
            
            self.status_var.set("Đang mã hóa dữ liệu...")
            self.progress['value'] = 40
            self.master.update_idletasks()
            
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
                self.status_var.set("Đang mã hóa khóa bằng RSA...")
                self.progress['value'] = 60
                self.master.update_idletasks()
                
                rsa_key = RSA.import_key(self.public_key)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                self.encrypted_key = cipher_rsa.encrypt(encryption_key)
            else:
                # Lưu khóa dưới dạng không mã hóa (chỉ cho mục đích demo)
                self.encrypted_key = encryption_key
                
            # Lưu dữ liệu mã hóa vào tệp
            self.status_var.set("Đang lưu tệp mã hóa...")
            self.progress['value'] = 80
            self.master.update_idletasks()
            
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
                
            self.progress['value'] = 100
            self.master.update_idletasks()
            
            # Xác thực OTP nếu đã tạo
            if self.otp:
                entered_otp = self.otp_var.get()
                if not entered_otp:
                    messagebox.showwarning("Cảnh báo", "Bạn chưa nhập mã OTP. Mã hóa đã hoàn tất nhưng không có xác thực OTP.")
                    self.add_log("Cảnh báo: Mã hóa không có xác thực OTP")
                elif entered_otp == self.otp:
                    messagebox.showinfo("Thành công", f"Mã hóa thành công với xác thực OTP.\nTệp đã được lưu tại: {output_file}")
                    self.add_log(f"Mã hóa thành công với OTP. Thuật toán: {algorithm_name}")
                else:
                    messagebox.showwarning("Cảnh báo", "OTP không đúng. Tệp đã được mã hóa nhưng xác thực thất bại.")
                    self.add_log("Cảnh báo: OTP không đúng, mã hóa hoàn tất")
            else:
                messagebox.showinfo("Thành công", f"Mã hóa thành công.\nTệp đã được lưu tại: {output_file}")
                self.add_log(f"Mã hóa thành công. Thuật toán: {algorithm_name}")
            
            # Cập nhật trạng thái
            self.status_var.set(f"Mã hóa thành công: {os.path.basename(output_file)}")
            
            # Cho người dùng biết các thuật toán đã sử dụng
            alg_message = f"Thuật toán sử dụng: {', '.join(selected_algorithms)}"
            self.add_log(alg_message)
            
            # Reset thanh tiến trình sau 1 giây
            self.master.after(1000, self.reset_progress)
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Mã hóa thất bại: {str(e)}")
            self.add_log(f"Lỗi mã hóa: {str(e)}")
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
        
        try:
            self.status_var.set("Đang đọc tệp mã hóa...")
            self.progress['value'] = 10
            self.master.update_idletasks()
            
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
            
            self.status_var.set("Đang giải mã khóa...")
            self.progress['value'] = 30
            self.master.update_idletasks()
            
            # Kiểm tra độ dài khóa để xác định xem khóa đã bị mã hóa bằng RSA chưa
            if key_length > 16:  # Khóa đã bị mã hóa bằng RSA
                rsa_key = RSA.import_key(self.private_key)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                decryption_key = cipher_rsa.decrypt(encrypted_key)
            else:
                # Khóa không bị mã hóa
                decryption_key = encrypted_key
            
            self.status_var.set("Đang giải mã dữ liệu...")
            self.progress['value'] = 50
            self.master.update_idletasks()
            
            # Sử dụng thuật toán tương ứng để giải mã
            if algorithm_name == "AES":
                decrypted_data = aes_decrypt(encrypted_data, decryption_key)
            elif algorithm_name == "DES":
                decrypted_data = des_decrypt(encrypted_data, decryption_key)
            else:
                raise ValueError(f"Thuật toán không được hỗ trợ: {algorithm_name}")
            
            # Tính hash và kiểm tra tính toàn vẹn
            self.status_var.set("Đang kiểm tra tính toàn vẹn...")
            self.progress['value'] = 70
            self.master.update_idletasks()
            
            decrypted_hash = hash_data(decrypted_data)
            self.decrypted_hash_var.set(f"Hash sau giải mã: {decrypted_hash}")
            self.original_hash_var.set(f"Hash gốc: {original_hash}")
            
            hash_match = original_hash == decrypted_hash
            if hash_match:
                self.hash_match_var.set("Trạng thái: Hash khớp - Dữ liệu toàn vẹn")
                self.add_log("Kiểm tra hash thành công - Dữ liệu toàn vẹn")
            else:
                self.hash_match_var.set("Trạng thái: Hash không khớp - Dữ liệu đã bị thay đổi!")
                self.add_log("Cảnh báo: Hash không khớp - Dữ liệu có thể đã bị sửa đổi")
                messagebox.showwarning("Cảnh báo", "Hash không khớp. Dữ liệu có thể đã bị thay đổi!")
                
            # Lưu dữ liệu giải mã vào tệp
            self.status_var.set("Đang lưu tệp giải mã...")
            self.progress['value'] = 90
            self.master.update_idletasks()
            
            # Xác định tên tệp gốc
            original_filename = os.path.basename(self.selected_file_path[:-4])  # Loại bỏ .enc
            output_dir = os.path.dirname(self.selected_file_path)
            
            # Tạo tên mới để tránh ghi đè
            base_name, ext = os.path.splitext(original_filename)
            output_file = os.path.join(output_dir, f"{base_name}_decrypted{ext}")
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
                
            self.progress['value'] = 100
            self.master.update_idletasks()
            
            # Xác thực OTP nếu đã tạo
            if self.otp:
                entered_otp = self.otp_var.get()
                if not entered_otp:
                    messagebox.showwarning("Cảnh báo", "Bạn chưa nhập mã OTP. Giải mã đã hoàn tất nhưng không có xác thực OTP.")
                    self.add_log("Cảnh báo: Giải mã không có xác thực OTP")
                elif entered_otp == self.otp:
                    messagebox.showinfo("Thành công", f"Giải mã thành công với xác thực OTP.\nTệp đã được lưu tại: {output_file}")
                    self.add_log(f"Giải mã thành công với OTP. Thuật toán: {algorithm_name}")
                else:
                    messagebox.showwarning("Cảnh báo", "OTP không đúng. Tệp đã được giải mã nhưng xác thực thất bại.")
                    self.add_log("Cảnh báo: OTP không đúng, giải mã hoàn tất")
            else:
                messagebox.showinfo("Thành công", f"Giải mã thành công.\nTệp đã được lưu tại: {output_file}")
                self.add_log(f"Giải mã thành công. Thuật toán: {algorithm_name}")
                
            # Cập nhật đường dẫn tệp giải mã
            self.decrypted_file_path = output_file
            
            # Kích hoạt nút xem hình ảnh nếu là tệp hình ảnh
            if is_image_file(output_file):
                self.view_image_button.config(state=tk.NORMAL)
                self.is_image = True
                self.update_image_preview(output_file)
                self.add_log("Hình ảnh đã được giải mã thành công")
            else:
                self.view_image_button.config(state=tk.DISABLED)
                self.is_image = False
                self.clear_image_preview()
                
            # Cập nhật trạng thái
            self.status_var.set(f"Giải mã thành công: {os.path.basename(output_file)}")
            
            # Reset thanh tiến trình sau 1 giây
            self.master.after(1000, self.reset_progress)
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Giải mã thất bại: {str(e)}")
            self.add_log(f"Lỗi giải mã: {str(e)}")
            self.status_var.set("Giải mã thất bại")
            self.progress['value'] = 0

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()