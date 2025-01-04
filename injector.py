import psutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import ctypes
import os

def inject_dll(process_id, dll_path):
    try:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)

        if not process_handle:
            raise Exception("Не удалось получить доступ к процессу.")

        dll_path_bytes = dll_path.encode("utf-8")
        dll_path_address = kernel32.VirtualAllocEx(
            process_handle, None, len(dll_path_bytes), 0x1000 | 0x2000, 0x40
        )

        if not dll_path_address:
            raise Exception("Не удалось выделить память в процессе.")

        written = ctypes.c_int(0)
        kernel32.WriteProcessMemory(
            process_handle,
            dll_path_address,
            dll_path_bytes,
            len(dll_path_bytes),
            ctypes.byref(written),
        )

        load_library_a = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")

        if not load_library_a:
            raise Exception("Не удалось получить адрес функции LoadLibraryA.")

        thread_id = ctypes.c_ulong(0)
        if not kernel32.CreateRemoteThread(
            process_handle,
            None,
            0,
            load_library_a,
            dll_path_address,
            0,
            ctypes.byref(thread_id),
        ):
            raise Exception("Не удалось создать поток для загрузки DLL.")

        kernel32.CloseHandle(process_handle)
        messagebox.showinfo("Успех", "DLL уже в процессе!")
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

def get_processes():
    """Получить список активных процессов"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

def select_process(pid_entry):
    """Окно выбора процесса"""
    def on_select():
        selected = tree.focus()
        if selected:
            process = tree.item(selected, 'values')
            pid_entry.delete(0, tk.END)
            pid_entry.insert(0, process[1])
            process_window.destroy()
        else:
            messagebox.showwarning("Предупреждение", "Выберите процесс из списка.")

    process_window = tk.Toplevel()
    process_window.title("Выберите процесс")
    process_window.geometry("600x400")

    tree = ttk.Treeview(process_window, columns=("Name", "PID"), show="headings")
    tree.heading("Name", text="Название процесса")
    tree.heading("PID", text="PID")
    tree.column("Name", width=400)
    tree.column("PID", width=100)

    scrollbar = ttk.Scrollbar(process_window, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscroll=scrollbar.set)

    processes = get_processes()
    for proc in processes:
        tree.insert("", tk.END, values=(proc['name'], proc['pid']))

    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    select_button = tk.Button(process_window, text="Выбрать", command=on_select)
    select_button.pack(pady=10)

    process_window.mainloop()

def main():
    def browse_dll():
        path = filedialog.askopenfilename(filetypes=[("DLL Files", "*.dll")])
        if path:
            dll_path_entry.delete(0, tk.END)
            dll_path_entry.insert(0, path)

    def inject():
        try:
            process_id = int(pid_entry.get())
            dll_path = dll_path_entry.get()
            if not dll_path:
                raise ValueError("Путь к DLL не указан.")
            inject_dll(process_id, dll_path)
        except ValueError as ve:
            messagebox.showerror("Ошибка", str(ve))

    root = tk.Tk()
    root.title("DLLinjector -- by matrix")

    tk.Label(root, text="Process ID:").grid(row=0, column=0, padx=5, pady=5)
    pid_entry = tk.Entry(root)
    pid_entry.grid(row=0, column=1, padx=5, pady=5)
    select_process_button = tk.Button(root, text="Выбрать процесс", command=lambda: select_process(pid_entry))
    select_process_button.grid(row=0, column=2, padx=5, pady=5)

    tk.Label(root, text="DLL Path:").grid(row=1, column=0, padx=5, pady=5)
    dll_path_entry = tk.Entry(root, width=40)
    dll_path_entry.grid(row=1, column=1, padx=5, pady=5)

    browse_button = tk.Button(root, text="Browse", command=browse_dll)
    browse_button.grid(row=1, column=2, padx=5, pady=5)

    inject_button = tk.Button(root, text="Inject", command=inject)
    inject_button.grid(row=2, column=0, columnspan=3, pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
