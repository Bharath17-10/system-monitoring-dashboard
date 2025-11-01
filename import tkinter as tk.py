import tkinter as tk
from tkinter import messagebox
import subprocess
import time
import os
import platform

# Use psutil for cross-platform system metrics and process management
try:
    import psutil
except Exception:
    psutil = None

class SystemDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("System Monitoring Dashboard")
        self.geometry("800x600")

        # CPU Usage Label
        self.cpu_label = tk.Label(self, text="CPU Usage: Calculating...", font=("Arial", 14))
        self.cpu_label.pack(pady=10)

        # Memory Usage Label
        self.mem_label = tk.Label(self, text="Memory Usage: Calculating...", font=("Arial", 14))
        self.mem_label.pack(pady=10)

        # Process List
        self.process_frame = tk.Frame(self)
        self.process_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.process_listbox = tk.Listbox(self.process_frame, font=("Arial", 12), selectmode=tk.SINGLE)
        self.process_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(self.process_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.process_listbox.yview)

        # Manage Buttons
        self.button_frame = tk.Frame(self)
        self.button_frame.pack(pady=10)

        self.refresh_button = tk.Button(self.button_frame, text="Refresh Processes", command=self.update_processes)
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.kill_button = tk.Button(self.button_frame, text="Kill Selected Process", command=self.kill_process)
        self.kill_button.pack(side=tk.LEFT, padx=5)

        # Control variables
        self.running = True
        self.refresh_interval_ms = 1000

        # Options: show system processes, sort order
        self.show_system_var = tk.BooleanVar(value=True)
        self.sort_by_var = tk.StringVar(value="cpu")

        opts_frame = tk.Frame(self)
        opts_frame.pack(pady=5)
        tk.Checkbutton(opts_frame, text="Show system processes", variable=self.show_system_var, command=self.update_processes).pack(side=tk.LEFT, padx=5)
        tk.Label(opts_frame, text="Sort by:").pack(side=tk.LEFT)
        tk.OptionMenu(opts_frame, self.sort_by_var, "cpu", "memory", "pid", "name", command=lambda _: self.update_processes()).pack(side=tk.LEFT)

        # Initial updates (use after loop instead of background thread to safely update UI)
        self.after(100, self.schedule_update)
        self.update_processes()

    def schedule_update(self):
        if not self.running:
            return
        self.update_cpu()
        self.update_memory()
        self.after(self.refresh_interval_ms, self.schedule_update)

    def update_cpu(self):
        # Cross-platform CPU usage using psutil when available; fallback to platform-specific
        try:
            if psutil:
                # psutil.cpu_percent blocks for interval seconds to sample usage — use small interval
                usage = psutil.cpu_percent(interval=0.1)
                self.cpu_label.config(text=f"CPU Usage: {usage:.2f}%")
            else:
                if platform.system() == 'Linux':
                    # Fallback to /proc/stat for Linux
                    def get_cpu_times():
                        with open('/proc/stat') as f:
                            line = f.readline().strip().split()
                            return list(map(int, line[1:]))

                    prev_times = get_cpu_times()
                    time.sleep(0.1)
                    curr_times = get_cpu_times()

                    prev_total = sum(prev_times)
                    curr_total = sum(curr_times)
                    prev_idle = prev_times[3] + (prev_times[4] if len(prev_times) > 4 else 0)
                    curr_idle = curr_times[3] + (curr_times[4] if len(curr_times) > 4 else 0)

                    delta_total = curr_total - prev_total
                    delta_idle = curr_idle - prev_idle

                    usage = 100 * (1 - delta_idle / delta_total) if delta_total > 0 else 0
                    self.cpu_label.config(text=f"CPU Usage: {usage:.2f}%")
                else:
                    self.cpu_label.config(text="CPU Usage: N/A (psutil not installed)")
        except Exception as e:
            self.cpu_label.config(text=f"CPU Usage: Error - {str(e)}")

    def update_memory(self):
        try:
            if psutil:
                vm = psutil.virtual_memory()
                usage_percent = vm.percent
                used_mb = vm.used // (1024 * 1024)
                total_mb = vm.total // (1024 * 1024)
                self.mem_label.config(text=f"Memory Usage: {usage_percent:.2f}% ({used_mb} MB / {total_mb} MB)")
            else:
                if platform.system() == 'Linux':
                    with open('/proc/meminfo') as f:
                        lines = f.readlines()
                        mem_total = int(lines[0].split()[1])  # kB
                        mem_free = int(lines[1].split()[1])
                        mem_available = int(lines[2].split()[1])
                    used = mem_total - mem_available
                    usage_percent = (used / mem_total) * 100 if mem_total > 0 else 0
                    self.mem_label.config(text=f"Memory Usage: {usage_percent:.2f}% ({used // 1024} MB / {mem_total // 1024} MB)")
                else:
                    self.mem_label.config(text="Memory Usage: N/A (psutil not installed)")
        except Exception as e:
            self.mem_label.config(text=f"Memory Usage: Error - {str(e)}")

    def update_processes(self):
        try:
            self.process_listbox.delete(0, tk.END)
            self.process_data = []

            if not psutil:
                # Try fallback to ps output on Unix
                output = subprocess.check_output(['ps', 'aux']).decode('utf-8')
                lines = output.splitlines()[1:]
                for line in lines:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        pid = int(parts[1])
                        cpu = parts[2]
                        mem = parts[3]
                        command = parts[10]
                        display = f"PID: {pid} | CPU: {cpu}% | MEM: {mem}% | CMD: {command}"
                        self.process_listbox.insert(tk.END, display)
                        self.process_data.append(pid)
                return

            # Ask psutil to update cpu counters briefly so per-process cpu_percent has data
            try:
                psutil.cpu_percent(interval=0.1)
            except Exception:
                pass

            procs = []
            for p in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    info = p.info
                    pid = info.get('pid')
                    name = info.get('name') or ''
                    username = info.get('username') or ''
                    # Filter system processes if needed
                    is_system = username.lower() in ('system', 'root', 'nt authority\\system')
                    if not self.show_system_var.get() and is_system:
                        continue
                    # Get cpu & memory percent (non-blocking)
                    try:
                        cpu = p.cpu_percent(interval=0.0)
                    except Exception:
                        cpu = 0.0
                    try:
                        mem = p.memory_percent()
                    except Exception:
                        mem = 0.0
                    # cmdline may be expensive — fallback to name
                    try:
                        cmd = ' '.join(p.cmdline()) if p.cmdline() else name
                    except Exception:
                        cmd = name

                    procs.append({'pid': pid, 'cpu': cpu, 'mem': mem, 'cmd': cmd, 'name': name, 'user': username})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            sort_key = self.sort_by_var.get()
            if sort_key == 'cpu':
                procs.sort(key=lambda x: x['cpu'], reverse=True)
            elif sort_key == 'memory':
                procs.sort(key=lambda x: x['mem'], reverse=True)
            elif sort_key == 'pid':
                procs.sort(key=lambda x: x['pid'])
            else:
                procs.sort(key=lambda x: x['name'].lower())

            for p in procs:
                display = f"PID: {p['pid']} | CPU: {p['cpu']:.1f}% | MEM: {p['mem']:.1f}% | USER: {p['user']} | CMD: {p['cmd']}"
                self.process_listbox.insert(tk.END, display)
                self.process_data.append(p['pid'])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch processes: {str(e)}")

        # bind double-click to inspect
        self.process_listbox.bind('<Double-1>', lambda ev: self.inspect_process())

    def kill_process(self):
        selected = self.process_listbox.curselection()
        if selected:
            index = selected[0]
            pid = self.process_data[index]
            confirm = messagebox.askyesno("Confirm Kill", f"Are you sure you want to kill process with PID {pid}?")
            if confirm:
                try:
                    if psutil:
                        p = psutil.Process(int(pid))
                        # Try gentle terminate first
                        p.terminate()
                        try:
                            p.wait(timeout=3)
                        except psutil.TimeoutExpired:
                            p.kill()
                    else:
                        # Fallback to platform call
                        if platform.system() == 'Windows':
                            subprocess.check_call(['taskkill', '/PID', str(pid), '/F'])
                        else:
                            subprocess.check_call(['kill', '-9', str(pid)])
                    messagebox.showinfo("Success", f"Process {pid} killed.")
                    self.update_processes()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to kill process: {str(e)} (May require elevated privileges)")
        else:
            messagebox.showwarning("Warning", "No process selected.")

    def inspect_process(self):
        selected = self.process_listbox.curselection()
        if not selected:
            return
        pid = self.process_data[selected[0]]
        try:
            if not psutil:
                messagebox.showinfo("Process Info", f"PID: {pid}\n(Install psutil for richer info)")
                return
            p = psutil.Process(int(pid))
            info_lines = []
            info_lines.append(f"PID: {p.pid}")
            info_lines.append(f"Name: {p.name()}")
            info_lines.append(f"Executable: {p.exe() if p.exe() else ''}")
            info_lines.append(f"Cmdline: {' '.join(p.cmdline())}")
            info_lines.append(f"User: {p.username()}")
            info_lines.append(f"Status: {p.status()}")
            try:
                info_lines.append(f"Threads: {p.num_threads()}")
            except Exception:
                pass
            try:
                info_lines.append(f"Memory: {p.memory_info().rss // (1024*1024)} MB")
            except Exception:
                pass

            messagebox.showinfo("Process Info", '\n'.join(info_lines))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to inspect process: {str(e)}")

    def on_closing(self):
        self.running = False
        self.destroy()

if __name__ == "__main__":
    app = SystemDashboard()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()