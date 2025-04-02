#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# s3loc_ Pentest Framework v1.0
# Developed exclusively for s3loc_

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import queue
import time
import os
import random
import json

class s3locPentestApp:
    def __init__(self, root):
        self.root = root
        self.root.title("s3loc_ Pentest Framework v1.0")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Stil ayarları
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#2c3e50')
        self.style.configure('TLabel', background='#2c3e50', foreground='#ecf0f1')
        self.style.configure('TButton', background='#3498db', foreground='#2c3e50')
        self.style.map('TButton', background=[('active', '#2980b9')])
        
        # Ana frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık çubuğu
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Başlık
        self.title_label = ttk.Label(self.header_frame, 
                                   text="s3loc_ PENTEST FRAMEWORK", 
                                   font=('Helvetica', 16, 'bold'),
                                   foreground='#e74c3c')
        self.title_label.pack(side=tk.LEFT, padx=10)
        
        # s3loc_ branding
        self.brand_label = ttk.Label(self.header_frame, 
                                    text="by s3loc_", 
                                    font=('Helvetica', 10, 'italic'),
                                    foreground='#3498db')
        self.brand_label.pack(side=tk.RIGHT, padx=10)
        
        # Notebook (sekmeler)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0,5))
        
        # Sekmeleri oluştur
        self.create_scan_tab()
        self.create_exploit_tab()
        self.create_results_tab()
        self.create_settings_tab()
        
        # Durum çubuğu
        self.status_var = tk.StringVar()
        self.status_var.set("s3loc_ Pentest Framework - Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Test verileri
        self.vulnerabilities = []
        self.scan_results = []
        self.exploit_results = []
        
        # Thread kuyruğu
        self.queue = queue.Queue()
        self.process_queue()
    
    def create_scan_tab(self):
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text='Scan Target')
        
        # Hedef bilgileri
        target_frame = ttk.LabelFrame(self.scan_tab, text="Target Information")
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Target URL/IP:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Tarama butonları
        button_frame = ttk.Frame(self.scan_tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        
        # Sonuçlar
        results_frame = ttk.LabelFrame(self.scan_tab, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.results_tree = ttk.Treeview(results_frame, columns=('type', 'target', 'details'), show='headings')
        self.results_tree.heading('type', text='Type')
        self.results_tree.heading('target', text='Target')
        self.results_tree.heading('details', text='Details')
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_exploit_tab(self):
        self.exploit_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.exploit_tab, text='Exploit')
        
        # Açıklar listesi
        vuln_frame = ttk.LabelFrame(self.exploit_tab, text="Detected Vulnerabilities")
        vuln_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=('id', 'name', 'severity'), show='headings')
        self.vuln_tree.heading('id', text='ID')
        self.vuln_tree.heading('name', text='Vulnerability')
        self.vuln_tree.heading('severity', text='Severity')
        
        scrollbar = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Exploit butonları
        button_frame = ttk.Frame(self.exploit_tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Run Exploit", command=self.run_exploit).pack(side=tk.LEFT, padx=5)
    
    def create_results_tab(self):
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text='Results')
        
        # Rapor
        report_frame = ttk.LabelFrame(self.results_tab, text="Report")
        report_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.report_text = scrolledtext.ScrolledText(report_frame, width=60, height=20)
        self.report_text.pack(fill=tk.BOTH, expand=True)
        
        # Butonlar
        button_frame = ttk.Frame(self.results_tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Generate Report", command=self.generate_report).pack(side=tk.LEFT, padx=5)
    
    def create_settings_tab(self):
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text='Settings')
        
        # Hakkında
        about_frame = ttk.LabelFrame(self.settings_tab, text="About")
        about_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        about_text = """
        s3loc_ Pentest Framework v1.0
        
        Developed exclusively for s3loc_
        
        Features:
        - Target scanning
        - Vulnerability detection
        - Exploit testing
        
        © 2023 s3loc_ Security Tools
        """
        
        self.about_text = scrolledtext.ScrolledText(about_frame, width=60, height=15)
        self.about_text.insert(tk.END, about_text)
        self.about_text.configure(state='disabled')
        self.about_text.pack(fill=tk.BOTH, expand=True)
    
    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.status_var.set(f"s3loc_ - Scanning {target}...")
        
        # Simüle edilmiş tarama işlemi
        threading.Thread(target=self.simulate_scan, args=(target,), daemon=True).start()
    
    def simulate_scan(self, target):
        time.sleep(2)  # Simüle edilmiş tarama süresi
        
        # Rastgele sonuçlar oluştur
        vulnerabilities = [
            ("1", "SQL Injection", "High"),
            ("2", "XSS", "Medium"),
            ("3", "Open Port", "Low"),
            ("4", "Weak Credentials", "Critical")
        ]
        
        for vuln in vulnerabilities:
            self.queue.put(('add_vulnerability', vuln))
        
        self.queue.put(('update_status', f"s3loc_ - Scan completed for {target}"))
    
    def run_exploit(self):
        selected = self.vuln_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a vulnerability")
            return
        
        item = self.vuln_tree.item(selected[0])
        vuln_name = item['values'][1]
        
        self.status_var.set(f"s3loc_ - Running exploit for {vuln_name}...")
        
        # Simüle edilmiş exploit işlemi
        threading.Thread(target=self.simulate_exploit, args=(vuln_name,), daemon=True).start()
    
    def simulate_exploit(self, vuln_name):
        time.sleep(2)  # Simüle edilmiş exploit süresi
        
        # Rastgele sonuçlar oluştur
        results = [
            f"Exploiting {vuln_name}...",
            "Vulnerability confirmed!",
            "Attempting exploit...",
            "Exploit successful!",
            "s3loc_ framework completed the attack"
        ]
        
        for line in results:
            self.queue.put(('add_exploit_result', line))
            time.sleep(0.5)
        
        self.queue.put(('update_status', f"s3loc_ - Exploit completed for {vuln_name}"))
    
    def generate_report(self):
        report = f"{'='*50}\n"
        report += f"{' '*15}s3loc_ PENTEST REPORT\n"
        report += f"{'='*50}\n\n"
        report += f"Generated: {time.ctime()}\n\n"
        
        report += "Vulnerabilities Found:\n"
        report += "-"*50 + "\n"
        for child in self.vuln_tree.get_children():
            item = self.vuln_tree.item(child)
            report += f"ID: {item['values'][0]}\n"
            report += f"Name: {item['values'][1]}\n"
            report += f"Severity: {item['values'][2]}\n\n"
        
        report += "\nRecommendations:\n"
        report += "-"*50 + "\n"
        report += "1. Patch all vulnerabilities immediately\n"
        report += "2. Implement security best practices\n\n"
        
        report += f"{'='*50}\n"
        report += "Report generated by s3loc_ Pentest Framework\n"
        report += f"{'='*50}"
        
        self.report_text.configure(state='normal')
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, report)
        self.report_text.configure(state='disabled')
    
    def process_queue(self):
        try:
            while True:
                task = self.queue.get_nowait()
                if task[0] == 'add_vulnerability':
                    self.vuln_tree.insert('', tk.END, values=task[1])
                    self.vulnerabilities.append(task[1])
                elif task[0] == 'add_exploit_result':
                    self.report_text.configure(state='normal')
                    self.report_text.insert(tk.END, task[1] + "\n")
                    self.report_text.configure(state='disabled')
                    self.report_text.see(tk.END)
                elif task[0] == 'update_status':
                    self.status_var.set(task[1])
        except queue.Empty:
            pass
        
        self.root.after(100, self.process_queue)
    
    def stop_scan(self):
        self.status_var.set("s3loc_ - Scan stopped by user")

if __name__ == "__main__":
    root = tk.Tk()
    app = s3locPentestApp(root)
    root.mainloop()
