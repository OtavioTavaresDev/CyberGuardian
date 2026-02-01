import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import re
import hashlib
import base64
from datetime import datetime
import requests
from urllib.parse import urlparse
import json
import os

class CyberGuardian:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberGuardian - Suíte de Segurança")
        self.root.geometry("900x700")
        self.root.configure(bg='#1e1e2e')
        
        # Estilo
        self.setup_styles()
        
        # Layout principal
        self.setup_ui()
        
        # Dados para análise
        self.common_passwords = self.load_common_passwords()
        self.malicious_keywords = [
            'hack', 'attack', 'malware', 'virus', 'exploit', 'injection',
            'unauthorized', 'failed', 'breach', 'intrusion', 'suspicious'
        ]
    
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Cores
        self.colors = {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'accent': '#89b4fa',
            'secondary': '#585b70',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'error': '#f38ba8'
        }
    
    def setup_ui(self):
        # Cabeçalho
        header_frame = tk.Frame(self.root, bg=self.colors['bg'])
        header_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = tk.Label(
            header_frame,
            text="🛡️ CyberGuardian",
            font=('Arial', 24, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['accent']
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            header_frame,
            text="Suíte de Ferramentas de Cibersegurança",
            font=('Arial', 10),
            bg=self.colors['bg'],
            fg=self.colors['secondary']
        )
        subtitle_label.pack()
        
        # Abas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Aba 1: Scanner de Portas
        self.create_port_scanner_tab()
        
        # Aba 2: Analisador de Senhas
        self.create_password_analyzer_tab()
        
        # Aba 3: Monitor de Logs
        self.create_log_monitor_tab()
        
        # Aba 4: Verificador de Links
        self.create_link_checker_tab()
        
        # Aba 5: Criptografia
        self.create_encryption_tab()
        
        # Rodapé
        footer_frame = tk.Frame(self.root, bg=self.colors['bg'])
        footer_frame.pack(fill='x', padx=20, pady=10)
        
        status_label = tk.Label(
            footer_frame,
            text="Status: Pronto | Desenvolvido com Python para segurança digital",
            font=('Arial', 8),
            bg=self.colors['bg'],
            fg=self.colors['secondary']
        )
        status_label.pack()
    
    def create_port_scanner_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='🔍 Scanner de Portas')
        
        # Controles
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(control_frame, text="Host:", font=('Arial', 10)).grid(row=0, column=0, padx=5)
        self.host_entry = tk.Entry(control_frame, width=30)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(control_frame, text="Porta Inicial:", font=('Arial', 10)).grid(row=0, column=2, padx=5)
        self.start_port = tk.Entry(control_frame, width=10)
        self.start_port.insert(0, "1")
        self.start_port.grid(row=0, column=3, padx=5)
        
        tk.Label(control_frame, text="Porta Final:", font=('Arial', 10)).grid(row=0, column=4, padx=5)
        self.end_port = tk.Entry(control_frame, width=10)
        self.end_port.insert(0, "1024")
        self.end_port.grid(row=0, column=5, padx=5)
        
        self.scan_btn = tk.Button(
            control_frame,
            text="Iniciar Scanner",
            command=self.start_port_scan,
            bg=self.colors['accent'],
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.scan_btn.grid(row=0, column=6, padx=10)
        
        # Resultados
        results_frame = ttk.LabelFrame(frame, text="Resultados do Scan")
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            font=('Consolas', 9)
        )
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_password_analyzer_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='🔐 Analisador de Senhas')
        
        tk.Label(
            frame,
            text="Digite uma senha para análise:",
            font=('Arial', 11)
        ).pack(pady=10)
        
        self.password_entry = tk.Entry(
            frame,
            width=40,
            font=('Arial', 12),
            show="•"
        )
        self.password_entry.pack(pady=5)
        
        self.analyze_btn = tk.Button(
            frame,
            text="Analisar Senha",
            command=self.analyze_password,
            bg=self.colors['accent'],
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.analyze_btn.pack(pady=10)
        
        # Resultados
        self.password_result = scrolledtext.ScrolledText(
            frame,
            height=15,
            font=('Arial', 10),
            wrap=tk.WORD
        )
        self.password_result.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Sugestões
        suggest_frame = ttk.LabelFrame(frame, text="Sugestões para Senhas Fortes")
        suggest_frame.pack(fill='x', padx=10, pady=5)
        
        suggestions = [
            "• Use pelo menos 12 caracteres",
            "• Combine letras maiúsculas e minúsculas",
            "• Inclua números e caracteres especiais",
            "• Evite sequências comuns (123, abc)",
            "• Não use informações pessoais"
        ]
        
        for suggestion in suggestions:
            tk.Label(suggest_frame, text=suggestion, anchor='w').pack(fill='x', padx=5)
    
    def create_log_monitor_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='📊 Monitor de Logs')
        
        # Controles
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(control_frame, text="Caminho do arquivo de log:", font=('Arial', 10)).pack(side='left', padx=5)
        self.log_path = tk.Entry(control_frame, width=40)
        self.log_path.insert(0, "./exemplo.log")
        self.log_path.pack(side='left', padx=5)
        
        self.monitor_btn = tk.Button(
            control_frame,
            text="Analisar Logs",
            command=self.analyze_logs,
            bg=self.colors['accent'],
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.monitor_btn.pack(side='left', padx=10)
        
        # Área de resultados
        results_frame = ttk.LabelFrame(frame, text="Análise de Logs")
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            font=('Consolas', 9)
        )
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Criar arquivo de log de exemplo
        self.create_example_log()
    
    def create_link_checker_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='🔗 Verificador de Links')
        
        tk.Label(
            frame,
            text="Digite a URL para verificação:",
            font=('Arial', 11)
        ).pack(pady=10)
        
        self.url_entry = tk.Entry(
            frame,
            width=50,
            font=('Arial', 11)
        )
        self.url_entry.insert(0, "https://exemplo.com")
        self.url_entry.pack(pady=5)
        
        self.check_url_btn = tk.Button(
            frame,
            text="Verificar URL",
            command=self.check_url,
            bg=self.colors['accent'],
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.check_url_btn.pack(pady=10)
        
        # Resultados
        self.url_result = scrolledtext.ScrolledText(
            frame,
            height=15,
            font=('Arial', 10),
            wrap=tk.WORD
        )
        self.url_result.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Informações
        info_frame = ttk.LabelFrame(frame, text="O que verificamos:")
        info_frame.pack(fill='x', padx=10, pady=5)
        
        checks = [
            "✓ Formato da URL",
            "✓ Domínio suspeito",
            "✓ Presença de caracteres maliciosos",
            "✓ Redirecionamentos HTTP",
            "✓ Encurtadores de URL comuns"
        ]
        
        for check in checks:
            tk.Label(info_frame, text=check, anchor='w').pack(fill='x', padx=5)
    
    def create_encryption_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='🔒 Criptografia')
        
        # Entrada de texto
        input_frame = ttk.LabelFrame(frame, text="Texto para processar")
        input_frame.pack(fill='x', padx=10, pady=10)
        
        self.crypto_text = scrolledtext.ScrolledText(
            input_frame,
            height=6,
            font=('Arial', 10)
        )
        self.crypto_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Chave
        key_frame = ttk.Frame(frame)
        key_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(key_frame, text="Chave (opcional):", font=('Arial', 10)).pack(side='left', padx=5)
        self.crypto_key = tk.Entry(key_frame, width=30, font=('Arial', 10))
        self.crypto_key.pack(side='left', padx=5)
        
        # Botões
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        self.encrypt_btn = tk.Button(
            btn_frame,
            text="Criptografar",
            command=self.encrypt_text,
            bg=self.colors['success'],
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.encrypt_btn.pack(side='left', padx=5)
        
        self.decrypt_btn = tk.Button(
            btn_frame,
            text="Descriptografar",
            command=self.decrypt_text,
            bg=self.colors['warning'],
            fg='black',
            font=('Arial', 10, 'bold')
        )
        self.decrypt_btn.pack(side='left', padx=5)
        
        self.hash_btn = tk.Button(
            btn_frame,
            text="Gerar Hash",
            command=self.generate_hash,
            bg=self.colors['accent'],
            fg='white',
            font=('Arial', 10, 'bold')
        )
        self.hash_btn.pack(side='left', padx=5)
        
        # Resultados
        output_frame = ttk.LabelFrame(frame, text="Resultado")
        output_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.crypto_result = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            font=('Consolas', 9)
        )
        self.crypto_result.pack(fill='both', expand=True, padx=5, pady=5)
    
    # ===== FUNCIONALIDADES =====
    
    def start_port_scan(self):
        host = self.host_entry.get()
        try:
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            
            if start > end or start < 1 or end > 65535:
                messagebox.showerror("Erro", "Intervalo de portas inválido!")
                return
                
            self.scan_btn.config(state='disabled', text="Escaneando...")
            self.results_text.delete(1.0, tk.END)
            
            thread = threading.Thread(target=self.scan_ports, args=(host, start, end))
            thread.daemon = True
            thread.start()
            
        except ValueError:
            messagebox.showerror("Erro", "Portas devem ser números válidos!")
    
    def scan_ports(self, host, start, end):
        self.results_text.insert(tk.END, f"Iniciando scan em {host} (portas {start}-{end})\n")
        self.results_text.insert(tk.END, "="*50 + "\n")
        
        open_ports = []
        
        for port in range(start, end + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Desconhecido"
                    
                    status = f"PORT {port}/TCP ABERTA - Serviço: {service}"
                    self.results_text.insert(tk.END, f"✅ {status}\n")
                    open_ports.append(port)
                
                sock.close()
                
            except Exception as e:
                self.results_text.insert(tk.END, f"⚠️ Erro na porta {port}: {str(e)}\n")
        
        self.results_text.insert(tk.END, "="*50 + "\n")
        if open_ports:
            self.results_text.insert(tk.END, f"✅ Scan completo! {len(open_ports)} portas abertas encontradas.\n")
            self.results_text.insert(tk.END, f"Portas abertas: {', '.join(map(str, open_ports))}\n")
        else:
            self.results_text.insert(tk.END, "✅ Scan completo! Nenhuma porta aberta encontrada.\n")
        
        self.scan_btn.config(state='normal', text="Iniciar Scanner")
    
    def analyze_password(self):
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("Aviso", "Digite uma senha para análise!")
            return
        
        self.password_result.delete(1.0, tk.END)
        
        # Análise da senha
        score = 0
        feedback = []
        
        # Comprimento
        if len(password) >= 12:
            score += 3
            feedback.append("✅ Comprimento excelente (12+ caracteres)")
        elif len(password) >= 8:
            score += 2
            feedback.append("✅ Comprimento bom (8+ caracteres)")
        else:
            score -= 2
            feedback.append("❌ Comprimento muito curto (menos de 8 caracteres)")
        
        # Complexidade
        if re.search(r'[A-Z]', password):
            score += 1
            feedback.append("✅ Contém letras maiúsculas")
        
        if re.search(r'[a-z]', password):
            score += 1
            feedback.append("✅ Contém letras minúsculas")
        
        if re.search(r'\d', password):
            score += 1
            feedback.append("✅ Contém números")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 2
            feedback.append("✅ Contém caracteres especiais")
        
        # Verificação contra senhas comuns
        if password.lower() in self.common_passwords:
            score -= 5
            feedback.append("❌ ALERTA: Esta senha está na lista de senhas comuns!")
        
        # Padrões simples
        if re.search(r'(.)\1{2,}', password):
            score -= 1
            feedback.append("⚠️ Evite caracteres repetidos em sequência")
        
        # Determinar força
        if score >= 7:
            strength = "FORTE"
            color = "#a6e3a1"
        elif score >= 4:
            strength = "MÉDIA"
            color = "#f9e2af"
        else:
            strength = "FRACA"
            color = "#f38ba8"
        
        # Exibir resultados
        self.password_result.insert(tk.END, f"📊 ANÁLISE DA SENHA\n")
        self.password_result.insert(tk.END, "="*40 + "\n\n")
        self.password_result.insert(tk.END, f"Pontuação: {score}/10\n")
        self.password_result.insert(tk.END, f"Força: ")
        self.password_result.insert(tk.END, f"{strength}\n", f"strength_{strength}")
        self.password_result.tag_config(f"strength_{strength}", foreground=color, font=('Arial', 11, 'bold'))
        
        self.password_result.insert(tk.END, f"\n🔍 DETALHES:\n")
        for item in feedback:
            self.password_result.insert(tk.END, f"• {item}\n")
    
    def create_example_log(self):
        log_content = """2024-01-15 10:23:45 INFO User 'admin' logged in successfully
2024-01-15 10:24:12 WARNING Failed login attempt for user 'root'
2024-01-15 10:25:03 ERROR Database connection timeout
2024-01-15 10:26:45 INFO Backup completed successfully
2024-01-15 10:27:30 WARNING Suspicious activity detected from IP 192.168.1.100
2024-01-15 10:28:15 ERROR File not found: /var/www/config.php
2024-01-15 10:29:00 INFO User 'john' changed password
2024-01-15 10:30:45 CRITICAL Malware injection attempt detected
2024-01-15 10:31:20 WARNING Multiple failed login attempts from IP 10.0.0.5
2024-01-15 10:32:10 INFO System update started"""
        
        try:
            with open("exemplo.log", "w") as f:
                f.write(log_content)
        except:
            pass
    
    def analyze_logs(self):
        log_file = self.log_path.get()
        
        if not os.path.exists(log_file):
            messagebox.showerror("Erro", f"Arquivo não encontrado: {log_file}")
            return
        
        self.log_text.delete(1.0, tk.END)
        
        try:
            with open(log_file, 'r') as f:
                logs = f.readlines()
            
            # Análise básica
            total_lines = len(logs)
            error_count = 0
            warning_count = 0
            suspicious_count = 0
            
            self.log_text.insert(tk.END, f"📋 ANÁLISE DO ARQUIVO DE LOG\n")
            self.log_text.insert(tk.END, f"Arquivo: {log_file}\n")
            self.log_text.insert(tk.END, f"Total de linhas: {total_lines}\n\n")
            self.log_text.insert(tk.END, "="*50 + "\n\n")
            
            # Processar cada linha
            for i, line in enumerate(logs, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Verificar nível de log
                if 'ERROR' in line or 'CRITICAL' in line:
                    error_count += 1
                    self.log_text.insert(tk.END, f"❌ [{i}] {line}\n", "error")
                elif 'WARNING' in line:
                    warning_count += 1
                    self.log_text.insert(tk.END, f"⚠️ [{i}] {line}\n", "warning")
                else:
                    self.log_text.insert(tk.END, f"📝 [{i}] {line}\n")
                
                # Verificar atividades suspeitas
                for keyword in self.malicious_keywords:
                    if keyword.lower() in line.lower():
                        suspicious_count += 1
                        self.log_text.insert(tk.END, f"   🚨 ATIVIDADE SUSPEITA DETECTADA: '{keyword}'\n", "suspicious")
            
            # Configurar tags para cores
            self.log_text.tag_config("error", foreground="#f38ba8")
            self.log_text.tag_config("warning", foreground="#f9e2af")
            self.log_text.tag_config("suspicious", foreground="#f38ba8", background="#f38ba822")
            
            # Resumo
            self.log_text.insert(tk.END, "\n" + "="*50 + "\n")
            self.log_text.insert(tk.END, "📊 RESUMO DA ANÁLISE\n\n")
            self.log_text.insert(tk.END, f"• Total de logs: {total_lines}\n")
            self.log_text.insert(tk.END, f"• Erros/CRITICAL: {error_count}\n")
            self.log_text.insert(tk.END, f"• Avisos: {warning_count}\n")
            self.log_text.insert(tk.END, f"• Atividades suspeitas: {suspicious_count}\n\n")
            
            if suspicious_count > 0:
                self.log_text.insert(tk.END, "🚨 ALERTA: Atividades suspeitas detectadas!\n", "alert")
                self.log_text.tag_config("alert", foreground="#f38ba8", font=('Arial', 10, 'bold'))
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao analisar logs: {str(e)}")
    
    def check_url(self):
        url = self.url_entry.get()
        
        if not url:
            messagebox.showwarning("Aviso", "Digite uma URL para verificação!")
            return
        
        self.url_result.delete(1.0, tk.END)
        
        # Análise da URL
        self.url_result.insert(tk.END, f"🔗 ANALISANDO URL: {url}\n")
        self.url_result.insert(tk.END, "="*50 + "\n\n")
        
        try:
            # Verificar formato
            parsed = urlparse(url)
            
            if not parsed.scheme:
                self.url_result.insert(tk.END, "❌ AVISO: URL sem protocolo especificado\n")
                url = 'http://' + url
                parsed = urlparse(url)
            
            self.url_result.insert(tk.END, f"📋 Informações da URL:\n")
            self.url_result.insert(tk.END, f"• Protocolo: {parsed.scheme}\n")
            self.url_result.insert(tk.END, f"• Domínio: {parsed.netloc}\n")
            self.url_result.insert(tk.END, f"• Caminho: {parsed.path}\n")
            
            # Verificações de segurança
            issues = []
            warnings = []
            
            # Domínios suspeitos
            suspicious_domains = ['free', 'download', 'click', 'bit.ly', 'tinyurl', 'shorte']
            for domain in suspicious_domains:
                if domain in parsed.netloc.lower():
                    warnings.append(f"Domínio contém palavra suspeita: '{domain}'")
            
            # HTTP vs HTTPS
            if parsed.scheme == 'http':
                issues.append("Usa HTTP (não seguro) em vez de HTTPS")
            
            # Caracteres suspeitos
            if '%' in url or '&' in url or '?' in url:
                warnings.append("Contém caracteres que podem indicar manipulação de URL")
            
            # Tentar acessar a URL
            self.url_result.insert(tk.END, f"\n🌐 Testando conexão...\n")
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                self.url_result.insert(tk.END, f"• Status: {response.status_code}\n")
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    redirect_url = response.headers.get('Location', 'Desconhecido')
                    warnings.append(f"URL redireciona para: {redirect_url}")
                
                # Verificar cabeçalhos de segurança
                headers = response.headers
                security_headers = {
                    'Content-Security-Policy': 'Política de Segurança de Conteúdo',
                    'X-Frame-Options': 'Proteção contra clickjacking',
                    'X-Content-Type-Options': 'Prevenção de MIME sniffing',
                    'Strict-Transport-Security': 'Força uso de HTTPS'
                }
                
                self.url_result.insert(tk.END, f"\n🛡️ Cabeçalhos de segurança:\n")
                for header, description in security_headers.items():
                    if header in headers:
                        self.url_result.insert(tk.END, f"✅ {description}: Presente\n")
                    else:
                        self.url_result.insert(tk.END, f"⚠️ {description}: Ausente\n")
                
            except requests.exceptions.RequestException as e:
                self.url_result.insert(tk.END, f"⚠️ Não foi possível acessar a URL: {str(e)}\n")
            
            # Resumo
            self.url_result.insert(tk.END, "\n" + "="*50 + "\n")
            self.url_result.insert(tk.END, "📊 RESUMO DE SEGURANÇA\n\n")
            
            if issues:
                self.url_result.insert(tk.END, "❌ PROBLEMAS ENCONTRADOS:\n")
                for issue in issues:
                    self.url_result.insert(tk.END, f"• {issue}\n", "issue")
                self.url_result.tag_config("issue", foreground="#f38ba8")
            
            if warnings:
                self.url_result.insert(tk.END, f"\n⚠️ AVISOS:\n")
                for warning in warnings:
                    self.url_result.insert(tk.END, f"• {warning}\n", "warning")
                self.url_result.tag_config("warning", foreground="#f9e2af")
            
            if not issues and not warnings:
                self.url_result.insert(tk.END, "✅ A URL parece segura!\n", "safe")
                self.url_result.tag_config("safe", foreground="#a6e3a1", font=('Arial', 11, 'bold'))
            
        except Exception as e:
            self.url_result.insert(tk.END, f"❌ Erro na análise: {str(e)}\n")
    
    def encrypt_text(self):
        text = self.crypto_text.get(1.0, tk.END).strip()
        key = self.crypto_key.get() or "cyberguardian"
        
        if not text:
            messagebox.showwarning("Aviso", "Digite um texto para criptografar!")
            return
        
        # Criptografia simples (Base64 + XOR para demonstração)
        try:
            # XOR simples com a chave
            encrypted = ""
            for i, char in enumerate(text):
                key_char = key[i % len(key)]
                encrypted += chr(ord(char) ^ ord(key_char))
            
            # Converter para Base64
            encrypted_bytes = encrypted.encode('latin-1')
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('latin-1')
            
            self.crypto_result.delete(1.0, tk.END)
            self.crypto_result.insert(tk.END, "🔒 TEXTO CRIPTOGRAFADO:\n")
            self.crypto_result.insert(tk.END, "="*40 + "\n\n")
            self.crypto_result.insert(tk.END, encrypted_b64)
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha na criptografia: {str(e)}")
    
    def decrypt_text(self):
        text = self.crypto_text.get(1.0, tk.END).strip()
        key = self.crypto_key.get() or "cyberguardian"
        
        if not text:
            messagebox.showwarning("Aviso", "Digite um texto para descriptografar!")
            return
        
        try:
            # Decodificar Base64
            encrypted_bytes = base64.b64decode(text.encode('latin-1'))
            encrypted = encrypted_bytes.decode('latin-1')
            
            # XOR simples com a chave
            decrypted = ""
            for i, char in enumerate(encrypted):
                key_char = key[i % len(key)]
                decrypted += chr(ord(char) ^ ord(key_char))
            
            self.crypto_result.delete(1.0, tk.END)
            self.crypto_result.insert(tk.END, "🔓 TEXTO DESCRIPTOGRAFADO:\n")
            self.crypto_result.insert(tk.END, "="*40 + "\n\n")
            self.crypto_result.insert(tk.END, decrypted)
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha na descriptografia: {str(e)}\nVerifique se o texto está no formato correto.")
    
    def generate_hash(self):
        text = self.crypto_text.get(1.0, tk.END).strip()
        
        if not text:
            messagebox.showwarning("Aviso", "Digite um texto para gerar hash!")
            return
        
        self.crypto_result.delete(1.0, tk.END)
        self.crypto_result.insert(tk.END, "🔏 HASHES GERADOS:\n")
        self.crypto_result.insert(tk.END, "="*40 + "\n\n")
        
        # Gerar diferentes tipos de hash
        hash_algorithms = [
            ('MD5', hashlib.md5),
            ('SHA-1', hashlib.sha1),
            ('SHA-256', hashlib.sha256),
            ('SHA-512', hashlib.sha512)
        ]
        
        for name, algo_func in hash_algorithms:
            hash_obj = algo_func(text.encode('utf-8'))
            hash_hex = hash_obj.hexdigest()
            self.crypto_result.insert(tk.END, f"{name}:\n")
            self.crypto_result.insert(tk.END, f"{hash_hex}\n\n")
    
    def load_common_passwords(self):
        # Lista de senhas comuns
        return {
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'baseball', 'abc123', 'football', 'monkey',
            'letmein', '696969', 'shadow', 'master', '666666',
            'qwertyuiop', '123321', 'mustang', '1234567890',
            'michael', '654321', 'superman', '1qaz2wsx', '7777777'
        }

def main():
    root = tk.Tk()
    app = CyberGuardian(root)
    root.mainloop()

if __name__ == "__main__":
    main()