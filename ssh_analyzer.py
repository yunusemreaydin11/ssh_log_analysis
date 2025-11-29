#!/usr/bin/env python3
"""
SSH Log Analiz ve Brute Force Tespit Aracı
Linux auth.log dosyalarını analiz ederek brute force saldırılarını tespit eder.
"""

import re
import json
import csv
import argparse
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from html import escape


def parse_auth_log(log_path):
    """
    auth.log dosyasını parse eder ve SSH olaylarını çıkarır.
    
    Args:
        log_path: Log dosyasının yolu
        
    Returns:
        List of dict: Her olay için timestamp, ip, event_type, user bilgileri
    """
    events = []
    
    # Log formatı: Jan 15 10:30:45 hostname sshd[12345]: message
    log_pattern = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(.*)'
    )
    
    # IP adresi pattern'i
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = log_pattern.match(line)
                if not match:
                    continue
                
                timestamp_str = match.group(1)
                message = match.group(2)
                
                # Timestamp'i parse et (yıl bilgisi yok, mevcut yılı kullan)
                current_year = datetime.now().year
                try:
                    timestamp = datetime.strptime(
                        f"{current_year} {timestamp_str}", 
                        "%Y %b %d %H:%M:%S"
                    )
                except ValueError:
                    # Eğer tarih gelecekteyse (yıl sonu), bir önceki yılı dene
                    timestamp = datetime.strptime(
                        f"{current_year - 1} {timestamp_str}", 
                        "%Y %b %d %H:%M:%S"
                    )
                
                # IP adresini bul
                ip_matches = ip_pattern.findall(message)
                ip = ip_matches[0] if ip_matches else None
                
                # Olay tipini belirle
                event_type = None
                user = None
                
                if 'Failed password' in message or 'Invalid user' in message:
                    event_type = 'failed'
                    # Kullanıcı adını çıkar
                    user_match = re.search(r'(?:for|user)\s+(\S+)', message, re.IGNORECASE)
                    if user_match:
                        user = user_match.group(1)
                elif 'Accepted password' in message or 'Accepted publickey' in message:
                    event_type = 'success'
                    # Kullanıcı adını çıkar
                    user_match = re.search(r'(?:for|user)\s+(\S+)', message, re.IGNORECASE)
                    if user_match:
                        user = user_match.group(1)
                
                if event_type and ip:
                    events.append({
                        'timestamp': timestamp,
                        'ip': ip,
                        'event_type': event_type,
                        'user': user,
                        'message': message
                    })
    
    except FileNotFoundError:
        print(f"Hata: Log dosyası bulunamadı: {log_path}")
        return []
    except Exception as e:
        print(f"Hata: Log dosyası okunurken bir sorun oluştu: {e}")
        return []
    
    return events


def detect_brute_force(events, time_window=5, threshold=5):
    """
    Brute force saldırılarını tespit eder.
    
    Args:
        events: parse_auth_log'den dönen olay listesi
        time_window: Zaman penceresi (dakika)
        threshold: Şüpheli kabul edilecek minimum deneme sayısı
        
    Returns:
        dict: Analiz sonuçları ve şüpheli IP'ler
    """
    # IP bazlı istatistikler
    ip_stats = defaultdict(lambda: {
        'failed_attempts': [],
        'successful_attempts': [],
        'users_tried': set()
    })
    
    # Tüm olayları IP'ye göre grupla
    for event in events:
        ip = event['ip']
        ip_stats[ip]['users_tried'].add(event.get('user', 'unknown'))
        
        if event['event_type'] == 'failed':
            ip_stats[ip]['failed_attempts'].append(event['timestamp'])
        elif event['event_type'] == 'success':
            ip_stats[ip]['successful_attempts'].append(event['timestamp'])
    
    # Brute force tespiti
    suspicious_ips = []
    
    for ip, stats in ip_stats.items():
        failed_attempts = sorted(stats['failed_attempts'])
        successful_attempts = sorted(stats['successful_attempts'])
        
        # Zaman penceresi içinde analiz
        time_delta = timedelta(minutes=time_window)
        brute_force_windows = []
        
        for i, attempt_time in enumerate(failed_attempts):
            window_start = attempt_time
            window_end = attempt_time + time_delta
            
            # Bu pencere içindeki denemeleri say
            window_attempts = [
                t for t in failed_attempts 
                if window_start <= t <= window_end
            ]
            
            if len(window_attempts) >= threshold:
                # Bu pencereyi kaydet
                brute_force_windows.append({
                    'start': window_start,
                    'end': window_end,
                    'attempts': len(window_attempts)
                })
        
        # Eğer brute force penceresi varsa, şüpheli olarak işaretle
        if brute_force_windows:
            total_failed = len(failed_attempts)
            total_successful = len(successful_attempts)
            
            suspicious_ips.append({
                'ip': ip,
                'total_failed_attempts': total_failed,
                'total_successful_attempts': total_successful,
                'brute_force_windows': brute_force_windows,
                'users_tried': list(stats['users_tried']),
                'first_attempt': min(failed_attempts) if failed_attempts else None,
                'last_attempt': max(failed_attempts) if failed_attempts else None,
                'success_rate': total_successful / (total_failed + total_successful) if (total_failed + total_successful) > 0 else 0
            })
    
    # Genel istatistikler
    total_events = len(events)
    total_failed = sum(1 for e in events if e['event_type'] == 'failed')
    total_successful = sum(1 for e in events if e['event_type'] == 'success')
    unique_ips = len(ip_stats)
    unique_suspicious_ips = len(suspicious_ips)
    
    return {
        'analysis_date': datetime.now().isoformat(),
        'time_window_minutes': time_window,
        'threshold': threshold,
        'statistics': {
            'total_events': total_events,
            'total_failed_attempts': total_failed,
            'total_successful_attempts': total_successful,
            'unique_ips': unique_ips,
            'suspicious_ips_count': unique_suspicious_ips,
            'success_rate': total_successful / total_events if total_events > 0 else 0
        },
        'suspicious_ips': sorted(suspicious_ips, key=lambda x: x['total_failed_attempts'], reverse=True)
    }


def generate_json_report(data, output_path):
    """JSON formatında rapor oluşturur."""
    # JSON serialization için datetime'ları string'e çevir
    json_data = {
        'analysis_date': data['analysis_date'],
        'time_window_minutes': data['time_window_minutes'],
        'threshold': data['threshold'],
        'statistics': data['statistics'],
        'suspicious_ips': []
    }
    
    for ip_data in data['suspicious_ips']:
        json_ip = {
            'ip': ip_data['ip'],
            'total_failed_attempts': ip_data['total_failed_attempts'],
            'total_successful_attempts': ip_data['total_successful_attempts'],
            'users_tried': ip_data['users_tried'],
            'success_rate': ip_data['success_rate'],
            'first_attempt': ip_data['first_attempt'].isoformat() if ip_data['first_attempt'] else None,
            'last_attempt': ip_data['last_attempt'].isoformat() if ip_data['last_attempt'] else None,
            'brute_force_windows': [
                {
                    'start': w['start'].isoformat(),
                    'end': w['end'].isoformat(),
                    'attempts': w['attempts']
                }
                for w in ip_data['brute_force_windows']
            ]
        }
        json_data['suspicious_ips'].append(json_ip)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    print(f"JSON raporu oluşturuldu: {output_path}")


def generate_csv_report(data, output_path):
    """CSV formatında rapor oluşturur."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Başlık satırı
        writer.writerow([
            'IP Adresi',
            'Toplam Başarısız Deneme',
            'Toplam Başarılı Deneme',
            'Başarı Oranı',
            'Denenen Kullanıcılar',
            'İlk Deneme',
            'Son Deneme',
            'Brute Force Pencere Sayısı'
        ])
        
        # Şüpheli IP'ler
        for ip_data in data['suspicious_ips']:
            writer.writerow([
                ip_data['ip'],
                ip_data['total_failed_attempts'],
                ip_data['total_successful_attempts'],
                f"{ip_data['success_rate']:.2%}",
                ', '.join(ip_data['users_tried']),
                ip_data['first_attempt'].strftime('%Y-%m-%d %H:%M:%S') if ip_data['first_attempt'] else '',
                ip_data['last_attempt'].strftime('%Y-%m-%d %H:%M:%S') if ip_data['last_attempt'] else '',
                len(ip_data['brute_force_windows'])
            ])
    
    print(f"CSV raporu oluşturuldu: {output_path}")


def generate_html_report(data, output_path):
    """HTML formatında görsel rapor oluşturur."""
    html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Brute Force Analiz Raporu</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            opacity: 0.9;
        }}
        .stat-card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .warning {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 30px;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .ip-cell {{
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #d32f2f;
        }}
        .high-risk {{
            background-color: #ffebee;
        }}
        .medium-risk {{
            background-color: #fff3e0;
        }}
        .low-risk {{
            background-color: #e8f5e9;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-high {{
            background-color: #f44336;
            color: white;
        }}
        .badge-medium {{
            background-color: #ff9800;
            color: white;
        }}
        .badge-low {{
            background-color: #4caf50;
            color: white;
        }}
        .info {{
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 4px solid #2196F3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SSH Brute Force Analiz Raporu</h1>
        
        <div class="info">
            <strong>Analiz Tarihi:</strong> {escape(data['analysis_date'])}<br>
            <strong>Zaman Penceresi:</strong> {data['time_window_minutes']} dakika<br>
            <strong>Eşik Değeri:</strong> {data['threshold']} başarısız deneme
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Toplam Olay</h3>
                <div class="value">{data['statistics']['total_events']}</div>
            </div>
            <div class="stat-card warning">
                <h3>Başarısız Deneme</h3>
                <div class="value">{data['statistics']['total_failed_attempts']}</div>
            </div>
            <div class="stat-card">
                <h3>Başarılı Giriş</h3>
                <div class="value">{data['statistics']['total_successful_attempts']}</div>
            </div>
            <div class="stat-card">
                <h3>Benzersiz IP</h3>
                <div class="value">{data['statistics']['unique_ips']}</div>
            </div>
            <div class="stat-card warning">
                <h3>Şüpheli IP</h3>
                <div class="value">{data['statistics']['suspicious_ips_count']}</div>
            </div>
            <div class="stat-card">
                <h3>Başarı Oranı</h3>
                <div class="value">{data['statistics']['success_rate']:.1%}</div>
            </div>
        </div>
        
        <h2>Şüpheli IP Adresleri</h2>
"""
    
    if data['suspicious_ips']:
        html_content += """
        <table>
            <thead>
                <tr>
                    <th>IP Adresi</th>
                    <th>Başarısız Deneme</th>
                    <th>Başarılı Deneme</th>
                    <th>Başarı Oranı</th>
                    <th>Risk Seviyesi</th>
                    <th>Denenen Kullanıcılar</th>
                    <th>İlk Deneme</th>
                    <th>Son Deneme</th>
                    <th>Brute Force Pencere</th>
                </tr>
            </thead>
            <tbody>
"""
        for ip_data in data['suspicious_ips']:
            # Risk seviyesini belirle
            failed = ip_data['total_failed_attempts']
            if failed >= 50:
                risk_level = 'Yüksek'
                risk_class = 'high-risk'
                badge_class = 'badge-high'
            elif failed >= 20:
                risk_level = 'Orta'
                risk_class = 'medium-risk'
                badge_class = 'badge-medium'
            else:
                risk_level = 'Düşük'
                risk_class = 'low-risk'
                badge_class = 'badge-low'
            
            html_content += f"""
                <tr class="{risk_class}">
                    <td class="ip-cell">{escape(ip_data['ip'])}</td>
                    <td>{ip_data['total_failed_attempts']}</td>
                    <td>{ip_data['total_successful_attempts']}</td>
                    <td>{ip_data['success_rate']:.1%}</td>
                    <td><span class="badge {badge_class}">{risk_level}</span></td>
                    <td>{', '.join([escape(u) for u in ip_data['users_tried'][:5]])}{'...' if len(ip_data['users_tried']) > 5 else ''}</td>
                    <td>{ip_data['first_attempt'].strftime('%Y-%m-%d %H:%M:%S') if ip_data['first_attempt'] else 'N/A'}</td>
                    <td>{ip_data['last_attempt'].strftime('%Y-%m-%d %H:%M:%S') if ip_data['last_attempt'] else 'N/A'}</td>
                    <td>{len(ip_data['brute_force_windows'])}</td>
                </tr>
"""
        html_content += """
            </tbody>
        </table>
"""
    else:
        html_content += """
        <div class="info">
            <p>✅ Şüpheli IP adresi tespit edilmedi. Sistem güvenli görünüyor.</p>
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML raporu oluşturuldu: {output_path}")


def main():
    """Ana fonksiyon - komut satırı argümanlarını işler."""
    parser = argparse.ArgumentParser(
        description='SSH log analiz ve brute force tespit aracı',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek kullanım:
  python ssh_analyzer.py --log /var/log/auth.log --format all
  python ssh_analyzer.py --log auth.log --format html --time-window 10 --threshold 3
        """
    )
    
    parser.add_argument(
        '--log',
        type=str,
        default='/var/log/auth.log',
        help='Analiz edilecek log dosyasının yolu (varsayılan: /var/log/auth.log)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='./reports',
        help='Raporların kaydedileceği dizin (varsayılan: ./reports)'
    )
    
    parser.add_argument(
        '--format',
        type=str,
        choices=['json', 'csv', 'html', 'all'],
        default='all',
        help='Rapor formatı (varsayılan: all)'
    )
    
    parser.add_argument(
        '--time-window',
        type=int,
        default=5,
        help='Brute force tespiti için zaman penceresi (dakika, varsayılan: 5)'
    )
    
    parser.add_argument(
        '--threshold',
        type=int,
        default=5,
        help='Şüpheli kabul edilecek minimum başarısız deneme sayısı (varsayılan: 5)'
    )
    
    args = parser.parse_args()
    
    # Çıktı dizinini oluştur
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Log dosyasını parse et
    print(f"Log dosyası okunuyor: {args.log}")
    events = parse_auth_log(args.log)
    
    if not events:
        print("Uyarı: Log dosyasında SSH olayı bulunamadı.")
        return
    
    print(f"Toplam {len(events)} SSH olayı bulundu.")
    
    # Brute force tespiti
    print(f"Brute force analizi yapılıyor (zaman penceresi: {args.time_window} dakika, eşik: {args.threshold})...")
    analysis_data = detect_brute_force(events, args.time_window, args.threshold)
    
    # Raporları oluştur
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if args.format in ['json', 'all']:
        json_path = output_dir / f'ssh_analysis_{timestamp}.json'
        generate_json_report(analysis_data, json_path)
    
    if args.format in ['csv', 'all']:
        csv_path = output_dir / f'ssh_analysis_{timestamp}.csv'
        generate_csv_report(analysis_data, csv_path)
    
    if args.format in ['html', 'all']:
        html_path = output_dir / f'ssh_analysis_{timestamp}.html'
        generate_html_report(analysis_data, html_path)
    
    # Özet bilgi
    print("\n" + "="*60)
    print("ANALİZ ÖZETİ")
    print("="*60)
    print(f"Toplam Olay: {analysis_data['statistics']['total_events']}")
    print(f"Başarısız Deneme: {analysis_data['statistics']['total_failed_attempts']}")
    print(f"Başarılı Giriş: {analysis_data['statistics']['total_successful_attempts']}")
    print(f"Benzersiz IP: {analysis_data['statistics']['unique_ips']}")
    print(f"Şüpheli IP: {analysis_data['statistics']['suspicious_ips_count']}")
    print("="*60)


if __name__ == '__main__':
    main()

