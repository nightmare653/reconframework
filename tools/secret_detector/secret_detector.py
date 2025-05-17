#!/usr/bin/python3
# secret_detector.py
'''
@haxshadow
@ibrahimsql
'''

import re
from typing import List, Dict, Tuple, Set
import argparse
from pathlib import Path
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
import concurrent.futures
import threading
import sys
from tqdm import tqdm
import urllib3
import warnings
import random
import subprocess
import json
import atexit
import signal


# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecretDetector:
    def __init__(self):
        # Track scan statistics
        self.stats = {
            "total_scanned": 0,
            "total_findings": 0,
            "start_time": 0,
            "end_time": 0,
            "scan_duration": 0
        }
        
        # API Keys & Tokens patterns (web-focused)
        self.api_patterns = {
            # Google, Firebase, Maps, Analytics, OAuth
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'Google OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
            'Google Maps Key': r'AIza[0-9A-Za-z-_]{35}',
            'Google Analytics ID': r'UA-\d{4,10}-\d+',
            'Google Client ID': r'[0-9]+\-([a-z0-9]+\.)+[a-z0-9]+\.apps\.googleusercontent\.com',
            'Google Captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            # Firebase
            'Firebase API Key': r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}',
            'Firebase Config': r'AIza[0-9A-Za-z-_]{35}',
            # AWS
            'AWS Access Key': r'A[SK]IA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws(.{0,20})?(secret|private)?(.{0,20})?([0-9a-zA-Z\/+=]{40})',
            'AWS Session Token': r'ASIA[0-9A-Z]{16}',
            # Azure
            'Azure Storage Key': r'(?i)DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{86,88};',
            'Azure SAS Token': r'sv=\d{4}-\d{2}-\d{2}&ss=[a-zA-Z]+&srt=[a-zA-Z]+&sp=[a-zA-Z]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&spr=https?&sig=[A-Za-z0-9%/+]{20,}',
            'Azure Client ID': r'[0-9a-fA-F\-]{36}',
            'Azure Client Secret': r'(?i)azure(.{0,20})?(secret|private)?(.{0,20})?([0-9a-zA-Z\/+=]{40,})',
            # GCP
            'GCP API Key': r'AIza[0-9A-Za-z-_]{35}',
            'GCP Service Account Email': r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com',
            'GCP Project ID': r'[a-z0-9\-]{6,30}',
            # DigitalOcean
            'DigitalOcean Token': r'dop_v1_[a-f0-9]{64}',
            # Heroku
            'Heroku API Key': r'heroku_[0-9a-fA-F]{32}',
            # Slack
            'Slack Webhook': r'https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+',
            'Slack Bot Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
            # GitHub/GitLab/Bitbucket
            'GitHub Token': r'ghp_[A-Za-z0-9]{36,}',
            'GitHub App Secret': r'ghs_[A-Za-z0-9]{36,}',
            'GitLab Token': r'glpat-[0-9a-zA-Z\-_]{20,}',
            'Bitbucket App Password': r'(?i)bitbucket(.{0,20})?(app_password|token|secret)[=:][\'\"]?([A-Za-z0-9]{20,})[\'\"]?',
            # Database URIs
            'MongoDB URI': r'mongodb(?:\+srv)?:\/\/(?:[a-zA-Z0-9._%+-]+:[^@]+@)?[a-zA-Z0-9.-]+(:\d+)?\/[a-zA-Z0-9._%+-]+',
            'PostgreSQL URI': r'postgresql:\/\/(?:[a-zA-Z0-9._%+-]+:[^@]+@)?[a-zA-Z0-9.-]+(:\d+)?\/[a-zA-Z0-9._%+-]+',
            'MySQL URI': r'mysql:\/\/(?:[a-zA-Z0-9._%+-]+:[^@]+@)?[a-zA-Z0-9.-]+(:\d+)?\/[a-zA-Z0-9._%+-]+',
            'SQL Server URI': r'sqlserver:\/\/(?:[a-zA-Z0-9._%+-]+:[^@]+@)?[a-zA-Z0-9.-]+(:\d+)?;databaseName=[a-zA-Z0-9._%+-]+',
            'Oracle DB URI': r'oracle:\/\/(?:[a-zA-Z0-9._%+-]+:[^@]+@)?[a-zA-Z0-9.-]+(:\d+)?\/[a-zA-Z0-9._%+-]+',
            'Redis URI': r'redis:\/\/(?:[a-zA-Z0-9._%+-]+:[^@]+@)?[a-zA-Z0-9.-]+(:\d+)?',
            'Elasticsearch Basic Auth': r'https?:\/\/[a-zA-Z0-9._%+-]+:[^@]+@[a-zA-Z0-9.-]+',
            'RabbitMQ URI': r'amqp:\/\/(?:[a-zA-Z0-9._%+-]+:[^@]+@)?[a-zA-Z0-9.-]+(:\d+)?',
            # Payment & E-Commerce
            'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
            'PayPal Client ID': r'Ab[a-zA-Z0-9-_]{20,}',
            'PayPal Secret': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Square Application Secret': r'sq0csp-[0-9A-Za-z\-_]{22,}',
            # Messaging & Communication
            'Twilio Account SID': r'AC[a-zA-Z0-9]{32}',
            'Twilio Auth Token': r'[a-f0-9]{32}',
            'Sendinblue API Key': r'xkeysib-[a-zA-Z0-9]{32}-[a-zA-Z0-9]{32}',
            'Mailjet API Key': r'[a-zA-Z0-9]{24}',
            'Mailjet Secret Key': r'[a-zA-Z0-9]{32}',
            'SMTP Password': r'smtp_pass[=:][\'\"]?([A-Za-z0-9]{8,})[\'\"]?',
            # Miscellaneous
            'Shopify Private App Key': r'shpss_[0-9a-fA-F]{32}',
            'Cloudflare API Token': r'cf-[a-zA-Z0-9-_]{30,}',
            'Okta API Token': r'00[a-zA-Z0-9]{38}',
            'Auth0 Client ID': r'[a-zA-Z0-9]{20,}',
            'Auth0 Client Secret': r'[a-zA-Z0-9]{40,}',
        }

        # Web Auth & Session patterns
        self.auth_patterns = {
            'JWT Token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'Session Cookie': r'(sessionid|_session|sessid|connect.sid|sid|JSESSIONID|PHPSESSID)=[a-zA-Z0-9-_]{10,}',
            'CSRF Token': r'csrf(_token|middlewaretoken|token)?[=:][\'\"]?[a-zA-Z0-9-_]{8,}',
            'XSRF Token': r'xsrf(_token)?[=:][\'\"]?[a-zA-Z0-9-_]{8,}',
            'Bearer Token': r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
            'OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
        }

        # Web config & leak patterns
        self.secret_patterns = {
            'API Key/Token': r'(?i)(?:api[_-]?key|access[_-]?token|secret|client[_-]?secret|apikey|private[_-]?key|refresh[_-]?token)[=:]\s*[\'\"]([^\'\"\s]{8,})[\'\"]',
            'Password/Secret': r'(?i)(?:password|passwd|pwd|token|secret|passphrase|auth|access)[=:]\s*[\'\"]([^\'\"\s]+)[\'\"]',
            'Hardcoded Secret': r'(?i)(?:secret|token|key|pass)[^\n]{0,30}=[^\n]{0,100}',
            'JWT Secret': r'(?i)jwt[_-]?secret[=:][\'\"]?([A-Za-z0-9\-_/+=]{10,})[\'\"]?',
            # Web config leaks in JS/JSON
            'Firebase Config Leak': r'apiKey\s*:\s*[\'\"]AIza[0-9A-Za-z-_]{35}[\'\"]',
            'Vercel Env Leak': r'(?i)vercel(.{0,20})?([a-z0-9]{24,})',
            'Netlify Env Leak': r'(?i)netlify(.{0,20})?([a-z0-9]{40})',
            'Supabase Config Leak': r'sb[a-z0-9]{32,}',
            'window.__env__': r'window\.__env__\s*=\s*{[^}]+}',
            'window.env': r'window\.env\s*=\s*{[^}]+}',
            'globalThis.config': r'globalThis\.config\s*=\s*{[^}]+}',
            'Meta Tag Leak': r'<meta\s+name=[\'\"](api|token|key|secret)[\'\"]\s+content=[\'\"][^\'\"]+[\'\"]',
        }

        # Web config/identifier patterns
        self.identifier_patterns = {
            'Email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,7}',
            'URL': r'https?://[\w\.-]+(?:/[\w\.-]*)*',
            'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'UUID': r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b',
            'Google Analytics ID': r'UA-\d{4,10}-\d+',
            'Sentry DSN': r'https://[0-9a-f]+@[a-z0-9\.-]+/[0-9]+',
            'Mixpanel Token': r'[0-9a-f]{32}',
        }

        # Extra dominant/hidden file regex patterns
        self.critical_patterns = {
            'SSH Private Key': r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----',
            'DSA Private Key': r'-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----',
            'EC Private Key': r'-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----',
            'AWS Access Key (env)': r'aws_access_key_id[=: ]+([A-Z0-9]{20})',
            'AWS Secret Key (env)': r'aws_secret_access_key[=: ]+([A-Za-z0-9/+=]{40})',
            'Dotenv Secret': r'(?i)(?:secret|token|key|password|passphrase|client_id|client_secret)[=: ]+[\'\"]?([A-Za-z0-9\-_/+=]{8,})[\'\"]?',
            'JWT Token (generic)': r'[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}',
            'Google Service Account': r'"type":\s*"service_account"',
            'Google Private Key Block': r'"private_key":\s*"-----BEGIN PRIVATE KEY-----[\\s\\S]+?-----END PRIVATE KEY-----"',
        }

        # Extra patterns
        self.extra_patterns = {
            # API/Token/Secret
            'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Facebook App Secret': r'(?i)facebook(.{0,20})?(secret|private)?(.{0,20})?([0-9a-zA-Z\/+]{32,})',
            'Twitter API Key': r'(?i)twitter(.{0,20})?(key|secret|token)[=:][\'\"]?([A-Za-z0-9]{35,44})[\'\"]?',
            'Twitter Bearer Token': r'AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9]{35,}',
            'LinkedIn Client ID': r'86[a-zA-Z0-9]{12,}',
            'LinkedIn Secret': r'(?i)linkedin(.{0,20})?(secret|private)?(.{0,20})?([0-9a-zA-Z\/+]{32,})',
            'Discord Token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            'Discord Webhook': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
            'Telegram Bot Token': r'\d{9}:[a-zA-Z0-9_-]{35}',
            'Shopify Access Token': r'shpat_[a-fA-F0-9]{32}',
            'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'SendGrid API Key': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            'Algolia API Key': r'(?i)algolia(.{0,20})?(key|token)[=:][\'\"]?([A-Za-z0-9]{32})[\'\"]?',
            # Cloud
            'Cloudinary API Key': r'CLOUDINARY_URL=cloudinary://[0-9]{15}:[A-Za-z0-9_-]{20,40}@[a-z0-9]+',
            'Firebase DB URL': r'https://[a-z0-9-]+\.firebaseio\.com',
            'Heroku Postgres URL': r'postgres://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            # Database
            'Amazon RDS Endpoint': r'[a-z0-9-]+\.rds\.amazonaws\.com',
            'Mongo Atlas Endpoint': r'cluster[0-9]+\.[a-z0-9]+\.mongodb\.net',
            # SSH/Private Keys
            'OpenSSH Ed25519 Key': r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----',
            'PuTTY Private Key': r'PuTTY-User-Key-File-2: [A-Za-z0-9]+',
            # OAuth/JWT
            'OAuth Refresh Token': r'(?i)refresh_token[=:][\'\"]?([A-Za-z0-9\-_.=]{20,})[\'\"]?',
            'JWT Auth Token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'OAuth Refresh Token': r'(?i)refresh_token[=:][\'\"]?([A-Za-z0-9\-_.=]{20,})[\'\"]?',
            'Cookie Value': r'(?:^|; )([A-Za-z0-9_]+)=([A-Za-z0-9\-_.]{10,})',
            'Session ID': r'(?:sessionid|sessid|sid|phpsessid|jsessionid)[=:][\'\"]?([A-Za-z0-9\-_.]{10,})[\'\"]?',
            'Wasabi Bucket': r'https?://s3\.wasabisys\.com/[a-z0-9\-_/\.]+',
            'Backblaze B2 Bucket': r'b2://[a-z0-9\-_/\.]+',
            'Alibaba OSS Bucket': r'https?://[a-z0-9\-]+\.oss-[a-z0-9\-]+\.aliyuncs\.com/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'IBM COS Bucket': r'https?://[a-z0-9\-]+\.s3\.[a-z0-9\-]+\.cloud-object-storage\.appdomain\.cloud/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'Yandex Object Storage': r'https?://[a-z0-9\-]+\.storage\.yandexcloud\.net/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'Oracle Cloud Bucket': r'https?://objectstorage\.[a-z0-9\-]+\.[a-z0-9\-]+\.oraclecloud\.com/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'Linode Object Storage': r'https?://[a-z0-9\-]+\.linodeobjects\.com/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'Exoscale Bucket': r'https?://[a-z0-9\-]+\.sos-ch-dk-2\.exo.io/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'OpenStack Swift': r'https?://[a-z0-9\-]+\.swift\.openstack\.org/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'Scaleway Bucket': r'https?://s3\.fr-par\.scw\.cloud/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'DreamObjects Bucket': r'https?://objects\.dreamhost\.com/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'Vultr Object Storage': r'https?://[a-z0-9\-]+\.ewr1\.vultrobjects\.com/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'UpCloud Object Storage': r'https?://[a-z0-9\-]+\.fi-hel1\.upcloudobjects\.com/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'OVH Cloud Bucket': r'https?://[a-z0-9\-]+\.s3\.gra\.io\.cloud\.ovh\.net/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
            'Hetzner Storage Box': r'https?://[a-z0-9\-]+\.your-storagebox\.de/[a-zA-Z0-9!_\-\.\*\'\(\)]+',
        }

        # DATABASE 
        self.database_connections = {
            'Cassandra Connection String': r'cassandra://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            'Couchbase Connection String': r'couchbase://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            'DynamoDB Endpoint': r'https?://dynamodb\.[a-z0-9-]+\.amazonaws\.com',
            'Elasticsearch Endpoint': r'https?://[a-z0-9-]+\.es\.[a-z0-9-]+\.amazonaws\.com',
            'MariaDB Connection String': r'mariadb://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            'Oracle DB Connection String': r'oracle://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            'SQLite File': r'sqlite:///[a-zA-Z0-9/_\-\.]+\.db',
            'Snowflake Connection String': r'snowflake://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            'Firebase Secret': r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}',
            'CouchDB URL': r'https?://[a-zA-Z0-9\-]+:[^@]+@[a-zA-Z0-9\.-]+:[0-9]+/[a-zA-Z0-9_-]+',
            'Neo4j Connection String': r'neo4j://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+',
            'InfluxDB Connection String': r'influxdb://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+',
            'ClickHouse Connection String': r'clickhouse://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+',
            'TimescaleDB Connection String': r'timescaledb://[^:]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+',
        }

        # EXTENDED CLOUD CONFIG/SECRET
        self.cloud_config = {
            'GCP Service Account': r'"type":\s*"service_account"',
            'Azure Storage Key': r'AccountKey=[A-Za-z0-9+/=]{88}',
            'DigitalOcean API Key': r'do[0-9a-f]{62}',
            'IBM Cloud API Key': r'ibmcloudapikey[0-9a-zA-Z]{32,}',
            'Yandex API Key': r'AQVN[a-zA-Z0-9_-]{35,}',
        }

        # EXTENDED FINANCIAL
        self.financial = {
            'Discover Card Number': r'6(?:011|5[0-9]{2})[0-9]{12}',
            'Maestro Card Number': r'(?:5[0678]\d{2}|6304|6390|67\d{2})\d{8,15}',
            'JCB Card Number': r'(?:2131|1800|35\d{3})\d{11}',
            'Diners Club Card Number': r'3(?:0[0-5]|[68][0-9])\d{11}',
            'SWIFT/BIC': r'\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b',
        }

        # EXTENDED PERSONAL/ID
        self.personal_id = {
            'TC Kimlik No': r'\b[1-9][0-9]{10}\b',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Passport Number': r'\b[A-Z0-9]{6,9}\b',
            'Driver License': r'\b[A-Z0-9]{5,15}\b',
            'Phone Number': r'\b(?:\+\d{1,3}[- ]?)?(?:\(\d{1,4}\)[- ]?)?\d{1,4}[- ]?\d{1,4}[- ]?\d{1,9}\b',
            'Address': r'\d{1,5}\s+([A-Za-z0-9\.,\-\s]+)',
            'Birth Date': r'\b\d{4}[-/]\d{2}[-/]\d{2}\b',
        }

        # EXTENDED PASSWORD/SECRET FORMAT
        self.password_secret = {
            'bcrypt Hash': r'\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}',
            'scrypt Hash': r'\$scrypt\$N=[0-9]+,r=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+',
            'argon2 Hash': r'\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+',
            'htpasswd Hash': r':[A-Za-z0-9./$]{13,}',
            'crypt Hash': r'\$[0-9a-zA-Z]{1,2}\$[A-Za-z0-9./]{8,}',
            'Base64 String': r'([A-Za-z0-9+/]{40,}={0,2})',
            'Hex String': r'\b[0-9a-fA-F]{32,}\b',
        }

        # EXTENDED CONFIG/ENV FILES
        self.config_env = {
            '.npmrc Auth Token': r'_auth=([A-Za-z0-9+/=]{32,})',
            '.pypirc Password': r'password\s*=\s*([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:\'\",.<>/?]+)',
            '.dockerconfigjson Auth': r'"auths"\s*:\s*\{',
            '.dockercfg Auth': r'\"auth\":\s*\"[A-Za-z0-9+/=]+\"',
            '.aws Credentials': r'\[default\]\s*aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}',
            '.azure Credentials': r'AccountKey=[A-Za-z0-9+/=]{88}',
            '.gcloud Credentials': r'"private_key_id":\s*"[a-f0-9]{40}"',
            '.netrc Machine': r'machine\s+[a-zA-Z0-9.\-]+\s+login\s+[a-zA-Z0-9._-]+\s+password\s+[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:\'\",.<>/?]+',
            '.pgpass': r'^[^:]+:[0-9]+:[^:]+:[^:]+:[^\s]+$',
            '.my.cnf Password': r'password\s*=\s*[^\s]+',
            '.s3cfg Access Key': r'access_key\s*=\s*AKIA[0-9A-Z]{16}',
            '.boto Credentials': r'aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}',
            '.git-credentials': r'https?://[^:]+:[^@]+@[a-zA-Z0-9.-]+',
            '.gitconfig User': r'name\s*=\s*[^\n]+',
            '.ssh Config Host': r'Host\s+[^\n]+',
            '.bash_history Command': r'\b(passwd|ssh|mysql|psql|su|sudo|ftp|scp|curl|wget|openssl|gpg|docker|kubectl|aws|gcloud|az)\b',
            '.zsh_history Command': r'\b(passwd|ssh|mysql|psql|su|sudo|ftp|scp|curl|wget|openssl|gpg|docker|kubectl|aws|gcloud|az)\b',
        }

        # Pre-compile all regex patterns for speed
        self.compiled_patterns = {}
        for group in [self.critical_patterns, self.api_patterns, self.auth_patterns, self.secret_patterns, self.identifier_patterns, self.extra_patterns, self.database_connections, self.cloud_config, self.financial, self.personal_id, self.password_secret, self.config_env]:
            for k, v in group.items():
                try:
                    self.compiled_patterns[k] = re.compile(v, re.MULTILINE | re.IGNORECASE)
                except Exception:
                    pass

        # Pre-compile comprehensive false positive patterns for is_likely_false_positive
        self.false_positive_patterns = [
            # URLs and common web assets (ALWAYS filtered)
            r'^https?://', r'/assets/', r'/images/', r'/css/', r'/js/', r'/static/', r'/public/',
            r'wp-content', r'wp-includes',
            # Obvious media/font/binary extensions (ALWAYS filtered)
            r'\.jpg$', r'\.jpeg$', r'\.png$', r'\.gif$', r'\.ico$', r'\.svg$', r'\.mp3$', r'\.mp4$', r'\.woff$', r'\.woff2$', r'\.ttf$', r'\.eot$', r'\.zip$', r'\.tar$', r'\.gz$', r'\.rar$', r'\.7z$', r'\.exe$', r'\.dll$', r'\.bin$', r'\.so$', r'\.dylib$', r'\.apk$', r'\.ipa$', r'\.deb$', r'\.rpm$',
            # The rest (filtered only for non-critical files)
            r'\.css$', r'\.js$', r'\.json$', r'\.xml$', r'\.csv$', r'\.md$', r'\.txt$', r'\.pdf$', r'\.docx$', r'\.xlsx$', r'\.pptx$',
            r'\.bak$', r'\.tmp$', r'\.swp$', r'\.old$', r'\.sample$', r'\.test$', r'\.spec$', r'\.example$', r'\.template$', r'\.dist$', r'\.crt$', r'\.cer$', r'\.pem$', r'\.pub$', r'\.key$', r'\.csr$', r'\.pfx$', r'\.p12$', r'\.der$', r'\.jks$', r'\.keystore$', r'\.asc$', r'\.gpg$', r'\.pgp$',
            r'node_modules/',
            # Common code keywords and blocks
            r'\bfunction\b', r'\bclass\b', r'\bdef\b', r'\bimport\b', r'\bfrom\b', r'\breturn\b', r'\{.*\}', r'\[.*\]', r'\(.*\)', r'console\.log', r'System\.out', r'print\(', r'echo ',
            # Dummy/sample/test keys
            r'test', r'dummy', r'sample', r'example', r'your_', r'changeme', r'notasecret', r'12345', r'abcdef',
            # Common config/system paths
            r'/etc/', r'/usr/', r'/var/', r'/opt/', r'/home/', r'/tmp/', r'/dev/',
            # Public key block
            r'^ssh-rsa ', r'^ssh-ed25519 ', r'^ecdsa-sha2-nistp256 ',
            # Common data formats
            r'\b[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}\b',  # email
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',        # IPv4
            r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', # UUID
            r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b', # MAC
            # Hashes and encodings
            r'\b[a-f0-9]{32}\b',         # md5
            r'\b[a-f0-9]{40}\b',         # sha1
            r'\b[a-f0-9]{64}\b',         # sha256
            r'\b[a-f0-9]{128}\b',        # sha512
            r'^[A-Za-z0-9+/=]{40,}$',      # base64/hex long string
        ]
        # Partition patterns: always filter vs. only non-critical
        self.always_fp_patterns = self.false_positive_patterns[:16]  # URLs, media, font, binary, wp-content, etc.
        self.noncritical_fp_patterns = self.false_positive_patterns[16:]
        self.compiled_always_fp_patterns = [re.compile(p, re.IGNORECASE) for p in self.always_fp_patterns]
        self.compiled_noncritical_fp_patterns = [re.compile(p, re.IGNORECASE) for p in self.noncritical_fp_patterns]

    def get_random_user_agent(self):
        """
        Returns a random modern User-Agent string for browsers, bots, and mobile devices.
        """
        user_agents = [
            # Modern browsers
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
            # Mobile browsers
            'Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
            # Bots & crawlers
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)',
            'DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)',
            'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
            # Headless
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/123.0.0.0 Safari/537.36',
            # Others
            'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
            'TelegramBot (like TwitterBot)',
            'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
        ]
        return random.choice(user_agents)

    def calculate_severity(self, finding: Dict[str, str]) -> str:
        """
        Calculate the severity of a finding (critical, high, medium, low).
        """
        # Default severity is medium
        severity = "medium"
        
        # Critical patterns get critical severity
        critical_types = [
            "SSH Private Key", "DSA Private Key", "EC Private Key", "PGP Private Key",
            "AWS Access Key", "AWS Secret Key", "Google Private Key Block",
            "Firebase API Key", "Google OAuth Access Token", "Google API Key"
        ]
        
        # High severity types
        high_types = [
            "JWT Token", "Bearer Token", "Password/Secret", "Hardcoded Secret", 
            "Stripe Publishable Key", "Twilio Account SID", "Twilio Auth Token",
            "GitHub Token", "GitLab Token", "API Key/Token"
        ]
        
        # Low severity types
        low_types = [
            "Email", "URL", "IP Address", "UUID", "Google Analytics ID",
            "Session Cookie", "Set-Cookie"
        ]
        
        # Determine severity based on type
        if finding.get('priority') == 'critical' or any(t in finding['type'] for t in critical_types):
            severity = "critical"
        elif any(t in finding['type'] for t in high_types):
            severity = "high"
        elif any(t in finding['type'] for t in low_types):
            severity = "low"
            
        return severity
    
    def is_likely_false_positive(self, finding: Dict[str, str]) -> bool:
        """
        Less aggressive false positive filtering for critical files/fields.
        Also applies special logic for certain types (UUID, hash, email, IP, MAC, etc).
        """
        value = finding['value'].lower()
        ftype = finding.get('type', '').lower()
        is_critical = finding.get('priority') == 'critical'
        # Always filter these patterns
        for pattern in getattr(self, 'compiled_always_fp_patterns', []):
            if pattern.search(value):
                return True
        # Only filter these if not critical
        if not is_critical:
            for pattern in getattr(self, 'compiled_noncritical_fp_patterns', []):
                if pattern.search(value):
                    return True
            # Heuristic: very short or very long values
            if len(value) < 8 or len(value) > 256:
                return True
            # Heuristic: common dummy/test types
            dummy_types = ['test', 'dummy', 'sample', 'example', 'changeme', 'notasecret']
            if any(dt in value for dt in dummy_types):
                return True
            # Heuristic: very common types
            common_types = ['url', 'path', 'filename', 'file', 'dir', 'directory', 'domain', 'email', 'ip', 'uuid', 'mac', 'hash']
            if any(ct in ftype for ct in common_types):
                return True
        # UUID: filter if part of a file path or URL, or surrounded by typical id field names
        if finding.get('type', '').upper() == 'UUID':
            if '/' in value or '.' in value:
                return True
            # Check if UUID is surrounded by typical ID field names
            # (Assume finding has 'start' and 'end' for context, else skip)
            if 'start' in finding and 'end' in finding and 'source' in finding:
                try:
                    with open(finding['source'], 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        surrounding = content[max(0, finding['start']-20):finding['end']+20].lower()
                        id_fields = ['style', 'class', 'div', 'span', 'image', 'img', 'src', 'id', 'data-id']
                        if any(idf in surrounding for idf in id_fields):
                            return True
                except Exception:
                    pass
        # Hashes: filter if type is hash and value is in a known hash field or path
        if ftype in ['md5', 'sha1', 'sha256', 'sha512', 'hash']:
            if '/' in value or '.' in value:
                return True
        # Email: filter if value is part of a path or url
        if ftype == 'email':
            if '/' in value or ':' in value:
                return True
        # IP: filter if value is in a url or path
        if ftype == 'ip':
            if '/' in value or ':' in value:
                return True
        # MAC: filter if value is in a url or path
        if ftype == 'mac':
            if '/' in value or ':' in value:
                return True
        return False

    def scan_text(self, text: str, file_path: str = None, exclusion_patterns: List[str] = None) -> List[Dict[str, str]]:
        """
        Scan text for sensitive information using all patterns.
        Returns a list of dictionaries containing the type of secret and the matched value.
        If file_path is provided, checks for hidden/critical file or directory.
        If exclusion_patterns is provided, skips findings matching these patterns.
        """
        findings = []
        # Combine all patterns into one dictionary
        all_patterns = { **self.critical_patterns, **self.api_patterns, **self.auth_patterns, **self.secret_patterns, **self.identifier_patterns, **self.extra_patterns, **self.database_connections, **self.cloud_config, **self.financial, **self.personal_id, **self.password_secret, **self.config_env }
        # Use pre-compiled patterns for speed
        compiled_patterns = getattr(self, 'compiled_patterns', None)
        # Hidden/critical file or directory keywords
        critical_keywords = ['.env', '.aws', '.ssh', '.git', '.docker', '.config', '.credentials', '.vault', '.secrets', 'id_rsa', 'id_dsa', 'id_ed25519', 'private_key', 'service-account', 'firebase.json', 'settings.json', 'local.settings.json']
        is_critical_file = False
        if file_path:
            lower_path = file_path.lower()
            if any(x in lower_path for x in critical_keywords):
                is_critical_file = True
                
        # Compile exclusion patterns if provided
        compiled_exclusions = []
        if exclusion_patterns:
            for pattern in exclusion_patterns:
                try:
                    compiled_exclusions.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    print(f"Warning: Invalid exclusion pattern: {pattern}")
                    
        for secret_type, pattern in all_patterns.items():
            regex = compiled_patterns[secret_type] if compiled_patterns and secret_type in compiled_patterns else re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            matches = regex.finditer(text)
            for match in matches:
                finding = {
                    'type': secret_type,
                    'value': match.group(0),
                    'start': match.start(),
                    'end': match.end()
                }
                if is_critical_file:
                    finding['priority'] = 'critical'
                    finding['source'] = file_path
                    
                # Check if finding matches any exclusion pattern
                should_exclude = False
                if compiled_exclusions:
                    for exclusion in compiled_exclusions:
                        if exclusion.search(finding['value']):
                            should_exclude = True
                            break
                            
                if not should_exclude and not self.is_likely_false_positive(finding):
                    # Add severity rating
                    finding['severity'] = self.calculate_severity(finding)
                    findings.append(finding)

        return findings

    def scan_file(self, file_path: str, verbose: bool = False, exclusion_patterns: List[str] = None) -> List[Dict[str, str]]:
        """
        Scan a file for sensitive information.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                lines = content.split('\n')
                # Check if file contains URLs (one per line)
                urls = []
                for line in lines:
                    line = line.strip()
                    if line.startswith(('http://', 'https://')):
                        urls.append(line)
                # If file contains URLs, scan each URL
                if urls:
                    print(f"\nFound {len(urls)} URLs in file")
                    findings = []
                    session = requests.Session()
                    session.verify = False
                    session.headers.update({
                        'User-Agent': self.get_random_user_agent(),
                        'Accept': '*/*'
                    })
                    with tqdm(total=len(urls), desc="Scanning URLs", unit="url") as pbar:
                        for url in urls:
                            try:
                                response = session.get(url, timeout=10)
                                if response.status_code == 200:
                                    content_type = response.headers.get('content-type', '').lower()
                                    if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                                        temp_findings = self.scan_text(response.text, exclusion_patterns=["example"], file_path=file_path)
                                        for finding in temp_findings:
                                            finding['url'] = url
                                            findings.append(finding)
                                            if verbose:
                                                tqdm.write(f"\nFound in {url}:")
                                                tqdm.write(f"Type: {finding['type']}")
                                                tqdm.write(f"Value: {finding['value']}")
                                                tqdm.write(f"Position: {finding['start']}-{finding['end']}")
                                                tqdm.write("-" * 40)
                            except Exception as e:
                                tqdm.write(f"Error scanning {url}: {str(e)}")
                            pbar.update(1)
                    return findings
                # If not a URL file, scan the content directly
                else:
                    print("\nScanning file content...")
                    findings = self.scan_text(content, file_path=file_path, exclusion_patterns=exclusion_patterns)
                    if verbose and findings:
                        print("\nFindings while scanning:")
                        print("-" * 40)
                        for finding in findings:
                            print(f"Type: {finding['type']}")
                            print(f"Value: {finding['value']}")
                            print(f"Position: {finding['start']}-{finding['end']}")
                            if finding.get('priority') == 'critical':
                                print("!!! CRITICAL SECRET (from hidden/config file) !!!")
                            print("-" * 40)
                    return findings
        except Exception as e:
            print(f"\nError scanning file {file_path}: {str(e)}")
            return []

    def scan_directory(self, directory_path: str, verbose: bool = False, exclusion_patterns: List[str] = None, max_workers: int = 10) -> List[Dict[str, str]]:
        """
        Scan all files in a directory (recursively) for secrets.
        """
        findings = []
        directory = Path(directory_path)
        if not directory.is_dir():
            print(f"\nError: {directory_path} is not a directory.")
            return []
            
        # Get list of files to scan
        files_to_scan = []
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                # Skip binary files and large files for performance
                try:
                    if file_path.stat().st_size > 10 * 1024 * 1024:  # Skip files > 10MB
                        continue
                    # Check if it's likely a binary file by extension
                    if file_path.suffix.lower() in ['.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
                                                  '.mp4', '.webm', '.mp3', '.wav', '.avi', '.mov',
                                                  '.zip', '.tar', '.gz', '.rar', '.7z',
                                                  '.woff', '.woff2', '.ttf', '.eot', '.exe', '.dll',
                                                  '.so', '.dylib', '.bin', '.dat', '.pyc', '.pyo']:
                        continue
                    files_to_scan.append(str(file_path))
                except Exception:
                    continue
                    
        # Scan files in parallel for better performance
        with tqdm(total=len(files_to_scan), desc="Scanning files", unit="file") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                def scan_single_file(file_path):
                    try:
                        file_findings = self.scan_file(file_path, verbose=verbose, exclusion_patterns=exclusion_patterns)
                        for finding in file_findings:
                            finding['file'] = file_path
                        pbar.update(1)
                        return file_findings
                    except Exception as e:
                        if verbose:
                            tqdm.write(f"Error scanning {file_path}: {str(e)}")
                        pbar.update(1)
                        return []
                
                # Submit all file scanning tasks
                future_to_file = {executor.submit(scan_single_file, file_path): file_path for file_path in files_to_scan}
                
                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_file):
                    file_findings = future.result()
                    findings.extend(file_findings)
        print(f"\nScanned {directory_path}, found {len(findings)} potential secrets.")
        return findings

    def scan_git_history(self, repo_path: str, verbose: bool = False) -> List[Dict[str, str]]:
        """
        Scan git commit history for secrets by analyzing added/removed lines.
        """
        findings = []
        repo = Path(repo_path)
        if not (repo / '.git').exists():
            print(f"\nError: {repo_path} is not a git repository.")
            return []
        try:
            # Get all commit hashes (oldest to newest)
            result = subprocess.run([
                'git', '-C', str(repo_path), 'rev-list', '--reverse', '--all'
            ], capture_output=True, text=True)
            commit_hashes = result.stdout.strip().split('\n')
            print(f"\nFound {len(commit_hashes)} commits in git history.")
            for commit in tqdm(commit_hashes, desc="Scanning git commits", unit="commit"):
                # Get the diff for this commit (added lines only)
                diff_result = subprocess.run([
                    'git', '-C', str(repo_path), 'show', commit, '--unified=0', '--pretty=format:', '--no-color'
                ], capture_output=True, text=True)
                diff_lines = diff_result.stdout.split('\n')
                for line in diff_lines:
                    # Only look at added lines
                    if line.startswith('+') and not line.startswith('+++'):
                        secrets = self.scan_text(line)
                        for finding in secrets:
                            finding['commit'] = commit
                            finding['line'] = line[1:].strip()
                        findings.extend(secrets)
            print(f"\nScanned git history, found {len(findings)} potential secrets.")
        except Exception as e:
            print(f"\nError scanning git history: {str(e)}")
        return findings

    def extract_subdomains(self, url: str, html_content: str, base_domain: str) -> set:
        """
        Extract subdomains of the base domain from HTML content.
        """
        subdomains = set()
        try:
            # Find all URLs in the HTML
            urls = re.findall(r'https?://([\w.-]+)', html_content)
            for found in urls:
                if found.endswith(base_domain) and found != base_domain:
                    subdomains.add(found)
        except Exception:
            pass
        return subdomains

    def scan_website(self, domain: str, max_pages: int = 100, verbose: bool = False, max_workers: int = 10, autosave_callback=None, rate_limit: float = 0.0, exclusion_patterns: List[str] = None) -> List[Dict[str, str]]:
        """
        Scan a website for sensitive information with progress tracking.
        WARNING: This crawler does NOT respect robots.txt, canonical, noindex, or any SEO/crawling restrictions. It will aggressively crawl all discovered URLs and subdomains.
        SSL warnings and errors are always bypassed (verify=False).
        """
        findings = []
        findings_hash_set = set()  # To track unique findings
        urls_to_scan = []
        scanned_urls = set()
        queued_urls = set()  # To track URLs already in the queue
        discovered_subdomains = set()
        session = requests.Session()
        session.verify = False  # Ignore SSL errors
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': '*/*'
        })
        base_domain = domain.lower()
        verbose_lock = threading.Lock()
        def normalize_url(url: str) -> str:
            try:
                parsed = urlparse(url)
                url = url.split('#')[0].rstrip('/')
                netloc = parsed.netloc.lower()
                if ':80' in netloc and parsed.scheme == 'http':
                    netloc = netloc.replace(':80', '')
                if ':443' in netloc and parsed.scheme == 'https':
                    netloc = netloc.replace(':443', '')
                if netloc.startswith('www.'):
                    netloc = netloc[4:]
                query = parsed.query
                if query:
                    params = sorted(query.split('&'))
                    query = '&'.join(params)
                base = f"{parsed.scheme}://{netloc}{parsed.path}"
                return f"{base}?{query}" if query else base
            except:
                return url
        def create_finding_hash(finding: Dict[str, str]) -> str:
            return f"{finding['type']}:{finding['value']}:{finding.get('url', '')}"
        def is_valid_url(url: str) -> bool:
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    print(f"[is_valid_url] Rejected (no scheme/netloc): {url}")
                    return False
                
                # Domain matching
                site_domain = base_domain
                url_domain = parsed.netloc.lower().split(':')[0]  # Remove port if present
                
                # Check domain match including subdomains
                domain_match = (
                    url_domain == site_domain or
                    url_domain.endswith(f".{site_domain}") or
                    site_domain in url_domain
                )
                
                # Only exclude binary and font files
                excluded_extensions = {
                    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
                    '.mp4', '.webm', '.mp3', '.wav', '.avi', '.mov',
                    '.zip', '.tar', '.gz', '.rar', '.7z',
                    '.woff', '.woff2', '.ttf', '.eot', '.exe', '.dll',
                    '.so', '.dylib', '.bin', '.dat', '.pyc', '.pyo'
                }
                
                path = parsed.path.lower()
                for ext in excluded_extensions:
                    if path.endswith(ext):
                        print(f"[is_valid_url] Rejected (excluded extension {ext}): {url}")
                        return False
                valid = (
                    domain_match and
                    parsed.scheme in ['http', 'https'] and
                    not any(path.endswith(ext) for ext in excluded_extensions)
                )
                if valid:
                    print(f"[is_valid_url] Accepted: {url}")
                return valid
            except Exception as e:
                print(f"[is_valid_url] Exception for {url}: {e}")
                return False

        def extract_urls(url: str, html_content: str) -> set:
            urls = set()
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Extract URLs
                for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe']):
                    for attr in ['href', 'src', 'action', 'data-url']:
                        link = tag.get(attr)
                        if link:
                            try:
                                absolute_url = urljoin(url, link)
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls] Found: {link} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls] Exception for {link}: {e}")
                                continue
                
                # Extract URLs from onclick attributes
                elements_with_onclick = soup.find_all(attrs={"onclick": True})
                for element in elements_with_onclick:
                    onclick = element.get('onclick', '')
                    matches = re.findall(r'["\']((https?://|/)[^"\']+)["\']', onclick)
                    for match in matches:
                        try:
                            absolute_url = urljoin(url, match[0])
                            normalized_url = normalize_url(absolute_url)
                            print(f"[extract_urls][onclick] Found: {match[0]} -> {normalized_url}")
                            if is_valid_url(normalized_url):
                                urls.add(normalized_url)
                                print(f"[extract_urls][onclick] Added: {normalized_url}")
                        except Exception as e:
                            print(f"[extract_urls][onclick] Exception for {match[0]}: {e}")
                            continue
                
                # Extract URLs from inline JavaScript
                for script in soup.find_all('script'):
                    if script.string:
                        matches = re.findall(r'["\']((https?://|/)[^"\']+)["\']', script.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match[0])
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls][script] Found: {match[0]} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls][script] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls][script] Exception for {match[0]}: {e}")
                                continue
                
                # Extract URLs from CSS
                for style in soup.find_all('style'):
                    if style.string:
                        matches = re.findall(r'url\(["\']?([^)"]+)["\']?\)', style.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match)
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls][style] Found: {match} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls][style] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls][style] Exception for {match}: {e}")
                                continue
            except Exception:
                pass
            return urls

        def scan_single_url(url):
            page_findings = []
            new_urls = set()
            normalized_url = normalize_url(url)
            
            try:
                response = session.get(url, timeout=15, allow_redirects=True)
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Process text-based content
                    if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                        content = response.text
                        temp_findings = self.scan_text(content, exclusion_patterns=["example"], file_path=normalized_url)

                        
                        # Add URL and deduplicate findings
                        for finding in temp_findings:
                            finding['url'] = normalized_url
                            finding_hash = create_finding_hash(finding)
                            if finding_hash not in findings_hash_set:
                                findings_hash_set.add(finding_hash)
                                page_findings.append(finding)
                                if verbose:
                                    with verbose_lock:
                                        tqdm.write(f"\nFound in {normalized_url}:")
                                        tqdm.write(f"Type: {finding['type']}")
                                        tqdm.write(f"Value: {finding['value']}")
                                        tqdm.write(f"Position: {finding['start']}-{finding['end']}")
                                        tqdm.write("-" * 40)
                        
                        # Extract new URLs from HTML content
                        if 'text/html' in content_type:
                            new_urls = extract_urls(url, content)
                
            except Exception as e:
                tqdm.write(f"\nError scanning {url}: {str(e)}")
            
            return url, page_findings, new_urls

        print(f"\nInitializing scan of {domain} (with subdomain support, parallel mode {max_workers} threads)...")
        start_urls = [
            f"https://{domain}",
            f"http://{domain}",
        ]
        for url in start_urls:
            if is_valid_url(url):
                urls_to_scan.append(url)
                queued_urls.add(url)
        with tqdm(total=max_pages, desc="Scanning URLs", ncols=100) as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                while urls_to_scan and len(scanned_urls) < max_pages:
                    batch = []
                    while urls_to_scan and len(batch) < max_workers and len(scanned_urls) + len(batch) < max_pages:
                        url = urls_to_scan.pop(0)
                        normalized_url = normalize_url(url)
                        if normalized_url not in scanned_urls:
                            batch.append(url)
                    if not batch:
                        break
                    future_to_url = {executor.submit(scan_single_url, url): url for url in batch}
                    for future in concurrent.futures.as_completed(future_to_url):
                        url, page_findings, new_urls = future.result()
                        normalized_current = normalize_url(url)
                        findings.extend(page_findings)
                        scanned_urls.add(normalized_current)
                        pbar.update(1)
                        for url in new_urls:
                            normalized_url = normalize_url(url)
                            if normalized_url not in scanned_urls and normalized_url not in queued_urls:
                                urls_to_scan.append(normalized_url)
                                queued_urls.add(normalized_url)
                        # Apply rate limiting if specified
                        if rate_limit > 0:
                            time.sleep(rate_limit)
                        else:
                            time.sleep(0.05)
                        # Call autosave callback if provided
                        if autosave_callback and callable(autosave_callback):
                            autosave_callback(findings)
        print(f"\nScan completed. Scanned {len(scanned_urls)} unique pages (including subdomains, parallel mode).")
        if findings:
            print(f"\nTotal findings: {len(findings)} (unique)")
        return findings

    def scan_website_crawler(self, domain: str, max_pages: int = 100, max_depth: int = 3, verbose: bool = False, autosave_callback=None, rate_limit: float = 0.0, exclusion_patterns: List[str] = None) -> List[Dict[str, str]]:
        """
        Deep recursive crawler for website secret scanning (respects max_pages and max_depth).
        WARNING: This crawler does NOT respect robots.txt, canonical, noindex, or any SEO/crawling restrictions. It will aggressively crawl all discovered URLs and subdomains.
        SSL warnings and errors are always bypassed (verify=False).
        """
        # This crawler intentionally ignores robots.txt, canonical, noindex, and any form of crawling restrictions.
        findings = []
        findings_hash_set = set()
        urls_to_scan = []
        scanned_urls = set()
        queued_urls = set()
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': '*/*'
        })
        # Crawler ignores robots.txt, canonical, noindex, etc. by design (no check implemented)

        def normalize_url(url: str) -> str:
            try:
                parsed = urlparse(url)
                url = url.split('#')[0].rstrip('/')
                netloc = parsed.netloc.lower()
                if ':80' in netloc and parsed.scheme == 'http':
                    netloc = netloc.replace(':80', '')
                if ':443' in netloc and parsed.scheme == 'https':
                    netloc = netloc.replace(':443', '')
                if netloc.startswith('www.'):
                    netloc = netloc[4:]
                query = parsed.query
                if query:
                    params = sorted(query.split('&'))
                    query = '&'.join(params)
                base = f"{parsed.scheme}://{netloc}{parsed.path}"
                return f"{base}?{query}" if query else base
            except:
                return url

        def create_finding_hash(finding: Dict[str, str]) -> str:
            return f"{finding['type']}:{finding['value']}:{finding.get('url', '')}"

        def is_valid_url(url: str) -> bool:
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    print(f"[is_valid_url] Rejected (no scheme/netloc): {url}")
                    return False
                
                # Domain matching
                site_domain = domain.lower()
                url_domain = parsed.netloc.lower().split(':')[0]  # Remove port if present
                
                # Check domain match including subdomains
                domain_match = (
                    url_domain == site_domain or
                    url_domain.endswith(f".{site_domain}") or
                    site_domain in url_domain
                )
                
                # Only exclude binary and font files
                excluded_extensions = {
                    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
                    '.mp4', '.webm', '.mp3', '.wav', '.avi', '.mov',
                    '.zip', '.tar', '.gz', '.rar', '.7z',
                    '.woff', '.woff2', '.ttf', '.eot'
                }
                
                path = parsed.path.lower()
                for ext in excluded_extensions:
                    if path.endswith(ext):
                        print(f"[is_valid_url] Rejected (excluded extension {ext}): {url}")
                        return False
                valid = (
                    domain_match and
                    parsed.scheme in ['http', 'https'] and
                    not any(path.endswith(ext) for ext in excluded_extensions)
                )
                if valid:
                    print(f"[is_valid_url] Accepted: {url}")
                return valid
            except Exception as e:
                print(f"[is_valid_url] Exception for {url}: {e}")
                return False

        def scan_page(url: str, depth: int) -> tuple[List[Dict[str, str]], Set[str]]:
            page_findings = []
            new_urls = set()
            normalized_url = normalize_url(url)
            
            try:
                response = session.get(url, timeout=15, allow_redirects=True)
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Process text-based content
                    if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                        content = response.text
                        temp_findings = self.scan_text(content, exclusion_patterns=exclusion_patterns)
                        
                        # Add URL and deduplicate findings
                        for finding in temp_findings:
                            finding['url'] = normalized_url
                            finding_hash = create_finding_hash(finding)
                            if finding_hash not in findings_hash_set:
                                findings_hash_set.add(finding_hash)
                                page_findings.append(finding)
                                if verbose:
                                    tqdm.write(f"\nFound in {normalized_url}:")
                                    tqdm.write(f"Type: {finding['type']}")
                                    tqdm.write(f"Value: {finding['value']}")
                                    tqdm.write(f"Position: {finding['start']}-{finding['end']}")
                                    tqdm.write("-" * 40)
                        
                        # Extract new URLs from HTML content
                        if 'text/html' in content_type and depth < max_depth:
                            new_urls = extract_urls(url, content)
                
            except Exception as e:
                tqdm.write(f"\nError scanning {url}: {str(e)}")
            
            return page_findings, new_urls

        # Initialize scan with different URL variations
        print(f"\nInitializing crawler scan of {domain} (max_depth={max_depth})...")
        start_urls = [
            f"https://{domain}",
            f"http://{domain}",
        ]
        
        # Find working URL
        for url in start_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    normalized_url = normalize_url(url)
                    if normalized_url not in queued_urls:
                        urls_to_scan.append((normalized_url, 0))
                        queued_urls.add(normalized_url)
                    break
            except:
                continue
        
        if not urls_to_scan:
            print(f"\nError: Could not connect to {domain}")
            return []

        # Main scanning loop with progress bar
        with tqdm(total=max_pages, desc="Scanning pages", unit="page") as pbar:
            while urls_to_scan and len(scanned_urls) < max_pages:
                # Get next URL to scan
                current_url, current_depth = urls_to_scan.pop(0)
                normalized_current = normalize_url(current_url)
                
                if normalized_current in scanned_urls or current_depth > max_depth:
                    continue
                
                # Scan the page
                print(f"\rCrawling: {current_url} (depth={current_depth})", end='', flush=True)
                page_findings, new_urls = scan_page(current_url, current_depth)
                
                # Process results
                findings.extend(page_findings)
                scanned_urls.add(normalized_current)
                pbar.update(1)
                
                # Add new URLs to scan
                for url in new_urls:
                    normalized_url = normalize_url(url)
                    if normalized_url not in scanned_urls and normalized_url not in queued_urls:
                        urls_to_scan.append((url, current_depth + 1))
                        queued_urls.add(normalized_url)
                        print(f"[queue] Queued: {normalized_url} (depth={current_depth + 1})")
                # Apply rate limiting if specified
                if rate_limit > 0:
                    time.sleep(rate_limit)
                else:
                    time.sleep(0.1)
                # Call autosave callback if provided
                if autosave_callback and callable(autosave_callback):
                    autosave_callback(findings)

        print(f"\nCrawler scan completed. Scanned {len(scanned_urls)} unique pages.")
        if findings:
            print(f"\nTotal findings: {len(findings)} (unique)")
        return findings

    def save_findings_to_file(self, findings: List[Dict[str, str]], output_file: str, format_type="text"):
        """Save findings to a file (text or JSON format)"""
        try:
            # Calculate scan stats
            self.stats["total_findings"] = len(findings)
            self.stats["end_time"] = time.time()
            self.stats["scan_duration"] = self.stats["end_time"] - self.stats["start_time"]
            
            # Add severity to findings if not already present
            for finding in findings:
                if 'severity' not in finding:
                    finding['severity'] = self.calculate_severity(finding)
            
            # Save in JSON format
            if format_type.lower() == "json":
                output_data = {
                    "scan_stats": {
                        "total_findings": len(findings),
                        "scan_duration_seconds": round(self.stats["scan_duration"], 2),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    },
                    "findings": []
                }
                
                # Group findings by URL
                findings_by_url = {}
                for finding in findings:
                    url = finding.get('url', finding.get('file', 'Unknown Source'))
                    if url not in findings_by_url:
                        findings_by_url[url] = []
                    # Clean up finding for JSON output
                    clean_finding = {
                        "type": finding["type"],
                        "value": finding["value"],
                        "severity": finding.get("severity", "medium"),
                        "position": f"{finding['start']}-{finding['end']}"
                    }
                    # Add optional fields if present
                    if "url" in finding:
                        clean_finding["url"] = finding["url"]
                    if "file" in finding:
                        clean_finding["file"] = finding["file"]
                    if "commit" in finding:
                        clean_finding["commit"] = finding["commit"]
                    if "line" in finding:
                        clean_finding["line"] = finding["line"]
                    findings_by_url[url].append(clean_finding)
                
                # Add to output data
                for url, url_findings in findings_by_url.items():
                    output_data["findings"].append({
                        "source": url,
                        "findings": url_findings
                    })
                
                with open(output_file, 'w') as f:
                    json.dump(output_data, f, indent=2)
            
            # Save in text format (default)
            else:
                with open(output_file, 'w') as f:
                    f.write(f"Secret Detection Results\n")
                    f.write(f"=====================\n\n")
                    f.write(f"Total findings: {len(findings)}\n")
                    f.write(f"Scan duration: {round(self.stats['scan_duration'], 2)} seconds\n\n")
                    
                    findings_by_url = {}
                    for finding in findings:
                        url = finding.get('url', finding.get('file', 'Unknown Source'))
                        if url not in findings_by_url:
                            findings_by_url[url] = []
                        findings_by_url[url].append(finding)
                    
                    # Count findings by severity
                    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    for finding in findings:
                        severity = finding.get("severity", "medium")
                        severity_counts[severity] += 1
                    
                    # Write severity summary
                    f.write(f"Severity summary:\n")
                    f.write(f"  Critical: {severity_counts['critical']}\n")
                    f.write(f"  High: {severity_counts['high']}\n")
                    f.write(f"  Medium: {severity_counts['medium']}\n")
                    f.write(f"  Low: {severity_counts['low']}\n\n")
                    
                    for url, url_findings in findings_by_url.items():
                        f.write(f"\nSource: {url}\n")
                        f.write("=" * (len(url) + 8) + "\n")
                        for finding in url_findings:
                            severity = finding.get("severity", "medium")
                            f.write(f"Type: {finding['type']} (Severity: {severity.upper()})\n")
                            f.write(f"Value: {finding['value']}\n")
                            f.write(f"Position: {finding['start']}-{finding['end']}\n")
                            f.write("-" * 50 + "\n")
            
            print(f"\nResults saved to: {output_file}")
        except Exception as e:
            print(f"\nError saving results to {output_file}: {str(e)}")

    def scan_url(self, url: str, verbose: bool = False) -> List[Dict[str, str]]:
        """
        Scan a single URL for sensitive information.
        """
        findings = []
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': '*/*'
        })

        try:
            print(f"\nScanning URL: {url}")
            response = session.get(url, timeout=15, allow_redirects=True)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                    content = response.text
                    findings = self.scan_text(content)
                    if verbose and findings:
                        print("\nFindings while scanning:")
                        print("-" * 40)
                        for finding in findings:
                            print(f"Type: {finding['type']}")
                            print(f"Value: {finding['value']}")
                            print(f"Position: {finding['start']}-{finding['end']}")
                            print("-" * 40)
                else:
                    print(f"\nWarning: Content type '{content_type}' not supported for scanning")
            else:
                print(f"\nError: Could not access URL (Status code: {response.status_code})")
                
        except Exception as e:
            print(f"\nError scanning URL: {str(e)}")
        
        return findings

def main():
    parser = argparse.ArgumentParser(
        description='''Secret Detector - A tool to find sensitive information in files, codebases, and websites.
        
This tool can detect various types of secrets including:
- API Keys (Google, AWS, Facebook, Twilio, etc.)
- Authentication Tokens
- Private Keys (RSA, DSA, EC, PGP)
- JWT Tokens
- Passwords and Secrets
- Email Addresses
- IP Addresses
- UUIDs''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    website_group = parser.add_argument_group('Website Scanning')
    website_group.add_argument(
        '--domain', '-d',
        help='Domain to scan (e.g., example.com)'
    )
    website_group.add_argument(
        '--all',
        action='store_true',
        help='Scan all pages of the website recursively'
    )
    website_group.add_argument(
        '--max-pages',
        type=int,
        default=100,
        help='Maximum number of pages to scan (default: 100)'
    )
    website_group.add_argument(
        '--list', '-l',
        help='Path to a file containing a list of domains to scan (one per line)'
    )
    website_group.add_argument(
        '--crawler',
        action='store_true',
        help='Enable deep recursive crawling (respects --max-pages and --depth)'
    )
    website_group.add_argument(
        '--depth',
        type=int,
        default=3,
        help='Maximum crawl depth for recursive website scanning (default: 3)'
    )
    website_group.add_argument(
        '--max-workers',
        type=int,
        default=10,
        help='Maximum number of threads for parallel scanning (default: 10)'
    )

    file_group = parser.add_argument_group('File Scanning')
    file_group.add_argument(
        '--file', '--scan-file',
        help='Path to a file to scan for secrets'
    )
    file_group.add_argument(
        '--scan-dir',
        help='Scan all files in a directory (recursively)'
    )
    file_group.add_argument(
        '--git-history',
        help='Scan git commit history for secrets (provide repository path)'
    )

    url_group = parser.add_argument_group('URL Scanning')
    url_group.add_argument(
        '--url', '-u',
        help='URL to scan (e.g., http://example.com/file.js)'
    )

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output', '-o',
        help='Save results to output file'
    )
    output_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show findings in real-time while scanning'
    )
    output_group.add_argument(
        '--autosave-interval',
        type=int,
        default=60,
        help='Interval in seconds to automatically save findings (default: 60)'
    )
    output_group.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (text or json)'
    )
    output_group.add_argument(
        '--exclude',
        action='append',
        help='Regex pattern to exclude from results (can be used multiple times)'
    )
    output_group.add_argument(
        '--rate-limit',
        type=float,
        default=0.0,
        help='Rate limit for website requests in seconds (e.g., 0.5 for 500ms delay between requests)'
    )
    
    performance_group = parser.add_argument_group('Performance Options')
    performance_group.add_argument(
        '--threads',
        type=int,
        default=20,
        help='Maximum number of worker threads for parallel processing (default: 20)'
    )
    performance_group.add_argument(
        '--max-file-size',
        type=int,
        default=10,
        help='Maximum file size in MB to scan (default: 10)'
    )
    performance_group.add_argument(
        '--optimize',
        action='store_true',
        help='Enable additional performance optimizations'
    )

    args = parser.parse_args()

    if not any([args.domain, args.file, args.url, args.list]):
        parser.print_help()
        sys.exit(1)

    detector = SecretDetector()
    detector.stats["start_time"] = time.time()
    findings = []
    last_save_time = time.time()
    output_file = args.output
    autosave_interval = args.autosave_interval
    output_format = args.format
    exclusion_patterns = args.exclude
    rate_limit = args.rate_limit

    def exit_handler():
        if findings and output_file:
            print("\nExiting. Saving any findings...")
            detector.save_findings_to_file(findings, output_file, format_type=output_format)
            print(f"Results saved to: {output_file}")
    
    def signal_handler(sig, frame):
        print("\nReceived interrupt signal. Saving findings before exit...")
        if findings and output_file:
            detector.save_findings_to_file(findings, output_file, format_type=output_format)
            print(f"Results saved to: {output_file}")
        sys.exit(0)
    
    # Register the handlers
    atexit.register(exit_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Function to save findings periodically and on exit
    def save_findings():
        if findings and output_file:
            print(f"\nSaving {len(findings)} findings to {output_file}...")
            detector.save_findings_to_file(findings, output_file, format_type=output_format)
            print(f"Results saved to: {output_file}")
    
    # Function to check if it's time to autosave
    def check_autosave():
        nonlocal last_save_time
        if output_file and findings and (time.time() - last_save_time) > min(autosave_interval, 30):  # Save at least every 30 seconds
            print(f"\nAuto-saving {len(findings)} findings...")
            detector.save_findings_to_file(findings, output_file, format_type=output_format)
            last_save_time = time.time()

    try:
        if args.scan_dir:
            # Measure scan time
            scan_start = time.time()
            print(f"\nStarting directory scan at {time.strftime('%H:%M:%S')}")
            
            findings = detector.scan_directory(
                args.scan_dir, 
                verbose=True, 
                exclusion_patterns=exclusion_patterns,
                max_workers=args.threads if hasattr(args, 'threads') else args.max_workers
            )
            
            scan_duration = time.time() - scan_start
            print(f"\nScan completed in {round(scan_duration, 2)} seconds")
            print(f"False positives filtered: {detector.stats.get('false_positives_filtered', 0)}")
        elif args.git_history:
            findings = detector.scan_git_history(args.git_history, verbose=True)
        elif args.file:
            findings = detector.scan_file(args.file, verbose=True)
        elif args.url:
            findings = detector.scan_url(args.url, verbose=True)
        elif args.list:
            list_file = args.list
            try:
                with open(list_file, 'r') as lf:
                    domains = [line.strip() for line in lf if line.strip() and not line.strip().startswith('#')]
                all_findings = []
                for domain in tqdm(domains, desc="Scanning domain list", unit="domain"):
                    print(f"\n--- Scanning domain: {domain} ---")
                    domain_findings = detector.scan_website(
                        domain,
                        max_pages=args.max_pages,
                        verbose=args.verbose,
                        max_workers=args.threads if hasattr(args, 'threads') else args.max_workers
                    )
                    for finding in domain_findings:
                        if 'url' not in finding:
                            finding['url'] = domain
                    all_findings.extend(domain_findings)
                    # Check if it's time to autosave
                    check_autosave()
                findings = all_findings
            except Exception as e:
                print(f"\nError reading domain list file: {str(e)}")
                save_findings()  # Save any findings we have before exiting
                sys.exit(1)
        elif args.domain:
            print(f"\nStarting scan of website: {args.domain}")
            # Create a threading event to signal when to save findings
            save_event = threading.Event()
            
            # Create a thread to periodically save findings
            def autosave_thread():
                nonlocal last_save_time
                while not save_event.is_set():
                    time.sleep(5)  # Check every 5 seconds
                    if output_file and findings:
                        current_time = time.time()
                        if (current_time - last_save_time) > min(autosave_interval, 30):  # Save at least every 30 seconds
                            print(f"\nAuto-saving {len(findings)} findings...")
                            try:
                                detector.save_findings_to_file(findings, output_file, format_type=output_format)
                                print(f"Results saved to: {output_file}")
                                last_save_time = current_time
                            except Exception as e:
                                print(f"Error during autosave: {e}")
            
            # Start the autosave thread if output file is specified
            if output_file:
                save_thread = threading.Thread(target=autosave_thread)
                save_thread.daemon = True
                save_thread.start()
            
            try:
                if args.crawler:
                    findings = detector.scan_website_crawler(
                        args.domain,
                        max_pages=args.max_pages,
                        max_depth=args.depth,
                        verbose=args.verbose,
                        rate_limit=rate_limit,
                        exclusion_patterns=exclusion_patterns
                    )
                else:
                    findings = detector.scan_website(
                        args.domain,
                        max_pages=args.max_pages,
                        verbose=args.verbose,
                        max_workers=args.threads if hasattr(args, 'threads') else args.max_workers,
                        rate_limit=rate_limit,
                        exclusion_patterns=exclusion_patterns
                    )
                
                # Stop the autosave thread
                if output_file:
                    save_event.set()
            except KeyboardInterrupt:
                print("\nScan interrupted by user.")
                # Stop the autosave thread
                if output_file:
                    save_event.set()
                save_findings()  # Save findings before exiting
                sys.exit(0)
        
        if findings:
            if output_file:
                save_findings()
            elif not args.verbose:
                findings_by_url = {}
                for finding in findings:
                    url = finding.get('url', 'Unknown URL')
                    if url not in findings_by_url:
                        findings_by_url[url] = []
                    findings_by_url[url].append(finding)
                
                print(f"\nFound {len(findings)} potential secrets:")
                print("-" * 50)
                
                for url, url_findings in findings_by_url.items():
                    print(f"\nURL: {url}")
                    for finding in url_findings:
                        print(f"Type: {finding['type']}")
                        print(f"Value: {finding['value']}")
                        print(f"Position: {finding['start']}-{finding['end']}")
                        print("-" * 40)
        else:
            print("\nNo secrets found.")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        save_findings()  # Save findings before exiting
        sys.exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        save_findings()  # Save findings before exiting
        sys.exit(1)

if __name__ == "__main__":
    main()