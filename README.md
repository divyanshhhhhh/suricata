# Suricata Rule Builder Dashboard

A comprehensive web-based interface for creating, editing, and managing Suricata IDS/IPS rules with advanced protocol-specific detection capabilities.

---

##  Quick Start

```bash
cd suricata-rule-builder
./start.sh
# Open http://localhost:5500 in your browser
```

That's it! The dashboard will be running and ready to use.

---

##  Features

### Core Functionality
- ✅ **Real-time Rule Preview** - See your rule as you build it
- ✅ **Dual Editing Modes** - Interactive form builder OR manual text editor
- ✅ **Syntax Validation** - Uses Suricata's built-in validator
- ✅ **Full CRUD Operations** - Create, read, update, delete rules
- ✅ **Service Control** - Reload Suricata directly from dashboard
- ✅ **Import/Export** - Backup and share rules as JSON
- ✅ **Auto SID Generation** - Automatically suggests next available ID
- ✅ **Comprehensive Help** - Built-in documentation and examples

### Rule Building Capabilities

#### Basic Components (All Protocols)
- **7 Actions**: alert, pass, drop, reject (+ variants)
- **11 Protocols**: tcp, udp, icmp, ip, http, dns, tls, ssh, ftp, smtp, smb
- **Network Configuration**: IP/Port with CIDR, variables, ranges, lists
- **Direction**: Unidirectional (→) or Bidirectional (↔)
- **Content Matching**: Multiple content fields with modifiers (nocase, offset, depth)
- **Flow Options**: established, to_server, to_client, from_server, from_client
- **35+ Classtypes**: web-application-attack, trojan-activity, policy-violation, etc.
- **Priority Levels**: 1 (high) to 4 (low)
- **Threshold Configuration**: Rate limiting with type, track, count, seconds
- **References**: CVE, URL, bugtraq, and other external references

#### Advanced Protocol-Specific Keywords

**HTTP Keywords** (14 total - appears when protocol=http)
- http.method, http.uri, http.user_agent, http.host
- http.cookie, http.referer, http.content_type, http.stat_code
- http.request_body, http.response_body, file.data

**TLS/SSL Keywords** (7 total - appears when protocol=tls)
- tls.version, tls.sni, tls.subject, tls.issuer
- tls.cert_fingerprint, ja3.hash, ja3s.hash

**DNS Keywords** (4 total - appears when protocol=dns)
- dns.query, dns.query.type, dns.answer, dns.opcode

### Smart UI Features
- **Protocol-Conditional Display**: Relevant sections appear automatically based on selected protocol
- **Collapsible Sections**: Click headers to expand/collapse for clean interface
- **Real-Time Updates**: Rule preview updates as you type
- **Keyboard Shortcuts**: Ctrl+S (save), Ctrl+Enter (validate), Esc (close modals)
- **Responsive Design**: Works on desktop, tablet, and mobile devices

---

## Requirements

- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Suricata IDS/IPS (optional - for full validation, falls back to basic validation if not available)

---

##  Installation

### Method 1: Quick Start (Recommended)
```bash
cd suricata-rule-builder
./start.sh
```

The script will:
- Create Python virtual environment
- Install dependencies
- Create custom.rules file
- Start the web server on port 5500

### Method 2: Manual Installation
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Method 3: Production Deployment
```bash
# Run the installation script
./install.sh

# Follow prompts to:
# - Install to /opt/suricata-rule-builder
# - Configure sudo permissions
# - Set up systemd service

# Start the service
sudo systemctl start suricata-builder
```

---

##  Usage Guide

### Creating Your First Rule

#### Step 1: Basic Configuration
1. **Action**: Select `alert` (or drop, pass, reject)
2. **Protocol**: Select `tcp` (or udp, http, dns, tls, etc.)
3. **Source IP**: Enter `any` or specific IP/network (e.g., 192.168.1.0/24, $HOME_NET)
4. **Source Port**: Enter `any` or specific port (e.g., 80, 1:1024, [80,443])
5. **Direction**: Select `->` (unidirectional) or `<>` (bidirectional)
6. **Destination IP**: Enter `any` or specific IP/network
7. **Destination Port**: Enter `any` or specific port

#### Step 2: Rule Options
1. **Message**: Enter descriptive text (e.g., "SQL Injection Attempt")
2. **SID**: Click "Get Next" for auto-generated ID (or enter manually ≥ 1000000)
3. **Revision**: Default is 1
4. **Classtype**: Select appropriate classification (e.g., web-application-attack)
5. **Priority**: Select 1 (high) to 4 (low)

#### Step 3: Content Matching (Optional)
1. Click "**+ Add Content Match**"
2. Enter content to detect (e.g., "union select")
3. Check modifiers:
   - **Case Insensitive**: Ignore case
   - **Offset**: Start position
   - **Depth**: Search depth
4. Add more content fields as needed

#### Step 4: Protocol-Specific Options (Advanced)

**For HTTP Rules** (when protocol=http):
1. Change **Protocol** to `http`
2. **HTTP Keywords** section appears below Content Matching
3. Click "**▶ HTTP Keywords**" to expand
4. Fill in fields:
   - **HTTP Method**: GET, POST, PUT, DELETE
   - **HTTP URI**: URL path to match (e.g., /admin, /api/users)
   - **User-Agent**: Browser or tool signature
   - **Host**: Hostname in Host header
   - **Cookie**: Cookie content to match
   - **Status Code**: HTTP response code (200, 404, 500)
5. Check buffer modifiers:
   - **Match in Request Body**: Search POST data
   - **Match in Response Body**: Search server responses
   - **Match in File Data**: Search file content

**For TLS Rules** (when protocol=tls):
1. Change **Protocol** to `tls`
2. **TLS/SSL Keywords** section appears
3. Click to expand and fill:
   - **TLS Version**: 1.0, 1.1, 1.2, 1.3, SSLv3
   - **SNI**: Server Name Indication hostname
   - **Certificate Subject**: CN, O, OU fields
   - **Certificate Issuer**: Issuing CA
   - **JA3 Hash**: Client fingerprint
   - **JA3S Hash**: Server fingerprint

**For DNS Rules** (when protocol=dns):
1. Change **Protocol** to `dns`
2. **DNS Keywords** section appears
3. Click to expand and fill:
   - **DNS Query**: Domain name to match
   - **Query Type**: A, AAAA, MX, TXT, CNAME, etc.
   - **DNS Answer**: Answer content
   - **Opcode**: Query, IQuery, Status, Notify, Update

#### Step 5: Flow Options (Optional)
Check applicable flow states:
- **Established Connection**
- **To Server** / **From Server**
- **To Client** / **From Client**

#### Step 6: Threshold Options (Optional)
Configure rate limiting:
- **Type**: limit, threshold, or both
- **Track By**: by_src, by_dst, or by_both
- **Count**: Number of events
- **Seconds**: Time period

#### Step 7: Validate and Save
1. Click "**✓ Check Syntax**" to validate
2. Review any errors and fix
3. Click "**💾 Save Rule**"
4. Rule appears in the table below

### Example Rules

**Example 1: Detect SQL Injection**
```
alert http any any -> any any (
    msg:"SQL Injection in Login Form";
    http.method; content:"POST";
    http.uri; content:"/login";
    http.request_body; content:"union select"; nocase;
    classtype:web-application-attack;
    priority:1;
    sid:1000001; rev:1;
)
```

**Example 2: Detect Outdated TLS**
```
alert tls any any -> any any (
    msg:"Deprecated TLS 1.0 Connection";
    tls.version:"1.0";
    flow:established;
    classtype:policy-violation;
    priority:2;
    sid:1000002; rev:1;
)
```

**Example 3: Detect DNS Tunneling**
```
alert dns any any -> any any (
    msg:"Possible DNS Tunneling - Excessive TXT Queries";
    dns.query.type:TXT;
    threshold:type threshold, track by_src, count 20, seconds 60;
    classtype:policy-violation;
    priority:1;
    sid:1000003; rev:1;
)
```

**Example 4: Detect Malware Download**
```
alert http any any -> any any (
    msg:"Malware Download - EXE File";
    http.uri; content:".exe";
    file.data; content:"MZ"; offset:0; depth:2;
    classtype:trojan-activity;
    priority:1;
    sid:1000004; rev:1;
)
```

---

##  Configuration

### Rules File Location
Default: `/etc/suricata/rules/custom.rules`
Fallback: `./custom.rules` (in application directory)

To change the rules file location, edit `app.py`:
```python
RULES_FILE = '/path/to/your/rules.rules'
```

### Server Port
Default: `5500`

To change, edit `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=8080)  # Change port here
```

### Suricata Service Reload
The application attempts to reload Suricata using (in order):
1. `sudo systemctl reload suricata`
2. `sudo service suricata reload`
3. `sudo killall -USR2 suricata`

**Configure sudo for password-less reload:**
```bash
sudo visudo
```

Add this line (replace `username`):
```
username ALL=(ALL) NOPASSWD: /bin/systemctl reload suricata, /usr/sbin/service suricata reload, /usr/bin/killall -USR2 suricata
```

---

##  API Endpoints

The application provides a RESTful API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main dashboard |
| GET | `/api/rules` | List all rules |
| POST | `/api/rules` | Save new rule |
| PUT | `/api/rules/<sid>` | Update rule by SID |
| DELETE | `/api/rules/<sid>` | Delete rule by SID |
| POST | `/api/validate` | Validate rule syntax |
| POST | `/api/reload` | Reload Suricata service |
| GET | `/api/next-sid` | Get next available SID |
| GET | `/api/export` | Export rules as JSON |
| POST | `/api/import` | Import rules from JSON |

### API Examples

**Get all rules:**
```bash
curl http://localhost:5500/api/rules
```

**Validate a rule:**
```bash
curl -X POST http://localhost:5500/api/validate \
  -H "Content-Type: application/json" \
  -d '{"rule": "alert tcp any any -> any 80 (msg:\"Test\"; sid:1000001; rev:1;)"}'
```

**Save a rule:**
```bash
curl -X POST http://localhost:5500/api/rules \
  -H "Content-Type: application/json" \
  -d '{"raw_rule": "alert tcp any any -> any 80 (msg:\"Test\"; sid:1000001; rev:1;)"}'
```

---

##  Rule Syntax Reference

### Rule Structure
```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

### IP Address Formats
- `any` - Any IP address
- `192.168.1.1` - Single IP
- `192.168.1.0/24` - CIDR notation (network)
- `$HOME_NET` - Variable (defined in suricata.yaml)
- `[10.0.0.0/8,172.16.0.0/12]` - Multiple addresses
- `!192.168.1.1` - Negation (not this IP)

### Port Formats
- `any` - Any port
- `80` - Single port
- `1:1024` - Range (ports 1-1024)
- `[80,443,8080]` - Multiple ports
- `!80` - Negation (not port 80)

### Common Options
- `msg` - Rule description (required)
- `sid` - Signature ID (required, use ≥1000000 for custom)
- `rev` - Revision number
- `content` - Payload content match
- `nocase` - Case-insensitive match
- `offset` - Start position for content match
- `depth` - Search depth from start/offset
- `flow` - Traffic flow state
- `classtype` - Rule classification
- `priority` - Alert priority (1=high, 4=low)
- `threshold` - Rate limiting
- `reference` - External reference (CVE, URL, etc.)

---

##  Troubleshooting

### Issue: Protocol-Specific Sections Not Showing

**This is intentional!** Sections only appear when relevant protocol is selected.

**Solution:**
1. Change **Protocol** dropdown to `http`, `tls`, or `dns`
2. Scroll down to between "Content Matching" and "Flow Options"
3. Click "**▶ HTTP Keywords**" (or TLS/DNS) to expand

**Visual Guide:**
```
When Protocol = tcp:
  [Content Matching]
                        ← No protocol sections here
  [Flow Options]

When Protocol = http:
  [Content Matching]
  ▶ HTTP Keywords       ← Section appears!
  [Flow Options]

After clicking header:
  [Content Matching]
  ▼ HTTP Keywords       ← Expanded!
    [All HTTP fields]
  [Flow Options]
```

### Issue: Port 5500 Already in Use
```bash
# Change port in app.py to 8080 or another free port
# Or kill existing process:
sudo lsof -ti:5500 | xargs kill -9
```

### Issue: Dependencies Won't Install
```bash
# Upgrade pip first
pip install --upgrade pip
# Then install requirements
pip install -r requirements.txt
```

### Issue: Can't Save Rules
**Check file permissions:**
```bash
ls -l custom.rules
chmod 644 custom.rules
```

### Issue: Validation Always Fails
**If Suricata is not installed:**
```bash
# Check if installed
suricata --version

# Install on Ubuntu/Debian
sudo apt-get install suricata

# Install on CentOS/RHEL
sudo yum install suricata
```

**Note:** The app will use basic regex validation if Suricata is not available.

### Issue: Service Reload Doesn't Work
**Configure sudo permissions** (see Configuration section above)

Or manually reload:
```bash
sudo systemctl reload suricata
# Or
sudo service suricata reload
```

### Issue: JavaScript Errors in Console
**Hard refresh the browser:**
- Chrome/Firefox: `Ctrl+Shift+R`
- Or clear browser cache completely

---

##  Project Structure

```
suricata-rule-builder/
├── app.py                      # Flask backend (600+ lines)
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── templates/
│   └── index.html             # Main dashboard UI (500+ lines)
│
├── static/
│   ├── css/
│   │   └── style.css          # Styling (700+ lines)
│   └── js/
│       └── app.js             # Frontend logic (800+ lines)
│
├── start.sh                   # Development startup script
├── install.sh                 # Production installation script
├── test_app.py                # Test suite
├── suricata-builder.service   # Systemd service file
│
├── custom.rules               # Your rules (auto-created)
├── sample-rules.json          # Basic example rules (15 rules)
└── sample-rules-enhanced.json # Advanced examples (25 rules)
```

---

##  Production Deployment

### Using Gunicorn (Recommended)
```bash
# Install gunicorn (already in requirements.txt)
pip install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 0.0.0.0:5500 app:app
```

### Using Systemd Service
```bash
# Run installation script
./install.sh

# Follow prompts to install to /opt

# Enable and start service
sudo systemctl enable suricata-builder
sudo systemctl start suricata-builder

# Check status
sudo systemctl status suricata-builder

# View logs
sudo journalctl -u suricata-builder -f
```

### Behind Nginx (Recommended)
```nginx
server {
    listen 80;
    server_name suricata-builder.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5500;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /static {
        alias /opt/suricata-rule-builder/static;
        expires 30d;
    }
}
```

---

##  Security Considerations

1. **Access Control**: This application has no built-in authentication. Deploy behind:
   - VPN
   - Reverse proxy with authentication (Nginx + Basic Auth, OAuth, etc.)
   - Firewall rules limiting access

2. **Sudo Permissions**: Configure minimal permissions as shown in Configuration section

3. **Input Validation**: All rules are validated through Suricata before saving

4. **File Permissions**: Ensure custom.rules has appropriate permissions (644)

5. **HTTPS**: Use a reverse proxy with SSL/TLS for production

---

##  Tips & Best Practices

### Rule Writing Tips
1. **Use SIDs ≥ 1000000** for custom rules to avoid conflicts
2. **Always validate** before saving
3. **Use meaningful messages** to describe what the rule detects
4. **Set appropriate priority** and classtype for better alert management
5. **Use flow options** to reduce false positives
6. **Test incrementally** - add one feature at a time

### Protocol-Specific Tips

**HTTP Rules:**
- Combine multiple HTTP keywords for precision
- Use `http.request_body` for POST data analysis
- Match `http.stat_code` for error monitoring
- Use `file.data` for malware download detection

**TLS Rules:**
- Monitor `tls.version` for policy compliance
- Use `ja3.hash` for malware fingerprinting
- Check `tls.sni` for C2 domain detection
- Validate certificates with `tls.subject` and `tls.issuer`

**DNS Rules:**
- Use thresholds with `dns.query.type:TXT` for tunneling detection
- Monitor for DGA domains with pattern matching
- Track excessive queries with `threshold` options
- Watch for DNS amplification with `dns.query.type:ANY`

### Performance Tips
1. **Use flow options** to reduce processing overhead
2. **Be specific** with IP/port ranges
3. **Use fast_pattern** for content matching optimization
4. **Avoid overly broad rules** (e.g., alert tcp any any -> any any)

---

##  Additional Resources

### Suricata Documentation
- Official Docs: https://suricata.readthedocs.io/
- Rule Format: https://suricata.readthedocs.io/en/latest/rules/
- Rule Keywords: https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html

### Community Resources
- Suricata Forums: https://forum.suricata.io/
- Emerging Threats Rules: https://rules.emergingthreats.net/
- OISF GitHub: https://github.com/OISF/suricata

---

##  Support

### Getting Help
1. Check this README for documentation
2. Use the "Help" button in the dashboard
3. Review example rules in `sample-rules-enhanced.json`
4. Check Suricata official documentation

### Reporting Issues
When reporting issues, provide:
- Browser console errors (F12 → Console)
- Steps to reproduce
- Expected vs actual behavior
- Browser and version
- Screenshot if applicable

---

##  Summary

This Suricata Rule Builder Dashboard provides:

✅ **37 Total Keywords** (15 basic + 22 protocol-specific)
✅ **Smart Protocol-Conditional UI**
✅ **Real-Time Validation**
✅ **Professional Rule Generation**
✅ **Complete CRUD Operations**
✅ **Import/Export Functionality**
✅ **Production-Ready Deployment**

**Start building advanced Suricata rules in minutes!**

```bash
./start.sh
# Open http://localhost:5500
# Select a protocol (http/tls/dns)
# Build your first rule!
```

---

**Made by divyanshhhhhh** | **Open Source**
