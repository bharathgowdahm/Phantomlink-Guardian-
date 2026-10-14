import streamlit as st
import re, urllib.parse, ipaddress

st.set_page_config(page_title="PhantomLink Guardian", page_icon="🛡️", layout="wide")

SUSPICIOUS_TLDS = {"tk","ml","ga","cf","gq","xyz","top","club","work","zip","mov","click","country","stream"}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","adf.ly","cutt.ly"}
BRANDS = ["google","facebook","instagram","amazon","flipkart","paypal","hdfc","sbi","icici","apple","microsoft","netflix"]

def analyze_url(raw):
    url = raw.strip()
    if not url:
        return None
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = "http://" + url
    findings = []
    score = 0
    p = urllib.parse.urlparse(url)
    host = (p.hostname or "").lower()
    full = url

    try:
        ipaddress.ip_address(host)
        findings.append(("🔴 High", "Host is an IP address, not a domain. Legit sites rarely do this.", 25))
        score += 25
    except:
        pass

    if "@" in full:
        findings.append(("🔴 High", "Contains '@' — browsers ignore everything before it.", 20))
        score += 20

    if "xn--" in host:
        findings.append(("🔴 High", "Punycode (xn--) — possible homograph attack.", 20))
        score += 20

    parts = host.split(".")
    if len(parts) > 4:
        findings.append(("🟡 Medium", f"{len(parts)-2} subdomains — phishing stacks subdomains.", 10))
        score += 10

    if "-" in host:
        findings.append(("🔵 Low", "Hyphens common in phishing lookalikes.", 5))
        score += 5

    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(("🟡 Medium", f"TLD '.{tld}' frequently abused.", 10))
        score += 10

    if host in SHORTENERS:
        findings.append(("🟡 Medium", "URL shortener hides real destination.", 10))
        score += 10

    if len(full) > 120:
        findings.append(("🔵 Low", f"Very long URL ({len(full)} chars).", 5))
        score += 5

    for b in BRANDS:
        if b in host and host != b + ".com" and not host.endswith("." + b + ".com"):
            findings.append(("🔴 High", f"Contains brand '{b}' but domain is '{host}' — impersonation.", 20))
            score += 20
            break

    if p.scheme == "http":
        findings.append(("🔵 Low", "Uses HTTP, not HTTPS.", 5))
        score += 5

    digits = sum(c.isdigit() for c in host)
    if digits > 5:
        findings.append(("🔵 Low", f"{digits} digits in domain — unusual.", 5))
        score += 5

    try:
        host.encode('ascii')
    except:
        findings.append(("🟡 Medium", "Non-ASCII chars — homograph risk.", 10))
        score += 10

    score = min(score, 100)
    if score >= 60:
        verdict, color = "🚨 Dangerous", "red"
    elif score >= 30:
        verdict, color = "⚠️ Suspicious", "orange"
    elif score > 0:
        verdict, color = "🔵 Caution", "blue"
    else:
        verdict, color = "✅ Looks Safe", "green"
    return dict(url=url, host=host, score=score, verdict=verdict, color=color, findings=findings)

st.markdown("<h1 style='text-align:center'>🛡️ PhantomLink Guardian</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;color:gray'>Detect suspicious URLs & explain phishing indicators — 12 signals</p>", unsafe_allow_html=True)

col1, col2 = st.columns([3, 1])
with col1:
    url_in = st.text_input("Paste suspicious URL", placeholder="e.g. http://secure-paypal-login.tk/verify")
with col2:
    st.write("")
    st.write("")
    scan_btn = st.button("🔍 Scan URL", use_container_width=True)

st.markdown("**Try samples:**")
s1, s2, s3, s4 = st.columns(4)
clicked = None
if s1.button("IP host"):
    clicked = "http://192.168.1.1/secure-login"
if s2.button("@ trick"):
    clicked = "http://secure-paypal-login.tk/verify@evil.com"
if s3.button("Shortener"):
    clicked = "https://bit.ly/3xyzAbC"
if s4.button("Typosquat"):
    clicked = "http://paypaI-secure.com/login"
if clicked:
    url_in = clicked
    scan_btn = True

if scan_btn and url_in:
    r = analyze_url(url_in)
    st.divider()
    c1, c2 = st.columns([1, 2])
    with c1:
        st.metric("Risk Score", f"{r['score']}/100")
        if r['color'] == "red":
            st.error(r['verdict'])
        elif r['color'] == "orange":
            st.warning(r['verdict'])
        elif r['color'] == "blue":
            st.info(r['verdict'])
        else:
            st.success(r['verdict'])
        st.caption(f"Domain: {r['host']}")
        st.progress(r['score'] / 100)
    with c2:
        st.subheader("Findings")
        if not r['findings']:
            st.success("No red flags found. Still stay cautious with unknown links.")
        for sev, msg, pts in r['findings']:
            if "High" in sev:
                st.error(f"{sev} (+{pts}) — {msg}")
            elif "Medium" in sev:
                st.warning(f"{sev} (+{pts}) — {msg}")
            else:
                st.info(f"{sev} (+{pts}) — {msg}")
    st.caption("⚠️ Educational tool. Always verify on the official site before entering credentials.")
