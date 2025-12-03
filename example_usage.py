#!/usr/bin/env python3
"""
FlareTunnel - Quick Usage Example
Make sure proxy is running: python FlareTunnel.py tunnel --verbose
"""

import requests
import urllib3
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# FlareTunnel proxy configuration
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

print("=" * 80)
print("FlareTunnel - Usage Example")
print("=" * 80)
print()
print("Make sure proxy is running: python FlareTunnel.py tunnel --verbose")
print()
print("=" * 80)
print()

# Test 1: Simple GET
print("📡 Test 1: GET Request")
print("-" * 40)
try:
    response = requests.get(
        "https://httpbin.org/get?test=123",
        proxies=proxies,
        verify=False,
        timeout=10
    )
    print(f"✓ Status: {response.status_code}")
    data = response.json()
    print(f"✓ Origin IP: {data.get('origin', 'N/A')}")
    print(f"✓ Args: {data.get('args', {})}")
    print()
except Exception as e:
    print(f"✗ Error: {e}")
    print()

# Test 2: POST with JSON
print("📤 Test 2: POST Request with JSON")
print("-" * 40)
try:
    response = requests.post(
        "https://httpbin.org/post",
        json={
            "username": "testuser",
            "action": "login",
            "timestamp": time.time()
        },
        proxies=proxies,
        verify=False,
        timeout=10
    )
    print(f"✓ Status: {response.status_code}")
    data = response.json()
    print(f"✓ Received JSON: {data.get('json', {})}")
    print()
except Exception as e:
    print(f"✗ Error: {e}")
    print()

# Test 3: Custom Headers
print("📋 Test 3: Custom Headers")
print("-" * 40)
try:
    response = requests.get(
        "https://httpbin.org/headers",
        headers={
            "X-Custom-Header": "FlareTunnel-Test",
            "User-Agent": "FlareTunnel/2.0"
        },
        proxies=proxies,
        verify=False,
        timeout=10
    )
    print(f"✓ Status: {response.status_code}")
    data = response.json()
    headers_received = data.get('headers', {})
    print(f"✓ Custom Header: {headers_received.get('X-Custom-Header', 'Not received')}")
    print(f"✓ User-Agent: {headers_received.get('User-Agent', 'Not received')}")
    print()
except Exception as e:
    print(f"✗ Error: {e}")
    print()

# Test 4: IP Rotation Check
print("🔄 Test 4: IP Rotation (5 requests)")
print("-" * 40)
ips = set()
for i in range(5):
    try:
        response = requests.get(
            "https://httpbin.org/ip",
            proxies=proxies,
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            ip = response.json().get('origin', 'N/A')
            ips.add(ip)
            print(f"  Request {i+1}: {ip}")
        time.sleep(0.5)
    except Exception as e:
        print(f"  Request {i+1}: Error - {e}")

print(f"\n✓ Unique IPs: {len(ips)}")
for ip in sorted(ips):
    print(f"    - {ip}")
print()

# Test 5: Real Website
print("🌐 Test 5: Real Website (example.com)")
print("-" * 40)
try:
    response = requests.get(
        "https://example.com",
        proxies=proxies,
        verify=False,
        timeout=10
    )
    print(f"✓ Status: {response.status_code}")
    print(f"✓ Size: {len(response.content):,} bytes")
    # Show first 100 chars
    content_preview = response.text[:100].replace('\n', ' ')
    print(f"✓ Preview: {content_preview}...")
    print()
except Exception as e:
    print(f"✗ Error: {e}")
    print()

# Summary
print("=" * 80)
print("✅ All tests completed!")
print("=" * 80)
print()
print("💡 Key Points:")
print("  • All requests went through Cloudflare Workers")
print("  • Use rotation modes to change IPs (--mode random)")
print("  • Use blacklist to save Worker requests (default: blacklist-minimal.txt)")
print("  • IP addresses are blocked by default (Cloudflare doesn't support them)")
print()
print("📚 Learn More:")
print("  • README.md - Full documentation")
print("  • python FlareTunnel.py --help - All commands")
print()
