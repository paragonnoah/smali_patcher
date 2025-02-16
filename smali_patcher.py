#!/usr/bin/env python3
import zipfile
import re
import os
import sys
import tempfile


bred='\033[1;31m'
bgreen='\033[1;32m'
byellow='\033[1;33m'
bblue='\033[1;34m'
bpurple='\033[1;35m'
bcyan='\033[1;36m'
bwhite='\033[1;37m'
end='\033[0m'


banner = f"""{byellow}
    .___              ________              \n  __| _/____ ___  ___/  _____/ __ __  ____  \n / __ |/ __ \\\\  \\/  /   \\  ___|  |  \\/    \\ \n/ /_/ \\  ___/ >    <\\    \\_\\  \\  |  /   |  \\\n\\____ |\\___  >__/\\_ \\\\______  /____/|___|  /\n     \\/    \\/      \\/       \\/           \\/ 
{end}
"""

def print_banner():
	os.system('clear')
	print(banner)
	print(f"{bwhite}Version: 7.0{end}")
	print(f"{bwhite}Created by{bred}@G0D_of_CONFIG {bwhite}& {bred}G0D_of_CONFIG{end} {bwhite}& {bgreen}L-Mon{end}")
	print(f"{bblue}Telegram Channel: https://t.me/G0D_of_CONFIG{end}\n")

def create_Utils(extract_folder):
	sf_path = os.path.join(extract_folder, 'Utils.smali')
	with open(sf_path, 'w') as special_file:
		special_file.write(".class public LdexGun/Utils;\n.super Ljava/lang/Object;\n\n# static fields\n.field private static final TAG:Ljava/lang/String; = \"[dexGun]\"\n\n# direct methods\n.method public constructor <init>()V\n    .registers 1\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n\n.method public static addFlags(Landroid/view/Window;I)V\n    .registers 3\n    const/16 v0, 0x2000\n    if-eq p1, v0, :cond_7\n    invoke-virtual {p0, p1}, Landroid/view/Window;->addFlags(I)V\n    :cond_7\n    return-void\n.end method\n\n.method public static log(Ljava/lang/String;)V\n    .registers 2\n    const-string v0, \"[dexGun]\"\n    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n    return-void\n.end method\n\n.method public static setFlags(Landroid/view/Window;II)V\n    .registers 4\n    const/16 v0, 0x2000\n    if-eq p1, v0, :cond_9\n    if-eq p2, v0, :cond_9\n    invoke-virtual {p0, p1, p2}, Landroid/view/Window;->setFlags(II)V\n    :cond_9\n    return-void\n.end method\n\n.method public static installer()Ljava/lang/String;\n    .registers 1\n    const-string v0, \"com.android.vending\"\n    return v0\n.end method")
	return sf_path

def modify_file_content(file_path, rel_path):
	with open(file_path, 'r') as f:
		original_content = f.read()
	modified_content = original_content
	created_Utils = False

	new_content = re.sub(r'(\.method (.+) (isVpnConnected|isWifiProxy|isNetworkStatus|isNetworkConnected|checkXpFormMap|isHookByStack|isXposed|isEmulator).*\)Z\n\s{4}\.registers \d+)[\w\W]+?\.end method', r'\1\nconst/4 v0, 0x0\nreturn v0\n\.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed some detections {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'invoke-static.*Ljava/lang/System;->exit.*', 'nop', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Blocked System.exit {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'invoke-static.*Landroid/os/Process;->killProcess.*', 'nop', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Blocked Process.kill {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
#Bypassed anti screen restrictions
	new_content = re.sub(r'invoke-virtual (\{.*\}), Landroid/view/Window;->setFlags\(II\)V', r'invoke-static \1, LdexGun/Utils;->setFlags(Landroid/view/Window;II)V', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Anti-Screen restrictions {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
		created_Utils = True

	new_content = re.sub(r'invoke-virtual (\{.*\}), Landroid/view/Window;->addFlags\(I\)V', r'invoke-static \1, LdexGun/Utils;->addFlags(Landroid/view/Window;I)V', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Anti-Screen restrictions {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
		created_Utils = True
# Bypassing Device detection 
	new_content = re.sub(r'const-string [vp]\d+, \"(generic|goldfish)\"\n\n\s{4}invoke-static \{[vp]\d+\}, Landroid/os/Build;->get(Device|Hardware)\(\)Ljava/lang/String;\n\n\s{4}move-result-object [vp]\d+\n\n\s{4}invoke-virtual \{[vp]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z\n\n\s{4}move-result ([vp]\d+)', r'const/4 \3, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Device detection in {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass Frida
	new_content = re.sub(r'const-string [vp]\d+, \"(/data/local/tmp/frida|/data/local/tmp/frida-server)\"\n\n\s{4}invoke-static \{[vp]\d+\}, Ljava/io/File;->exists\(\)Z\n\n\s{4}move-result ([vp]\d+)', r'const/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Frida detection in {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass Vpn/Proxy
	new_content = re.sub(r'(const/4 [pv]\d+, 0x4\n\n\s{4}invoke-virtual \{[pv]\d+, [pv]\d+\}, Landroid/net/NetworkCapabilities;->hasTransport\(I\)Z)\n\n\s{4}move-result ([pv]\d+)', r'\1\n\nconst/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection Network Transport {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(const/4 [pv]\d+, 0x4\n\n\s{4}invoke-virtual \{[pv]\d+, [pv]\d+\}, Landroid/net/NetworkCapabilities;->hasTransport\(I\)Z\n\n\s{4})move-result ([pv]\d+)', r'\1const/4 \3\4, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection NetworkCapabilities {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(invoke-virtual \{[vp]\d+\}, Ljava/net/NetworkInterface;->isUp\(\)Z\n\n\s{4})move-result ([vp]\d+)', r'\1const/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection NetworkInterface {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(Ljava/net/NetworkInterface[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z(?:[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z)*[\s\S]*?)move-result (.*)', r'\1const/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection NetworkInterface {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(Ljava/net/NetworkInterface[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z(?:[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z)*[\s\S]*?)move-result (.*)', r'\1const/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection NetworkInterface {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(Ljava/net/NetworkInterface[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z(?:[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z)*[\s\S]*?)move-result (.*)', r'\1const/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection NetworkInterface {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(Ljava/net/NetworkInterface[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z(?:[\s\S]*?invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z)*[\s\S]*?)move-result (.*)', r'\1const/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection NetworkInterface {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(const-string [vp]\d+, \"(tun|tunl0|tun0|utun0|utun1|utun2|utun3|utun4|pptp|ppp|pp0|ppp0|p2p0|ccmni0|ipsec)\"\n\n\s{4}invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/lang/String;->contains\(Ljava/lang/CharSequence;\)Z\n\n\s{4})move-result ([vp]\d+)', r'\1const/4 \3, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Vpn/Proxy detection NetworkInterface {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass Mock detection
	new_content = re.sub(r'invoke-virtual \{[pv]\d+\}, Landroid/location/Location;->(isFromMockProvider|isMock).*\)Z\n\n\s{4}move-result ([pv]\d+)', r'const/4 \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Mock detection in {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass Dev Mode enabled
	new_content = re.sub(r'(const-string [vp]\d+, "development_settings_enabled"\n\n\s{4}invoke-virtual \{.*\}, Landroid/content/Context;->getContentResolver\(\)Landroid/content/ContentResolver;\n\n\s{4}invoke-static \{.*\}, Landroid/provider/Settings\$Global;->getInt\(Landroid/content/ContentResolver;Ljava/lang/String;\)I\n\n\s{4})move-result ([vp]\d+)', r'\1const \2, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Dev Mode detection in {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Fix Installer
	new_content = re.sub(r'invoke-virtual \{([pv]\d+), ([pv]\d+)\}, Landroid/content/pm/PackageManager;->(getInstallerPackageName|InstallerPackageName)\(Ljava/lang/String;\)Ljava/lang/String;', r'invoke-static {}, LdexGun/Utils;->installer()Ljava/lang/String;', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Fixed Installer {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
		created_Utils = True
# Bypass HostnameVerifier
	new_content = re.sub(r'(.method (.+) verify\(Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z\n\s+\.(.+) \d+\n\s+)const/4 ([pv]\d+), 0x0((?:.|\n)*?\.end method)', r'\1const/4 v0, 0x1\n\n    return v0\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}HostnameVerifier {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass checkClientTrusted
	new_content = re.sub(r'(.method (.+) checkClientTrusted\(\[Ljava/security/cert/X509Certificate;Ljava/lang/String;\)V\n\s+\.(.+) \d+\n\s+)((?:.|\n)*?\.end method)', r'\1\n    return-void\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}checkClientTrusted {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass checkServerTrusted
	new_content = re.sub(r'(.method (.+) checkServerTrusted\(\[Ljava/security/cert/X509Certificate;Ljava/lang/String;\)V\n\s+\.(.+) \d+\n\s+)((?:.|\n)*?\.end method)', r'\1\n    return-void\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}checkServerTrusted {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass getAcceptedIssuers
	new_content = re.sub(r'(.method (.+) getAcceptedIssuers\(\)(.+)\n\s+\.(.+) \d+\n\s+)((?:.|\n)*?\.end method)', r'\1const/4 v0, 0x0\n\nnew-array v0, v0, [Ljava/security/cert/X509Certificate;\n\n    return-object v0\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}getAcceptedIssuers {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass CertificatePinner & HostnameVerifier
	new_content = re.sub(r'(.method (.+) (.+) check\(Ljava/lang/String;Ljava/util/List;\)V\n\s+\.(.+) \d+\n\s+)[^\n]*\n(?:.|\n)*?\.end method', r'\1\n    return-void\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}CertificatePinner & HostnameVerifier {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(.method (.+) check\(Ljava/lang/String;Ljava/util/List;\)V\n\s+\.(.+) \d+\n\s+)[^\n]*\n(?:.|\n)*?\.end method', r'\1\n    return-void\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}CertificatePinner & HostnameVerifier {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass check$okhttp
	new_content = re.sub(r'(.method (.+) (.+) check(.*)okhttp\((.+)\)V\n\s+\.(.+) \d+\n\s+)[^\n]*\n(?:.|\n)*?\.end method', r'\1\n    return-void\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}check$okhttp {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'(.method (.+) check(.*)okhttp\((.+)\)V\n\s+\.(.+) \d+\n\s+)[^\n]*\n(?:.|\n)*?\.end method', r'\1\n    return-void\n.end method', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}check$okhttp {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Patch Signature.verify
	new_content = re.sub(r'invoke-virtual \{[pv]\d+, [pv]\d+\}, Ljava/security/Signature;->verify.*\)Z\n\n\{4}move-result ([pv]\d+)', r'const/4 \1, 0x1', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Signature.verify = True {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass ConnectivityManager
	new_content = re.sub(r'invoke-virtual \{[vp]\d+\}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo\(\)Landroid/net/NetworkInfo;\n\n\s{4}move-result-object ([vp]\d+)', r'const/4 \1, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Disabled ConnectivityManager.getActiveNetworkInfo {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Disable NetworkInfo
	new_content = re.sub(r'invoke-virtual \{[vp]\d+\}, Landroid/net/NetworkInfo;->isAvailable\(\)Z\n\n\s{4}move-result ([vp]\d+)', r'const/4 \1, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Disabled NetworkInfo.isAvailable {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'invoke-virtual \{[vp]\d+\}, Landroid/net/NetworkInfo;->isConnected.*\)Z\n\n\s{4}move-result ([vp]\d+)', r'const/4 \1, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Disabled NetworkInfo.isConnected {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Disable WiFi
	new_content = re.sub(r'invoke-virtual \{[vp]\d+\}, Landroid/net/wifi/WifiManager;->isWifiEnabled\(\)Z\n\n\s{4}move-result ([vp]\d+)', r'const/4 \1, 0x0', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Disabled WiFi connection {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass update dialog 
	new_content = re.sub(r'[ias]get ([vp]\d+).*Landroid/content/pm/PackageInfo;->version.*:I', r'const \1, 0x7ffffff', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Changed version/build {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	new_content = re.sub(r'[ias]get ([vp]\d+).*Landroid/content/pm/PackageInfo;->version.*:Ljava/lang/String;', r'const-string \1, "134217727', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Changed version/build {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content
# Bypass Client-Side LVL
	new_content = re.sub(r'(invoke-interface \{[pv]\d+\}, Lcom/google/android/vending/licensing/Policy;->allowAccess\(\)Z\n\n\s{4})move-result ([pv]\d+)', r'\1const/4 \3, 0x1', modified_content)
	if new_content != modified_content:
		print(f"{bgreen}[{bred}*{bgreen}] {bcyan}Bypassed Client-Side LVL {bwhite}-> {byellow}{rel_path}{end}")
		modified_content = new_content

	return modified_content, created_Utils

def start_fix(zip_file):
	with tempfile.TemporaryDirectory() as extract_folder:
		with zipfile.ZipFile(zip_file, 'r') as zip_ref:
			zip_ref.extractall(extract_folder)

		modified_files = []
		created_Utils = False

		for root, _, files in os.walk(extract_folder):
			for file_name in files:
				if file_name.endswith(".smali"):
					file_path = os.path.join(root, file_name)
					rel_path = os.path.relpath(file_path, extract_folder)
					modified_content, special_file_created = modify_file_content(file_path, rel_path)
					if modified_content != open(file_path, 'r').read():
						modified_files.append(file_path)
						with open(file_path, 'w') as f:
							f.write(modified_content)
					if special_file_created:
						created_Utils = True

		if modified_files:
			z_output = "fixed.zip"
			with zipfile.ZipFile(z_output, 'w') as zip_ref:
				for file_path in modified_files:
					rel_path = os.path.relpath(file_path, extract_folder)
					zip_ref.write(file_path, rel_path)
				if created_Utils:
					sf_path = create_Utils(extract_folder)
					zip_ref.write(sf_path, 'Utils.smali')
			return z_output


if __name__ == '__main__':
	print_banner()

	if len(sys.argv) < 2:
		print(f"{bwhite}Usage: python {bred}{sys.argv[0]} {bpurple}/path/to/dex2smali.zip{end}\n")
		sys.exit(1)
	zinput = sys.argv[1]
	updated_zip_file = start_fix(zinput)

	if updated_zip_file:
		print(f"\n{bgreen}[✓] {bwhite}Output: {updated_zip_file}{end}\n")
	else:
		print(f"\n{bred}[!] {bwhite}No modifications were made.{end}\n")
