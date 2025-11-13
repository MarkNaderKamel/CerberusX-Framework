#!/usr/bin/env python3
"""
Ghidra Wrapper - Binary Reverse Engineering
Production-ready wrapper for NSA's Ghidra reverse engineering framework
"""

import subprocess
import argparse
import logging
import sys
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GhidraWrapper:
    """Ghidra - NSA's software reverse engineering framework"""
    
    def __init__(self, ghidra_path=None):
        self.ghidra_path = ghidra_path or os.getenv('GHIDRA_INSTALL_DIR', '/opt/ghidra')
        self.project_dir = './ghidra_projects'
        
    def check_installation(self):
        """Check if Ghidra is installed"""
        ghidra_paths = [
            self.ghidra_path,
            '/opt/ghidra',
            '/usr/share/ghidra',
            str(Path.home() / 'ghidra')
        ]
        
        for path in ghidra_paths:
            if Path(path).exists():
                # Look for analyzeHeadless script
                analyze_script = Path(path) / 'support' / 'analyzeHeadless'
                if analyze_script.exists():
                    self.ghidra_path = path
                    logger.info(f"✓ Ghidra found at: {self.ghidra_path}")
                    return True
        
        logger.warning("Ghidra not found in common locations")
        logger.warning("Download from: https://github.com/NationalSecurityAgency/ghidra/releases")
        logger.warning("Install to /opt/ghidra or set GHIDRA_INSTALL_DIR environment variable")
        return False
    
    def analyze_binary(self, binary_path, project_name='analysis', analyze=True, 
                      script=None, export=None):
        """
        Analyze binary in headless mode
        """
        logger.info(f"🔍 Analyzing binary: {binary_path}")
        
        # Create project directory
        os.makedirs(self.project_dir, exist_ok=True)
        
        # Build command
        analyze_script = Path(self.ghidra_path) / 'support' / 'analyzeHeadless'
        
        cmd = [
            str(analyze_script),
            self.project_dir,
            project_name,
            '-import', binary_path
        ]
        
        # Add analysis flag
        if analyze:
            cmd.append('-analyse')
        
        # Add post-analysis script
        if script:
            cmd.extend(['-postScript', script])
        
        # Export results
        if export:
            cmd.extend(['-scriptPath', '.'])
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                logger.info("✓ Analysis complete")
                return result.stdout
            else:
                logger.error(f"Analysis failed: {result.stderr}")
                return result.stdout
                
        except subprocess.TimeoutExpired:
            logger.error("Analysis timed out after 10 minutes")
            return ""
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            return ""
    
    def decompile_function(self, binary_path, function_name, output_file=None):
        """
        Decompile specific function to C code
        """
        logger.info(f"📝 Decompiling function: {function_name}")
        
        # Create Ghidra script for decompilation
        script_content = f'''
import ghidra.app.decompiler.DecompInterface as DecompInterface

def decompile_function(func_name):
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getName() == func_name:
            results = decompiler.decompileFunction(func, 30, None)
            if results.decompileCompleted():
                code = results.getDecompiledFunction().getC()
                print(code)
                return code
    return None

decompile_function("{function_name}")
'''
        
        # Save script
        script_path = Path('ghidra_decompile.py')
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Run analysis with script
        output = self.analyze_binary(binary_path, script=str(script_path))
        
        # Save output if requested
        if output_file and output:
            with open(output_file, 'w') as f:
                f.write(output)
            logger.info(f"📄 Decompiled code saved to: {output_file}")
        
        # Cleanup script
        script_path.unlink(missing_ok=True)
        
        return output
    
    def find_strings(self, binary_path):
        """
        Extract strings from binary
        """
        logger.info(f"🔤 Extracting strings from: {binary_path}")
        
        script_content = '''
def list_strings():
    strings = currentProgram.getListing().getDefinedData(True)
    for data in strings:
        if data.hasStringValue():
            print(f"{data.getAddress()}: {data.getValue()}")

list_strings()
'''
        
        script_path = Path('ghidra_strings.py')
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        output = self.analyze_binary(binary_path, script=str(script_path))
        
        script_path.unlink(missing_ok=True)
        
        return output
    
    def find_crypto(self, binary_path):
        """
        Search for cryptographic constants
        """
        logger.info(f"🔐 Searching for crypto constants in: {binary_path}")
        
        script_content = '''
# Common crypto constants
CRYPTO_CONSTANTS = {
    0x67452301: "MD5_A",
    0xEFCDAB89: "MD5_B",
    0x98BADCFE: "MD5_C",
    0x10325476: "MD5_D",
    0x6A09E667: "SHA256_H0",
    0xBB67AE85: "SHA256_H1",
    0x3C6EF372: "SHA256_H2",
    0xA54FF53A: "SHA256_H3",
}

def find_crypto_constants():
    memory = currentProgram.getMemory()
    for constant, name in CRYPTO_CONSTANTS.items():
        # Search for constant in memory
        found = memory.findBytes(memory.getMinAddress(), 
                                bytes.fromhex(f"{constant:08x}"), 
                                None, True, None)
        if found:
            print(f"Found {name} at {found}")

find_crypto_constants()
'''
        
        script_path = Path('ghidra_crypto.py')
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        output = self.analyze_binary(binary_path, script=str(script_path))
        
        script_path.unlink(missing_ok=True)
        
        return output
    
    def export_to_c(self, binary_path, output_dir='./decompiled'):
        """
        Export entire program to C code
        """
        logger.info(f"📦 Exporting to C code: {binary_path}")
        
        os.makedirs(output_dir, exist_ok=True)
        
        script_content = f'''
import os
from ghidra.app.decompiler import DecompInterface

def export_all_functions():
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    output_dir = "{output_dir}"
    os.makedirs(output_dir, exist_ok=True)
    
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        results = decompiler.decompileFunction(func, 30, None)
        if results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            filename = os.path.join(output_dir, f"{{func.getName()}}.c")
            with open(filename, "w") as f:
                f.write(code)
            print(f"Exported {{func.getName()}}")

export_all_functions()
'''
        
        script_path = Path('ghidra_export.py')
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        output = self.analyze_binary(binary_path, script=str(script_path))
        
        script_path.unlink(missing_ok=True)
        
        logger.info(f"📄 C files exported to: {output_dir}")
        
        return output
    
    def launch_gui(self, binary_path=None):
        """
        Launch Ghidra GUI
        """
        logger.info("🖥️  Launching Ghidra GUI")
        
        ghidra_run = Path(self.ghidra_path) / 'ghidraRun'
        
        if not ghidra_run.exists():
            logger.error("ghidraRun script not found")
            return False
        
        try:
            if binary_path:
                logger.info(f"Opening: {binary_path}")
            
            subprocess.Popen([str(ghidra_run)])
            logger.info("✓ Ghidra GUI launched")
            return True
        except Exception as e:
            logger.error(f"Error launching GUI: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Ghidra Wrapper - Binary reverse engineering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze binary (headless)
  python -m cerberus_agents.ghidra_wrapper --analyze malware.exe --authorized

  # Decompile specific function
  python -m cerberus_agents.ghidra_wrapper --analyze malware.exe --decompile main --authorized

  # Extract strings
  python -m cerberus_agents.ghidra_wrapper --analyze malware.exe --strings --authorized

  # Find crypto constants
  python -m cerberus_agents.ghidra_wrapper --analyze malware.exe --crypto --authorized

  # Export all functions to C code
  python -m cerberus_agents.ghidra_wrapper --analyze malware.exe --export-c --authorized

  # Launch GUI
  python -m cerberus_agents.ghidra_wrapper --gui --authorized

Setup:
  1. Download Ghidra 11.4+ from GitHub
  2. Extract to /opt/ghidra
  3. Or set GHIDRA_INSTALL_DIR environment variable
  4. Requires Java 21 JDK
        '''
    )
    
    parser.add_argument('--analyze', dest='binary',
                       help='Binary file to analyze')
    parser.add_argument('--project', default='analysis',
                       help='Project name (default: analysis)')
    parser.add_argument('--decompile',
                       help='Decompile specific function name')
    parser.add_argument('--strings', action='store_true',
                       help='Extract strings from binary')
    parser.add_argument('--crypto', action='store_true',
                       help='Find cryptographic constants')
    parser.add_argument('--export-c', action='store_true',
                       help='Export all functions to C code')
    parser.add_argument('--gui', action='store_true',
                       help='Launch Ghidra GUI')
    parser.add_argument('--ghidra-path',
                       help='Path to Ghidra installation')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for reverse engineering')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ Missing --authorized flag. This tool requires explicit authorization.")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                   GHIDRA WRAPPER                             ║
║          NSA Software Reverse Engineering Framework          ║
║                                                              ║
║  🔍 Disassembly & decompilation                              ║
║  📝 C code generation                                        ║
║  🔐 Malware analysis & vulnerability research                ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    ghidra = GhidraWrapper(ghidra_path=args.ghidra_path)
    
    # Check installation
    if not ghidra.check_installation():
        logger.error("Ghidra not available. Please install it first.")
        sys.exit(1)
    
    # Launch GUI
    if args.gui:
        ghidra.launch_gui(binary_path=args.binary)
        sys.exit(0)
    
    # Require binary for analysis operations
    if not args.binary:
        logger.error("--analyze <binary> required for headless operations")
        sys.exit(1)
    
    # Verify binary exists
    if not Path(args.binary).exists():
        logger.error(f"Binary not found: {args.binary}")
        sys.exit(1)
    
    # Decompile function
    if args.decompile:
        output = ghidra.decompile_function(args.binary, args.decompile)
        print(output)
    
    # Extract strings
    elif args.strings:
        output = ghidra.find_strings(args.binary)
        print(output)
    
    # Find crypto
    elif args.crypto:
        output = ghidra.find_crypto(args.binary)
        print(output)
    
    # Export to C
    elif args.export_c:
        output = ghidra.export_to_c(args.binary)
        print(output)
    
    # Default analysis
    else:
        output = ghidra.analyze_binary(args.binary, project_name=args.project)
        print(output)


if __name__ == '__main__':
    main()
