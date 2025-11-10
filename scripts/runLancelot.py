
lancelotBin = r'C:\Users\fredc\Desktop\lancelot\target\debug\lancelot.exe'

import glob
import subprocess
import argparse
import os
import sys
import textwrap


def processFile(dirName, fileName):
    """
    Process a single ELF file with Lancelot to extract function boundaries
    
    Args:
        dirName: Directory containing the binary
        fileName: Full path to the binary file
    """
    baseName = os.path.basename(fileName)
    print('Processing {:s}'.format(baseName))
    
    # Output file will have .newgt extension (compatible with countMatch.py)
    outputFile = baseName + '.newgt'
    
    # Run lancelot with -v functions command
    # Command format: lancelot -v functions <binary_file>
    
    try:
        # Run lancelot with function extraction
        # Try without -v first, then with -v if that doesn't work
        cmd = '"{:s}" functions "{:s}"'.format(lancelotBin, fileName)
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print('  ERROR: Lancelot crashed or failed')
            print('  Return code: {:d}'.format(result.returncode))
            if result.stderr:
                # Show just the last few lines of stderr
                stderr_lines = result.stderr.strip().split('\n')
                if len(stderr_lines) > 5:
                    print('  Error (last 5 lines):')
                    for line in stderr_lines[-5:]:
                        print('    ' + line)
                else:
                    print('  Error: ' + result.stderr.strip())
            return
        
        # Parse lancelot output and convert to the format expected by countMatch.py
        # Format: <hex_address> <decimal_size>
        # Lancelot output format: 0x<address> <function_name>
        # Note: We're only comparing function starts, so size can be 0
        
        function_count = 0
        with open(outputFile, 'w') as outf:
            for line in result.stdout.splitlines():
                line = line.strip()
                
                # Skip empty lines, debug/info messages
                if not line or '[' in line or 'found' in line.lower():
                    continue
                
                # Parse function line: 0x<address> <name>
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith('0x'):
                    try:
                        addr = parts[0]
                        # Output with size 0 since we only care about function starts
                        outf.write('{:s} 0\n'.format(addr))
                        function_count += 1
                    except ValueError:
                        continue
        
        if function_count > 0:
            print('  -> Created {:s} ({:d} functions)'.format(outputFile, function_count))
        else:
            print('  -> WARNING: No functions found in output')
        
    except FileNotFoundError:
        print('Error: {:s} not found. Please install Lancelot or update the lancelotBin path.'.format(lancelotBin))
        print('Expected command format: lancelot -v functions <binary_file>')
        sys.exit(1)
    except Exception as e:
        print('Error processing {:s}: {:s}'.format(fileName, str(e)))


def main():
    formatter = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=formatter,
                                    description=textwrap.dedent('''\
Lancelot Function Boundary Detection Results Interface

   This program runs Lancelot and generates .newgt files for each 
   binary in the specified directory. Results are stored in the
   current directory. Contents of these files are function start 
   address, in hex, followed by number of bytes, in decimal.
   
   The output format is compatible with countMatch.py for comparison
   with ground truth (.sym files).
   
   Make sure that the lancelot executable is on your search path
   or modify the lancelotBin variable in this script.
   
   Usage:
       python runLancelot.py --dir <directory_of_binaries>
       
   Example:
       mkdir lancelot_results
       cd lancelot_results
       python ../scripts/runLancelot.py --dir ../datasets/strippedTestSuites/x64gcc
       python ../scripts/countMatch.py --funcDir . --symDir ../datasets/groundTruth/x64gcc
   '''))

    required = parser.add_argument_group(title='required')
    required.add_argument('--dir', required=True,
                         help='directory of binaries to analyze')

    args = parser.parse_args()
    dirName = args.dir
    dirName = os.path.abspath(dirName)
    
    if not os.path.exists(dirName):
        print('Error: Directory {:s} does not exist'.format(dirName))
        sys.exit(1)
    
    dirList = glob.glob(dirName + '/*')
    
    if not dirList:
        print('Warning: No files found in {:s}'.format(dirName))
        sys.exit(1)
    
    print('Processing {:d} files from {:s}'.format(len(dirList), dirName))
    
    processed = 0
    failed = 0
    
    for fileName in sorted(dirList):
        # Skip directories
        if os.path.isdir(fileName):
            continue
        
        # Skip symbolic links
        if os.path.islink(fileName):
            continue
        
        try:
            processFile(dirName, fileName)
            processed += 1
        except Exception as e:
            print('  EXCEPTION: {:s}'.format(str(e)))
            failed += 1
            continue
    
    print('\n' + '='*70)
    print('Processing complete!')
    print('Successfully processed: {:d} files'.format(processed))
    if failed > 0:
        print('Failed: {:d} files (Lancelot crashed or errored)'.format(failed))
    print('='*70)
    print('\nTo compare with ground truth, run:')
    print('  python ../scripts/countMatch.py --funcDir . --symDir ../datasets/groundTruth/<compiler>')
    print('\nExample:')
    print('  python ../scripts/countMatch.py --funcDir . --symDir ../datasets/groundTruth/x64gcc')

    
if __name__ == "__main__":
    main()
