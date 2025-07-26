#!/usr/bin/env python3

import sys
import os
import subprocess

def check_python_version():
    if sys.version_info < (3, 7):
        print("ERROR: Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)

def check_nmap_installation():
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✓ Nmap is installed and accessible")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Nmap is not installed or not accessible
        pass
    
    print("ERROR: Nmap is not installed or not in PATH")
    print("Please install nmap:")
    print("  Ubuntu/Debian: sudo apt-get install nmap")
    print("  CentOS/RHEL: sudo yum install nmap")
    print("  Kali Linux: sudo apt-get install nmap")
    return False

def check_system_dependencies():
    """Check and install system dependencies on Kali/Debian/Ubuntu"""
    try:
        # Check if we're on a Debian-based system
        result = subprocess.run(['which', 'apt-get'], capture_output=True)
        if result.returncode != 0:
            print("INFO: Not a Debian-based system, skipping system dependency check")
            return True
        
        # Check for required development packages
        missing_packages = []
        
        # Check for PyQt5 development files
        result = subprocess.run(['dpkg', '-l', 'python3-pyqt5-dev'], capture_output=True)
        if result.returncode != 0:
            missing_packages.extend(['python3-pyqt5', 'python3-pyqt5-dev'])
        
        if missing_packages:
            print(f"Installing system dependencies: {' '.join(missing_packages)}")
            try:
                subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y'] + missing_packages, check=True)
                print("✓ System dependencies installed")
            except subprocess.CalledProcessError:
                print("WARNING: Could not install system dependencies automatically")
                print("Please run: sudo apt-get install python3-pyqt5 python3-pyqt5-dev")
                return False
        
        return True
    except Exception as e:
        print(f"WARNING: System dependency check failed: {e}")
        return True  # Continue anyway

def setup_virtual_environment():
    venv_path = os.path.join(os.path.dirname(__file__), 'venv')
    
    if not os.path.exists(venv_path):
        print("Creating virtual environment...")
        try:
            subprocess.run([sys.executable, '-m', 'venv', venv_path], check=True)
            print("✓ Virtual environment created")
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to create virtual environment: {e}")
            return False
    else:
        print("✓ Virtual environment already exists")
    
    # Determine pip path
    if os.name == 'nt':  # Windows
        pip_path = os.path.join(venv_path, 'Scripts', 'pip')
        python_path = os.path.join(venv_path, 'Scripts', 'python')
    else:  # Unix/Linux
        pip_path = os.path.join(venv_path, 'bin', 'pip')
        python_path = os.path.join(venv_path, 'bin', 'python')
    
    # Upgrade pip first
    try:
        subprocess.run([pip_path, 'install', '--upgrade', 'pip'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("WARNING: Could not upgrade pip")
    
    # Install requirements
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        print("Installing requirements...")
        try:
            subprocess.run([pip_path, 'install', '-r', requirements_path], check=True)
            print("✓ Requirements installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to install requirements: {e}")
            print("\nTrying alternative installation method...")
            
            # Try installing system packages instead
            try:
                subprocess.run(['sudo', 'apt-get', 'install', '-y', 
                              'python3-pyqt5', 'python3-requests', 'python3-matplotlib', 
                              'python3-numpy', 'python3-pil', 'python3-psutil'], check=True)
                print("✓ Installed system packages instead")
                return python_path
            except subprocess.CalledProcessError:
                print("ERROR: Could not install packages. Please install manually:")
                print("sudo apt-get install python3-pyqt5 python3-requests python3-matplotlib python3-numpy python3-pil python3-psutil")
                return False
    
    return python_path

def run_application(python_path):
    main_script = os.path.join(os.path.dirname(__file__), 'main.py')
    
    if not os.path.exists(main_script):
        print(f"ERROR: main.py not found at {main_script}")
        return False
    
    print("Starting NetHawk Scanner...")
    print("=" * 50)
    
    try:
        # Set environment variables
        env = os.environ.copy()
        env['PYTHONPATH'] = os.path.dirname(__file__)
        
        # Run the application
        result = subprocess.run([python_path, main_script], env=env)
        return result.returncode == 0
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        return True
    except Exception as e:
        print(f"ERROR: Failed to run application: {e}")
        return False

def main():
    print("NetHawk Scanner - Network Vulnerability Assessment Tool")
    print("=" * 60)
    
    # Check Python version
    check_python_version()
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Check if we're running as root (required for some nmap features)
    if os.name != 'nt' and os.geteuid() != 0:
        print("WARNING: Not running as root. Some scan features may be limited.")
        print("For full functionality, run with: sudo python3 run.py")
    
    # Check Nmap installation
    if not check_nmap_installation():
        sys.exit(1)
    
    # Check system dependencies
    if not check_system_dependencies():
        print("WARNING: System dependency issues detected. The app may not work properly.")
    
    # Setup virtual environment and install dependencies
    python_path = setup_virtual_environment()
    if not python_path:
        sys.exit(1)
    
    # Run the application
    success = run_application(python_path)
    
    if success:
        print("\nNetHawk Scanner finished successfully")
    else:
        print("\nNetHawk Scanner encountered an error")
        sys.exit(1)

if __name__ == "__main__":
    main()