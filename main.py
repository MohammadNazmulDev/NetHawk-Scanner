#!/usr/bin/env python3

import sys
import os
import logging
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gui.main_window import MainWindow
from core.config import ConfigManager
from utils.logger import setup_logging

def main():
    # Set high DPI attributes before creating QApplication
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    setup_logging()
    logger = logging.getLogger(__name__)
    
    app = QApplication(sys.argv)
    app.setApplicationName("NetHawk Scanner")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("NetHawk Security")
    app.setOrganizationDomain("nethawk.security")
    
    config_manager = ConfigManager()
    
    window = MainWindow(config_manager)
    window.show()
    
    logger.info("NetHawk Scanner started successfully")
    
    try:
        exit_code = app.exec_()
        logger.info("NetHawk Scanner exited cleanly")
        return exit_code
    except Exception as e:
        logger.critical(f"Critical error during application execution: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())