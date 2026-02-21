"""
USB Device Detection Module
============================
Detects USB storage devices and provides device information.
"""

import os
import sys
import time
import psutil
from typing import List, Dict, Optional
from datetime import datetime


class USBDevice:
    """Represents a USB storage device."""
    
    def __init__(self, mount_point: str, device_info: dict):
        self.mount_point = mount_point
        self.device = device_info.get('device', 'Unknown')
        self.fstype = device_info.get('fstype', 'Unknown')
        self.opts = device_info.get('opts', '')
        self.total = device_info.get('total', 0)
        self.used = device_info.get('used', 0)
        self.free = device_info.get('free', 0)
        self.percent = device_info.get('percent', 0)
        self.detected_at = datetime.now()
    
    def __repr__(self):
        return f"USBDevice(mount={self.mount_point}, fs={self.fstype}, size={self.total_gb:.2f}GB)"
    
    @property
    def total_gb(self) -> float:
        """Get total size in GB."""
        return self.total / (1024**3) if self.total else 0
    
    @property
    def used_gb(self) -> float:
        """Get used size in GB."""
        return self.used / (1024**3) if self.used else 0
    
    @property
    def free_gb(self) -> float:
        """Get free size in GB."""
        return self.free / (1024**3) if self.free else 0
    
    def get_info(self) -> str:
        """Get formatted device information."""
        info = []
        info.append(f"Drive: {self.mount_point}")
        info.append(f"Type: {self.fstype}")
        info.append(f"Total: {self.total_gb:.2f} GB")
        info.append(f"Used: {self.used_gb:.2f} GB ({self.percent}%)")
        info.append(f"Free: {self.free_gb:.2f} GB")
        info.append(f"Detected: {self.detected_at.strftime('%Y-%m-%d %H:%M:%S')}")
        return "\n".join(info)


class USBDetector:
    """Detects and monitors USB storage devices."""
    
    def __init__(self):
        """Initialize USB detector."""
        self.known_devices = set()
        self._update_known_devices()
    
    def _update_known_devices(self):
        """Update list of currently connected devices."""
        current = self.get_removable_drives()
        self.known_devices = {dev.mount_point for dev in current}
    
    def get_removable_drives(self) -> List[USBDevice]:
        """
        Get all removable storage devices (USB drives).
        
        Returns:
            List of USBDevice objects
        """
        devices = []
        
        for partition in psutil.disk_partitions(all=False):
            # On Windows, check for removable drives
            if sys.platform == 'win32':
                # Check if it's a removable drive (USB)
                # Typically USB drives have drive letters like E:, F:, etc.
                drive_letter = partition.mountpoint[0].upper()
                
                # Skip system drives (usually C:)
                if drive_letter in ['C', 'A', 'B']:
                    continue
                
                # Check if drive is accessible
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    
                    device_info = {
                        'device': partition.device,
                        'fstype': partition.fstype,
                        'opts': partition.opts,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                    
                    devices.append(USBDevice(partition.mountpoint, device_info))
                except (PermissionError, OSError):
                    pass
            
            # On Linux/Mac, check for removable media
            else:
                if 'removable' in partition.opts or '/media/' in partition.mountpoint or '/mnt/' in partition.mountpoint:
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        
                        device_info = {
                            'device': partition.device,
                            'fstype': partition.fstype,
                            'opts': partition.opts,
                            'total': usage.total,
                            'used': usage.used,
                            'free': usage.free,
                            'percent': usage.percent
                        }
                        
                        devices.append(USBDevice(partition.mountpoint, device_info))
                    except (PermissionError, OSError):
                        pass
        
        return devices
    
    def wait_for_device(self, timeout: Optional[float] = None) -> Optional[USBDevice]:
        """
        Wait for a new USB device to be connected.
        
        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)
        
        Returns:
            USBDevice object if detected, None if timeout
        """
        start_time = time.time()
        
        print("\n[~] Waiting for USB device to be connected...")
        print("   Please insert a USB drive...")
        
        while True:
            current_devices = self.get_removable_drives()
            current_paths = {dev.mount_point for dev in current_devices}
            
            # Check for new devices
            new_paths = current_paths - self.known_devices
            
            if new_paths:
                # New device detected!
                new_path = list(new_paths)[0]
                new_device = next(dev for dev in current_devices if dev.mount_point == new_path)
                self.known_devices.add(new_path)
                return new_device
            
            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                return None
            
            time.sleep(1)  # Check every second
    
    def list_devices(self) -> List[USBDevice]:
        """
        List all currently connected USB devices.
        
        Returns:
            List of USBDevice objects
        """
        return self.get_removable_drives()
    
    def print_devices(self):
        """Print all detected USB devices."""
        devices = self.list_devices()
        
        if not devices:
            print("[X] No USB devices detected")
            return
        
        print(f"\n[USB] Detected {len(devices)} USB Device(s):")
        print("=" * 70)
        
        for i, device in enumerate(devices, 1):
            print(f"\n[Device {i}]")
            print(device.get_info())
        
        print("\n" + "=" * 70)


def auto_detect_usb() -> Optional[str]:
    """
    Automatically detect and select USB device for analysis.
    
    Returns:
        Path to USB device, or None if no device found
    """
    detector = USBDetector()
    devices = detector.list_devices()
    
    if not devices:
        print("\n[X] No USB devices currently connected")
        print("\nOptions:")
        print("  1. Insert a USB drive and wait for detection")
        print("  2. Manually specify a path to analyze")
        
        choice = input("\nWait for USB device? (y/n): ").strip().lower()
        
        if choice == 'y':
            device = detector.wait_for_device(timeout=60)
            if device:
                print(f"\n[+] USB Device Detected: {device.mount_point}")
                print(f"   Size: {device.total_gb:.2f} GB ({device.fstype})")
                return device.mount_point
            else:
                print("\n[!] Timeout: No device detected within 60 seconds")
                return None
        else:
            return None
    
    elif len(devices) == 1:
        # Only one device, auto-select
        device = devices[0]
        print(f"\n[+] USB Device Auto-Detected: {device.mount_point}")
        print(f"   Size: {device.total_gb:.2f} GB ({device.fstype})")
        print(f"   Free Space: {device.free_gb:.2f} GB")
        
        return device.mount_point
    
    else:
        # Multiple devices, let user choose
        print(f"\n[USB] Multiple USB Devices Detected ({len(devices)}):")
        print("=" * 70)
        
        for i, device in enumerate(devices, 1):
            print(f"\n[{i}] {device.mount_point}")
            print(f"    Size: {device.total_gb:.2f} GB ({device.fstype})")
            print(f"    Used: {device.used_gb:.2f} GB ({device.percent}%)")
        
        print("\n" + "=" * 70)
        
        while True:
            try:
                choice = input(f"\nSelect device (1-{len(devices)}): ").strip()
                idx = int(choice) - 1
                
                if 0 <= idx < len(devices):
                    selected = devices[idx]
                    print(f"\n[+] Selected: {selected.mount_point}")
                    return selected.mount_point
                else:
                    print(f"[X] Invalid choice. Please enter 1-{len(devices)}")
            except (ValueError, KeyboardInterrupt):
                print("\n[X] Selection cancelled")
                return None


if __name__ == "__main__":
    """Test USB detection functionality."""
    print("USB Device Detection Test")
    print("=" * 70)
    
    detector = USBDetector()
    detector.print_devices()
    
    # Test auto-detection
    print("\n\nTesting Auto-Detection:")
    path = auto_detect_usb()
    if path:
        print(f"\nReady to analyze: {path}")
    else:
        print("\nNo device selected")
