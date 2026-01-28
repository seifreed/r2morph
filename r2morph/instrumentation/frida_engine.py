"""
Core Frida engine for dynamic instrumentation.

This module provides the main interface to Frida for instrumenting
target processes and collecting runtime information.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

try:
    import frida
    import frida.core
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None

logger = logging.getLogger(__name__)


class InstrumentationMode(Enum):
    """Frida instrumentation modes."""
    
    SPAWN = "spawn"         # Spawn new process
    ATTACH = "attach"       # Attach to existing process
    REMOTE = "remote"       # Remote instrumentation


@dataclass
class InstrumentationResult:
    """Result from dynamic instrumentation."""
    
    success: bool = False
    process_id: int = 0
    instrumentation_time: float = 0.0
    api_calls_captured: int = 0
    memory_dumps: list[dict[str, Any]] = field(default_factory=list)
    anti_analysis_detected: list[str] = field(default_factory=list)
    error_message: str | None = None


class FridaEngine:
    """
    Core Frida engine for dynamic binary instrumentation.
    
    Provides high-level interface for:
    - Process spawning and attachment
    - Script injection and management
    - Runtime data collection
    - Anti-analysis detection and bypass
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialize Frida engine.
        
        Args:
            timeout: Default timeout for operations
        """
        if not FRIDA_AVAILABLE:
            raise ImportError("Frida is required for dynamic instrumentation. Install with: pip install frida frida-tools")
        
        self.timeout = timeout
        self.device: Any | None = None
        self.session: Any | None = None
        self.scripts: dict[str, Any] = {}
        
        # Runtime data collection
        self.api_calls: list[dict[str, Any]] = []
        self.memory_accesses: list[dict[str, Any]] = []
        self.anti_analysis_events: list[dict[str, Any]] = []
        
        # Statistics
        self.stats = {
            "processes_instrumented": 0,
            "scripts_loaded": 0,
            "api_calls_intercepted": 0,
            "errors_encountered": 0,
        }
    
    def initialize(self, device_id: str | None = None) -> bool:
        """
        Initialize Frida device connection.
        
        Args:
            device_id: Specific device ID, None for local
            
        Returns:
            True if initialization successful
        """
        try:
            if device_id:
                self.device = frida.get_device(device_id)
            else:
                self.device = frida.get_local_device()
            
            logger.info(f"Connected to Frida device: {self.device.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Frida device: {e}")
            return False
    
    def instrument_binary(self, 
                         binary_path: str | Path,
                         mode: InstrumentationMode = InstrumentationMode.SPAWN,
                         arguments: list[str] | None = None,
                         environment: dict[str, str] | None = None) -> InstrumentationResult:
        """
        Instrument a binary for dynamic analysis.
        
        Args:
            binary_path: Path to binary executable
            mode: Instrumentation mode
            arguments: Command line arguments
            environment: Environment variables
            
        Returns:
            InstrumentationResult with analysis data
        """
        start_time = time.time()
        result = InstrumentationResult()
        
        try:
            if not self.device:
                if not self.initialize():
                    result.error_message = "Failed to initialize Frida device"
                    return result
            
            binary_path = Path(binary_path)
            
            if mode == InstrumentationMode.SPAWN:
                # Spawn new process
                pid = self._spawn_process(binary_path, arguments, environment)
            elif mode == InstrumentationMode.ATTACH:
                # Attach to existing process
                pid = self._find_and_attach_process(binary_path.name)
            else:
                result.error_message = f"Unsupported instrumentation mode: {mode}"
                return result
            
            if not pid:
                result.error_message = "Failed to get target process ID"
                return result
            
            # Attach Frida session
            self.session = self.device.attach(pid)
            result.process_id = pid
            
            # Load basic instrumentation scripts
            self._load_basic_instrumentation()
            
            # Start analysis
            if mode == InstrumentationMode.SPAWN:
                self.device.resume(pid)
            
            # Collect data for specified time
            time.sleep(min(self.timeout, 10))  # Collect for up to 10 seconds
            
            result.success = True
            result.instrumentation_time = time.time() - start_time
            result.api_calls_captured = len(self.api_calls)
            result.anti_analysis_detected = [
                event["type"] for event in self.anti_analysis_events
            ]
            
            self.stats["processes_instrumented"] += 1
            
        except Exception as e:
            logger.error(f"Instrumentation failed: {e}")
            result.error_message = str(e)
            self.stats["errors_encountered"] += 1
        
        return result
    
    def _spawn_process(self, 
                      binary_path: Path,
                      arguments: list[str] | None = None,
                      environment: dict[str, str] | None = None) -> int | None:
        """Spawn a new process for instrumentation."""
        try:
            spawn_args = [str(binary_path)]
            if arguments:
                spawn_args.extend(arguments)
            
            spawn_options = {}
            if environment:
                spawn_options["env"] = environment
            
            pid = self.device.spawn(spawn_args, **spawn_options)
            logger.info(f"Spawned process {binary_path.name} with PID {pid}")
            return pid
            
        except Exception as e:
            logger.error(f"Failed to spawn process: {e}")
            return None
    
    def _find_and_attach_process(self, process_name: str) -> int | None:
        """Find and attach to existing process."""
        try:
            processes = self.device.enumerate_processes()
            
            for process in processes:
                if process.name == process_name:
                    logger.info(f"Found process {process_name} with PID {process.pid}")
                    return process.pid
            
            logger.error(f"Process {process_name} not found")
            return None
            
        except Exception as e:
            logger.error(f"Failed to find process: {e}")
            return None
    
    def _load_basic_instrumentation(self):
        """Load basic instrumentation scripts."""
        # API call monitoring script
        api_monitor_script = self._create_api_monitor_script()
        self.load_script("api_monitor", api_monitor_script)
        
        # Anti-analysis detection script
        anti_analysis_script = self._create_anti_analysis_script()
        self.load_script("anti_analysis", anti_analysis_script)
        
        # Memory access monitoring script
        memory_monitor_script = self._create_memory_monitor_script()
        self.load_script("memory_monitor", memory_monitor_script)
    
    def _create_api_monitor_script(self) -> str:
        """Create JavaScript script for API call monitoring."""
        return '''
        // API Call Monitoring Script
        
        // Track common Windows API calls
        const apis_to_monitor = [
            "kernel32.dll!CreateFileW",
            "kernel32.dll!CreateFileA", 
            "kernel32.dll!WriteFile",
            "kernel32.dll!ReadFile",
            "kernel32.dll!VirtualAlloc",
            "kernel32.dll!VirtualProtect",
            "kernel32.dll!GetProcAddress",
            "kernel32.dll!LoadLibraryA",
            "kernel32.dll!LoadLibraryW",
            "ntdll.dll!NtCreateFile",
            "ntdll.dll!NtWriteFile",
            "ntdll.dll!NtReadFile",
            "advapi32.dll!RegOpenKeyExW",
            "advapi32.dll!RegSetValueExW",
            "wininet.dll!InternetConnectW",
            "ws2_32.dll!connect",
            "ws2_32.dll!send",
            "ws2_32.dll!recv"
        ];
        
        apis_to_monitor.forEach(function(api) {
            try {
                const parts = api.split("!");
                const module = parts[0];
                const func = parts[1];
                
                const addr = Module.findExportByName(module, func);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                type: "api_call",
                                module: module,
                                function: func,
                                address: this.context.pc.toString(),
                                timestamp: Date.now(),
                                args: args.map(arg => arg.toString())
                            });
                        }
                    });
                }
            } catch (e) {
                // API not available in this process
            }
        });
        '''
    
    def _create_anti_analysis_script(self) -> str:
        """Create script for detecting anti-analysis techniques."""
        return '''
        // Anti-Analysis Detection Script
        
        // Detect debugger checks
        const debugger_apis = [
            "kernel32.dll!IsDebuggerPresent",
            "kernel32.dll!CheckRemoteDebuggerPresent",
            "ntdll.dll!NtQueryInformationProcess"
        ];
        
        debugger_apis.forEach(function(api) {
            try {
                const parts = api.split("!");
                const addr = Module.findExportByName(parts[0], parts[1]);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                type: "anti_debug",
                                api: parts[1],
                                address: this.context.pc.toString(),
                                timestamp: Date.now()
                            });
                        }
                    });
                }
            } catch (e) {}
        });
        
        // Detect VM detection attempts
        const vm_apis = [
            "kernel32.dll!GetSystemFirmwareTable",
            "advapi32.dll!RegOpenKeyExW"
        ];
        
        vm_apis.forEach(function(api) {
            try {
                const parts = api.split("!");
                const addr = Module.findExportByName(parts[0], parts[1]);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                type: "vm_detection",
                                api: parts[1],
                                address: this.context.pc.toString(),
                                timestamp: Date.now()
                            });
                        }
                    });
                }
            } catch (e) {}
        });
        
        // Detect timing attacks
        const timing_apis = [
            "kernel32.dll!GetTickCount",
            "kernel32.dll!QueryPerformanceCounter"
        ];
        
        timing_apis.forEach(function(api) {
            try {
                const parts = api.split("!");
                const addr = Module.findExportByName(parts[0], parts[1]);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                type: "timing_check",
                                api: parts[1],
                                address: this.context.pc.toString(),
                                timestamp: Date.now()
                            });
                        }
                    });
                }
            } catch (e) {}
        });
        '''
    
    def _create_memory_monitor_script(self) -> str:
        """Create script for monitoring memory operations."""
        return '''
        // Memory Access Monitoring Script
        
        // Monitor VirtualAlloc/VirtualProtect for dynamic code
        const memory_apis = [
            "kernel32.dll!VirtualAlloc",
            "kernel32.dll!VirtualProtect",
            "ntdll.dll!NtAllocateVirtualMemory",
            "ntdll.dll!NtProtectVirtualMemory"
        ];
        
        memory_apis.forEach(function(api) {
            try {
                const parts = api.split("!");
                const addr = Module.findExportByName(parts[0], parts[1]);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                type: "memory_operation",
                                api: parts[1],
                                address: this.context.pc.toString(),
                                timestamp: Date.now(),
                                operation: "allocate_or_protect"
                            });
                        }
                    });
                }
            } catch (e) {}
        });
        '''
    
    def load_script(self, name: str, script_source: str) -> bool:
        """
        Load a Frida script.
        
        Args:
            name: Script name
            script_source: JavaScript source code
            
        Returns:
            True if script loaded successfully
        """
        try:
            if not self.session:
                logger.error("No active session to load script")
                return False
            
            script = self.session.create_script(script_source)
            script.on('message', self._on_script_message)
            script.load()
            
            self.scripts[name] = script
            self.stats["scripts_loaded"] += 1
            
            logger.debug(f"Loaded script: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load script {name}: {e}")
            return False
    
    def _on_script_message(self, message: dict[str, Any], data: Any):
        """Handle messages from Frida scripts."""
        try:
            if message.get('type') == 'send':
                payload = message.get('payload', {})
                msg_type = payload.get('type')
                
                if msg_type == 'api_call':
                    self.api_calls.append(payload)
                    self.stats["api_calls_intercepted"] += 1
                elif msg_type in ['anti_debug', 'vm_detection', 'timing_check']:
                    self.anti_analysis_events.append(payload)
                elif msg_type == 'memory_operation':
                    self.memory_accesses.append(payload)
                
                logger.debug(f"Received message: {msg_type}")
                
        except Exception as e:
            logger.error(f"Error processing script message: {e}")
    
    def dump_memory_region(self, address: int, size: int) -> bytes | None:
        """
        Dump memory region from target process.
        
        Args:
            address: Start address
            size: Number of bytes to dump
            
        Returns:
            Memory contents or None if failed
        """
        try:
            if not self.session:
                return None
            
            # Create script to dump memory
            dump_script = f'''
            const addr = ptr({address});
            const size = {size};
            
            try {{
                const data = addr.readByteArray(size);
                send({{ type: "memory_dump", data: data }});
            }} catch (e) {{
                send({{ type: "error", message: e.message }});
            }}
            '''
            
            script = self.session.create_script(dump_script)
            
            memory_data = None
            
            def on_message(message, data):
                nonlocal memory_data
                if message.get('type') == 'send':
                    payload = message.get('payload', {})
                    if payload.get('type') == 'memory_dump':
                        memory_data = data
            
            script.on('message', on_message)
            script.load()
            
            # Wait for dump to complete
            time.sleep(0.1)
            script.unload()
            
            return memory_data
            
        except Exception as e:
            logger.error(f"Failed to dump memory: {e}")
            return None
    
    def get_runtime_statistics(self) -> dict[str, Any]:
        """Get runtime analysis statistics."""
        return {
            **self.stats,
            "api_calls_collected": len(self.api_calls),
            "memory_accesses_tracked": len(self.memory_accesses),
            "anti_analysis_events": len(self.anti_analysis_events),
            "unique_apis_called": len(set(
                call.get("function", "") for call in self.api_calls
            )),
        }
    
    def cleanup(self):
        """Clean up Frida resources."""
        try:
            # Unload all scripts
            for name, script in self.scripts.items():
                try:
                    script.unload()
                except Exception as e:
                    logger.debug(f"Failed to unload script '{name}': {e}")
            
            self.scripts.clear()
            
            # Detach session
            if self.session:
                self.session.detach()
                self.session = None
            
            logger.info("Cleaned up Frida resources")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def export_runtime_data(self, output_path: Path) -> bool:
        """
        Export collected runtime data to file.
        
        Args:
            output_path: Path to save data
            
        Returns:
            True if export successful
        """
        try:
            import json
            
            export_data = {
                "statistics": self.get_runtime_statistics(),
                "api_calls": self.api_calls,
                "memory_accesses": self.memory_accesses,
                "anti_analysis_events": self.anti_analysis_events,
                "timestamp": time.time(),
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Exported runtime data to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export runtime data: {e}")
            return False