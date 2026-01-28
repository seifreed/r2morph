#!/usr/bin/env python3
"""
Enhanced analysis example demonstrating the new obfuscated binary analysis capabilities.

This example showcases:
1. Advanced obfuscation detection (VMProtect, Themida, etc.)
2. Symbolic execution with Angr integration
3. Dynamic instrumentation with Frida
4. VM handler analysis and devirtualization
5. MBA expression simplification
6. Syntia semantic learning integration

Usage:
    python examples/enhanced_obfuscated_analysis.py /path/to/obfuscated_binary
"""

import sys
import time
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from r2morph import Binary
from r2morph.detection import ObfuscationDetector, PackerType, ObfuscationType
from r2morph.analysis.symbolic import AngrBridge, PathExplorer, ConstraintSolver, SyntiaFramework
from r2morph.instrumentation import FridaEngine, FRIDA_AVAILABLE
from r2morph.devirtualization import VMHandlerAnalyzer, MBASolver


def analyze_obfuscation_techniques(binary: Binary):
    """Demonstrate enhanced obfuscation detection."""
    print("\n" + "=" * 60)
    print("ENHANCED OBFUSCATION DETECTION")
    print("=" * 60)
    
    detector = ObfuscationDetector()
    result = detector.analyze_binary(binary)
    
    print(f"\n📦 Packer Detection:")
    print(f"  Detected: {result.packer_detected.value}")
    
    print(f"\n🔍 Obfuscation Techniques Found:")
    for technique in result.obfuscation_techniques:
        confidence = result.confidence_scores.get(technique.value, 0.0)
        print(f"  • {technique.value}: {confidence:.2f} confidence")
    
    if result.vm_detected:
        print(f"\n🤖 Virtual Machine Detection:")
        print(f"  VM Detected: ✅ Yes")
        print(f"  Handler Count: {result.vm_handler_count}")
        print(f"  Confidence: {result.confidence_scores.get('virtualization', 0.0):.2f}")
    
    if result.mba_expressions_found > 0:
        print(f"\n🧮 Mixed Boolean Arithmetic:")
        print(f"  MBA Expressions: {result.mba_expressions_found}")
        
    if result.opaque_predicates_found > 0:
        print(f"\n🎭 Opaque Predicates:")
        print(f"  Opaque Predicates: {result.opaque_predicates_found}")
    
    print(f"\n📋 Analysis Recommendations:")
    if result.requires_devirtualization:
        print("  ⚡ Devirtualization required")
    if result.requires_dynamic_analysis:
        print("  🏃 Dynamic analysis recommended")
    
    return result


def demonstrate_symbolic_execution(binary: Binary):
    """Demonstrate symbolic execution with Angr."""
    print("\n" + "=" * 60)
    print("SYMBOLIC EXECUTION ANALYSIS")
    print("=" * 60)
    
    try:
        # Initialize Angr bridge
        angr_bridge = AngrBridge(binary)
        path_explorer = PathExplorer(angr_bridge)
        
        print("\n🔄 Initializing symbolic execution...")
        
        # Get functions for analysis
        functions = binary.get_functions()
        if not functions:
            print("  ❌ No functions found for symbolic execution")
            return
        
        # Analyze first few functions
        for i, func in enumerate(functions[:3]):
            func_addr = func.get("offset", 0)
            func_name = func.get("name", f"func_{func_addr:x}")
            
            print(f"\n🎯 Analyzing function: {func_name} @ 0x{func_addr:x}")
            
            # Explore paths in this function
            result = path_explorer.explore_function(
                func_addr,
                max_paths=20,
                timeout=10
            )
            
            print(f"  • Paths explored: {result.paths_explored}")
            print(f"  • Execution time: {result.execution_time:.2f}s")
            
            if result.vm_handlers_found > 0:
                print(f"  • VM handlers found: {result.vm_handlers_found}")
            
            if result.opaque_predicates_found > 0:
                print(f"  • Opaque predicates: {result.opaque_predicates_found}")
    
    except ImportError:
        print("  ❌ Angr not available - install with: pip install angr")
    except Exception as e:
        print(f"  ❌ Symbolic execution failed: {e}")


def demonstrate_dynamic_instrumentation(binary_path: Path):
    """Demonstrate dynamic instrumentation with Frida."""
    print("\n" + "=" * 60)
    print("DYNAMIC INSTRUMENTATION")
    print("=" * 60)
    
    if not FRIDA_AVAILABLE:
        print("  ❌ Frida not available - install with: pip install frida frida-tools")
        return
    
    try:
        frida_engine = FridaEngine(timeout=10)
        
        print("\n🚀 Starting dynamic analysis...")
        
        # Instrument the binary
        result = frida_engine.instrument_binary(
            binary_path,
            arguments=[],
        )
        
        if result.success:
            print(f"  ✅ Instrumentation successful")
            print(f"  • Process ID: {result.process_id}")
            print(f"  • API calls captured: {result.api_calls_captured}")
            print(f"  • Analysis time: {result.instrumentation_time:.2f}s")
            
            if result.anti_analysis_detected:
                print(f"  • Anti-analysis detected: {', '.join(result.anti_analysis_detected)}")
            
            # Get detailed statistics
            stats = frida_engine.get_runtime_statistics()
            print(f"  • Unique APIs called: {stats.get('unique_apis_called', 0)}")
            print(f"  • Memory accesses tracked: {stats.get('memory_accesses_tracked', 0)}")
        else:
            print(f"  ❌ Instrumentation failed: {result.error_message}")
        
        # Cleanup
        frida_engine.cleanup()
    
    except Exception as e:
        print(f"  ❌ Dynamic instrumentation failed: {e}")


def demonstrate_vm_handler_analysis(binary: Binary, obfuscation_result):
    """Demonstrate VM handler analysis."""
    print("\n" + "=" * 60)
    print("VM HANDLER ANALYSIS")
    print("=" * 60)
    
    if not obfuscation_result.vm_detected:
        print("  ℹ️  No virtualization detected - skipping VM analysis")
        return
    
    try:
        analyzer = VMHandlerAnalyzer(binary)
        
        print("\n🔍 Searching for VM dispatcher...")
        
        # Try to find VM dispatcher (simplified approach)
        functions = binary.get_functions()
        potential_dispatchers = []
        
        for func in functions:
            func_addr = func.get("offset", 0)
            func_size = func.get("size", 0)
            
            # Large functions with many basic blocks might be dispatchers
            if func_size > 1000:  # Large function
                try:
                    blocks = binary.get_basic_blocks(func_addr)
                    if len(blocks) > 20:  # Many basic blocks
                        potential_dispatchers.append(func_addr)
                except Exception:
                    continue
        
        if potential_dispatchers:
            dispatcher_addr = potential_dispatchers[0]
            print(f"  🎯 Analyzing potential dispatcher at 0x{dispatcher_addr:x}")
            
            # Analyze VM architecture
            vm_arch = analyzer.analyze_vm_architecture(dispatcher_addr)
            
            print(f"\n📊 VM Architecture Analysis:")
            print(f"  • Dispatcher: 0x{vm_arch.dispatcher_address:x}")
            if vm_arch.handler_table_address:
                print(f"  • Handler table: 0x{vm_arch.handler_table_address:x}")
            print(f"  • Handlers found: {len(vm_arch.handlers)}")
            
            # Show handler statistics
            stats = analyzer.get_handler_statistics()
            print(f"  • Average confidence: {stats.get('average_confidence', 0.0):.2f}")
            
            handler_types = stats.get('handler_types', {})
            if handler_types:
                print(f"  • Handler types:")
                for handler_type, count in handler_types.items():
                    print(f"    - {handler_type}: {count}")
        else:
            print("  ⚠️  No VM dispatcher candidates found")
    
    except Exception as e:
        print(f"  ❌ VM handler analysis failed: {e}")


def demonstrate_mba_simplification():
    """Demonstrate MBA expression simplification."""
    print("\n" + "=" * 60)
    print("MBA EXPRESSION SIMPLIFICATION")
    print("=" * 60)
    
    try:
        solver = MBASolver()
        
        # Example MBA expressions (common obfuscation patterns)
        test_expressions = [
            "x + y - (x & y)",           # Should simplify to x | y
            "x ^ y + 2 * (x & y)",       # Should simplify to x + y  
            "(x & y) | ~(x ^ y)",        # Should simplify to x == y
            "x * 2 - y",                 # Can be simplified
            "a & b | a & c",             # Should simplify to a & (b | c)
        ]
        
        print("\n🧮 Testing MBA simplification:")
        
        for i, expr in enumerate(test_expressions, 1):
            print(f"\n  Test {i}: {expr}")
            
            # Analyze the expression
            mba = solver.analyze_mba_expression(expr)
            print(f"    • Variables: {', '.join(mba.variables) if mba.variables else 'none'}")
            print(f"    • Complexity: {mba.complexity.value}")
            print(f"    • Linear: {'Yes' if mba.is_linear else 'No'}")
            
            # Try to simplify
            result = solver.simplify_mba(expr)
            
            if result.success:
                print(f"    • Simplified: {result.simplified_expression}")
                print(f"    • Reduction: {result.complexity_reduction:.1%}")
                print(f"    • Method: {result.method_used}")
                if result.equivalent_native:
                    print(f"    • Native equivalent: {result.equivalent_native}")
            else:
                print(f"    • Simplification failed")
        
        # Show statistics
        stats = solver.get_solver_statistics()
        print(f"\n📈 MBA Solver Statistics:")
        print(f"  • Success rate: {stats.get('success_rate', 0.0):.1%}")
        print(f"  • Pattern matches: {stats.get('pattern_matches', 0)}")
        
    except Exception as e:
        print(f"  ❌ MBA simplification failed: {e}")


def demonstrate_syntia_integration():
    """Demonstrate Syntia semantic learning."""
    print("\n" + "=" * 60)
    print("SYNTIA SEMANTIC LEARNING")
    print("=" * 60)
    
    try:
        syntia = SyntiaFramework()
        
        print("\n🧠 Testing instruction semantic learning:")
        
        # Example instruction sequences (typical in obfuscated code)
        test_instructions = [
            (0x401000, b'\x01\xd8', "add eax, ebx"),
            (0x401002, b'\x31\xc0', "xor eax, eax"),
            (0x401004, b'\x50', "push eax"),
            (0x401005, b'\x58', "pop eax"),
            (0x401006, b'\x89\xd8', "mov eax, ebx"),
        ]
        
        for addr, inst_bytes, disasm in test_instructions:
            print(f"\n  📍 0x{addr:x}: {disasm}")
            
            # Learn semantics for this instruction
            semantics = syntia.learn_instruction_semantics(
                inst_bytes, addr, disasm
            )
            
            print(f"    • Learned: {semantics.learned_semantics}")
            print(f"    • Confidence: {semantics.confidence:.2f}")
            print(f"    • Complexity: {semantics.complexity.value}")
            print(f"    • Learning time: {semantics.learning_time:.3f}s")
        
        # Show statistics
        stats = syntia.get_synthesis_statistics()
        print(f"\n📊 Syntia Statistics:")
        print(f"  • Instructions analyzed: {stats.get('instructions_analyzed', 0)}")
        print(f"  • Semantics learned: {stats.get('semantics_learned', 0)}")
        print(f"  • Success rate: {stats.get('success_rate', 0.0):.1%}")
        print(f"  • Cache hits: {stats.get('cache_hits', 0)}")
        
    except Exception as e:
        print(f"  ❌ Syntia integration failed: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python enhanced_obfuscated_analysis.py <binary_path>")
        print("\nThis example demonstrates enhanced analysis of obfuscated binaries including:")
        print("  • Advanced packer detection (VMProtect, Themida, etc.)")
        print("  • Symbolic execution with Angr")
        print("  • Dynamic instrumentation with Frida")
        print("  • VM handler analysis and devirtualization")
        print("  • MBA expression simplification")
        print("  • Syntia semantic learning")
        sys.exit(1)

    binary_path = Path(sys.argv[1])
    
    if not binary_path.exists():
        print(f"❌ Binary not found: {binary_path}")
        sys.exit(1)

    print("=" * 80)
    print("R2MORPH - ENHANCED OBFUSCATED BINARY ANALYSIS")
    print("=" * 80)
    print(f"\n🎯 Analyzing binary: {binary_path}\n")

    start_time = time.time()

    try:
        with Binary(binary_path) as binary:
            print("[+] Loading and analyzing binary...")
            binary.analyze(level="aaa")

            arch_info = binary.get_arch_info()
            functions = binary.get_functions()

            print("\n📋 Binary Information:")
            print(f"  Architecture: {arch_info['arch']} ({arch_info['bits']}-bit)")
            print(f"  Format: {arch_info['format']}")
            print(f"  Functions: {len(functions)}")

            # 1. Enhanced obfuscation detection
            obfuscation_result = analyze_obfuscation_techniques(binary)
            
            # 2. Symbolic execution analysis
            demonstrate_symbolic_execution(binary)
            
            # 3. Dynamic instrumentation (if Frida available)
            demonstrate_dynamic_instrumentation(binary_path)
            
            # 4. VM handler analysis (if virtualization detected)
            demonstrate_vm_handler_analysis(binary, obfuscation_result)
            
            # 5. MBA simplification demonstration
            demonstrate_mba_simplification()
            
            # 6. Syntia semantic learning
            demonstrate_syntia_integration()

    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()

    total_time = time.time() - start_time
    
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)
    print(f"Total analysis time: {total_time:.2f} seconds")
    print("✅ Enhanced obfuscated binary analysis complete!")
    print("\nThis demonstrates r2morph's new capabilities for analyzing")
    print("sophisticated obfuscated binaries including VM-based packers.")
    print("=" * 80)


if __name__ == "__main__":
    main()