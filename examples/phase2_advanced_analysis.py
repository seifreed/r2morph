#!/usr/bin/env python3
"""
Phase 2 Advanced Deobfuscation Demonstration

This example demonstrates the complete Phase 2 enhanced obfuscated binary 
analysis pipeline including:

1. Advanced packer detection (20+ packers)
2. Control Flow Obfuscation (CFO) simplification
3. Iterative multi-pass simplification
4. Binary rewriting and reconstruction
5. Anti-analysis bypass techniques
6. Custom virtualizer detection
7. Metamorphic engine detection
8. Comprehensive reporting

Usage:
    python phase2_advanced_analysis.py <input_binary> [options]
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, Any

# r2morph imports
from r2morph import Binary
from r2morph.detection import (
    ObfuscationDetector, 
    AntiAnalysisBypass,
    AntiAnalysisType
)
from r2morph.devirtualization import (
    CFOSimplifier,
    IterativeSimplifier,
    BinaryRewriter,
    SimplificationStrategy
)
from r2morph.analysis.symbolic import (
    AngrBridge, 
    PathExplorer,
    ConstraintSolver
)
from r2morph.instrumentation import FridaEngine


def print_banner():
    """Print the analysis banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                    R2MORPH Phase 2 Advanced Analysis                ║
║                  Enhanced Obfuscated Binary Analysis                ║
╠══════════════════════════════════════════════════════════════════════╣
║ • Advanced Packer Detection (20+ packers)                           ║
║ • Control Flow Obfuscation Simplification                           ║
║ • Iterative Multi-Pass Deobfuscation                                ║
║ • Binary Rewriting & Reconstruction                                 ║
║ • Anti-Analysis Bypass Framework                                    ║
║ • Custom Virtualizer Detection                                      ║
║ • Metamorphic Engine Detection                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def analyze_basic_obfuscation(binary: Binary, detector: ObfuscationDetector) -> Dict[str, Any]:
    """Perform basic obfuscation analysis."""
    print("\n🔍 [1/8] Basic Obfuscation Analysis")
    print("=" * 50)
    
    # Basic detection
    result = detector.analyze_binary(binary)
    
    print(f"📦 Packer Detected: {result.packer_detected.value if result.packer_detected else 'None'}")
    print(f"🖥️  VM Protection: {'Yes' if result.vm_detected else 'No'}")
    print(f"🛡️  Anti-Analysis: {'Yes' if result.anti_analysis_detected else 'No'}")
    print(f"🔀 Control Flow Flattening: {'Yes' if result.control_flow_flattened else 'No'}")
    print(f"🧮 MBA Expressions: {result.mba_expressions_found}")
    print(f"🎭 Opaque Predicates: {result.opaque_predicates_found}")
    print(f"📊 Confidence Score: {result.confidence_score:.2f}")
    
    if result.obfuscation_techniques:
        print(f"\n🎯 Techniques Detected ({len(result.obfuscation_techniques)}):")
        for i, technique in enumerate(result.obfuscation_techniques[:5], 1):
            print(f"   {i}. {technique}")
        if len(result.obfuscation_techniques) > 5:
            print(f"   ... and {len(result.obfuscation_techniques) - 5} more")
    
    return {
        "basic_result": result.__dict__,
        "requires_advanced": result.vm_detected or result.mba_detected or result.control_flow_flattened
    }


def analyze_extended_packers(binary: Binary, detector: ObfuscationDetector) -> Dict[str, Any]:
    """Perform extended packer analysis."""
    print("\n🔍 [2/8] Extended Packer Detection")
    print("=" * 50)
    
    # Custom virtualizer detection
    custom_vm = detector.detect_custom_virtualizer(binary)
    print(f"🤖 Custom Virtualizer: {'Yes' if custom_vm['detected'] else 'No'}")
    if custom_vm['detected']:
        print(f"   Type: {custom_vm['vm_type']}")
        print(f"   Confidence: {custom_vm['confidence']:.2f}")
    
    # Layer analysis
    layers = detector.detect_code_packing_layers(binary)
    print(f"📚 Packing Layers: {layers['layers_detected']}")
    print(f"🔧 Requires Unpacking: {'Yes' if layers['requires_unpacking'] else 'No'}")
    
    if layers['packers']:
        print(f"\n📦 Detected Packers ({len(layers['packers'])}):")
        for packer in layers['packers']:
            print(f"   • {packer['name']} ({packer['confidence']:.2f})")
    
    # Metamorphic detection
    metamorphic = detector.detect_metamorphic_engine(binary)
    print(f"\n🧬 Metamorphic Engine: {'Yes' if metamorphic['detected'] else 'No'}")
    if metamorphic['detected']:
        print(f"   Polymorphic Ratio: {metamorphic['polymorphic_ratio']:.1%}")
        print(f"   Confidence: {metamorphic['confidence']:.2f}")
    
    return {
        "custom_vm": custom_vm,
        "layers": layers,
        "metamorphic": metamorphic
    }


def apply_anti_analysis_bypass(binary: Binary) -> Dict[str, Any]:
    """Apply anti-analysis bypass techniques."""
    print("\n🛡️ [3/8] Anti-Analysis Bypass")
    print("=" * 50)
    
    bypass_framework = AntiAnalysisBypass()
    
    # Detect anti-analysis techniques
    detected_techniques = bypass_framework.detect_anti_analysis_techniques(binary)
    print(f"🎯 Techniques Detected: {len(detected_techniques)}")
    
    for technique, confidence in detected_techniques.items():
        print(f"   • {technique.value}: {confidence:.2f}")
    
    # Apply comprehensive bypass
    if detected_techniques:
        print("\n🔧 Applying Bypasses...")
        bypass_result = bypass_framework.apply_comprehensive_bypass(detected_techniques)
        
        print(f"✅ Bypasses Applied: {len(bypass_result.techniques_applied)}")
        print(f"📊 Bypass Confidence: {bypass_result.bypass_confidence:.2f}")
        
        if bypass_result.warnings:
            print(f"⚠️  Warnings: {len(bypass_result.warnings)}")
            
        return {
            "detected_techniques": {t.value: c for t, c in detected_techniques.items()},
            "bypass_result": bypass_result.__dict__,
            "bypass_framework": bypass_framework
        }
    else:
        print("✅ No anti-analysis techniques detected")
        return {"detected_techniques": {}, "bypass_result": None}


def perform_symbolic_analysis(binary: Binary, has_vm: bool) -> Dict[str, Any]:
    """Perform symbolic execution analysis."""
    print("\n🧠 [4/8] Symbolic Execution Analysis")
    print("=" * 50)
    
    results = {}
    
    try:
        # Set up symbolic execution
        angr_bridge = AngrBridge(binary)
        
        if angr_bridge.project:
            print("✅ Angr project initialized")
            
            # Path exploration
            path_explorer = PathExplorer(angr_bridge)
            
            if has_vm:
                print("🔍 Exploring VM handlers...")
                vm_result = path_explorer.explore_vm_handlers()
                if vm_result:
                    print(f"   VM Handlers Found: {len(vm_result.vm_handlers_found)}")
                    results['vm_handlers'] = vm_result.__dict__
            else:
                print("🔍 Exploring function paths...")
                # Get first function for analysis
                functions = binary.get_functions()
                if functions:
                    func_addr = functions[0].get('offset', 0)
                    func_result = path_explorer.explore_function(func_addr)
                    if func_result:
                        print(f"   Paths Explored: {func_result.paths_explored}")
                        results['function_analysis'] = func_result.__dict__
            
            # Constraint solving
            print("🧮 Testing constraint solver...")
            constraint_solver = ConstraintSolver()
            test_constraints = ["x > 0", "x < 100", "x != 50"]
            solver_result = constraint_solver.solve_constraints(test_constraints)
            if solver_result:
                print("✅ Constraint solver operational")
                results['constraint_solver'] = True
        else:
            print("❌ Angr not available or failed to initialize")
            results['error'] = "Angr unavailable"
            
    except Exception as e:
        print(f"❌ Symbolic analysis failed: {e}")
        results['error'] = str(e)
    
    return results


def apply_cfo_simplification(binary: Binary) -> Dict[str, Any]:
    """Apply Control Flow Obfuscation simplification."""
    print("\n🔀 [5/8] Control Flow Obfuscation Simplification")
    print("=" * 50)
    
    results = {}
    
    try:
        cfo_simplifier = CFOSimplifier(binary)
        
        # Get functions to analyze
        functions = binary.get_functions()[:5]  # Limit for demo
        
        print(f"🎯 Analyzing {len(functions)} functions for CFO patterns...")
        
        total_complexity_reduction = 0
        simplified_functions = 0
        
        for func in functions:
            func_addr = func.get('offset', 0)
            result = cfo_simplifier.simplify_control_flow(func_addr)
            
            if result.success:
                complexity_reduction = result.original_complexity - result.simplified_complexity
                if complexity_reduction > 0:
                    simplified_functions += 1
                    total_complexity_reduction += complexity_reduction
                    print(f"   Function 0x{func_addr:x}: {complexity_reduction} complexity reduced")
        
        print(f"✅ Simplified {simplified_functions} functions")
        print(f"📊 Total Complexity Reduction: {total_complexity_reduction}")
        
        results = {
            "functions_analyzed": len(functions),
            "functions_simplified": simplified_functions,
            "total_complexity_reduction": total_complexity_reduction
        }
        
    except Exception as e:
        print(f"❌ CFO simplification failed: {e}")
        results['error'] = str(e)
    
    return results


def perform_iterative_simplification(binary: Binary) -> Dict[str, Any]:
    """Perform iterative multi-pass simplification."""
    print("\n🔄 [6/8] Iterative Multi-Pass Simplification")
    print("=" * 50)
    
    results = {}
    
    try:
        # Initialize iterative simplifier
        simplifier = IterativeSimplifier(binary)
        
        print("🚀 Starting iterative simplification...")
        print("   Strategy: Adaptive")
        print("   Max Iterations: 10")
        print("   Timeout: 60 seconds")
        
        # Run simplification
        result = simplifier.simplify(
            strategy=SimplificationStrategy.ADAPTIVE,
            max_iterations=10,
            timeout=60
        )
        
        if result.success:
            print(f"✅ Simplification completed in {result.metrics.execution_time:.1f}s")
            print(f"🔄 Iterations: {result.metrics.iteration}")
            print(f"📊 Complexity Reduction: {result.metrics.complexity_reduction:.1%}")
            print(f"🧮 Expressions Simplified: {result.metrics.simplified_expressions}")
            print(f"🖥️  Handlers Devirtualized: {result.metrics.devirtualized_handlers}")
            
            # Show phases completed
            print(f"\n📋 Phases Completed ({len(result.phases_completed)}):")
            for phase in result.phases_completed:
                print(f"   ✓ {phase.value}")
            
            results = {
                "success": True,
                "metrics": result.metrics.__dict__,
                "phases": [p.value for p in result.phases_completed],
                "warnings": result.warnings
            }
        else:
            print("❌ Iterative simplification failed")
            print(f"   Errors: {result.errors}")
            results = {"success": False, "errors": result.errors}
        
    except Exception as e:
        print(f"❌ Iterative simplification failed: {e}")
        results['error'] = str(e)
    
    return results


def perform_binary_rewriting(binary: Binary, output_path: str) -> Dict[str, Any]:
    """Perform binary rewriting and reconstruction."""
    print("\n🔧 [7/8] Binary Rewriting & Reconstruction")
    print("=" * 50)
    
    results = {}
    
    try:
        # Initialize binary rewriter
        rewriter = BinaryRewriter(binary)
        
        print("🔍 Analyzing binary structure...")
        stats = rewriter.get_rewrite_statistics()
        print(f"   Format: {stats['binary_format']}")
        print(f"   Architecture: {stats['architecture']}")
        print(f"   Sections: {stats['sections']}")
        print(f"   Relocations: {stats['relocations']}")
        
        # Add some example patches
        print("\n🔧 Adding example patches...")
        functions = binary.get_functions()[:3]  # First 3 functions
        
        patches_added = 0
        for func in functions:
            func_addr = func.get('offset', 0)
            # Add a simple NOP instruction as example
            if rewriter.add_patch(func_addr, ["nop"]):
                patches_added += 1
        
        print(f"   Patches Added: {patches_added}")
        
        # Perform rewriting
        print("\n⚙️  Performing binary rewrite...")
        rewrite_result = rewriter.rewrite_binary(output_path)
        
        if rewrite_result.success:
            print(f"✅ Binary rewritten successfully")
            print(f"   Output: {rewrite_result.output_path}")
            print(f"   Patches Applied: {rewrite_result.patches_applied}")
            print(f"   Relocations Updated: {rewrite_result.relocations_updated}")
            print(f"   Size Change: {rewrite_result.size_change} bytes")
            print(f"   Execution Time: {rewrite_result.execution_time:.1f}s")
            
            # Show integrity checks
            checks = rewrite_result.integrity_checks
            passed_checks = sum(1 for check in checks.values() if check)
            print(f"   Integrity Checks: {passed_checks}/{len(checks)} passed")
            
            results = {
                "success": True,
                "output_path": rewrite_result.output_path,
                "stats": rewrite_result.__dict__
            }
        else:
            print("❌ Binary rewriting failed")
            print(f"   Errors: {rewrite_result.errors}")
            results = {"success": False, "errors": rewrite_result.errors}
        
    except Exception as e:
        print(f"❌ Binary rewriting failed: {e}")
        results['error'] = str(e)
    
    return results


def generate_comprehensive_report(binary: Binary, detector: ObfuscationDetector, 
                                 analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate comprehensive analysis report."""
    print("\n📊 [8/8] Comprehensive Report Generation")
    print("=" * 50)
    
    try:
        # Generate comprehensive report
        report = detector.get_comprehensive_report(binary)
        
        # Add our analysis results
        report["phase2_analysis"] = analysis_results
        
        # Calculate overall statistics
        total_techniques = len(report.get("obfuscation_analysis", {}).get("obfuscation_techniques", []))
        vm_detected = report.get("obfuscation_analysis", {}).get("vm_detected", False)
        layers_detected = report.get("layer_analysis", {}).get("layers_detected", 0)
        
        print(f"📋 Report Generated:")
        print(f"   Timestamp: {report['timestamp']}")
        print(f"   Binary: {report['binary_info']['path']}")
        print(f"   Format: {report['binary_info']['format']}")
        print(f"   Architecture: {report['binary_info']['architecture']} {report['binary_info']['bits']}-bit")
        
        print(f"\n🎯 Summary:")
        print(f"   Obfuscation Techniques: {total_techniques}")
        print(f"   VM Protection: {'Yes' if vm_detected else 'No'}")
        print(f"   Packing Layers: {layers_detected}")
        
        # Show recommendations
        recommendations = report.get("recommendations", [])
        if recommendations:
            print(f"\n💡 Recommendations ({len(recommendations)}):")
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
        
        return report
        
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        return {"error": str(e)}


def save_results(results: Dict[str, Any], output_dir: Path):
    """Save analysis results to files."""
    try:
        output_dir.mkdir(exist_ok=True)
        
        # Save JSON report
        json_path = output_dir / "analysis_report.json"
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n💾 Results saved to: {output_dir}")
        print(f"   📄 JSON Report: {json_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to save results: {e}")
        return False


def main():
    """Main analysis function."""
    parser = argparse.ArgumentParser(
        description="R2morph Phase 2 Advanced Obfuscated Binary Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("binary", help="Path to binary file to analyze")
    parser.add_argument("-o", "--output", help="Output directory for results", default="./analysis_output")
    parser.add_argument("--skip-symbolic", action="store_true", help="Skip symbolic execution analysis")
    parser.add_argument("--skip-rewriting", action="store_true", help="Skip binary rewriting")
    parser.add_argument("--timeout", type=int, default=300, help="Analysis timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Validate input
    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"❌ Error: Binary file not found: {binary_path}")
        sys.exit(1)
    
    output_dir = Path(args.output)
    output_binary = output_dir / f"{binary_path.stem}_deobfuscated{binary_path.suffix}"
    
    print_banner()
    print(f"🎯 Target Binary: {binary_path}")
    print(f"📁 Output Directory: {output_dir}")
    print(f"⏱️  Timeout: {args.timeout}s")
    
    start_time = time.time()
    analysis_results = {}
    
    try:
        # Load and analyze binary
        print("\n🚀 Loading binary...")
        with Binary(str(binary_path)) as binary:
            binary.analyze()
            
            # Initialize detector
            detector = ObfuscationDetector()
            
            # Phase 2 Analysis Pipeline
            print("\n" + "="*70)
            print("                    PHASE 2 ANALYSIS PIPELINE")
            print("="*70)
            
            # 1. Basic obfuscation analysis
            analysis_results["basic"] = analyze_basic_obfuscation(binary, detector)
            
            # 2. Extended packer detection
            analysis_results["extended"] = analyze_extended_packers(binary, detector)
            
            # 3. Anti-analysis bypass
            analysis_results["bypass"] = apply_anti_analysis_bypass(binary)
            
            # 4. Symbolic execution (optional)
            if not args.skip_symbolic:
                has_vm = analysis_results["basic"]["basic_result"].get("vm_detected", False)
                analysis_results["symbolic"] = perform_symbolic_analysis(binary, has_vm)
            
            # 5. CFO simplification
            analysis_results["cfo"] = apply_cfo_simplification(binary)
            
            # 6. Iterative simplification
            analysis_results["iterative"] = perform_iterative_simplification(binary)
            
            # 7. Binary rewriting (optional)
            if not args.skip_rewriting:
                analysis_results["rewriting"] = perform_binary_rewriting(binary, str(output_binary))
            
            # 8. Comprehensive report
            analysis_results["report"] = generate_comprehensive_report(binary, detector, analysis_results)
        
        # Calculate final statistics
        end_time = time.time()
        total_time = end_time - start_time
        
        print("\n" + "="*70)
        print("                      ANALYSIS COMPLETE")
        print("="*70)
        print(f"⏱️  Total Analysis Time: {total_time:.1f}s")
        
        # Success metrics
        successful_phases = sum(1 for phase, result in analysis_results.items() 
                              if isinstance(result, dict) and result.get("success") != False 
                              and "error" not in result)
        total_phases = len(analysis_results)
        
        print(f"✅ Successful Phases: {successful_phases}/{total_phases}")
        
        # Save results
        if save_results(analysis_results, output_dir):
            print(f"📊 Analysis complete! Results saved to {output_dir}")
        
        # Cleanup environment if bypass was applied
        bypass_framework = analysis_results.get("bypass", {}).get("bypass_framework")
        if bypass_framework:
            print("\n🔧 Restoring environment...")
            bypass_framework.restore_environment()
            print("✅ Environment restored")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())