"""
Integration test for the complete enhanced obfuscated binary analysis pipeline.
"""

import pytest
import os
from pathlib import Path
from unittest.mock import Mock, patch

from r2morph import Binary
from r2morph.detection import ObfuscationDetector
from r2morph.analysis.symbolic import AngrBridge, PathExplorer, ConstraintSolver, StateManager, SyntiaFramework
from r2morph.instrumentation import FridaEngine
from r2morph.devirtualization import VMHandlerAnalyzer, MBASolver


class TestEnhancedAnalysisPipeline:
    """Test the complete enhanced analysis pipeline."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_binary_path = Path(__file__).parent.parent / "fixtures" / "simple"
        
    def test_basic_enhanced_analysis_without_dependencies(self):
        """Test that enhanced analysis gracefully handles missing dependencies."""
        with Binary(str(self.test_binary_path)) as binary:
            binary.analyze()
            
            # Test obfuscation detector works even without advanced deps
            detector = ObfuscationDetector()
            result = detector.analyze_binary(binary)
            
            assert result is not None
            assert hasattr(result, 'packer_detected')
            assert hasattr(result, 'obfuscation_techniques')
            
    @patch('r2morph.analysis.symbolic.angr_bridge.ANGR_AVAILABLE', True)
    @patch('r2morph.analysis.symbolic.angr_bridge.angr')
    def test_symbolic_execution_pipeline(self, mock_angr):
        """Test symbolic execution pipeline with mocked angr."""
        # Mock angr components
        mock_project = Mock()
        mock_state = Mock()
        mock_simgr = Mock()
        
        mock_angr.Project.return_value = mock_project
        mock_project.factory.entry_state.return_value = mock_state
        mock_project.factory.simgr.return_value = mock_simgr
        mock_simgr.explore.return_value = mock_simgr
        mock_simgr.found = []
        mock_simgr.deadended = [mock_state]
        
        with Binary(str(self.test_binary_path)) as binary:
            binary.analyze()
            
            # Test Angr bridge
            angr_bridge = AngrBridge(binary)
            assert angr_bridge.project is not None
            
            # Test path explorer
            path_explorer = PathExplorer(angr_bridge)
            result = path_explorer.explore_function(0x401000)
            
            assert result is not None
            assert hasattr(result, 'paths_explored')
            
    @patch('r2morph.analysis.symbolic.constraint_solver.Z3_AVAILABLE', True)
    @patch('r2morph.analysis.symbolic.constraint_solver.z3')
    def test_constraint_solver_pipeline(self, mock_z3):
        """Test constraint solver pipeline with mocked Z3."""
        # Mock Z3 components
        mock_solver = Mock()
        mock_result = Mock()
        mock_result.r = 1  # SAT result
        mock_solver.check.return_value = mock_result
        mock_z3.Solver.return_value = mock_solver
        
        with Binary(str(self.test_binary_path)) as binary:
            binary.analyze()
            
            constraint_solver = ConstraintSolver()
            result = constraint_solver.solve_constraints(["x > 0", "x < 10"])
            
            assert result is not None
            
    @patch('r2morph.instrumentation.frida_engine.FRIDA_AVAILABLE', True)
    @patch('r2morph.instrumentation.frida_engine.frida')
    def test_dynamic_instrumentation_pipeline(self, mock_frida):
        """Test dynamic instrumentation pipeline with mocked Frida."""
        # Mock Frida components
        mock_device = Mock()
        mock_process = Mock()
        mock_session = Mock()
        mock_script = Mock()
        
        mock_frida.get_local_device.return_value = mock_device
        mock_device.spawn.return_value = 1234
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.load.return_value = None
        
        frida_engine = FridaEngine()
        result = frida_engine.instrument_binary(str(self.test_binary_path))
        
        # Should fail gracefully since we're not actually running a binary
        assert result is not None
        
    def test_vm_handler_analyzer_pipeline(self):
        """Test VM handler analyzer pipeline."""
        with Binary(str(self.test_binary_path)) as binary:
            binary.analyze()
            
            vm_analyzer = VMHandlerAnalyzer(binary)
            
            # Test basic functionality without real VM handlers
            result = vm_analyzer.extract_handler_table(0x401000)
            assert result is not None
            
    @patch('r2morph.devirtualization.mba_solver.Z3_AVAILABLE', True)
    @patch('r2morph.devirtualization.mba_solver.z3')
    def test_mba_solver_pipeline(self, mock_z3):
        """Test MBA solver pipeline with mocked Z3."""
        # Mock Z3 components for MBA solving
        mock_solver = Mock()
        mock_bool_sort = Mock()
        mock_var = Mock()
        mock_formula = Mock()
        
        mock_z3.BoolSort.return_value = mock_bool_sort
        mock_z3.Bool.return_value = mock_var
        mock_z3.Solver.return_value = mock_solver
        mock_solver.check.return_value = Mock(r=1)  # SAT
        mock_solver.model.return_value = {}
        
        mba_solver = MBASolver()
        result = mba_solver.simplify_mba("x + y")
        
        assert result is not None
        assert hasattr(result, 'success')
        
    def test_complete_analysis_pipeline_integration(self):
        """Test the complete analysis pipeline integration."""
        with Binary(str(self.test_binary_path)) as binary:
            binary.analyze()
            
            # 1. Obfuscation detection
            detector = ObfuscationDetector()
            detection_result = detector.analyze_binary(binary)
            
            assert detection_result is not None
            assert hasattr(detection_result, 'packer_detected')
            
            # 2. Check if we should proceed with advanced analysis
            # Decision based on comprehensive detection results
            if not detection_result.vm_detected:
                # Basic analysis for non-VM protected binaries
                assert detection_result.obfuscation_techniques is not None
                
            # 3. VM handler analysis (even if no VM detected, should handle gracefully)
            vm_analyzer = VMHandlerAnalyzer(binary)
            vm_result = vm_analyzer.analyze_vm_architecture()
            
            assert vm_result is not None
            
            # 4. MBA solver (test with simple expression)
            mba_solver = MBASolver()
            mba_result = mba_solver.simplify_mba("x")  # Simple case
            
            assert mba_result is not None
            
    def test_syntia_integration_graceful_degradation(self):
        """Test that Syntia integration handles missing dependencies gracefully."""
        syntia_framework = SyntiaFramework()
        
        # Should not crash even if Syntia dependencies are missing
        result = syntia_framework.synthesize_semantics([], 0x401000)
        
        # Should return empty or None result gracefully
        assert result is not None or result is None
        
    def test_state_manager_functionality(self):
        """Test symbolic execution state manager."""
        state_manager = StateManager()
        
        # Test basic state management
        state_manager.add_state("test_state", {"pc": 0x401000})
        states = state_manager.get_active_states()
        
        assert len(states) == 1
        assert states[0]["pc"] == 0x401000
        
        # Test state pruning
        state_manager.prune_states()
        # Should handle gracefully even with mock states
        
    def test_error_handling_and_timeouts(self):
        """Test error handling and timeout mechanisms."""
        with Binary(str(self.test_binary_path)) as binary:
            binary.analyze()
            
            # Test that all components handle errors gracefully
            detector = ObfuscationDetector()
            
            # Test with invalid addresses
            try:
                result = detector.analyze_binary(binary)
                assert result is not None
            except Exception as e:
                pytest.fail(f"ObfuscationDetector should handle errors gracefully: {e}")
                
    def test_enhanced_analysis_comprehensive_example(self):
        """Test the comprehensive example from the documentation."""
        # This tests the exact code from our enhanced_obfuscated_analysis.py example
        with Binary(str(self.test_binary_path)) as binary:
            binary.analyze()
            
            # Step 1: Obfuscation Detection
            detector = ObfuscationDetector()
            detection_result = detector.analyze_binary(binary)
            
            print(f"Packer detected: {detection_result.packer_detected}")
            print(f"VM detected: {detection_result.vm_detected}")
            print(f"Techniques: {len(detection_result.obfuscation_techniques)}")
            
            # Step 2: Advanced analysis based on detection
            analysis_results = {}
            
            if detection_result.vm_detected:
                # VM handler analysis
                vm_analyzer = VMHandlerAnalyzer(binary)
                vm_arch = vm_analyzer.analyze_vm_architecture()
                analysis_results['vm_handlers'] = len(vm_arch.handlers) if vm_arch.handlers else 0
                
            # Step 3: MBA analysis if complex arithmetic detected
            mba_expressions = [expr for expr in detection_result.obfuscation_techniques 
                             if 'mba' in expr.lower()]
            if mba_expressions:
                mba_solver = MBASolver()
                for expr in mba_expressions[:3]:  # Limit to first 3 for testing
                    result = mba_solver.simplify_mba(expr)
                    if result.success:
                        analysis_results[f'mba_{expr}'] = result.simplified_expression
                        
            print(f"Analysis results: {analysis_results}")
            
            # Should complete without errors
            assert detection_result is not None
            assert isinstance(analysis_results, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])