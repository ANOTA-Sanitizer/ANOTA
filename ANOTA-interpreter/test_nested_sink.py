#!/usr/bin/env python3
"""Exercise taint propagation through a nested helper and sink."""

def sink(x):
    """Sink used by this smoke test."""
    print(f"Sink called with: {x}")

def process_data(data):
    """Forward data to the sink to mimic a nested call."""
    print(f"Processing data: {data}")
    # Direct sink call; expected to fail if data is tainted.
    sink(data)
    print("Processing completed successfully")

def main():
    print("=" * 60)
    print("Test: Taint propagation through function argument to sink")
    print("=" * 60)
    
    # Prepare a tainted input.
    tainted_value = 42
    ANOTA_TAINT(tainted_value, Sink=[sink])
    print(f"✓ Marked {tainted_value} as tainted with sink={sink.__name__}")
    
    print("\nCalling process_data(tainted_value)...")
    print("Expected: RuntimeError should be raised when sink() is called inside process_data()")
    print()
    
    try:
        process_data(tainted_value)
        print("\n❌ FAIL: No error was raised!")
        print("   The taint analysis did NOT detect the violation.")
    except RuntimeError as e:
        print(f"\n✅ SUCCESS: RuntimeError was raised as expected!")
        print(f"   Error message: {e}")
        print("   The taint analysis correctly detected that:")
        print("   1. tainted_value was passed to process_data()")
        print("   2. Inside process_data(), the tainted argument was passed to sink()")
        print("   3. This violated the taint policy and raised an error")

if __name__ == "__main__":
    try:
        main()
    except NameError as e:
        print(f"Error: {e}")
        print("This script requires the ANOTA interpreter with ANOTA_TAINT support.")
