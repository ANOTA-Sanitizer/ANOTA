import sys

def sink(x):
    print(f"Sink called with {x}")

def sanitizer(x):
    return x

def test_binary_op():
    print("Testing binary op propagation...")
    a = 10
    ANOTA_TAINT(a, Sink=[sink])
    b = a + 5
    try:
        sink(b)
        print("FAIL: Sink did not raise error for binary op result")
    except RuntimeError as e:
        print(f"SUCCESS: Sink raised error: {e}")

def test_inplace_op():
    print("Testing inplace op propagation...")
    a = 10
    print(f"Type of a: {type(a)}")
    print(f"Type of sink: {type(sink)}")
    try:
        hash(sink)
        print("sink is hashable")
    except TypeError:
        print("sink is NOT hashable")
    
    ANOTA_TAINT(a, Sink=[sink])
    a += 5
    try:
        sink(a)
        print("FAIL: Sink did not raise error for inplace op result")
    except RuntimeError as e:
        print(f"SUCCESS: Sink raised error: {e}")

def test_function_call_propagation():
    print("Testing function call propagation...")
    a = 10
    ANOTA_TAINT(a, Sink=[sink])
    
    def add_five(x):
        return x + 5
    
    b = add_five(a)
    try:
        sink(b)
        print("FAIL: Sink did not raise error for function call result")
    except RuntimeError as e:
        print(f"SUCCESS: Sink raised error: {e}")

def test_sanitizer():
    print("Testing sanitizer...")
    a = 10
    ANOTA_TAINT(a, sanitization=[sanitizer], Sink=[sink])
    
    b = sanitizer(a)
    try:
        sink(b)
        print("SUCCESS: Sink did not raise error for sanitized result")
    except RuntimeError as e:
        print(f"FAIL: Sink raised error for sanitized result: {e}")

if __name__ == "__main__":
    try:
        test_binary_op()
        test_inplace_op()
        test_function_call_propagation()
        test_sanitizer()
    except NameError:
        print("ANOTA_TAINT not available (not running in ANOTA interpreter?)")
