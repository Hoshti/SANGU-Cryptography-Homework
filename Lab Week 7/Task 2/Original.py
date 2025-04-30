def factorial(n):
    """
    Calculates the factorial of a non-negative integer n.
    Factorial(n) = n * (n-1) * ... * 1
    """
    if not isinstance(n, int) or n < 0:
        raise ValueError("Factorial requires a non-negative integer input.")
    elif n == 0 or n == 1:
        return 1
    else:
        result = 1
        # Loop from 2 up to n (inclusive)
        for i in range(2, n + 1):
            result *= i # Multiply result by the current number
        return result