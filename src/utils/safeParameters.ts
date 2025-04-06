/**
 * Utility functions for safe parameter handling across the application
 */
export class SafeParameters {
  /**
   * Maximum reasonable parameter length for general string inputs
   */
  private static readonly MAX_STRING_LENGTH = 1024;
  
  /**
   * Maximum reasonable parameter length for large binary data
   */
  private static readonly MAX_BINARY_LENGTH = 1024 * 1024; // 1MB
  
  /**
   * Check that a string parameter is valid and has a safe length
   * @param value The string to validate
   * @param maxLength Maximum allowed length (defaults to MAX_STRING_LENGTH)
   * @returns The validated string
   * @throws Error if validation fails
   */
  static validateString(value: unknown, maxLength = this.MAX_STRING_LENGTH): string {
    // Type check
    if (typeof value !== 'string') {
      throw new Error('Expected string parameter');
    }
    
    // Length check
    if (value.length > maxLength) {
      throw new Error(`Parameter exceeds maximum safe length (${maxLength} characters)`);
    }
    
    return value;
  }
  
  /**
   * Check that an array parameter is valid and has a safe length
   * @param value The array to validate
   * @param maxLength Maximum allowed length
   * @returns The validated array
   * @throws Error if validation fails
   */
  static validateArray<T>(value: unknown, maxLength = 100): T[] {
    // Type check
    if (!Array.isArray(value)) {
      throw new Error('Expected array parameter');
    }
    
    // Length check
    if (value.length > maxLength) {
      throw new Error(`Array exceeds maximum safe length (${maxLength} elements)`);
    }
    
    return value as T[];
  }
  
  /**
   * Check that a buffer parameter is valid and has a safe length
   * @param value The buffer to validate
   * @param maxLength Maximum allowed length (defaults to MAX_BINARY_LENGTH)
   * @returns The validated buffer
   * @throws Error if validation fails
   */
  static validateBuffer(value: unknown, maxLength = this.MAX_BINARY_LENGTH): Buffer {
    // Type check
    if (!Buffer.isBuffer(value)) {
      throw new Error('Expected Buffer parameter');
    }
    
    // Length check
    if (value.length > maxLength) {
      throw new Error(`Buffer exceeds maximum safe length (${maxLength} bytes)`);
    }
    
    return value;
  }
  
  /**
   * Check that a number parameter is valid and within safe bounds
   * @param value The number to validate
   * @param min Minimum allowed value
   * @param max Maximum allowed value
   * @returns The validated number
   * @throws Error if validation fails
   */
  static validateNumber(value: unknown, min = -Number.MAX_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER): number {
    // Type check
    if (typeof value !== 'number' || isNaN(value)) {
      throw new Error('Expected number parameter');
    }
    
    // Range check
    if (value < min || value > max) {
      throw new Error(`Number out of allowed range (${min} - ${max})`);
    }
    
    return value;
  }
  
  /**
   * Check that an integer parameter is valid and within safe bounds
   * @param value The integer to validate
   * @param min Minimum allowed value
   * @param max Maximum allowed value
   * @returns The validated integer
   * @throws Error if validation fails
   */
  static validateInteger(value: unknown, min = -Number.MAX_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER): number {
    const num = this.validateNumber(value, min, max);
    
    // Integer check
    if (!Number.isInteger(num)) {
      throw new Error('Expected integer parameter');
    }
    
    return num;
  }
  
  /**
   * Shortens an Ethereum address for display in logs
   * @param address Ethereum address to shorten
   * @returns Shortened address (e.g., 0x1234...5678)
   */
  static shortenAddress(address: string): string {
    if (!address || typeof address !== 'string' || address.length < 10) {
      return 'invalid-address';
    }
    
    return `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
  }
}
