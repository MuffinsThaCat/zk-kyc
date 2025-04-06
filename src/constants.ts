/**
 * Constants for secure parameter handling
 * These provide size limits for various parameters to ensure safe handling
 * Following principles from the Wasmlanche work on parameter validation
 */

/**
 * Maximum sizes for various parameters in bytes or characters
 * Used for input validation to prevent buffer overflows and memory issues
 */
export const MAX_PARAMETER_SIZES = {
  // Credential parameter size limits
  CREDENTIAL_ID: 128,           // Maximum credential ID length
  ISSUER_ID: 64,                // Maximum issuer ID length
  SUBJECT_ID: 64,               // Maximum subject ID length
  ATTRIBUTE_NAME: 64,           // Maximum attribute name length
  ATTRIBUTE_VALUE: 1024,        // Maximum attribute value length
  ATTRIBUTE_ARRAY: 100,         // Maximum number of attributes in an array
  PROOF_VALUE: 2048,            // Maximum proof value length
  
  // Storage parameter size limits
  ENCRYPTED_DATA: 1024 * 1024,  // 1MB maximum encrypted data size
  PASSWORD: 128,                // Maximum password length
  
  // Request parameter size limits
  REQUEST_BODY: 1024 * 1024,    // 1MB maximum request body size
  
  // Generic limits
  MAX_ARRAY_LENGTH: 1000,       // Maximum length for any array
  MAX_STRING_LENGTH: 10000      // Maximum length for any string
};

/**
 * Default values for various parameters
 * Used as fallbacks when input validation fails
 */
export const DEFAULT_VALUES = {
  // Default credential values
  DEFAULT_CREDENTIAL_ID: '',
  DEFAULT_ISSUER_ID: '',
  
  // Default attribute set
  DEFAULT_ATTRIBUTES: {},
  
  // Default proof values
  DEFAULT_PROOF_VALUE: '',
  
  // Default array values
  EMPTY_ARRAY: [],
  EMPTY_OBJECT: {}
};

/**
 * Safe validation functions for different parameter types
 */
export const validateAttributeArray = (attributes: string[]): string[] => {
  if (!Array.isArray(attributes)) {
    return [];
  }
  
  // Apply size limit
  if (attributes.length > MAX_PARAMETER_SIZES.ATTRIBUTE_ARRAY) {
    attributes = attributes.slice(0, MAX_PARAMETER_SIZES.ATTRIBUTE_ARRAY);
  }
  
  // Filter out invalid attribute names
  return attributes.filter(attr => {
    if (typeof attr !== 'string') return false;
    if (attr.length > MAX_PARAMETER_SIZES.ATTRIBUTE_NAME) return false;
    return true;
  });
};
