// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title KYCVerifier
 * @dev Contract for verifying zero-knowledge proofs of KYC credentials
 * This contract works with the Nocturne privacy system
 */
// Import the Groth16 verifier interface
import "./KYCGroth16Verifier.sol";

contract KYCVerifier {
    // The admin who can update verifier keys and trusted issuers
    address public admin;
    
    // The address of the Groth16 verifier contract
    KYCGroth16Verifier public groth16Verifier;
    
    // Mapping of trusted KYC issuers
    mapping(address => bool) public trustedIssuers;
    
    // Mapping to track verified users (address => isVerified)
    mapping(address => bool) public verifiedUsers;
    
    // Mapping to track user attribute flags (address => attributeHash => isTrue)
    mapping(address => mapping(bytes32 => bool)) public userAttributes;
    
    // Events
    event KYCVerified(address indexed user, bytes32 proofHash);
    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event VerifierChanged(address indexed oldVerifier, address indexed newVerifier);
    event AttributeVerified(address indexed user, string attributeName, bool value);

    /**
     * @dev Constructor sets the admin and initial trusted issuers
     * @param _admin Address of the admin
     * @param _initialIssuers Array of initial trusted issuer addresses
     */
    constructor(address _admin, address[] memory _initialIssuers, address _verifierAddress) {
        require(_admin != address(0), "Invalid admin address");
        require(_verifierAddress != address(0), "Invalid verifier address");
        admin = _admin;
        groth16Verifier = KYCGroth16Verifier(_verifierAddress);
        
        for (uint i = 0; i < _initialIssuers.length; i++) {
            trustedIssuers[_initialIssuers[i]] = true;
            emit IssuerAdded(_initialIssuers[i]);
        }
    }
    
    /**
     * @dev Modifier to restrict functions to admin only
     */
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }
    
    /**
     * @dev Change the admin address
     * @param _newAdmin The address of the new admin
     */
    function changeAdmin(address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "Invalid admin address");
        emit AdminChanged(admin, _newAdmin);
        admin = _newAdmin;
    }
    
    /**
     * @dev Add a trusted issuer
     * @param _issuer The address of the issuer to add
     */
    function addTrustedIssuer(address _issuer) external onlyAdmin {
        require(_issuer != address(0), "Invalid issuer address");
        trustedIssuers[_issuer] = true;
        emit IssuerAdded(_issuer);
    }
    
    /**
     * @dev Remove a trusted issuer
     * @param _issuer The address of the issuer to remove
     */
    function removeTrustedIssuer(address _issuer) external onlyAdmin {
        require(trustedIssuers[_issuer], "Issuer not trusted");
        trustedIssuers[_issuer] = false;
        emit IssuerRemoved(_issuer);
    }
    
    /**
     * @dev Update the Groth16 verifier contract address
     * @param _newVerifier Address of the new verifier contract
     */
    function updateVerifier(address _newVerifier) external onlyAdmin {
        require(_newVerifier != address(0), "Invalid verifier address");
        // Prevent redundant updates
        require(_newVerifier != address(groth16Verifier), "Verifier already set to this address");
        
        address oldVerifier = address(groth16Verifier);
        groth16Verifier = KYCGroth16Verifier(_newVerifier);
        emit VerifierChanged(oldVerifier, _newVerifier);
    }
    
    /**
     * @dev External function to verify a KYC proof
     * @param _proof Array containing the zk-SNARK proof data
     * @param _publicSignals Array containing the public signals for the proof
     * @param _revealedAttributes Array of strings containing revealed attributes in "key:value" format
     * @return Whether the verification was successful
     */
    function verifyKYCProof(
        uint256[] calldata _proof,
        uint256[] calldata _publicSignals,
        string[] calldata _revealedAttributes
    ) external returns (bool) {
        // Get the issuer address from the public signals
        address issuer = address(uint160(_publicSignals[0]));
        
        // Verify the issuer is trusted
        require(trustedIssuers[issuer], "Untrusted KYC issuer");
        
        // Verify the zkSNARK proof
        bool isValid = verifyProof(_proof, _publicSignals);
        require(isValid, "Invalid KYC proof");
        
        // Mark user as verified
        verifiedUsers[msg.sender] = true;
        
        // Process revealed attributes
        processRevealedAttributes(msg.sender, _revealedAttributes);
        
        // Generate a hash of the proof for the event
        bytes32 proofHash = keccak256(abi.encodePacked(_proof, _publicSignals));
        emit KYCVerified(msg.sender, proofHash);
        
        return true;
    }
    
    /**
     * @dev Process and store revealed attributes
     * @param _user Address of the user
     * @param _revealedAttributes Array of strings containing revealed attributes in "key:value" format
     */
    function processRevealedAttributes(
        address _user,
        string[] calldata _revealedAttributes
    ) internal {
        for (uint i = 0; i < _revealedAttributes.length; i++) {
            // Parse the attribute string (format: "key:value")
            (string memory key, string memory value) = parseAttribute(_revealedAttributes[i]);
            
            // For boolean attributes (e.g., "over18:true")
            if (compareStrings(value, "true") || compareStrings(value, "false")) {
                bool boolValue = compareStrings(value, "true");
                bytes32 attrHash = keccak256(abi.encodePacked(key));
                userAttributes[_user][attrHash] = boolValue;
                emit AttributeVerified(_user, key, boolValue);
            }
            // Other attribute types can be handled similarly
        }
    }
    
    /**
     * @dev Check if a user has a specific boolean attribute
     * @param _user Address of the user
     * @param _attributeName Name of the attribute to check
     * @return Whether the attribute is true for the user
     */
    function hasAttribute(address _user, string calldata _attributeName) external view returns (bool) {
        require(verifiedUsers[_user], "User not KYC verified");
        bytes32 attrHash = keccak256(abi.encodePacked(_attributeName));
        return userAttributes[_user][attrHash];
    }
    
    /**
     * @dev Check if a user is KYC verified
     * @param _user Address of the user
     * @return Whether the user is verified
     */
    function isUserVerified(address _user) external view returns (bool) {
        return verifiedUsers[_user];
    }
    
    /**
     * @dev Parse an attribute string in format "key:value"
     * @param _attribute The attribute string to parse
     * @return key The attribute key
     * @return value The attribute value
     */
    function parseAttribute(string calldata _attribute) internal pure returns (string memory, string memory) {
        bytes memory attributeBytes = bytes(_attribute);
        uint colonPos = 0;
        
        // Find position of colon
        for (uint i = 0; i < attributeBytes.length; i++) {
            if (attributeBytes[i] == bytes1(":")) {
                colonPos = i;
                break;
            }
        }
        
        require(colonPos > 0 && colonPos < attributeBytes.length - 1, "Invalid attribute format");
        
        // Extract key and value
        string memory key = substring(_attribute, 0, colonPos);
        string memory value = substring(_attribute, colonPos + 1, attributeBytes.length - colonPos - 1);
        
        return (key, value);
    }
    
    /**
     * @dev Extract a substring from a string
     * @param _str The original string
     * @param _startIndex The starting index
     * @param _length The length of the substring
     * @return The extracted substring
     */
    function substring(string calldata _str, uint _startIndex, uint _length) internal pure returns (string memory) {
        bytes memory strBytes = bytes(_str);
        bytes memory result = new bytes(_length);
        
        for (uint i = 0; i < _length; i++) {
            result[i] = strBytes[_startIndex + i];
        }
        
        return string(result);
    }
    
    /**
     * @dev Compare two strings for equality
     * @param a First string
     * @param b Second string
     * @return Whether the strings are equal
     */
    function compareStrings(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
    
    /**
     * @dev Verify a zkSNARK proof
     * @param _proof The proof data
     * @param _publicSignals The public signals
     * @return Whether the proof is valid
     */
    function verifyProof(
        uint256[] calldata _proof,
        uint256[] calldata _publicSignals
    ) internal view returns (bool) {
        // Ensure the proof has the correct structure for our Groth16 verifier
        require(_proof.length == 8, "Invalid proof structure");
        require(_publicSignals.length >= 1, "Invalid public signals");
        
        // Bounds check all parameters to ensure safe handling
        for (uint i = 0; i < _proof.length; i++) {
            require(_proof[i] < KYCGroth16Verifier.PRIME_Q, "Proof value exceeds field size");
        }
        
        for (uint i = 0; i < _publicSignals.length; i++) {
            require(_publicSignals[i] < KYCGroth16Verifier.PRIME_Q, "Public signal exceeds field size");
        }
        
        // Convert the format from flattened array to the structures expected by the verifier
        uint[2] memory a = [_proof[0], _proof[1]];
        uint[2][2] memory b = [
            [_proof[2], _proof[3]],
            [_proof[4], _proof[5]]
        ];
        uint[2] memory c = [_proof[6], _proof[7]];
        
        // Create a copy of public signals (excluding the issuer address)
        uint[] memory publicInputs = new uint[](_publicSignals.length - 1);
        for (uint i = 1; i < _publicSignals.length; i++) {
            publicInputs[i - 1] = _publicSignals[i];
        }
        
        // Call the Groth16 verifier contract
        return groth16Verifier.verify(a, b, c, publicInputs);
    }
}
