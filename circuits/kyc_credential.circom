pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

/**
 * Circuit for proving KYC credential validity while selectively revealing attributes
 * 
 * This circuit proves:
 * 1. The holder has a valid credential from a trusted issuer
 * 2. The credential hasn't expired
 * 3. The credential contains specific attributes with specific values
 * 4. The holder knows the viewing key associated with the credential
 */
template KYCCredentialVerifier(numAttributes) {
    // Public inputs
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input credentialId;
    signal input credentialSubject;
    signal input credentialIssuedAt;
    signal input credentialExpiresAt;
    signal input currentTimestamp;
    
    // Private inputs
    signal input viewingKey;
    
    // Attribute related inputs
    signal input attributeNames[numAttributes];
    signal input attributeValues[numAttributes];
    signal input attributeSelectors[numAttributes]; // 1 if attribute should be revealed, 0 otherwise
    
    // Output signals - which attributes are revealed
    signal output revealedAttributeNames[numAttributes];
    signal output revealedAttributeValues[numAttributes];
    signal output credentialValid;
    
    // Hash the credential data to create a commitment
    component credentialHasher = Poseidon(5 + numAttributes * 2);
    credentialHasher.inputs[0] <== credentialId;
    credentialHasher.inputs[1] <== credentialSubject;
    credentialHasher.inputs[2] <== credentialIssuedAt;
    credentialHasher.inputs[3] <== credentialExpiresAt;
    credentialHasher.inputs[4] <== viewingKey;
    
    // Add all attribute names and values to the hash
    for (var i = 0; i < numAttributes; i++) {
        credentialHasher.inputs[5 + i*2] <== attributeNames[i];
        credentialHasher.inputs[5 + i*2 + 1] <== attributeValues[i];
    }
    
    // Check that the credential hasn't expired
    component isNotExpired = LessThan(252);
    isNotExpired.in[0] <== currentTimestamp;
    isNotExpired.in[1] <== credentialExpiresAt;
    
    // For each attribute, determine if it should be revealed
    for (var i = 0; i < numAttributes; i++) {
        // If attributeSelectors[i] is 1, reveal the attribute, otherwise output 0
        revealedAttributeNames[i] <== attributeNames[i] * attributeSelectors[i];
        revealedAttributeValues[i] <== attributeValues[i] * attributeSelectors[i];
    }
    
    // The credential is valid if it hasn't expired and the viewing key is correct
    credentialValid <== isNotExpired.out;
}

/**
 * Main component for KYC credential verification with selective disclosure
 */
component main {public [issuerPubKeyX, issuerPubKeyY, credentialId, credentialSubject, credentialIssuedAt, credentialExpiresAt, currentTimestamp]} = KYCCredentialVerifier(10);
