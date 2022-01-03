pragma circom 2.0.0;

include "poseidon.circom";  // For using Poseidon hash function
include "eddsaposeidon.circom";     // For signature verification

// Template to verify a new checkpoint 
// Idea: Hash old validator set (pk of validators) and new validator set. 
//       Check if 2/3+1 has signed new validator set
// Validator Set format: (validator public key x coord, validator public key y coord, weight)
// TODO: fix checkpoint (now = oldValidatorSetHash, ideal = new val set hash & chain state root)
template VerifyCheckpoint(oldValidatorSetSize, newValidatorSetSize){
    // Input: Old Validator set -> (pk_x, pk_y, weight) * (size of val set)
    signal input oldValidatorSet[oldValidatorSetSize * 3];
    // signal input newValidatorSet[newValidatorSetSize * 2];
    // signal input checkpoint[3];         // checkpoint = (oldhash, newhash, checkpointRoot)
    signal input checkpoint;         

    component oldValidatorSetHash = Poseidon(oldValidatorSetSize * 3);
    for (var i = 0; i < oldValidatorSetSize * 3; i += 3){
        oldValidatorSetHash.inputs[i] <== oldValidatorSet[i];
        oldValidatorSetHash.inputs[i+1] <== oldValidatorSet[i+1];
        oldValidatorSetHash.inputs[i+2] <== oldValidatorSet[i+2];
    }
    
    checkpoint === oldValidatorSetHash.out;

    // Verify signature
    component ValidatorSigCheck[oldValidatorSetSize];

    signal input validatorsR8x[oldValidatorSetSize];
    signal input validatorsR8y[oldValidatorSetSize];
    signal input validatorsS[oldValidatorSetSize];
    signal input validatorsIsSigned[oldValidatorSetSize];

    var weight_total = 0;
    var weight_signed = 0;

    for (var i = 0; i < oldValidatorSetSize; i++){
        ValidatorSigCheck[i] = EdDSAPoseidonVerifier();
        assert(validatorsIsSigned[i] * (validatorsIsSigned[i]-1) == 0 );
        ValidatorSigCheck[i].enabled <== validatorsIsSigned[i];
        weight_signed += oldValidatorSet[i*3 + 2] * validatorsIsSigned[i];
        weight_total += oldValidatorSet[i*3 + 2];
        ValidatorSigCheck[i].Ax <== oldValidatorSet[i*3];
        ValidatorSigCheck[i].Ay <== oldValidatorSet[i*3 + 1];
        ValidatorSigCheck[i].R8x <== validatorsR8x[i];
        ValidatorSigCheck[i].R8y <== validatorsR8y[i];
        ValidatorSigCheck[i].S <== validatorsS[i];
        ValidatorSigCheck[i].M <== checkpoint;
    }
    
    // Check 2/3+1 of weight has signed checkpoint
    assert((weight_total * 2)/3 + 1 <= weight_signed);

}


    