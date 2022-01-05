pragma circom 2.0.0;

include "poseidon.circom";  // For using Poseidon hash function
include "eddsaposeidon.circom";     // For signature verification

// Template to verify a new checkpoint 
// Idea: Hash old validator set (pk of validators) and new validator set. 
//       Check if 2/3+1 has signed new validator set and state root.
// Validator Set format: (validator public key x coord, validator public key y coord, weight)
template VerifyCheckpoint(oldValidatorSetSize, newValidatorSetSize){
    // Old Validator set -> (pk_x, pk_y, weight) * (size of val set)
    signal input oldValidatorSet[oldValidatorSetSize * 3];
    signal input newValidatorSet[newValidatorSetSize * 3];
    signal input checkpoint;

    signal input oldValidatorSetHashInput;
    signal input newValidatorSetHashInput;

    // Verify old validator set hash matches the hash of old validator set
    component oldValidatorSetHash = Poseidon(oldValidatorSetSize * 3);
    for (var i = 0; i < oldValidatorSetSize * 3; i += 3){
        oldValidatorSetHash.inputs[i] <== oldValidatorSet[i];
        oldValidatorSetHash.inputs[i+1] <== oldValidatorSet[i+1];
        oldValidatorSetHash.inputs[i+2] <== oldValidatorSet[i+2];
    }
    oldValidatorSetHashInput === oldValidatorSetHash.out;

    // Verify new validator set hash matches the hash of new validator set
    component newValidatorSetHash = Poseidon(newValidatorSetSize * 3);
    for (var i = 0; i < newValidatorSetSize * 3; i += 3){
        newValidatorSetHash.inputs[i] <== newValidatorSet[i];
        newValidatorSetHash.inputs[i+1] <== newValidatorSet[i+1];
        newValidatorSetHash.inputs[i+2] <== newValidatorSet[i+2];
    }
    newValidatorSetHashInput === newValidatorSetHash.out;

    // Calculate message = hash(checkpoint, newValidatorSetHash)
    component msgHasher = Poseidon(2);
    msgHasher.inputs[0] <== checkpoint;
    msgHasher.inputs[1] <== newValidatorSetHashInput;
    var msg = msgHasher.out;

    // Verify signature on the message by old validator set
    component ValidatorSigCheck[oldValidatorSetSize];

    signal input validatorsR8x[oldValidatorSetSize];
    signal input validatorsR8y[oldValidatorSetSize];
    signal input validatorsS[oldValidatorSetSize];
    signal input validatorsIsSigned[oldValidatorSetSize];

    // TODO: Should we check if weight_total is >=x? 
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
        ValidatorSigCheck[i].M <== msg;
    }
    
    // Check 2/3+1 of weight has signed checkpoint
    // TODO: Can there be problem due to rounding off of weights? 
    assert((weight_total * 2)/3 + 1 <= weight_signed);

}


    