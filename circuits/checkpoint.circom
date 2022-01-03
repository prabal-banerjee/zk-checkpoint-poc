pragma circom 2.0.0;

include "poseidon.circom";  // For using Poseidon hash function
include "eddsaposeidon.circom";     // For signature verification

// Template to verify a new checkpoint 
// Idea: Hash old validator set (pk of validators) and new validator set. 
//       Check if 2/3+1 has signed new validator set
// old, new: number of validators in last epoch and new epoch respectively
// input: public key of old validator set, public key of new validator set
// TODO: fix checkpoint (now = oldValidatorSetHash, ideal = new val set hash +  chain state root)
// TODO: check 2/3+1
// TODO: add weights
template VerifyCheckpoint(oldValidatorSetSize, newValidatorSetSize){
    signal input oldValidatorSet[oldValidatorSetSize * 2];
    // signal input newValidatorSet[newValidatorSetSize * 2];
    // signal input checkpoint[3];         // checkpoint = (oldhash, newhash, checkpointRoot)
    signal input checkpoint;         

    component oldValidatorSetHash = Poseidon(oldValidatorSetSize * 2);
    for (var i = 0; i < oldValidatorSetSize * 2; i += 2){
        oldValidatorSetHash.inputs[i] <== oldValidatorSet[i];
        oldValidatorSetHash.inputs[i+1] <== oldValidatorSet[i+1];
    }
    
    checkpoint === oldValidatorSetHash.out;

    // Verify signature
    component ValidatorSigCheck[oldValidatorSetSize];

    signal input validatorsR8x[oldValidatorSetSize];
    signal input validatorsR8y[oldValidatorSetSize];
    signal input validatorsS[oldValidatorSetSize];

    for (var i = 0; i < oldValidatorSetSize; i++){
        ValidatorSigCheck[i] = EdDSAPoseidonVerifier();
        ValidatorSigCheck[i].enabled <== 1;
        ValidatorSigCheck[i].Ax <== oldValidatorSet[i*2];
        ValidatorSigCheck[i].Ay <== oldValidatorSet[i*2 + 1];
        ValidatorSigCheck[i].R8x <== validatorsR8x[i];
        ValidatorSigCheck[i].R8y <== validatorsR8y[i];
        ValidatorSigCheck[i].S <== validatorsS[i];
        ValidatorSigCheck[i].M <== checkpoint;
    }
    

}


    