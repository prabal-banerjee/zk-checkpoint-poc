pragma circom 2.0.0;

// Using Poseidon hash function
include "./poseidon.circom";

// Build a Merkle tree where leaves are pk of validators
// n: number of validators
// input: public keys of n validators
// TODO: add weight. this version assumes all validators equally staked. 
// template ValidatorMerkleTree(n){
//     signal input in[n];
//     signal output root; 
// }

// Template to verify a new checkpoint 
// Idea: Hash old validator set (pk of validators) and new validator set. 
//       Check if 2/3+1 has signed new validator set
// old, new: number of validators in last epoch and new epoch respectively
// input: public key of old validator set, public key of new validator set
// TODO: add weights
template VerifyCheckpoint(old, new){
    signal input oldValidatorSet[old*2];
    // signal input newValidatorSet[new];
    // signal input checkpoint[3];         // checkpoint = (oldhash, newhash, checkpointRoot)
    signal input checkpoint;         

    // log(oldValidatorSet[0]);

    component oldValidatorSetHash = Poseidon(old*2);
    for (var i = 0; i < old*2; i+=2){
        oldValidatorSetHash.inputs[i] <== oldValidatorSet[i];
        oldValidatorSetHash.inputs[i+1] <== oldValidatorSet[i+1];
    }
    // component newValidatorSetHash = Poseidon(new);
    // for (var i = 0; i < new; i++){
    //     newValidatorSetHash.inputs[i] <== newValidatorSet[i];
    // }
    // log(checkpoint[0]);
    // log(checkpoint[1]);
    // log(checkpoint[2]);
    log(checkpoint);
    log(oldValidatorSetHash.out);
    
    checkpoint === oldValidatorSetHash.out;
    // checkpoint[1] === newValidatorSetHash.out;

    // Verify signature
    signal output out;
    out <== 1;
}


    