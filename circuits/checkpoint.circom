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
    signal input oldValidatorSet[old];
    signal input newValidatorSet[new];
    signal input checkpoint[3];         // checkpoint = (oldhash, newhash, checkpointRoot)

    component oldValidatorSetHash = Poseidon(old);
    for (var i = 0; i < old; i++){
        oldValidatorSetHash.inputs[i] <== oldValidatorSet[i];
    }
    component newValidatorSetHash = Poseidon(new);
    for (var i = 0; i < new; i++){
        newValidatorSetHash.inputs[i] <== newValidatorSet[i];
    }
    
    checkpoint[0] === oldValidatorSetHash.out;
    checkpoint[1] === newValidatorSetHash.out;

    // Verify signature
    signal output out;
    out <== 1;
}

component main {
    public [checkpoint]
    } = VerifyCheckpoint(5, 5);

    