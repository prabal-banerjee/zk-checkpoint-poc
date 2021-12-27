pragma circom 2.0.0;

// Using Poseidon hash function
include "../../circuits/poseidon.circom";

template simpleHash(size){
    signal input sampleSet[size];
    signal input sampleSetHash;         

    log(sampleSetHash);

    component sampleSetHashGeneration = Poseidon(size);
    for (var i = 0; i < size; i++){
        sampleSetHashGeneration.inputs[i] <== sampleSet[i];
    }
    log(sampleSetHashGeneration.out);
    
    sampleSetHash === sampleSetHashGeneration.out;
}

component main = simpleHash(5);