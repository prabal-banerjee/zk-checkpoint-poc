const chai = require("chai");
const path = require("path");
const crypto = require("crypto");

const wasm_tester = require("circom_tester").wasm;

const buildEddsa = require("circomlibjs").buildEddsa;
const buildBabyjub = require("circomlibjs").buildBabyjub;
const buildPoseidon = require("circomlibjs").buildPoseidon;

const assert = chai.assert;

describe("checkpoint verification test", function () {
    let circuit;
    let F;

    this.timeout(100000);

    before( async () => {
        eddsa = await buildEddsa();
        babyJub = await buildBabyjub();
        poseidon = await buildPoseidon();
        F = poseidon.F;
        circuit = await wasm_tester(path.join(__dirname, "circuits", "checkpoint_test.circom"));
    });
    after(async () => {
        // globalThis.curve_bn128.terminate();
    });

    it("Successful checkpoint - 5 validators - all sign correctly", async () => 
        checkpointGenerate(F, circuit, poseidon, eddsa, 5, [1,2,3,4,5], [1,1,1,1,1])
    );
    it("Successful checkpoint - 5 validators - >2/3 sign", async () => 
        checkpointGenerate(F, circuit, poseidon, eddsa, 5, [1,2,3,4,5], [0,0,1,1,1])
    );
    it("Failed checkpoint - 5 validators - <=2/3 sign", async () => {
        try {
            checkpointGenerate(F, circuit, poseidon, eddsa, 5, [1,2,3,4,5], [1,1,1,1,0]);
        } catch(err) {
	        assert(err.message.includes("Assert Failed"));
        }
    });
});

async function checkpointGenerate(F, circuit, poseidon, eddsa, SIZE, validatorWeights, validatorsIsSigned){

    var oldValidatorSet = [];
    var oldValidatorSetPvtKeys = [];
    var oldValidatorSetWeights = validatorWeights;

    for(var i=0; i<SIZE; i++) {
        var prvKey = crypto.randomBytes(32);
        oldValidatorSetPvtKeys.push(prvKey);

        var pubKey = eddsa.prv2pub(prvKey);
        var pubKeyX = F.toObject(pubKey[0]);
        var pubKeyY = F.toObject(pubKey[1]);
        oldValidatorSet.push(pubKeyX);
        oldValidatorSet.push(pubKeyY);
        oldValidatorSet.push(oldValidatorSetWeights[i]);
    }
    // console.log(oldValidatorSet);

    var newValidatorSet = [];
    var newValidatorSetPvtKeys = [];
    var newValidatorSetWeights = [5,4,3,2,1];

    for(var i=0; i<SIZE; i++) {
        var prvKey = crypto.randomBytes(32);
        newValidatorSetPvtKeys.push(prvKey);

        var pubKey = eddsa.prv2pub(prvKey);
        var pubKeyX = F.toObject(pubKey[0]);
        var pubKeyY = F.toObject(pubKey[1]);
        newValidatorSet.push(pubKeyX);
        newValidatorSet.push(pubKeyY);
        newValidatorSet.push(newValidatorSetWeights[i]);
    }
    // console.log(newValidatorSet);

    var oldValidatorSetHash = poseidon(oldValidatorSet);
    var newValidatorSetHash = poseidon(newValidatorSet);
    var checkpoint = poseidon([0]);       // sample state root

    // Sign hash(checkpoint, newValidatorSetHash) by oldValidatorSet
    var msg = poseidon([checkpoint, newValidatorSetHash]);
    var validatorsSignature = [];
    var validatorsR8x = [];
    var validatorsR8y = [];
    for(var i=0; i<SIZE; i++){
        var signature = eddsa.signPoseidon(oldValidatorSetPvtKeys[i], msg);
        assert(eddsa.verifyPoseidon(msg, signature, eddsa.prv2pub(oldValidatorSetPvtKeys[i])));

        validatorsSignature.push(signature.S);
        validatorsR8x.push(F.toObject(signature.R8[0]));
        validatorsR8y.push(F.toObject(signature.R8[1]));
    }

    // var validatorsIsSigned = [1,1,1,1,1];

    const w = await circuit.calculateWitness({
        oldValidatorSet: oldValidatorSet, 
        newValidatorSet: newValidatorSet, 
        checkpoint: F.toObject(checkpoint),
        oldValidatorSetHashInput: F.toObject(oldValidatorSetHash),
        newValidatorSetHashInput: F.toObject(newValidatorSetHash),
        validatorsR8x: validatorsR8x,
        validatorsR8y: validatorsR8y,
        validatorsS: validatorsSignature,
        validatorsIsSigned: validatorsIsSigned
    }, true);

    await circuit.checkConstraints(w);
}