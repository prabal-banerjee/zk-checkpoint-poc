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

    let SIZE = 5;

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

    it("Submit a checkpoint", async () => {

        var oldValidatorSet = [];
        var oldValidatorSetPvtKeys = [];
        var oldValidatorSetWeights = [1,2,3,4,5];

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
        console.log(oldValidatorSet);

        // var newValidatorSet = [];

        // for(var i=0; i<5; i++) {
        //     var prvKey = crypto.randomBytes(32);
        //     var pubKey = eddsa.prv2pub(prvKey);
        //     var pubKeyX = F.toObject(pubKey[0]);
        //     var pubKeyY = F.toObject(pubKey[1]);
        //     // var pPubKey = babyJub.packPoint(pubKey);
        //     // var pubKeyBits = buffer2bits(pPubKey);
        //     newValidatorSet.push(pubKeyX);
        //     newValidatorSet.push(pubKeyY);
        // }
        // console.log(newValidatorSet);

        var oldValidatorSetHash = poseidon(oldValidatorSet);
        // var newValidatorSetHash = poseidon(newValidatorSet);
        // var checkpoint = [oldValidatorSetHash, newValidatorSetHash, 0];
        var checkpoint = oldValidatorSetHash;

        // Sign checkpoint
        var validatorsSignature = [];
        var validatorsR8x = [];
        var validatorsR8y = [];
        for(var i=0; i<SIZE; i++){
            var signature = eddsa.signPoseidon(oldValidatorSetPvtKeys[i], checkpoint);
            assert(eddsa.verifyPoseidon(checkpoint, signature, eddsa.prv2pub(oldValidatorSetPvtKeys[i])));

            validatorsSignature.push(signature.S);
            validatorsR8x.push(F.toObject(signature.R8[0]));
            validatorsR8y.push(F.toObject(signature.R8[1]));
        }

        var validatorsIsSigned = [0,1,1,1,1];

        const w = await circuit.calculateWitness({
            oldValidatorSet: oldValidatorSet, 
            // newValidatorSet: newValidatorSet, 
            checkpoint: F.toObject(checkpoint),
            validatorsR8x: validatorsR8x,
            validatorsR8y: validatorsR8y,
            validatorsS: validatorsSignature,
            validatorsIsSigned: validatorsIsSigned
        }, true);

        await circuit.checkConstraints(w);
    });
});
