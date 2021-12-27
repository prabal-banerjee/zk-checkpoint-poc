const chai = require("chai");
const path = require("path");
const crypto = require("crypto");

const wasm_tester = require("circom_tester").wasm;

const buildEddsa = require("circomlibjs").buildEddsa;
const buildBabyjub = require("circomlibjs").buildBabyjub;
const buildPoseidon = require("circomlibjs").buildPoseidon;

const Scalar = require("ffjavascript").Scalar;

const assert = chai.assert;

function buffer2bits(buff) {
    const res = [];
    for (let i=0; i<buff.length; i++) {
        for (let j=0; j<8; j++) {
            if ((buff[i]>>j)&1) {
                res.push(1n);
            } else {
                res.push(0n);
            }
        }
    }
    return res;
}


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

        for(var i=0; i<SIZE; i++) {
            var prvKey = crypto.randomBytes(32);
            var pubKey = eddsa.prv2pub(prvKey);
            var pubKeyX = F.toObject(pubKey[0]);
            var pubKeyY = F.toObject(pubKey[1]);
            // var pPubKey = babyJub.packPoint(pubKey);
            // var pubKeyBits = buffer2bits(pPubKey);
            oldValidatorSet.push(pubKeyX);
            oldValidatorSet.push(pubKeyY);
            // oldValidatorSet.push(pPubKey);
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

        var oldValidatorSetHash = F.toObject(poseidon(oldValidatorSet));
        // var newValidatorSetHash = poseidon(newValidatorSet);
        // var checkpoint = [oldValidatorSetHash, newValidatorSetHash, 0];
        var checkpoint = oldValidatorSetHash;

        console.log("Checkpoint (js): ", checkpoint);

        const w = await circuit.calculateWitness({
            oldValidatorSet: oldValidatorSet, 
            // newValidatorSet: newValidatorSet, 
            checkpoint: checkpoint
        }, true);

        await circuit.checkConstraints(w);
        //assert output
    });
});
