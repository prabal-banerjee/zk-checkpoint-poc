const chai = require("chai");
const path = require("path");

const wasm_tester = require("circom_tester").wasm;

const buildPoseidon = require("circomlibjs").buildPoseidon;

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


describe("simple poseidon test", function () {
    let circuit;
    let F;

    this.timeout(100000);

    before( async () => {
        poseidon = await buildPoseidon();
        F = poseidon.F;
        circuit = await wasm_tester(path.join(__dirname, "circuits", "simple_poseidon_test.circom"));
    });
    after(async () => {
        globalThis.curve_bn128.terminate();
    });

    it("Poseidon Hash computation", async () => {

        var sampleSet = [1,2,3,4,5];

        var sampleSetHash = F.toObject(poseidon(sampleSet));
        console.log(sampleSetHash);

        const w = await circuit.calculateWitness({
            sampleSet: sampleSet, 
            sampleSetHash: sampleSetHash
        }, true);

        await circuit.checkConstraints(w);
    });
});
