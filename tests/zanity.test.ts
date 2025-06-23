import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import { getPublicKey, Point } from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

describe("Zanity", () => {
  let circuit: WitnessTester<
    ["r", "x", "y", "iv", "s1", "s2", "priv_key", "vanity"],
    ["ct_pubkey", "ct", "ct_hmac", "vanity_pubkey","matches"]
  >;
  describe("Zanity", () => {
    before(async () => {
      circuit = await circomkit.WitnessTester(`Zanity`, {
        file: "zanity",
        template: "Zanity",
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    const priv_key = "2e40f2393ca9b0f3ecda7df8848782d99ceccf0c151ac1f69fa72f176f13a838";
    const mined_priv_key = "6f3d888dbf78ffaab54a9daee30fb70653bdc7a024db378dff4f56534559a482";
    const priv_key_big = BigInt("0x" + priv_key);
    // const pub_key = Point.fromPrivateKey(Buffer.from(priv_key, "hex"));
    const mined_pub_key = Point.fromPrivateKey(Buffer.from(mined_priv_key, "hex"));

    const iv = [38, 243, 60, 81, 23, 164, 6, 250, 43, 14, 233, 137, 159, 143, 170, 226];

    const s1: number[] = [];
    const s2: number[] = [];

    const r = priv_key;

    it("zanity", async () => {
      await circuit.calculateWitness({
        r: bigint_to_array(8, 32, priv_key_big),
        x: bigint_to_array(8, 32, mined_pub_key.x),
        y: bigint_to_array(8, 32, mined_pub_key.y),
        iv: iv,
        s1: s1,
        s2: s2,
        priv_key: bigint_to_array(8, 32, priv_key_big),
        // vanity: c4e3a5.................
        vanity: [
          0xc4, 0xe3, 0xa5, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e,
          0x2e, 0x2e,
        ],
      });
    });
  });
});

export function bigint_to_array(n: number, k: number, x: bigint) {
  let mod: bigint = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: bigint[] = [];
  var x_temp: bigint = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}
