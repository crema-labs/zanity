import { WitnessTester } from "circomkit";
import { circomkit } from "./common";

describe("Zanity", () => {
  let circuit: WitnessTester<
    []
    // ["r", "x", "y", "iv", "s1", "s2", "priv_key"],
    // ["ct_pubkey", "ct", "ct_hmac", "vanity_pubkey"]
  >;
  describe("Zanity", () => {
    before(async () => {
      circuit = await circomkit.WitnessTester(`Zanity`, {
        file: "zanity",
        template: "Zanity",
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("zanity", async () => {
      await circuit.calculateWitness({});
    });
  });
});
